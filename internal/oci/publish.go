package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Pushed names the index digest and the tags confirmed to point at it.
type Pushed struct {
	Digest     string
	Repository string
	References []string
}

// PushError reports a failed push without the library's cause, which can embed
// credentialed URLs. Use errors.As to reach the cause.
type PushError struct {
	Repository string
	cause      error
}

func (e *PushError) Error() string {
	if errors.Is(e, ErrReferrersUnsupported) {
		return fmt.Sprintf("%s: %v", e.Repository, ErrReferrersUnsupported)
	}
	return fmt.Sprintf("push to %s failed (details redacted)", e.Repository)
}

// ErrReferrersUnsupported reports a push that asked a registry to index attachments
// under their subject and found no Referrers API. The tag fallback that would rewrite
// a shared index tag is refused, because a concurrent push to the same subject could
// drop an entry, and because the tags belong to the image.
var ErrReferrersUnsupported = errors.New(
	"registry does not support the Referrers API, so attachments cannot be listed under the image")

// fallbackDisabled is the refusal the registry client returns when it finds no
// Referrers endpoint and is not allowed to rewrite the fallback tag.
const fallbackDisabled = "referrers tag fallback is disabled"

// attachmentPushError reports a failed statement upload, naming the missing Referrers
// API as its own case so the caller can tell it from a transport failure.
func attachmentPushError(repository string, err error) error {
	if strings.Contains(err.Error(), fallbackDisabled) {
		return &PushError{Repository: repository, cause: errors.Join(ErrReferrersUnsupported, err)}
	}
	return &PushError{Repository: repository, cause: err}
}

func (e *PushError) Unwrap() error { return e.cause }

// Push uploads the layout's index, images and layers. If the layout has
// attestations, it uploads the image by digest and attaches them before writing
// any tags. Every reference must be a tag in the same repository. On failure
// while publishing tags, the result lists the tags confirmed before the failure.
func (l *Layout) Push(ctx context.Context, source BlobSource, references []string,
	options ...remote.Option,
) (Pushed, error) {
	if ctx == nil {
		return Pushed{}, errors.New("push context must not be nil")
	}
	if source == nil {
		return Pushed{}, errors.New("push blob source must not be nil")
	}
	targets, repository, err := parseReferences(references)
	if err != nil {
		return Pushed{}, err
	}
	index, err := l.registryIndex(source)
	if err != nil {
		return Pushed{}, err
	}
	digest, err := index.Digest()
	if err != nil {
		return Pushed{}, &PushError{Repository: repository, cause: err}
	}
	if digest.String() != l.Index.Digest {
		return Pushed{}, fmt.Errorf("pushed index %s is not the built index %s", digest, l.Index.Digest)
	}
	// A reused pusher would ignore the fallback setting below.
	options = append(options, remote.WithContext(ctx), remote.Reuse((*remote.Pusher)(nil)),
		remote.WithReferrersTagFallback(false))
	pusher, err := remote.NewPusher(options...)
	if err != nil {
		return Pushed{}, &PushError{Repository: repository, cause: err}
	}
	if err := l.stageAttestedIndex(ctx, pusher, targets[0].Context(), index); err != nil {
		return Pushed{}, err
	}
	pushed := Pushed{Digest: digest.String(), Repository: repository, References: make([]string, 0, len(targets))}
	for _, target := range targets {
		if err := pusher.Push(ctx, target, index); err != nil {
			return pushed, fmt.Errorf("%w: tag %s not confirmed", &PushError{Repository: repository, cause: err}, target)
		}
		pushed.References = append(pushed.References, target.String())
	}
	return pushed, nil
}

// parseReferences turns declared references into upload targets. One repository is
// required because a registry client writes one repository per upload session.
func parseReferences(references []string) ([]name.Tag, string, error) {
	if len(references) == 0 {
		return nil, "", errors.New("push requires at least one reference")
	}
	targets := make([]name.Tag, 0, len(references))
	repository := ""
	for _, reference := range references {
		// Strict parsing refuses both inferences a lenient parse would make: a
		// missing registry would silently mean Docker Hub, and a missing tag would
		// silently mean "latest". A push is hard to undo, so it takes the full
		// reference it was given or nothing.
		if strings.Contains(reference, "@") {
			return nil, "", fmt.Errorf("push reference %q must name a tag, not a digest", reference)
		}
		tag, err := name.NewTag(reference, name.StrictValidation)
		if err != nil {
			return nil, "", fmt.Errorf(
				"push reference %q must name a registry host, a repository and a tag", reference)
		}
		if repository == "" {
			repository = tag.Context().String()
		} else if tag.Context().String() != repository {
			return nil, "", fmt.Errorf("push requires one repository, got %s and %s",
				repository, tag.Context().String())
		}
		targets = append(targets, tag)
	}
	return targets, repository, nil
}

// registryIndex adapts the layout to the object model the registry client expects.
// It serves the bytes Vapor built, so the client computes the digests that were
// already reported to the user.
func (l *Layout) registryIndex(source BlobSource) (v1.ImageIndex, error) {
	if len(l.Index.Bytes) == 0 {
		return nil, errors.New("layout requires an index")
	}
	images := make(map[v1.Hash]*Image, len(l.Images))
	for index := range l.Images {
		image := &l.Images[index]
		digest, err := v1.NewHash(image.ManifestDigest)
		if err != nil {
			return nil, fmt.Errorf("image manifest digest: %w", err)
		}
		images[digest] = image
	}
	layers := make(map[v1.Hash]CompressedLayer, len(l.Layers))
	for _, layer := range l.Layers {
		digest, err := v1.NewHash(layer.Digest)
		if err != nil {
			return nil, fmt.Errorf("layer digest: %w", err)
		}
		layers[digest] = layer
	}
	manifest, err := unmarshalIndex(l.Index.Bytes)
	if err != nil {
		return nil, err
	}
	return &publishedIndex{
		layout: l, manifest: manifest, images: images, layers: layers, source: source,
	}, nil
}

// publishedIndex is one layout index, read back from the bytes and identities it
// was built from.
type publishedIndex struct {
	layout   *Layout
	manifest *v1.IndexManifest
	images   map[v1.Hash]*Image
	layers   map[v1.Hash]CompressedLayer
	source   BlobSource
}

func (i *publishedIndex) RawManifest() ([]byte, error) { return i.layout.Index.Bytes, nil }

// Digest is computed from the manifest bytes, so an index whose recorded digest
// disagrees with its content cannot be pushed under the recorded name.
func (i *publishedIndex) Digest() (v1.Hash, error) { return digestHash(i.layout.Index.Bytes) }

func (i *publishedIndex) Size() (int64, error) { return int64(len(i.layout.Index.Bytes)), nil }

func (i *publishedIndex) MediaType() (types.MediaType, error) {
	return types.MediaType(MediaTypeIndex), nil
}

func (i *publishedIndex) IndexManifest() (*v1.IndexManifest, error) { return i.manifest, nil }

// Image returns the image one index entry names. Refusing an unknown digest keeps a
// registry client from uploading something the index does not describe.
func (i *publishedIndex) Image(digest v1.Hash) (v1.Image, error) {
	image, ok := i.images[digest]
	if !ok {
		return nil, fmt.Errorf("index lists no image %s", digest)
	}
	return imageForPush(image, i.layers, i.source)
}

// ImageIndex refuses a nested index: a Vapor index lists images only.
func (i *publishedIndex) ImageIndex(digest v1.Hash) (v1.ImageIndex, error) {
	return nil, fmt.Errorf("index lists no image index %s", digest)
}

// imageForPush wraps one built image in the shape the registry client uploads.
func imageForPush(image *Image, layers map[v1.Hash]CompressedLayer, source BlobSource) (v1.Image, error) {
	return partial.CompressedToImage(&publishedImage{image: image, layers: layers, source: source})
}

// publishedImage serves one image's config, manifest and layers.
type publishedImage struct {
	image  *Image
	layers map[v1.Hash]CompressedLayer
	source BlobSource
}

func (i publishedImage) RawConfigFile() ([]byte, error) { return i.image.Config, nil }

func (i publishedImage) RawManifest() ([]byte, error) { return i.image.Manifest, nil }

func (i publishedImage) MediaType() (types.MediaType, error) {
	return types.MediaType(i.image.MediaType), nil
}

// LayerByDigest returns the layer one manifest entry names, served from the layout
// source rather than from memory.
func (i publishedImage) LayerByDigest(digest v1.Hash) (partial.CompressedLayer, error) {
	layer, ok := i.layers[digest]
	if !ok {
		return nil, fmt.Errorf("image %s refers to unknown layer %s", i.image.ManifestDigest, digest)
	}
	return publishedLayer{layer: layer, source: i.source}, nil
}

// publishedLayer streams one compressed layer from the source as the client uploads
// it, so a push never holds a whole layer in memory.
type publishedLayer struct {
	layer  CompressedLayer
	source BlobSource
}

func (l publishedLayer) Digest() (v1.Hash, error) { return v1.NewHash(l.layer.Digest) }

func (l publishedLayer) Size() (int64, error) { return l.layer.Size, nil }

func (l publishedLayer) MediaType() (types.MediaType, error) {
	return types.MediaType(MediaTypeLayer), nil
}

func (l publishedLayer) Compressed() (io.ReadCloser, error) {
	return l.source.Open(strings.TrimPrefix(l.layer.Digest, "sha256:"), l.layer.Size)
}

// digestHash names bytes the way descriptors do.
func digestHash(encoded []byte) (v1.Hash, error) { return v1.NewHash(digestOf(encoded)) }

// unmarshalIndex decodes the index bytes the layout holds.
func unmarshalIndex(encoded []byte) (*v1.IndexManifest, error) {
	manifest := &v1.IndexManifest{}
	if err := json.Unmarshal(encoded, manifest); err != nil {
		return nil, fmt.Errorf("decode index: %w", err)
	}
	return manifest, nil
}

func (l *Layout) stageAttestedIndex(ctx context.Context, pusher *remote.Pusher, repo name.Repository,
	index v1.ImageIndex,
) error {
	if len(l.Attestations) == 0 {
		return nil
	}
	if err := pusher.Push(ctx, repo.Digest(l.Index.Digest), index); err != nil {
		return &PushError{Repository: repo.String(), cause: err}
	}
	for position := range l.Attestations {
		if err := pushAttestation(ctx, pusher, repo, &l.Attestations[position]); err != nil {
			return attachmentPushError(repo.String(), err)
		}
	}
	return nil
}

// pushAttestation writes one attachment: its payload, its empty config and then its
// manifest, which the registry indexes under the subject the manifest names.
func pushAttestation(ctx context.Context, pusher *remote.Pusher, repo name.Repository,
	attached *Attached,
) error {
	payload := static.NewLayer(attached.Payload, types.MediaType(attached.MediaType))
	if err := pusher.Upload(ctx, repo, payload); err != nil {
		return fmt.Errorf("%s %s payload: %w", attached.Platform, attached.Kind, err)
	}
	config := static.NewLayer(emptyConfig, MediaTypeEmptyConfig)
	if err := pusher.Upload(ctx, repo, config); err != nil {
		return fmt.Errorf("%s %s config: %w", attached.Platform, attached.Kind, err)
	}
	target, err := name.NewDigest(repo.String() + "@" + attached.ManifestDigest)
	if err != nil {
		return fmt.Errorf("%s %s manifest reference: %w", attached.Platform, attached.Kind, err)
	}
	if err := pusher.Put(ctx, target, attachmentManifest{manifest: attached.Manifest}); err != nil {
		return fmt.Errorf("%s %s manifest: %w", attached.Platform, attached.Kind, err)
	}
	return nil
}

// attachmentManifest is the bytes of an attachment as the registry client writes them.
type attachmentManifest struct {
	manifest []byte
}

func (m attachmentManifest) RawManifest() ([]byte, error) { return m.manifest, nil }

func (m attachmentManifest) MediaType() (types.MediaType, error) {
	return types.MediaType(MediaTypeManifest), nil
}
