package oci

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// BlobSource provides the layer bytes a layout refers to, keyed by the bare hex
// digest every other store in Vapor uses. The verified cache implements it, so
// exporting never needs the builder's assembly state.
type BlobSource interface {
	Open(digest string, size int64) (io.ReadCloser, error)
}

// Layout is one complete OCI image layout: the index, the per-platform manifests
// and configs, and the layers those manifests point at. It holds identities, not
// bytes, so layers are read from the source as they are written.
type Layout struct {
	Index  Index
	Images []Image
	Layers []CompressedLayer
	// Tags are the local tag descriptors written beside the build index. They name
	// the index this layout publishes, so a tag cannot change what a build reports
	// or pushes.
	Tags []string
	// Attestations are the statements written beside the images. Each one is a
	// manifest whose subject is a platform manifest, listed in the layout index but
	// never in the build index, so attaching metadata cannot change the image digest.
	Attestations []Attached
}

// layoutVersion is the only image layout version the specification defines.
type layoutVersion struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// layoutEntry is one file of the layout. Entries with a digest are content
// addressed and read from the source; the rest carry their bytes.
type layoutEntry struct {
	path   string
	digest string
	body   []byte
	size   int64
}

func (l *Layout) entries(archive bool) ([]layoutEntry, error) {
	if len(l.Index.Bytes) == 0 {
		return nil, errors.New("layout requires an index")
	}
	if len(l.Images) == 0 {
		return nil, errors.New("layout requires at least one image")
	}
	version, err := marshalCanonical(layoutVersion{ImageLayoutVersion: "1.0.0"})
	if err != nil {
		return nil, err
	}
	var indexJSON []byte
	var includeIndex bool
	if archive {
		indexJSON, err = l.archiveIndex()
		includeIndex = true
	} else {
		indexJSON, includeIndex, err = l.indexJSON(l.Tags)
	}
	if err != nil {
		return nil, err
	}
	entries := []layoutEntry{
		{path: "oci-layout", body: version, size: int64(len(version))},
		{path: "index.json", body: indexJSON, size: int64(len(indexJSON))},
	}
	if includeIndex {
		entry, blobErr := blobEntry(l.Index.Digest, l.Index.Bytes)
		if blobErr != nil {
			return nil, blobErr
		}
		entries = append(entries, entry)
	}
	imageBlobs, err := l.imageBlobs(archive)
	if err != nil {
		return nil, err
	}
	return uniqueEntries(append(entries, imageBlobs...))
}

func (l *Layout) imageBlobs(archive bool) ([]layoutEntry, error) {
	images, err := imageEntries(l.Images)
	if err != nil {
		return nil, err
	}
	layers, err := layerEntries(l.Layers)
	if err != nil {
		return nil, err
	}
	images = append(images, layers...)
	if archive {
		return images, nil
	}
	attached, err := attachmentEntries(l.Attestations)
	if err != nil {
		return nil, err
	}
	return append(images, attached...), nil
}

func (l *Layout) archiveIndex() ([]byte, error) {
	descriptor, err := l.buildIndexDescriptor()
	if err != nil {
		return nil, err
	}
	if len(l.Tags) > 0 {
		if _, tagErr := tagNames(l.Tags[:1]); tagErr != nil {
			return nil, tagErr
		}
		descriptor = tagged(&descriptor, l.Tags[0])
	}
	return marshalCanonical(v1.IndexManifest{
		SchemaVersion: 2, MediaType: types.MediaType(MediaTypeIndex), Manifests: []v1.Descriptor{descriptor},
	})
}

// uniqueEntries sorts the entries by path and collapses repetitions. Two images
// that produced the same bytes share one blob, which is what an artifact-only
// multi-platform build needs; the same path described differently is a conflict,
// because the file can only hold one of them.
func uniqueEntries(entries []layoutEntry) ([]layoutEntry, error) {
	slices.SortFunc(entries, func(left, right layoutEntry) int {
		return strings.Compare(left.path, right.path)
	})
	unique := entries[:0]
	for _, entry := range entries {
		if len(unique) > 0 && unique[len(unique)-1].path == entry.path {
			previous := &unique[len(unique)-1]
			if !sameEntry(*previous, entry) {
				return nil, fmt.Errorf("layout describes %q twice with different content", entry.path)
			}
			continue
		}
		unique = append(unique, entry)
	}
	return unique, nil
}

// sameEntry reports whether two entries describe the same bytes. Content-addressed
// entries are compared by digest and size; the rest by their bytes.
func sameEntry(left, right layoutEntry) bool {
	if left.digest != right.digest || left.size != right.size {
		return false
	}
	return bytes.Equal(left.body, right.body)
}

// indexJSON renders the layout's index. Without declared tags it is the build
// index byte for byte. With tags, each one is a descriptor beside the build index
// and still points at that index's digest, so the image a reader tags is exactly
// the image the build reported and pushed.
func (l *Layout) indexJSON(tags []string) ([]byte, bool, error) {
	names, err := tagNames(tags)
	if err != nil {
		return nil, false, err
	}
	if len(names) == 0 {
		return l.indexWithAttestations()
	}
	descriptor, err := l.buildIndexDescriptor()
	if err != nil {
		return nil, false, err
	}
	manifest, err := unmarshalIndex(l.Index.Bytes)
	if err != nil {
		return nil, false, err
	}
	descriptors := make([]v1.Descriptor, 0, len(manifest.Manifests)+len(l.Attestations)+len(names))
	descriptors = append(descriptors, manifest.Manifests...)
	// Attachments are listed before the tags, so the tag descriptors stay the last
	// entries a reader sees and still point at the build index.
	for position := range l.Attestations {
		descriptors = append(descriptors, l.Attestations[position].Descriptor)
	}
	for _, name := range names {
		descriptors = append(descriptors, tagged(&descriptor, name))
	}
	manifest.Manifests = descriptors
	encoded, err := marshalCanonical(manifest)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

func (l *Layout) buildIndexDescriptor() (v1.Descriptor, error) {
	if err := validateDigest(l.Index.Digest); err != nil {
		return v1.Descriptor{}, fmt.Errorf("build index: %w", err)
	}
	if l.Index.Size <= 0 || l.Index.Size != int64(len(l.Index.Bytes)) {
		return v1.Descriptor{}, errors.New("build index size does not match its bytes")
	}
	return v1.Descriptor{
		MediaType: types.MediaType(MediaTypeIndex),
		Digest:    v1.Hash{Algorithm: "sha256", Hex: strings.TrimPrefix(l.Index.Digest, "sha256:")},
		Size:      l.Index.Size,
	}, nil
}

// indexWithAttestations lists the attachments beside the build index, so a reader of
// the directory finds them even when the build declared no tag. The build index bytes
// are returned untouched when a build wrote no attachments.
func (l *Layout) indexWithAttestations() ([]byte, bool, error) {
	if len(l.Attestations) == 0 {
		return l.Index.Bytes, false, nil
	}
	manifest, err := unmarshalIndex(l.Index.Bytes)
	if err != nil {
		return nil, false, err
	}
	descriptors := make([]v1.Descriptor, 0, len(manifest.Manifests)+len(l.Attestations))
	descriptors = append(descriptors, manifest.Manifests...)
	for position := range l.Attestations {
		descriptors = append(descriptors, l.Attestations[position].Descriptor)
	}
	manifest.Manifests = descriptors
	encoded, err := marshalCanonical(manifest)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

// tagged returns a copy of a descriptor annotated with one local tag. The build
// index descriptor keeps no annotation, so a reader can tell the image from its
// tags.
func tagged(descriptor *v1.Descriptor, name string) v1.Descriptor {
	annotation := map[string]string{RefNameAnnotation: name}
	if descriptor.Annotations != nil {
		annotation = make(map[string]string, len(descriptor.Annotations)+1)
		maps.Copy(annotation, descriptor.Annotations)
	}
	annotation[RefNameAnnotation] = name
	marked := *descriptor
	marked.Annotations = annotation
	return marked
}

// tagPattern is the image tag grammar the specification accepts, so the layout
// writer refuses exactly what the loader refuses.
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// tagNames validates the declared tags once, so a bad name fails the export before
// any bytes are written. The loader has already checked them; this keeps the layout
// writer from depending on that.
func tagNames(tags []string) ([]string, error) {
	names := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if !tagPattern.MatchString(tag) {
			return nil, fmt.Errorf("layout tag %q is not a valid image tag", tag)
		}
		if _, duplicate := seen[tag]; duplicate {
			return nil, fmt.Errorf("layout tag %q is declared twice", tag)
		}
		seen[tag] = struct{}{}
		names = append(names, tag)
	}
	return names, nil
}

// imageEntries lists the configs and manifests, checking each against the digest
// its descriptor names.
func imageEntries(images []Image) ([]layoutEntry, error) {
	entries := make([]layoutEntry, 0, 2*len(images))
	for index := range images {
		image := &images[index]
		config, err := blobEntry(image.ConfigDigest, image.Config)
		if err != nil {
			return nil, err
		}
		manifest, err := blobEntry(image.ManifestDigest, image.Manifest)
		if err != nil {
			return nil, err
		}
		entries = append(entries, config, manifest)
	}
	return entries, nil
}

// layerEntries lists the layer blobs. Their bytes stay in the source, so only the
// identity and size are recorded here.
func layerEntries(layers []CompressedLayer) ([]layoutEntry, error) {
	entries := make([]layoutEntry, 0, len(layers))
	for index := range layers {
		layer := &layers[index]
		if err := validateDigest(layer.Digest); err != nil {
			return nil, fmt.Errorf("layer: %w", err)
		}
		if layer.Size <= 0 {
			return nil, fmt.Errorf("layer %s: size must be positive", layer.Digest)
		}
		entries = append(entries, layoutEntry{
			path: blobPath(layer.Digest), digest: layer.Digest, size: layer.Size,
		})
	}
	return entries, nil
}

func blobEntry(digest string, body []byte) (layoutEntry, error) {
	if err := validateDigest(digest); err != nil {
		return layoutEntry{}, err
	}
	if computed := digestOf(body); computed != digest {
		return layoutEntry{}, fmt.Errorf("layout blob %s does not match its content %s", digest, computed)
	}
	return layoutEntry{path: blobPath(digest), body: body, size: int64(len(body))}, nil
}

// blobPath is where the layout stores a content-addressed file.
func blobPath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}
