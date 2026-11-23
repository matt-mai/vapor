package oci

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// IndexInput is the finished per-platform images plus the platforms the spec
// declared. The declaration order does not reach the index: entries are sorted.
type IndexInput struct {
	Images    []Image
	Platforms []Platform
}

// Index is the multi-platform image index and its identity.
type Index struct {
	Bytes  []byte
	Digest string
	Size   int64
}

// SubjectOf returns the attachment subject for this platform image, so a future
// attestation can describe the manifest rather than the index. Nothing in the index
// needs this value, which is what keeps the graph acyclic.
func (i *Image) SubjectOf() Subject {
	return Subject{MediaType: i.MediaType, Digest: i.ManifestDigest, Size: i.ManifestSize}
}

// BuildIndex assembles the index from one image per declared platform. It refuses
// a platform without an image, an image for an undeclared platform, and any pair of
// images claiming the same platform, so the index always describes exactly the
// platforms the spec asked for.
func BuildIndex(input *IndexInput) (Index, error) {
	if input == nil {
		return Index{}, errors.New("index input must not be nil")
	}
	if len(input.Platforms) == 0 {
		return Index{}, errors.New("index input requires at least one platform")
	}
	declared, err := checkPlatforms(input.Platforms)
	if err != nil {
		return Index{}, err
	}
	images, err := checkImages(input.Images, declared)
	if err != nil {
		return Index{}, err
	}
	index := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeIndex,
		Manifests:     make([]v1.Descriptor, 0, len(input.Platforms)),
	}
	for _, platform := range sortedPlatforms(input.Platforms) {
		descriptor, entryErr := platformDescriptor(platform, images[platform])
		if entryErr != nil {
			return Index{}, entryErr
		}
		index.Manifests = append(index.Manifests, descriptor)
	}
	encoded, err := marshalCanonical(index)
	if err != nil {
		return Index{}, err
	}
	return Index{Bytes: encoded, Digest: digestOf(encoded), Size: int64(len(encoded))}, nil
}

// sortedPlatforms returns the platforms in canonical order. Reordering one platform
// in the spec must not change the index, because both builds list the same images.
func sortedPlatforms(platforms []Platform) []Platform {
	ordered := append([]Platform(nil), platforms...)
	slices.SortFunc(ordered, func(left, right Platform) int {
		return strings.Compare(left.String(), right.String())
	})
	return ordered
}

// checkPlatforms refuses a duplicate or unsupported declared platform and returns the
// declared set.
func checkPlatforms(platforms []Platform) (map[Platform]bool, error) {
	declared := make(map[Platform]bool, len(platforms))
	for _, platform := range platforms {
		if _, err := ParsePlatform(platform.String()); err != nil {
			return nil, err
		}
		if declared[platform] {
			return nil, fmt.Errorf("platform %s is declared more than once", platform)
		}
		declared[platform] = true
	}
	return declared, nil
}

// checkImages refuses an image for an undeclared platform, two images for one
// platform, or a declared platform with no image, and returns the images by platform.
func checkImages(images []Image, declared map[Platform]bool) (map[Platform]*Image, error) {
	byPlatform := make(map[Platform]*Image, len(declared))
	for i := range images {
		image := &images[i]
		if !declared[image.Platform] {
			return nil, fmt.Errorf("image for undeclared platform %s", image.Platform)
		}
		if _, present := byPlatform[image.Platform]; present {
			return nil, fmt.Errorf("more than one image for platform %s", image.Platform)
		}
		byPlatform[image.Platform] = image
	}
	for platform := range declared {
		if _, present := byPlatform[platform]; !present {
			return nil, fmt.Errorf("declared platform %s has no image", platform)
		}
	}
	return byPlatform, nil
}

// platformDescriptor renders one index entry from a finished image manifest. The
// digest and size the index publishes are the ones a reader will verify against the
// bytes it fetches, so they are taken from the manifest rather than trusted: a
// metadata field that disagrees with the bytes would make the index name nothing that
// exists.
func platformDescriptor(platform Platform, image *Image) (v1.Descriptor, error) {
	if image.MediaType != MediaTypeManifest {
		return v1.Descriptor{}, fmt.Errorf("platform %s: media type %q is not an image manifest",
			platform, image.MediaType)
	}
	digest, size, err := manifestIdentity(platform, image)
	if err != nil {
		return v1.Descriptor{}, err
	}
	return v1.Descriptor{
		MediaType: types.MediaType(image.MediaType),
		Size:      size,
		Digest:    digest,
		Platform:  &v1.Platform{OS: platform.OS, Architecture: platform.Architecture},
	}, nil
}

// manifestIdentity returns the digest and size of the manifest bytes, refusing a
// declared pair that disagrees with them.
func manifestIdentity(platform Platform, image *Image) (v1.Hash, int64, error) {
	if len(image.Manifest) == 0 {
		return v1.Hash{}, 0, fmt.Errorf("platform %s: manifest bytes are absent", platform)
	}
	digest, err := v1.NewHash(digestOf(image.Manifest))
	if err != nil {
		return v1.Hash{}, 0, fmt.Errorf("platform %s: manifest digest: %w", platform, err)
	}
	size := int64(len(image.Manifest))
	if image.ManifestDigest != "" && image.ManifestDigest != digest.String() {
		return v1.Hash{}, 0, fmt.Errorf("platform %s: manifest digest %s does not match its bytes %s",
			platform, image.ManifestDigest, digest)
	}
	if image.ManifestSize != 0 && image.ManifestSize != size {
		return v1.Hash{}, 0, fmt.Errorf("platform %s: manifest size %d does not match its bytes %d",
			platform, image.ManifestSize, size)
	}
	return digest, size, nil
}

// DeclaredPlatforms parses the spec's platform list into ordered platforms. A spec
// without a list builds for linux/amd64, which is the loader's default.
func DeclaredPlatforms(declared []string) ([]Platform, error) {
	if len(declared) == 0 {
		return nil, errors.New("a spec must declare at least one platform")
	}
	platforms := make([]Platform, 0, len(declared))
	for _, entry := range declared {
		platform, err := ParsePlatform(entry)
		if err != nil {
			return nil, err
		}
		platforms = append(platforms, platform)
	}
	return platforms, nil
}
