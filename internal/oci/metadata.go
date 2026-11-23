package oci

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"strings"
)

// OCI media types for Vapor output. A layer is always gzip-framed, including at
// level 0, so no uncompressed layer media type is produced.
const (
	MediaTypeConfig   = "application/vnd.oci.image.config.v1+json"
	MediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeIndex    = "application/vnd.oci.image.index.v1+json"
	MediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// RefNameAnnotation names a tag on a descriptor in a local layout index.
const RefNameAnnotation = "org.opencontainers.image.ref.name"

// ManifestAnnotations returns the annotations one platform manifest carries. The
// declared map is copied verbatim and nothing is generated into a manifest, so a
// declared key can never be overwritten by a later stage.
func ManifestAnnotations(declared map[string]string) (map[string]string, error) {
	if _, reserved := declared[RefNameAnnotation]; reserved {
		return nil, fmt.Errorf("annotations must not declare %q: the tag list sets it",
			RefNameAnnotation)
	}
	if len(declared) == 0 {
		return nil, nil //nolint:nilnil // an image without annotations is not an error
	}
	annotations := make(map[string]string, len(declared))
	maps.Copy(annotations, declared)
	return annotations, nil
}

// TagReferences renders the declared tags as image references in declared order.
// Omitted tags mean no references at all: a latest tag is never implied. The tags
// are already validated by the loader, so this only refuses a missing repository.
func TagReferences(repository string, tags []string) ([]string, error) {
	if repository == "" {
		return nil, errors.New("an image reference requires a repository")
	}
	references := make([]string, 0, len(tags))
	for _, tag := range tags {
		references = append(references, repository+":"+tag)
	}
	return references, nil
}

// Subject identifies the artifact an attachment describes. It is always the
// platform manifest: an index and the attachment itself are never subjects, which
// keeps the reference graph acyclic.
type Subject struct {
	MediaType string
	Digest    string
	Size      int64
}

// Validate reports whether this subject can be attached to.
func (s Subject) Validate() error {
	if s.MediaType != MediaTypeManifest {
		return fmt.Errorf("subject media type %q is not an image manifest", s.MediaType)
	}
	if err := validateDigest(s.Digest); err != nil {
		return err
	}
	if s.Size <= 0 {
		return errors.New("subject size must be positive")
	}
	return nil
}

// validateDigest checks the sha256 form Vapor writes: a lowercase algorithm and
// exactly one lowercase hex corpus.
func validateDigest(digest string) error {
	hexed := strings.TrimPrefix(digest, "sha256:")
	if hexed == digest || len(hexed) != sha256.Size*2 || strings.ToLower(hexed) != hexed {
		return fmt.Errorf("digest %q must be sha256 with lowercase hex", digest)
	}
	for _, digit := range []byte(hexed) {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return fmt.Errorf("digest %q must be sha256 with lowercase hex", digest)
		}
	}
	return nil
}
