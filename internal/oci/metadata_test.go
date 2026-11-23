package oci_test

import (
	"maps"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/oci"
)

const testDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestManifestAnnotations_CopiesDeclared checks that declared annotations survive
// unchanged and that the caller's map is not shared with the result.
func TestManifestAnnotations_CopiesDeclared(t *testing.T) {
	declared := map[string]string{"org.opencontainers.image.description": "Minimal", "com.example.a": "", "x": "multi\nline"}
	annotations, err := oci.ManifestAnnotations(declared)
	if err != nil {
		t.Fatalf("ManifestAnnotations: %v", err)
	}
	if !maps.Equal(annotations, declared) {
		t.Fatalf("annotations = %v, want %v", annotations, declared)
	}
	annotations["x"] = "changed"
	if declared["x"] != "multi\nline" {
		t.Fatal("the declared annotation map was shared with the result")
	}
}

// TestManifestAnnotations_Omitted checks that an absent or empty declaration stays
// absent, so nothing is generated for the caller to notice later.
func TestManifestAnnotations_Omitted(t *testing.T) {
	for _, declared := range []map[string]string{nil, {}} {
		annotations, err := oci.ManifestAnnotations(declared)
		if err != nil || annotations != nil {
			t.Fatalf("annotations = %v %v, want none", annotations, err)
		}
	}
}

// TestManifestAnnotations_ReservedRefName is the collision rule: the tag list owns
// the ref.name annotation, so a declaration that would compete with it is refused
// instead of silently losing.
func TestManifestAnnotations_ReservedRefName(t *testing.T) {
	_, err := oci.ManifestAnnotations(map[string]string{oci.RefNameAnnotation: "v1"})
	if err == nil || !strings.Contains(err.Error(), "tag list") {
		t.Fatalf("error = %v, want a reserved-annotation refusal", err)
	}
}

// TestTagReferences covers the tag-to-reference mapping, including the rule that an
// omitted tag list produces no references and therefore no implied latest.
func TestTagReferences(t *testing.T) {
	tags, err := oci.TagReferences("ghcr.io/example/app", []string{"v2", "V1", "42"})
	if err != nil {
		t.Fatalf("TagReferences: %v", err)
	}
	want := []string{"ghcr.io/example/app:v2", "ghcr.io/example/app:V1", "ghcr.io/example/app:42"}
	if len(tags) != len(want) {
		t.Fatalf("references = %v, want %v", tags, want)
	}
	for i := range want {
		if tags[i] != want[i] {
			t.Fatalf("reference %d = %q, want %q", i, tags[i], want[i])
		}
	}
	for _, declared := range [][]string{nil, {}} {
		references, err := oci.TagReferences("ghcr.io/example/app", declared)
		if err != nil || len(references) != 0 {
			t.Fatalf("references = %v %v, want none", references, err)
		}
	}
	if _, err := oci.TagReferences("", []string{"v1"}); err == nil {
		t.Fatal("empty repository accepted")
	}
}

// TestSubject_Validate covers the accepted subject shape and every refusal.
func TestSubject_Validate(t *testing.T) {
	valid := oci.Subject{MediaType: oci.MediaTypeManifest, Digest: testDigest, Size: 1024}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid subject rejected: %v", err)
	}
	// An index is refused even though it is a real OCI artifact: attaching to it
	// would let an artifact describe something that lists it.
	for name, subject := range map[string]oci.Subject{
		"index":      {MediaType: oci.MediaTypeIndex, Digest: testDigest, Size: 1024},
		"config":     {MediaType: oci.MediaTypeConfig, Digest: testDigest, Size: 1024},
		"layer":      {MediaType: oci.MediaTypeLayer, Digest: testDigest, Size: 1024},
		"no media":   {Digest: testDigest, Size: 1024},
		"no digest":  {MediaType: oci.MediaTypeManifest, Size: 1024},
		"short":      {MediaType: oci.MediaTypeManifest, Digest: "sha256:00", Size: 1024},
		"wrong algo": {MediaType: oci.MediaTypeManifest, Digest: "sha512:" + testDigest[7:], Size: 1024},
		"uppercase":  {MediaType: oci.MediaTypeManifest, Digest: "sha256:" + strings.ToUpper(testDigest[7:]), Size: 1024},
		"not hex":    {MediaType: oci.MediaTypeManifest, Digest: "sha256:" + strings.Repeat("z", 64), Size: 1024},
		"zero size":  {MediaType: oci.MediaTypeManifest, Digest: testDigest},
		"no algo":    {MediaType: oci.MediaTypeManifest, Digest: testDigest[7:], Size: 1024},
		"too long":   {MediaType: oci.MediaTypeManifest, Digest: testDigest + "0", Size: 1024},
		"not digest": {MediaType: oci.MediaTypeManifest, Digest: "not-a-digest", Size: 1024},
	} {
		if err := subject.Validate(); err == nil {
			t.Fatalf("%s: invalid subject accepted: %+v", name, subject)
		}
	}
}
