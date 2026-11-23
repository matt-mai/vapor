package oci_test

import (
	"bytes"
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/matt-mai/vapor/internal/oci"
)

// platformImage renders one platform's image from a layer named after the platform,
// so the two platforms never share a manifest digest.
func platformImage(t *testing.T, platform string) oci.Image {
	t.Helper()
	image, err := oci.BuildImage(inputOf(t, platform, []oci.CompressedLayer{compressTree(t, platform)}...))
	if err != nil {
		t.Fatalf("BuildImage(%s): %v", platform, err)
	}
	return image
}

func indexPlatforms(t *testing.T, declared ...string) []oci.Platform {
	t.Helper()
	platforms := make([]oci.Platform, 0, len(declared))
	for _, entry := range declared {
		parsed, err := oci.ParsePlatform(entry)
		if err != nil {
			t.Fatalf("ParsePlatform(%q): %v", entry, err)
		}
		platforms = append(platforms, parsed)
	}
	return platforms
}

// TestBuildIndex_BothPlatforms checks the index lists exactly the declared platforms,
// each pointing at that platform's manifest.
func TestBuildIndex_BothPlatforms(t *testing.T) {
	amd64 := platformImage(t, "linux/amd64")
	arm64 := platformImage(t, "linux/arm64")
	index, err := oci.BuildIndex(&oci.IndexInput{
		Images:    []oci.Image{arm64, amd64}, // supplied out of order on purpose
		Platforms: indexPlatforms(t, "linux/amd64", "linux/arm64"),
	})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	parsed, err := v1.ParseIndexManifest(bytes.NewReader(index.Bytes))
	if err != nil {
		t.Fatalf("parse index: %v", err)
	}
	if parsed.MediaType != oci.MediaTypeIndex || parsed.SchemaVersion != 2 {
		t.Fatalf("index header = %s/%d", parsed.MediaType, parsed.SchemaVersion)
	}
	if parsed.Subject != nil || parsed.ArtifactType != "" || len(parsed.Annotations) != 0 {
		t.Fatalf("index carries generated metadata: %+v", parsed)
	}
	if len(parsed.Manifests) != 2 {
		t.Fatalf("manifests = %d", len(parsed.Manifests))
	}
	want := []struct{ image oci.Image }{{amd64}, {arm64}}
	for i, entry := range want {
		descriptor := parsed.Manifests[i]
		if descriptor.Digest.String() != entry.image.ManifestDigest ||
			descriptor.Size != entry.image.ManifestSize ||
			descriptor.MediaType != oci.MediaTypeManifest {
			t.Fatalf("descriptor %d = %+v, want %s", i, descriptor, entry.image.ManifestDigest)
		}
		if descriptor.Platform == nil || descriptor.Platform.String() != entry.image.Platform.String() {
			t.Fatalf("descriptor %d platform = %v", i, descriptor.Platform)
		}
	}
}

// TestBuildIndex_StableBytes is the reproducibility claim for the index: neither the
// caller's slice order nor the spec's declaration order decides the bytes.
func TestBuildIndex_StableBytes(t *testing.T) {
	amd64 := platformImage(t, "linux/amd64")
	arm64 := platformImage(t, "linux/arm64")
	platforms := indexPlatforms(t, "linux/arm64", "linux/amd64")
	first, err := oci.BuildIndex(&oci.IndexInput{Images: []oci.Image{amd64, arm64}, Platforms: platforms})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	second, err := oci.BuildIndex(&oci.IndexInput{Images: []oci.Image{arm64, amd64}, Platforms: platforms})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	if !bytes.Equal(first.Bytes, second.Bytes) || first.Digest != second.Digest {
		t.Fatal("index bytes depend on the order images were supplied in")
	}
	if first.Size != int64(len(first.Bytes)) {
		t.Fatalf("index size = %d, want %d", first.Size, len(first.Bytes))
	}
	// One platform order yields one index: listing the same platforms differently
	// changes nothing, because the entries are sorted.
	reordered, err := oci.BuildIndex(&oci.IndexInput{
		Images:    []oci.Image{amd64, arm64},
		Platforms: indexPlatforms(t, "linux/amd64", "linux/arm64"),
	})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	if !bytes.Equal(reordered.Bytes, first.Bytes) || reordered.Digest != first.Digest {
		t.Fatal("the declared platform order changed the index")
	}
}

// TestBuildIndex_Refusals covers the coverage rules and the descriptor checks.
func TestBuildIndex_Refusals(t *testing.T) {
	amd64 := platformImage(t, "linux/amd64")
	arm64 := platformImage(t, "linux/arm64")
	brokenManifest := amd64
	brokenManifest.ManifestDigest = "sha256:nothex"
	brokenSize := amd64
	brokenSize.ManifestSize = amd64.ManifestSize + 1
	absentManifest := amd64
	absentManifest.Manifest = nil
	brokenMedia := amd64
	brokenMedia.MediaType = oci.MediaTypeIndex
	cases := map[string]*oci.IndexInput{
		"missing image":    {Images: []oci.Image{amd64}, Platforms: indexPlatforms(t, "linux/amd64", "linux/arm64")},
		"undeclared image": {Images: []oci.Image{amd64, arm64}, Platforms: indexPlatforms(t, "linux/amd64")},
		"duplicate image": {
			Images:    []oci.Image{amd64, amd64},
			Platforms: indexPlatforms(t, "linux/amd64"),
		},
		"duplicate platform": {
			Images:    []oci.Image{amd64},
			Platforms: indexPlatforms(t, "linux/amd64", "linux/amd64"),
		},
		"no platforms":              {Images: []oci.Image{amd64}},
		"unsupported":               {Images: []oci.Image{amd64}, Platforms: []oci.Platform{{OS: "linux", Architecture: "386"}}},
		"bad digest":                {Images: []oci.Image{brokenManifest}, Platforms: indexPlatforms(t, "linux/amd64")},
		"non-manifest":              {Images: []oci.Image{brokenMedia}, Platforms: indexPlatforms(t, "linux/amd64")},
		"size disagrees with bytes": {Images: []oci.Image{brokenSize}, Platforms: indexPlatforms(t, "linux/amd64")},
		"absent manifest":           {Images: []oci.Image{absentManifest}, Platforms: indexPlatforms(t, "linux/amd64")},
	}
	for name, input := range cases {
		if _, err := oci.BuildIndex(input); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := oci.BuildIndex(nil); err == nil {
		t.Fatal("nil input accepted")
	}
}

// TestBuildIndex_DerivesTheDescriptorFromTheManifest checks that an image whose
// metadata fields were left empty still produces an entry naming its real manifest,
// so the index can never publish a digest or size that the bytes do not have.
func TestBuildIndex_DerivesTheDescriptorFromTheManifest(t *testing.T) {
	amd64 := platformImage(t, "linux/amd64")
	bare := amd64
	bare.ManifestDigest = ""
	bare.ManifestSize = 0
	built, err := oci.BuildIndex(&oci.IndexInput{
		Images:    []oci.Image{bare},
		Platforms: indexPlatforms(t, "linux/amd64"),
	})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	var index v1.IndexManifest
	if err := json.Unmarshal(built.Bytes, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("index describes %d manifests", len(index.Manifests))
	}
	descriptor := index.Manifests[0]
	if descriptor.Digest.String() != amd64.ManifestDigest || descriptor.Size != amd64.ManifestSize {
		t.Fatalf("descriptor = %s/%d, manifest = %s/%d", descriptor.Digest, descriptor.Size,
			amd64.ManifestDigest, amd64.ManifestSize)
	}
}

// TestSubjectOf_AttachesToManifest checks the attachment subject is the platform
// manifest, which is what keeps the index free of circular digests.
func TestSubjectOf_AttachesToManifest(t *testing.T) {
	image := platformImage(t, "linux/amd64")
	subject := image.SubjectOf()
	if err := subject.Validate(); err != nil {
		t.Fatalf("subject: %v", err)
	}
	if subject.Digest != image.ManifestDigest || subject.Size != image.ManifestSize ||
		subject.MediaType != image.MediaType {
		t.Fatalf("subject = %+v, image = %s/%d", subject, image.ManifestDigest, image.ManifestSize)
	}
}

// TestDeclaredPlatforms covers the declared list, including the default the loader
// already applies and the duplicate the planner must catch.
func TestDeclaredPlatforms(t *testing.T) {
	platforms, err := oci.DeclaredPlatforms([]string{"linux/arm64", "linux/amd64"})
	if err != nil {
		t.Fatalf("DeclaredPlatforms: %v", err)
	}
	if len(platforms) != 2 || platforms[0].String() != "linux/arm64" ||
		platforms[1].String() != "linux/amd64" {
		t.Fatalf("platforms = %v", platforms)
	}
	if _, err := oci.DeclaredPlatforms(nil); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := oci.DeclaredPlatforms([]string{"linux/amd64", "linux/386"}); err == nil {
		t.Fatal("unsupported platform accepted")
	}
}
