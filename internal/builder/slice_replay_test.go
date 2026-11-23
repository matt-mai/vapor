package builder_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/matt-mai/vapor/internal/builder"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

func TestBuild_ReplaysCrossPackageSliceOrder(t *testing.T) {
	t.Parallel()
	inputs := interleavedSliceFixture(t)
	canonical, err := inputs.Lockfile.CanonicalYAML()
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(inputs.Lockfile.Slices)
	reversed, err := yaml.Marshal(inputs.Lockfile)
	if err != nil {
		t.Fatal(err)
	}
	var firstLayer string
	var firstLock []byte
	for _, raw := range [][]byte{canonical, reversed} {
		inputs.Lockfile = readReplayLock(t, raw)
		identity, err := inputs.Lockfile.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		image := buildReplayImage(t, inputs)
		if firstLayer == "" {
			firstLayer, firstLock = image.Layer.Digest, identity
		} else if image.Layer.Digest != firstLayer || !bytes.Equal(identity, firstLock) {
			t.Fatal("reordering package records changed the lock identity or layer digest")
		}
	}
}

func TestBuild_RejectsIncompleteSliceClosureWithMatchingDefinitionDigest(t *testing.T) {
	t.Parallel()
	inputs := interleavedSliceFixture(t)
	record := &inputs.Lockfile.Slices[0]
	record.Closure = []string{"release-info"}
	record.DefinitionDigest = definitionDigest(t, inputs.Lockfile.Catalogues[0].Manifest, record.Closure...)
	input, err := builder.Open(t.Context(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Content(t.Context(), "linux/amd64"); err == nil ||
		!strings.Contains(err.Error(), "locked slice closure does not match the catalogue selection") {
		t.Fatalf("Content = %v, want closure mismatch", err)
	}
}

func interleavedSliceFixture(t *testing.T) *builder.Inputs {
	t.Helper()
	inputs, store := contentFixture(t)
	helperFile := `package: helper
archive: ubuntu
slices:
  middle:
    essential:
      base-files_boot:
    mutate: |
      content.write("/trace", content.read("/trace") + "B")
`
	digest, size := storeFile(t, store, []byte(helperFile))
	helper := lock.CatalogueEntry{Kind: "file", Path: "slices/helper.yaml", SHA256: digest, Size: size}
	catalogue, manifest := catalogueWithRoot(t, store, chiselYAML(newRootKey(t)), `package: base-files
archive: ubuntu
slices:
  boot:
    contents:
      /trace: {text: "", mutable: true}
    mutate: |
      content.write("/trace", content.read("/late"))
  release-info:
    essential:
      helper_middle:
    contents:
      /late: {text: "A"}
    mutate: |
      content.write("/trace", content.read("/trace") + "C")
`, helper)
	inputs.Lockfile.Catalogues = []lock.Catalogue{*catalogue}
	base := &inputs.Lockfile.Slices[0]
	base.Closure = []string{"boot", "release-info"}
	base.DefinitionDigest = definitionDigest(t, manifest, base.Closure...)
	helperDefinition, err := slicespkg.DefinitionDigest(helper.Path, digest, size, []string{"middle"})
	if err != nil {
		t.Fatal(err)
	}
	payload := debBytes(t, "helper", "1", tarMember{name: "./unused", mode: 0o644, body: []byte("fixture")})
	payloadDigest, payloadSize := storeFile(t, store, payload)
	inputs.Lockfile.Slices = append(inputs.Lockfile.Slices, lock.Slice{
		Platform: base.Platform, Package: "helper", Version: "1", Architecture: "amd64",
		Catalogue: base.Catalogue, Archive: base.Archive, Repository: base.Repository,
		Content: lock.Content{Path: "pool/helper.deb", SHA256: payloadDigest, Size: payloadSize},
		Closure: []string{"middle"}, DefinitionDigest: helperDefinition,
	})
	return inputs
}

func readReplayLock(t *testing.T, data []byte) *lock.Lockfile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.lock.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := lock.LoadLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func buildReplayImage(t *testing.T, inputs *builder.Inputs) builder.Image {
	t.Helper()
	input, err := builder.Open(t.Context(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	image, err := input.BuildPlatform(t.Context(), oci.Platform{OS: "linux", Architecture: "amd64"}, oci.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := image.Tree.Read("/trace")
	if err != nil || string(trace) != "ABC" {
		t.Fatalf("mutation trace = %q, %v, want ABC", trace, err)
	}
	return image
}
