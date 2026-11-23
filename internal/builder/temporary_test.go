package builder_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	schemacontents "github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// sharedTemporaryPath is the path both a slice and another input ship.
const sharedTemporaryPath = "/var/lib/fixture-cache"

// A path a slice declares `until: mutate` can also ship in a whole package or an
// artifact. Merging sees identical bytes, so the entry survives with a permanent
// contributor as well as the slice's own origin. Mutation cleanup runs on the
// combined tree, so a temporary list carrying that path would delete the other
// input's file: the list has to be decided after every input has merged.
func TestContent_PermanentContributorKeepsASharedTemporaryPath(t *testing.T) {
	cases := map[string]func(*testing.T, *builder.Inputs, *cache.Cache){
		"whole package": func(t *testing.T, inputs *builder.Inputs, store *cache.Cache) {
			digest, size := storeFile(t, store, debBytes(t, "openssl", "3.0-1",
				tarMember{name: "." + sharedTemporaryPath, body: []byte("cached\n"), mode: 0o644}))
			inputs.Lockfile.Packages[0].Content = lock.Content{Path: "pool/openssl.deb", SHA256: digest, Size: size}
		},
		"package artifact": func(t *testing.T, inputs *builder.Inputs, store *cache.Cache) {
			installPackageArtifact(t, inputs, store, debBytes(t, "myapp", "1.0",
				tarMember{name: "." + sharedTemporaryPath, body: []byte("cached\n"), mode: 0o644}))
		},
	}
	for name, addPermanent := range cases {
		t.Run(name, func(t *testing.T) {
			inputs, store := temporaryFixture(t)
			addPermanent(t, inputs, store)
			input, err := builder.Open(t.Context(), inputs)
			if err != nil {
				t.Fatal(err)
			}
			assembled, err := input.Content(t.Context(), "linux/amd64")
			if err != nil {
				t.Fatalf("Content: %v", err)
			}
			if len(assembled.Temporary) != 0 {
				t.Fatalf("temporary = %v, want the shared path kept", assembled.Temporary)
			}
			entry, ok := assembled.Tree.Lookup(sharedTemporaryPath)
			if !ok || entry.Size != int64(len("cached\n")) {
				t.Fatalf("shared path = %+v, ok=%v", entry, ok)
			}
			final, err := input.Assemble(t.Context(), assembled, "linux/amd64")
			if err != nil {
				t.Fatalf("Assemble: %v", err)
			}
			if _, ok := final.Lookup(sharedTemporaryPath); !ok {
				t.Fatal("mutation removed a path another input ships permanently")
			}
		})
	}
}

// A slice-only temporary path is still removed, so the ownership check above does
// not disable cleanup.
func TestContent_SliceOnlyTemporaryPathIsStillRemoved(t *testing.T) {
	inputs, _ := temporaryFixture(t)
	input, err := builder.Open(t.Context(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	assembled, err := input.Content(t.Context(), "linux/amd64")
	if err != nil {
		t.Fatalf("Content: %v", err)
	}
	if strings.Join(assembled.Temporary, ",") != sharedTemporaryPath {
		t.Fatalf("temporary = %v", assembled.Temporary)
	}
	final, err := input.Assemble(t.Context(), assembled, "linux/amd64")
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if _, ok := final.Lookup(sharedTemporaryPath); ok {
		t.Fatal("a slice-only temporary path survived mutation")
	}
}

// temporaryFixture declares one slice whose only content is a temporary copy of a
// file its payload ships at sharedTemporaryPath.
func temporaryFixture(t *testing.T) (*builder.Inputs, *cache.Cache) {
	t.Helper()
	inputs, store := contentFixture(t)
	catalogue, manifest := catalogueWithSlices(t, store, fmt.Sprintf(`package: base-files
archive: ubuntu
slices:
  release-info:
    contents:
      %s: {until: mutate}
`, sharedTemporaryPath))
	inputs.Lockfile.Catalogues = []lock.Catalogue{*catalogue}
	record := &inputs.Lockfile.Slices[0]
	record.DefinitionDigest = definitionDigest(t, manifest, "release-info")
	payload := debBytes(t, record.Package, record.Version, debArchitecture(record.Architecture),
		tarMember{name: "." + sharedTemporaryPath, mode: 0o644, body: []byte("cached\n")})
	record.Content.SHA256, record.Content.Size = storeFile(t, store, payload)
	return inputs, store
}

// installPackageArtifact declares and locks one package artifact whose payload is
// the given DEB, so its content merges beside the slice content.
func installPackageArtifact(t *testing.T, inputs *builder.Inputs, store *cache.Cache, payload []byte) {
	t.Helper()
	digest, size := storeFile(t, store, payload)
	unpack := schemacontents.ArtifactUnpackPackage
	inputs.Lockfile.Artifacts = []lock.Artifact{{
		Name: "myapp", Platform: "linux/amd64", Path: "files/myapp.deb",
		SHA256: digest, Size: size, Unpack: &unpack,
		SBOM: schemacontents.ArtifactIdentity{Name: "myapp", Version: "1.0"},
	}}
	declared := strings.Replace(contentSpec, "\nfilesystem:", fmt.Sprintf(`
  artifacts:
    - name: myapp
      unpack: package
      sbom:
        name: myapp
        version: "1.0"
      sources:
        - platforms: [linux/amd64]
          path: files/myapp.deb
          sha256: %s

filesystem:`, digest), 1)
	inputs.Spec = loadSpec(t, declared)
	specDigest, err := inputs.Spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	inputs.Lockfile.SpecDigest = specDigest
}
