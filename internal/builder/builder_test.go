package builder_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/mutation"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

const minimalSpec = `version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: "26.04"
`

// catalogueSpec declares one remote catalogue, so the lock must carry a manifest
// for it.
const catalogueSpec = minimalSpec + `contents:
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
`

// rootKey is one armored OpenPGP key the fixture catalogue trusts, with the id the
// catalogue must refer to.
type rootKey struct {
	id    string
	armor string
}

// testKeyConfig generates an Ed25519 key: key generation is effectively free,
// and the production verifier accepts any algorithm it is not configured to
// reject.
var testKeyConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEd25519}

// sharedRootKey builds the fixture root key once per test binary; every fixture
// cache is independent, so reusing one key costs no isolation.
var sharedRootKey = sync.OnceValues(func() (rootKey, error) {
	entity, err := openpgp.NewEntity("Vapor test", "", "test@example.invalid", testKeyConfig)
	if err != nil {
		return rootKey{}, err
	}
	entity.Subkeys = nil
	buffer := &bytes.Buffer{}
	writer, err := armor.Encode(buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		return rootKey{}, err
	}
	if err = entity.Serialize(writer); err != nil {
		return rootKey{}, err
	}
	if err = writer.Close(); err != nil {
		return rootKey{}, err
	}
	armorText := "      " + strings.ReplaceAll(
		strings.TrimSuffix(buffer.String(), "\n"), "\n", "\n      ")
	return rootKey{id: fmt.Sprintf("%016X", entity.PrimaryKey.KeyId), armor: armorText}, nil
})

func newRootKey(t *testing.T) rootKey {
	t.Helper()
	key, err := sharedRootKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func chiselYAML(key rootKey) string {
	return fmt.Sprintf(`format: v3
maintenance:
  standard: 2026-04-23
  expanded: 2031-05-29
  legacy: 2036-04-23
  end-of-life: 2038-04-27
archives:
  ubuntu:
    version: "26.04"
    suites: [resolute]
    components: [main]
    priority: 10
    public-keys: [test]
public-keys:
  test:
    id: "%s"
    armor: |
%s
`, key.id, key.armor)
}

const sliceYAML = `package: base-files
archive: ubuntu
slices:
  release-info:
    contents:
      /etc/os-release:
  state:
    contents:
      /etc/vapor-state: {text: "", mutable: true}
    mutate: |
      content.write("/etc/vapor-state", "ready")
`

// storeFile publishes data into the cache and returns its digest and size.
func storeFile(t *testing.T, store *cache.Cache, data []byte) (string, int64) {
	t.Helper()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err := store.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatalf("store: %v", err)
	}
	return digest, int64(len(data))
}

// fixtureCatalogue publishes a minimal catalogue into the cache and returns the
// manifest a lock records for it, plus its tree digest.
func fixtureCatalogue(t *testing.T, store *cache.Cache) (*lock.Catalogue, []lock.CatalogueEntry) {
	t.Helper()
	return catalogueWithSlices(t, store, sliceYAML)
}

// catalogueWithSlices is fixtureCatalogue with the slice file a test supplies, so a
// test can give a slice a script the package-level fixture does not have.
func catalogueWithSlices(t *testing.T, store *cache.Cache, slices string) (*lock.Catalogue, []lock.CatalogueEntry) {
	t.Helper()
	return catalogueWithRoot(t, store, chiselYAML(newRootKey(t)), slices)
}

// catalogueWithRoot is catalogueWithSlices with a caller-supplied catalogue root, so
// a test can declare archives the minimal fixture does not have.
func catalogueWithRoot(t *testing.T, store *cache.Cache, chisel, slices string, extra ...lock.CatalogueEntry) (
	*lock.Catalogue, []lock.CatalogueEntry,
) {
	t.Helper()
	chiselDigest, chiselSize := storeFile(t, store, []byte(chisel))
	sliceDigest, sliceSize := storeFile(t, store, []byte(slices))
	manifest := make([]lock.CatalogueEntry, 0, 3+len(extra))
	manifest = append(manifest,
		lock.CatalogueEntry{Path: "chisel.yaml", Kind: "file", SHA256: chiselDigest, Size: chiselSize},
		lock.CatalogueEntry{Path: "slices", Kind: "dir"},
		lock.CatalogueEntry{Path: "slices/base-files.yaml", Kind: "file", SHA256: sliceDigest, Size: sliceSize},
	)
	manifest = append(manifest, extra...)
	tree, err := catalogue.NewTree(treeEntries(manifest))
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	digest, err := tree.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return &lock.Catalogue{
		Name: "custom",
		Source: lock.CatalogueSource{Type: "remote", URL: "https://example.com/catalogue",
			Selector: &lock.CatalogueSelector{Branch: new("ubuntu-26.04")}, Commit: strings.Repeat("4", 40)},
		Tree:     digest,
		Manifest: manifest,
		Archive:  &lock.Archive{SHA256: strings.Repeat("c", 64), Size: 512},
	}, manifest
}

func treeEntries(manifest []lock.CatalogueEntry) []catalogue.Entry {
	entries := make([]catalogue.Entry, len(manifest))
	for i := range manifest {
		entry := &manifest[i]
		entries[i] = catalogue.Entry{
			Path: entry.Path, Kind: catalogue.EntryKind(entry.Kind), Executable: entry.Executable,
			SHA256: entry.SHA256, Size: entry.Size, Target: entry.Target,
		}
	}
	return entries
}

func loadSpec(t *testing.T, text string) *spec.Spec {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

// fixture builds a spec, cache and lock that agree, so a test can break exactly one
// thing.
func fixture(t *testing.T) (*builder.Inputs, *cache.Cache) {
	t.Helper()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	loaded := loadSpec(t, catalogueSpec)
	digest, err := loaded.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	locked, _ := fixtureCatalogue(t, store)
	return &builder.Inputs{
		Spec:     loaded,
		Lockfile: &lock.Lockfile{Version: 1, SpecDigest: digest, Provider: lock.Provider{Distro: "ubuntu", Release: "26.04"}, Platforms: []string{"linux/amd64"}, Catalogues: []lock.Catalogue{*locked}},
		Provider: ubuntu.New("26.04"),
		Blobs:    store,
	}, store
}

func TestOpen_VerifiesLockStructure(t *testing.T) {
	inputs, _ := fixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if input == nil {
		t.Fatal("Open returned no input")
	}
}

func TestOpen_RefusesDriftedLock(t *testing.T) {
	inputs, _ := fixture(t)
	inputs.Lockfile.SpecDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := builder.Open(context.Background(), inputs); err == nil {
		t.Fatal("accepted a lock whose spec digest is wrong")
	}
}

func TestOpen_RefusesMissingInputs(t *testing.T) {
	inputs, _ := fixture(t)
	broken := map[string]*builder.Inputs{
		"no spec":     {Lockfile: inputs.Lockfile, Provider: inputs.Provider, Blobs: inputs.Blobs},
		"no lock":     {Spec: inputs.Spec, Provider: inputs.Provider, Blobs: inputs.Blobs},
		"no provider": {Spec: inputs.Spec, Lockfile: inputs.Lockfile, Blobs: inputs.Blobs},
		"no blobs":    {Spec: inputs.Spec, Lockfile: inputs.Lockfile, Provider: inputs.Provider},
	}
	for name, incomplete := range broken {
		if _, err := builder.Open(context.Background(), incomplete); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := builder.Open(context.Background(), nil); err == nil {
		t.Fatal("nil inputs: accepted")
	}
	// A nil context must be refused, not silently replaced.
	var noContext context.Context
	if _, err := builder.Open(noContext, inputs); err == nil {
		t.Fatal("nil context: accepted")
	}
}

func TestCatalogues_ParsesLockedCatalogue(t *testing.T) {
	inputs, _ := fixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	catalogues, err := input.Catalogues(context.Background())
	if err != nil {
		t.Fatalf("Catalogues: %v", err)
	}
	if len(catalogues) != 1 {
		t.Fatalf("catalogues = %d", len(catalogues))
	}
	rebuilt := catalogues[0]
	if rebuilt.Name != "custom" || rebuilt.Metadata.Format != "v3" {
		t.Fatalf("catalogue = %+v", rebuilt)
	}
	slice, ok := rebuilt.Packages["base-files"]
	if !ok {
		t.Fatalf("packages = %v", rebuilt.Packages)
	}
	if _, ok := slice.Slices["release-info"]; !ok {
		t.Fatalf("slices = %v", slice.Slices)
	}
	if len(rebuilt.Tree.Entries()) == 0 {
		t.Fatal("tree is empty")
	}
}

// TestCatalogues_RefusesTamperedManifest covers the digest the lock recorded: a
// manifest that describes different files is not the catalogue that was locked.
func TestCatalogues_RefusesTamperedManifest(t *testing.T) {
	inputs, store := fixture(t)
	extraDigest, extraSize := storeFile(t, store, []byte("package: injected\n"))
	inputs.Lockfile.Catalogues[0].Manifest = append(inputs.Lockfile.Catalogues[0].Manifest,
		lock.CatalogueEntry{Path: "slices/injected.yaml", Kind: "file", SHA256: extraDigest, Size: extraSize})
	requireCatalogueRejected(t, inputs, "manifest that does not match the locked tree")
}

// TestCatalogues_RefusesMissingBlob proves the build reads only the cache: a
// manifest entry whose bytes were never stored fails instead of downloading them.
func TestCatalogues_RefusesMissingBlob(t *testing.T) {
	inputs, store := fixture(t)
	empty, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inputs.Blobs = empty
	requireCatalogueRejected(t, inputs, "catalogue whose blobs are not cached")
	// The fixture cache still holds them, so it succeeds.
	inputs.Blobs = store
	input, openErr := builder.Open(context.Background(), inputs)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if _, err := input.Catalogues(context.Background()); err != nil {
		t.Fatalf("cached catalogue rejected: %v", err)
	}
}

// requireCatalogueRejected accepts either stage: the lock replay already reads the
// catalogue roots, so a bad one is refused before parsing starts.
func requireCatalogueRejected(t *testing.T, inputs *builder.Inputs, what string) {
	t.Helper()
	input, err := builder.Open(context.Background(), inputs)
	if err == nil {
		_, err = input.Catalogues(context.Background())
	}
	if err == nil {
		t.Fatalf("accepted a %s", what)
	}
}

// TestCatalogues_RefusesPoisonedBlob proves the builder trusts the recorded size even
// when a store hands back shorter bytes: a truncated catalogue file is refused, not
// parsed as if it were complete.
func TestCatalogues_RefusesPoisonedBlob(t *testing.T) {
	inputs, store := fixture(t)
	inputs.Blobs = &truncatingStore{inner: store}
	requireCatalogueRejected(t, inputs, "blob shorter than its recorded size")
}

// truncatingStore returns one byte less than the recorded size, imitating a store
// that verifies nothing.
type truncatingStore struct{ inner *cache.Cache }

func (s *truncatingStore) Open(digest string, size int64) (io.ReadCloser, error) {
	reader, err := s.inner.Open(digest, size)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.LimitReader(reader, size-1)), nil
}

func TestCatalogues_StopsOnCancelledContext(t *testing.T) {
	inputs, _ := fixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := input.Catalogues(ctx); err == nil {
		t.Fatal("accepted a canceled context")
	}
}

// TestMain turns the test binary into a sandbox worker when the builder
// re-executes it, so a build that runs slice scripts crosses the real process
// boundary rather than a stub.
func TestMain(m *testing.M) {
	if mutation.WorkerRequested() {
		os.Exit(mutation.RunWorker(os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}
