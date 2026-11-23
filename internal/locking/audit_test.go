package locking

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

func TestAuditCountsVerifiedBytes(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	local := store.add("key")
	catalogueBlob := store.add("tree")
	tree, err := catalogue.NewTree([]catalogue.Entry{{
		Path: "chisel.yaml", Kind: catalogue.KindFile, SHA256: catalogueBlob.digest, Size: catalogueBlob.size,
	}})
	if err != nil {
		t.Fatal(err)
	}
	treeDigest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	artifact := store.add("artifact")
	artifactARM := store.add("artifact-arm")
	lockfile := &lock.Lockfile{
		LocalInputs: []lock.LocalInput{{Role: "trust-key", Path: "key.asc", SHA256: local.digest, Size: local.size}},
		Catalogues: []lock.Catalogue{{
			Name: "custom", Tree: treeDigest,
			Manifest: []lock.CatalogueEntry{{
				Path: "chisel.yaml", Kind: string(catalogue.KindFile), SHA256: catalogueBlob.digest, Size: catalogueBlob.size,
			}},
		}},
		Artifacts: []lock.Artifact{
			{Name: "server", SHA256: artifact.digest, Size: artifact.size},
			{Name: "server", SHA256: artifactARM.digest, Size: artifactARM.size},
		},
	}
	stats, err := Audit(lockfile, store)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Packages != 0 {
		t.Fatalf("packages = %d", stats.Packages)
	}
	want := local.size + catalogueBlob.size + artifact.size + artifactARM.size
	if stats.VerifiedBytes != want {
		t.Fatalf("verified bytes = %d, want %d", stats.VerifiedBytes, want)
	}
}

// auditBlobs is audit without the repository verification, which these payload cases
// do not need.
func auditBlobs(ctx context.Context, lockfile *lock.Lockfile, store BlobStore, stats *Stats) error {
	blobs, err := Blobs(lockfile)
	if err != nil {
		return err
	}
	for i := range blobs {
		if err := auditBlob(ctx, store, &blobs[i], stats); err != nil {
			return err
		}
	}
	return nil
}

func TestAuditPayloadsChecksCachedBytes(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	pkg := store.add("package")
	pkgARM := store.add("package-arm")
	slice := store.add("slice")
	lockfile := &lock.Lockfile{
		Packages: []lock.Package{
			{Name: "openssl", Version: "3.0", Architecture: "amd64", Repository: "repo",
				Content: lock.Content{Path: "pool/openssl.deb", SHA256: pkg.digest, Size: pkg.size}},
			{Name: "openssl", Version: "3.0", Architecture: "arm64", Repository: "repo",
				Content: lock.Content{Path: "pool/openssl.deb", SHA256: pkgARM.digest, Size: pkgARM.size}},
		},
		Slices: []lock.Slice{{
			Package: "base-files", Version: "1", Architecture: "all", Repository: "repo",
			Content: lock.Content{Path: "pool/base-files.deb", SHA256: slice.digest, Size: slice.size},
		}},
	}
	stats := Stats{Packages: len(lockfile.Packages)}
	if err := auditBlobs(t.Context(), lockfile, store, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.VerifiedBytes != pkg.size+pkgARM.size+slice.size {
		t.Fatalf("verified bytes = %d", stats.VerifiedBytes)
	}
	lockfile.Slices[0].Content.Size++
	if err := auditBlobs(t.Context(), lockfile, store, &stats); err == nil {
		t.Fatal("audit accepted a slice archive with the wrong size")
	}
	lockfile.Slices[0].Content.Size--
	delete(store.blobs, pkg.digest)
	if err := auditBlobs(t.Context(), lockfile, store, &stats); err == nil {
		t.Fatal("audit accepted missing package bytes")
	}
}

func TestAuditValidation(t *testing.T) {
	t.Parallel()
	if _, err := Audit(nil, newMemoryStore()); err == nil {
		t.Fatal("nil lock accepted")
	}
	if _, err := Audit(&lock.Lockfile{}, nil); err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestAuditRepositorySizes(t *testing.T) {
	t.Parallel()
	repository := &lock.Repository{
		Trust: lock.RepositoryTrust{Keys: []lock.RepositoryKey{{Size: 3}}},
		Release: lock.RepositoryRelease{
			Size:      5,
			Signature: &lock.Content{Size: 7},
		},
		Indexes: []lock.Index{{Size: 11}},
	}
	stats := Stats{}
	for _, blob := range repositoryBlobs(repository) {
		if blob.Read {
			t.Fatalf("repository blob %q is read again", blob.Label)
		}
		if err := addBytes(&stats.VerifiedBytes, blob.Size); err != nil {
			t.Fatal(err)
		}
	}
	if stats.VerifiedBytes != 26 {
		t.Fatalf("verified bytes = %d", stats.VerifiedBytes)
	}
}

func TestAddBytesRejectsInvalidSizes(t *testing.T) {
	t.Parallel()
	total := int64(0)
	if err := addBytes(&total, -1); err == nil {
		t.Fatal("negative size accepted")
	}
	total = math.MaxInt64
	if err := addBytes(&total, 1); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestAuditRejectsSizeMismatch(t *testing.T) {
	t.Parallel()
	lockfile := &lock.Lockfile{LocalInputs: []lock.LocalInput{{
		Role: "ca", Path: "ca.pem", SHA256: strings.Repeat("a", 64), Size: 1,
	}}}
	if _, err := Audit(lockfile, oversizedStore{}); err == nil {
		t.Fatal("oversized blob accepted")
	}
}

type failingStore struct {
	err error
}

func (s failingStore) Open(string, int64) (io.ReadCloser, error) { return nil, s.err }

func TestReadBlobHidesStoreDetails(t *testing.T) {
	t.Parallel()
	pathErr := &fs.PathError{Op: "open", Path: "/secret/cache/path", Err: fs.ErrNotExist}
	var total int64
	err := readBlob(t.Context(), failingStore{err: pathErr}, "digest", 1, &total)
	if err == nil {
		t.Fatal("missing blob accepted")
	}
	if strings.Contains(err.Error(), "/secret") {
		t.Fatalf("error exposed store path: %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("cause was not preserved: %v", err)
	}
}

func TestAuditRejectsIncompleteCatalogueManifest(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	blob := store.add("tree")
	tree, err := catalogue.NewTree([]catalogue.Entry{{
		Path: "chisel.yaml", Kind: catalogue.KindFile, SHA256: blob.digest, Size: blob.size,
	}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	manifest := []lock.CatalogueEntry{{Path: "chisel.yaml", Kind: string(catalogue.KindFile), SHA256: blob.digest, Size: blob.size}}
	if _, err = Audit(&lock.Lockfile{Catalogues: []lock.Catalogue{{Name: "local", Tree: digest}}}, store); err == nil {
		t.Fatal("catalogue without a manifest was accepted")
	}
	if _, err = Audit(&lock.Lockfile{Catalogues: []lock.Catalogue{{
		Name: "local", Tree: digest, Manifest: []lock.CatalogueEntry{{Path: "chisel.yaml", Kind: string(catalogue.KindFile)}},
	}}}, store); err == nil {
		t.Fatal("manifest mismatch was accepted")
	}
	missing := newMemoryStore()
	if _, err = Audit(&lock.Lockfile{Catalogues: []lock.Catalogue{{
		Name: "local", Tree: digest, Manifest: manifest,
	}}}, missing); err == nil {
		t.Fatal("missing catalogue blob was accepted")
	}
}
