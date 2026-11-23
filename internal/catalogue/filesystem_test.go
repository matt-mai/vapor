package catalogue_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/catalogue"
)

type memoryStore map[string][]byte

func (m memoryStore) Open(digest string, size int64) (io.ReadCloser, error) {
	data, ok := m[digest]
	if !ok || int64(len(data)) != size {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m memoryStore) add(data []byte) (string, int64) {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	m[digest] = data
	return digest, int64(len(data))
}

func TestFileSystem_ReadsTreeFromStore(t *testing.T) {
	t.Parallel()
	store := memoryStore{}
	chiselDigest, chiselSize := store.add([]byte("format: v3\n"))
	sliceDigest, sliceSize := store.add([]byte("package: base-files\n"))
	tree, err := catalogue.NewTree([]catalogue.Entry{
		{Path: "chisel.yaml", Kind: catalogue.KindFile, SHA256: chiselDigest, Size: chiselSize},
		{Path: "slices", Kind: catalogue.KindDir},
		{Path: "slices/base-files.yaml", Kind: catalogue.KindFile, SHA256: sliceDigest, Size: sliceSize},
		{Path: "latest", Kind: catalogue.KindSymlink, Target: "chisel.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := catalogue.FileSystem(tree, store)
	if err != nil {
		t.Fatalf("FileSystem: %v", err)
	}
	for name, want := range map[string]string{
		"chisel.yaml":            "format: v3\n",
		"slices/base-files.yaml": "package: base-files\n",
		"latest":                 "chisel.yaml",
	} {
		got, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			t.Fatalf("%s: %v", name, readErr)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	entries, err := fs.ReadDir(fsys, "slices")
	if err != nil || len(entries) != 1 || entries[0].Name() != "base-files.yaml" {
		t.Fatalf("slices = %v, %v", entries, err)
	}
}

func TestFileSystem_Refusals(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	tree, err := catalogue.NewTree([]catalogue.Entry{
		{Path: "chisel.yaml", Kind: catalogue.KindFile, SHA256: digest, Size: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalogue.FileSystem(tree, nil); err == nil {
		t.Fatal("accepted a missing store")
	}
	if _, err := catalogue.FileSystem(tree, memoryStore{}); err == nil {
		t.Fatal("accepted a file whose blob is not cached")
	}
	if _, err := catalogue.FileSystem(tree, memoryStore{digest: []byte("way too long")}); err == nil {
		t.Fatal("accepted a blob whose size does not match the entry")
	}
}
