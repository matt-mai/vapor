package catalogue_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
)

func TestSnapshotDirectory_CachesAndSurvivesChanges(t *testing.T) {
	t.Parallel()
	specDir := t.TempDir()
	root := filepath.Join(specDir, "catalogue")
	writeFile(t, filepath.Join(root, "slices", "base-files.yaml"), "base: 1\n", 0o644)
	writeFile(t, filepath.Join(root, "bin", "tool"), "#!/bin/sh\n", 0o755)
	if mkdirErr := os.Mkdir(filepath.Join(root, "empty"), 0o755); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if symlinkErr := os.Symlink("slices/base-files.yaml", filepath.Join(root, "latest")); symlinkErr != nil {
		t.Fatal(symlinkErr)
	}
	store := newStore(t)
	tree, err := catalogue.SnapshotDirectory(specDir, "catalogue", store)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	entries := tree.Entries()
	if !containsEntry(entries, "bin", catalogue.KindDir) ||
		!containsEntry(entries, "empty", catalogue.KindDir) ||
		!containsEntry(entries, "latest", catalogue.KindSymlink) {
		t.Fatalf("missing tree entries: %#v", entries)
	}
	tool := findEntry(t, entries, "bin/tool")
	if !tool.Executable || tool.Size != 10 {
		t.Fatalf("tool entry = %#v", tool)
	}
	if old := string(readBlob(t, store, tool.SHA256, tool.Size)); old != "#!/bin/sh\n" {
		t.Fatalf("cached tool = %q", old)
	}

	writeFile(t, filepath.Join(root, "bin", "tool"), "changed\n", 0o644)
	if removeErr := os.Remove(filepath.Join(root, "slices", "base-files.yaml")); removeErr != nil {
		t.Fatal(removeErr)
	}
	writeFile(t, filepath.Join(root, "added.yaml"), "new\n", 0o644)
	again, err := catalogue.SnapshotDirectory(specDir, "catalogue", store)
	if err != nil {
		t.Fatal(err)
	}
	againDigest, err := again.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if againDigest == digest {
		t.Fatal("post-snapshot local changes did not change the new tree")
	}
	if old := string(readBlob(t, store, tool.SHA256, tool.Size)); old != "#!/bin/sh\n" {
		t.Fatalf("cached bytes changed with local file: %q", old)
	}
}

func TestSnapshotDirectory_ResolvesSpecRelative(t *testing.T) {
	t.Parallel()
	specDir := filepath.Join(t.TempDir(), "specs")
	writeFile(t, filepath.Join(specDir, "..", "shared", "cat", "file.yaml"), "x\n", 0o644)
	tree, err := catalogue.SnapshotDirectory(specDir, "../shared/cat", newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Entries()) != 1 || tree.Entries()[0].Path != "file.yaml" {
		t.Fatalf("entries = %#v", tree.Entries())
	}
	for _, invalid := range []string{"/absolute", "a/../../escape", `a\b`, "a/./b"} {
		if _, err := catalogue.SnapshotDirectory(specDir, invalid, newStore(t)); err == nil {
			t.Fatalf("invalid declaration %q accepted", invalid)
		}
	}
}

func TestSnapshotDirectory_RejectsUnsafeLinks(t *testing.T) {
	t.Parallel()
	for name, links := range map[string][][2]string{
		"escape":   {{"escape", "../../etc/passwd"}},
		"absolute": {{"absolute", "/etc/passwd"}},
		"ancestor": {{"a/b/up", ".."}},
		"self":     {{"self", "self"}},
		"cycle":    {{"a", "b"}, {"b", "a"}},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "catalogue")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, link := range links {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(root, link[0])), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(link[1], filepath.Join(root, link[0])); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := catalogue.SnapshotDirectory(filepath.Dir(root), "catalogue", newStore(t)); err == nil {
				t.Fatal("unsafe local symlink accepted")
			}
		})
	}
}

func TestSnapshot_EnumerationOrder(t *testing.T) {
	t.Parallel()
	first := filepath.Join(t.TempDir(), "catalogue")
	second := filepath.Join(t.TempDir(), "catalogue")
	for _, root := range []string{first, second} {
		if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(first, "a", "one"), "1\n", 0o644)
	writeFile(t, filepath.Join(first, "b"), "2\n", 0o644)
	writeFile(t, filepath.Join(second, "b"), "2\n", 0o644)
	writeFile(t, filepath.Join(second, "a", "one"), "1\n", 0o644)
	treeOne, err := catalogue.SnapshotDirectory(filepath.Dir(first), "catalogue", newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	treeTwo, err := catalogue.SnapshotDirectory(filepath.Dir(second), "catalogue", newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := treeOne.Digest()
	secondDigest, _ := treeTwo.Digest()
	if firstDigest != secondDigest {
		t.Fatalf("enumeration order changed digest: %s != %s", firstDigest, secondDigest)
	}
}

func TestSnapshotArchive_MatchesDirectory(t *testing.T) {
	t.Parallel()
	data := tarData(t, false,
		tarItem{header: tar.Header{Name: "./slices/base-files.yaml", Mode: 0o644, Size: 7}, body: "base: 1"},
		tarItem{header: tar.Header{Name: "./bin/tool", Mode: 0o755, Size: 10}, body: "#!/bin/sh\n"},
		tarItem{header: tar.Header{Name: "./latest", Typeflag: tar.TypeSymlink, Linkname: "slices/base-files.yaml"}},
		tarItem{header: tar.Header{Name: "./empty/", Typeflag: tar.TypeDir, Mode: 0o755}},
	)
	store := newStore(t)
	fromArchive, err := catalogue.SnapshotArchive(data, store)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "catalogue")
	writeFile(t, filepath.Join(root, "slices", "base-files.yaml"), "base: 1", 0o644)
	writeFile(t, filepath.Join(root, "bin", "tool"), "#!/bin/sh\n", 0o755)
	if mkdirErr := os.Mkdir(filepath.Join(root, "empty"), 0o755); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if symlinkErr := os.Symlink("slices/base-files.yaml", filepath.Join(root, "latest")); symlinkErr != nil {
		t.Fatal(symlinkErr)
	}
	fromDirectory, err := catalogue.SnapshotDirectory(filepath.Dir(root), "catalogue", store)
	if err != nil {
		t.Fatal(err)
	}
	archiveDigest, _ := fromArchive.Digest()
	directoryDigest, _ := fromDirectory.Digest()
	if archiveDigest != directoryDigest {
		t.Fatalf("archive and directory digests differ: %s != %s", archiveDigest, directoryDigest)
	}
	sum := sha256.Sum256(data)
	if got := readBlob(t, store, hex.EncodeToString(sum[:]), int64(len(data))); !bytes.Equal(got, data) {
		t.Fatal("archive bytes were not cached")
	}

	compressed := gzipData(t, data)
	gzipped, err := catalogue.SnapshotArchive(compressed, store)
	if err != nil {
		t.Fatal(err)
	}
	gzippedDigest, _ := gzipped.Digest()
	if gzippedDigest != directoryDigest {
		t.Fatalf("gzip archive digest differs: %s", gzippedDigest)
	}
}

func TestSnapshotArchive_RejectsUnsafeEntries(t *testing.T) {
	t.Parallel()
	cases := map[string][]tarItem{
		"absolute":        {{header: tar.Header{Name: "/etc/passwd", Mode: 0o644, Size: 1}, body: "x"}},
		"parent":          {{header: tar.Header{Name: "../escape", Mode: 0o644, Size: 1}, body: "x"}},
		"parent inside":   {{header: tar.Header{Name: "a/../../escape", Mode: 0o644, Size: 1}, body: "x"}},
		"backslash":       {{header: tar.Header{Name: `a\b`, Mode: 0o644, Size: 1}, body: "x"}},
		"dot file":        {{header: tar.Header{Name: ".", Mode: 0o644, Size: 1}, body: "x"}},
		"trailing slash":  {{header: tar.Header{Name: "a/", Typeflag: tar.TypeSymlink, Linkname: "b"}}},
		"duplicate":       {{header: tar.Header{Name: "a", Mode: 0o644, Size: 1}, body: "x"}, {header: tar.Header{Name: "a", Mode: 0o644, Size: 1}, body: "y"}},
		"hardlink":        {{header: tar.Header{Name: "a", Typeflag: tar.TypeLink, Linkname: "b"}}},
		"character":       {{header: tar.Header{Name: "a", Typeflag: tar.TypeChar}}},
		"fifo":            {{header: tar.Header{Name: "a", Typeflag: tar.TypeFifo}}},
		"absolute target": {{header: tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}},
		"escaping target": {{header: tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"}}},
		"link cycle":      {{header: tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "b"}}, {header: tar.Header{Name: "b", Typeflag: tar.TypeSymlink, Linkname: "a"}}},
		"file under link": {{header: tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "b"}}, {header: tar.Header{Name: "a/b", Mode: 0o644, Size: 1}, body: "x"}},
	}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := catalogue.SnapshotArchive(tarData(t, false, items...), newStore(t)); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestSnapshotArchive_RejectsTruncationAndOversize(t *testing.T) {
	t.Parallel()
	truncated := tarData(t, true, tarItem{header: tar.Header{Name: "a", Mode: 0o644, Size: 10}, body: "abc"})
	if _, err := catalogue.SnapshotArchive(truncated, newStore(t)); err == nil {
		t.Fatal("truncated archive accepted")
	}
	oversize := tarData(t, true, tarItem{header: tar.Header{Name: "a", Mode: 0o644, Size: catalogue.MaxTreeFileSize + 1}})
	if _, err := catalogue.SnapshotArchive(oversize, newStore(t)); err == nil {
		t.Fatal("oversized archive entry accepted")
	}
	if _, err := catalogue.SnapshotArchive([]byte("not tar"), newStore(t)); err == nil {
		t.Fatal("invalid archive accepted")
	}
	if _, err := catalogue.SnapshotArchive([]byte{0x1f, 0x8b, 0x00}, newStore(t)); err == nil {
		t.Fatal("invalid gzip archive accepted")
	}
}

type tarItem struct {
	header tar.Header
	body   string
}

func tarData(t *testing.T, ignoreClose bool, items ...tarItem) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for i := range items {
		item := &items[i]
		if err := writer.WriteHeader(&item.header); err != nil {
			t.Fatal(err)
		}
		if item.body != "" {
			if _, err := io.WriteString(writer, item.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil && !ignoreClose {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func gzipData(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	// BestSpeed keeps the flood fixture cheap to build; the decompressed bytes
	// are identical either way.
	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func newStore(t *testing.T) *cache.Cache {
	t.Helper()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func readBlob(t *testing.T, store *cache.Cache, digest string, size int64) []byte {
	t.Helper()
	reader, err := store.Open(digest, size)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, name, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func containsEntry(entries []catalogue.Entry, name string, kind catalogue.EntryKind) bool {
	for _, entry := range entries {
		if entry.Path == name && entry.Kind == kind {
			return true
		}
	}
	return false
}

func findEntry(t *testing.T, entries []catalogue.Entry, name string) catalogue.Entry {
	t.Helper()
	for _, entry := range entries {
		if entry.Path == name {
			return entry
		}
	}
	t.Fatalf("entry %q not found", name)
	return catalogue.Entry{}
}
