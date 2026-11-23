package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRejectsInvalidDirectory(t *testing.T) {
	t.Parallel()
	if _, err := New(""); err == nil {
		t.Fatal("New accepted empty directory")
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("New accepted a regular file")
	}
}

func closeReader(t *testing.T, reader io.Closer) {
	t.Helper()
	if err := reader.Close(); err != nil {
		t.Errorf("close reader: %v", err)
	}
}

func newTestCache(t *testing.T) (*Cache, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func assertNoStaging(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".vapor-blob-") {
			t.Errorf("staging file leaked: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
