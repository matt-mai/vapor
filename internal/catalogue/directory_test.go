package catalogue_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/catalogue"
)

func TestDirectoryConfinesSymlinks(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte("format: v3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), filepath.Join(dir, "chisel.yaml")); err != nil {
		t.Fatal(err)
	}
	directory, err := catalogue.OpenDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if _, err := fs.ReadFile(directory, "chisel.yaml"); err == nil {
		t.Fatal("symlink outside the catalogue directory was followed")
	}
}

func TestDirectoryBoundsFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "huge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if truncateErr := file.Truncate(catalogue.MaxTreeFileSize + 1); truncateErr != nil {
		t.Fatal(truncateErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	directory, err := catalogue.OpenDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if _, err := fs.ReadFile(directory, "huge.yaml"); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("error = %v", err)
	}
}
