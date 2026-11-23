package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileAtomicReplacesAStaleFile checks that a rerun replaces the previous
// statement rather than appending to or truncating it in place.
func TestWriteFileAtomicReplacesAStaleFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "statement.json")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "fresh" {
		t.Fatalf("content = %q, err = %v", body, err)
	}
}

// TestWriteFileAtomicReplacesASymlink checks that a link planted at the destination is
// replaced instead of followed, so the write cannot land on another file.
func TestWriteFileAtomicReplacesASymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.json")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "statement.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("destination mode = %v, err = %v", info, statErr)
	}
	body, readErr := os.ReadFile(victim)
	if readErr != nil || string(body) != "untouched" {
		t.Fatalf("symlink target = %q, err = %v", body, readErr)
	}
}
