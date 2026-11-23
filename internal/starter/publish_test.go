package starter

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerate_ExistingEntriesUntouched(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"file", "directory", "symlink", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			options := testOptions(t)
			if err := os.MkdirAll(options.Dir, 0o755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(options.Dir, "image.yaml")
			switch kind {
			case "file":
				if err := os.WriteFile(filename, []byte("original"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(filename, 0o700); err != nil {
					t.Fatal(err)
				}
			default:
				linkTarget := target
				if kind == "dangling symlink" {
					linkTarget += ".missing"
				}
				if err := os.Symlink(linkTarget, filename); err != nil {
					t.Fatal(err)
				}
			}
			before, beforeErr := os.Lstat(filename)
			if beforeErr != nil {
				t.Fatal(beforeErr)
			}
			if err := Generate(options); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("want preserved wrapped ErrExist, got %v", err)
			}
			after, afterErr := os.Lstat(filename)
			if afterErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("existing entry replaced/changed: %v", afterErr)
			}
			if kind == "file" {
				data, err := os.ReadFile(filename)
				if err != nil || string(data) != "original" {
					t.Fatalf("existing file overwritten: %v", err)
				}
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "untouched" {
				t.Fatalf("symlink target changed: %v", err)
			}
			entries, err := os.ReadDir(options.Dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary-file leak: %v, %v", entries, err)
			}
		})
	}
}

func TestGenerate_ExistingDirectoryAndParentSymlink(t *testing.T) {
	t.Parallel()
	options := testOptions(t)
	realDir := t.TempDir()
	unrelated := filepath.Join(realDir, "keep.txt")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	options.Dir = filepath.Join(t.TempDir(), "chosen-directory")
	if err := os.Symlink(realDir, options.Dir); err != nil {
		t.Fatal(err)
	}
	if err := Generate(options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(realDir, "image.yaml")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(unrelated)
	if err != nil || string(data) != "keep" {
		t.Fatalf("unrelated file changed: %v", err)
	}
}

func TestPublish_PinnedDirectoryAfterRename(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	root, openErr := os.OpenRoot(original)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publish(root, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(moved, "image.yaml"))
	if err != nil || string(data) != "complete" {
		t.Fatalf("publication not pinned: %v", err)
	}
	entries, err := os.ReadDir(original)
	if err != nil || len(entries) != 0 {
		t.Fatalf("publication redirected into replacement directory: %v, %v", entries, err)
	}
}
