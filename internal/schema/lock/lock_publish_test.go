package lock

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishLockfile_WritesCanonicalYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "image.lock.yaml")
	lock := canonicalVectorLock()
	want := mustCanonicalYAML(t, lock)

	if err := PublishLockfile(path, lock); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("published bytes changed:\nwant:\n%s\ngot:\n%s", want, got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("published mode = %o, want 600", info.Mode().Perm())
	}

	if publishErr := PublishLockfile(path, lock); publishErr != nil {
		t.Fatal(publishErr)
	}
	again, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, again) {
		t.Fatal("repeated publication changed bytes")
	}
	assertOnlyLockFile(t, dir, "image.lock.yaml")
}

func TestPublishLockfile_ReplacesExistingLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "image.lock.yaml")
	if err := os.WriteFile(path, []byte("old lock\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := canonicalVectorLock()
	if err := PublishLockfile(path, lock); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustCanonicalYAML(t, lock)) {
		t.Fatal("new lock was not published")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("replaced mode = %o, want 600", info.Mode().Perm())
	}
	assertOnlyLockFile(t, dir, "image.lock.yaml")
}

func TestPublishLockfile_FailurePreservesOldLock(t *testing.T) {
	t.Parallel()
	const oldLock = "old lock bytes\n"
	injected := errors.New("injected failure")
	tests := []struct {
		name  string
		fail  func(*lockPublishOps)
		check func(error) bool
	}{
		{
			name: "write",
			fail: func(ops *lockPublishOps) {
				ops.write = func(*os.File, []byte) (int, error) { return 0, injected }
			},
			check: func(err error) bool { return errors.Is(err, injected) },
		},
		{
			name: "short write",
			fail: func(ops *lockPublishOps) {
				ops.write = func(*os.File, []byte) (int, error) { return 0, nil }
			},
			check: func(err error) bool { return errors.Is(err, io.ErrShortWrite) },
		},
		{
			name: "sync",
			fail: func(ops *lockPublishOps) {
				ops.sync = func(*os.File) error { return injected }
			},
			check: func(err error) bool { return errors.Is(err, injected) },
		},
		{
			name: "close",
			fail: func(ops *lockPublishOps) {
				ops.close = func(file *os.File) error {
					_ = file.Close()
					return injected
				}
			},
			check: func(err error) bool { return errors.Is(err, injected) },
		},
		{
			name: "rename",
			fail: func(ops *lockPublishOps) {
				ops.rename = func(string, string) error { return injected }
			},
			check: func(err error) bool { return errors.Is(err, injected) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "image.lock.yaml")
			if err := os.WriteFile(path, []byte(oldLock), 0o644); err != nil {
				t.Fatal(err)
			}
			ops := defaultLockPublishOps
			tt.fail(&ops)

			err := publishLockfile(path, []byte("new lock\n"), ops)
			if err == nil || !tt.check(err) {
				t.Fatalf("want injected error, got %v", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != oldLock {
				t.Fatalf("old lock changed: %q", got)
			}
			assertOnlyLockFile(t, dir, "image.lock.yaml")
		})
	}
}

func TestPublishLockfile_InvalidLockWritesNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "image.lock.yaml")
	lock := canonicalVectorLock()
	lock.Artifacts = []Artifact{{Name: "bad", Platform: "linux/amd64"}}
	if err := PublishLockfile(path, lock); err == nil {
		t.Fatal("invalid lock published")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destination created after encode error: %v", err)
	}
	assertOnlyLockFile(t, dir, "")
}

func assertOnlyLockFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		if len(entries) != 0 {
			t.Fatalf("temporary files leaked: %v", entries)
		}
		return
	}
	if len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("unexpected files: %v", entries)
	}
	if strings.HasPrefix(entries[0].Name(), ".vapor-lock-") {
		t.Fatal("temporary file leaked")
	}
}
