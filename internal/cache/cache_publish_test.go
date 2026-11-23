package cache

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreFailurePreservesExistingBlob(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected failure")
	tests := []struct {
		name string
		fail func(*storeOps)
	}{
		{
			name: "sync",
			fail: func(ops *storeOps) {
				ops.sync = func(*os.File) error { return injected }
			},
		},
		{
			name: "close",
			fail: func(ops *storeOps) {
				ops.close = func(file *os.File) error {
					_ = file.Close()
					return injected
				}
			},
		},
		{
			name: "rename",
			fail: func(ops *storeOps) {
				ops.rename = func(string, string) error { return injected }
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, dir := newTestCache(t)
			data := []byte("new blob")
			digest := digestOf(data)
			path := c.blobPath(digest)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("old blob"), 0o600); err != nil {
				t.Fatal(err)
			}
			ops := defaultStoreOps
			tt.fail(&ops)

			if err := c.store(bytes.NewReader(data), digest, int64(len(data)), ops); !errors.Is(err, injected) {
				t.Fatalf("want injected error, got %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "old blob" {
				t.Fatalf("existing blob changed: %q", got)
			}
			assertNoStaging(t, dir)
		})
	}
}
