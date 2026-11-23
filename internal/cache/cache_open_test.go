package cache

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenVerifiedBlob(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}

	reader, err := c.Open(digest, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader(t, reader)
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("read bytes = %q, want %q", got, data)
	}
}

func TestOpenEmptyBlob(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	digest := digestOf(nil)
	if err := c.Store(bytes.NewReader(nil), digest, 0); err != nil {
		t.Fatal(err)
	}

	reader, err := c.Open(digest, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader(t, reader)
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("read %d bytes, want empty", len(got))
	}
}

func TestOpenRejectsInvalidArguments(t *testing.T) {
	t.Parallel()
	digest := digestOf([]byte("data"))

	var nilCache *Cache
	if _, err := nilCache.Open(digest, 4); err == nil {
		t.Fatal("Open accepted a nil cache")
	}
	uninitialized := &Cache{}
	if _, err := uninitialized.Open(digest, 4); err == nil {
		t.Fatal("Open accepted an uninitialized cache")
	}
	c, _ := newTestCache(t)
	for _, tt := range []struct {
		name   string
		digest string
		size   int64
	}{
		{name: "short digest", digest: "abc", size: 0},
		{name: "uppercase digest", digest: strings.ToUpper(digest), size: 4},
		{name: "negative size", digest: digest, size: -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := c.Open(tt.digest, tt.size); err == nil {
				t.Fatal("Open accepted invalid arguments")
			}
		})
	}
}

func TestOpenMissingBlob(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	if _, err := c.Open(strings.Repeat("a", 64), 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open error = %v, want fs.ErrNotExist", err)
	}
}

func TestOpenRejectsMismatchedBlob(t *testing.T) {
	t.Parallel()
	data := []byte("verified data")
	for _, tt := range []struct {
		name    string
		digest  string
		size    int64
		prepare func(t *testing.T, path string)
	}{
		{
			name:   "wrong digest",
			digest: digestOf([]byte("other data")),
			size:   int64(len(data)),
		},
		{
			name:   "wrong size smaller",
			digest: digestOf(data),
			size:   int64(len(data) - 1),
		},
		{
			name:   "wrong size larger",
			digest: digestOf(data),
			size:   int64(len(data) + 1),
		},
		{
			name:   "corrupt bytes",
			digest: digestOf(data),
			size:   int64(len(data)),
			prepare: func(t *testing.T, path string) {
				t.Helper()
				corrupt := append([]byte(nil), data...)
				corrupt[0] ^= 0xff
				if err := os.WriteFile(path, corrupt, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "truncated file",
			digest: digestOf(data),
			size:   int64(len(data)),
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, data[:len(data)-1], 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "extended file",
			digest: digestOf(data),
			size:   int64(len(data)),
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, append(append([]byte(nil), data...), 'x'), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "not a regular file",
			digest: digestOf(data),
			size:   int64(len(data)),
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newTestCache(t)
			if err := c.Store(bytes.NewReader(data), digestOf(data), int64(len(data))); err != nil {
				t.Fatal(err)
			}
			path := c.blobPath(digestOf(data))
			if tt.prepare != nil {
				tt.prepare(t, path)
			}
			// A corrupt blob of the right size opens, so the failure has to arrive when
			// the bytes are read and hashed.
			reader, err := c.Open(tt.digest, tt.size)
			if err != nil {
				return
			}
			defer closeReader(t, reader)
			if _, err := io.ReadAll(reader); err == nil {
				t.Fatal("Open accepted a mismatched blob")
			}
		})
	}
}

func TestOpenHandleSurvivesReplacement(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	oldData := []byte("old verified blob")
	digest := digestOf(oldData)
	if err := c.Store(bytes.NewReader(oldData), digest, int64(len(oldData))); err != nil {
		t.Fatal(err)
	}
	reader, err := c.Open(digest, int64(len(oldData)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader(t, reader)

	replacement := []byte("different bytes")
	temp, err := os.CreateTemp(filepath.Dir(c.blobPath(digest)), ".replacement-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := temp.Write(replacement); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := temp.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if renameErr := os.Rename(temp.Name(), c.blobPath(digest)); renameErr != nil {
		t.Fatal(renameErr)
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldData) {
		t.Fatalf("open handle read %q, want %q", got, oldData)
	}
	if _, err := c.Open(digest, int64(len(oldData))); err == nil {
		t.Fatal("Open accepted replaced bytes")
	}
}
