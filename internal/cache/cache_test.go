package cache

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreVerifiedBlob(t *testing.T) {
	t.Parallel()
	c, dir := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)

	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	path := c.blobPath(digest)
	if want := filepath.Join(dir, "sha256", digest[:2], digest); path != want {
		t.Fatalf("blob path = %s, want %s", path, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("blob bytes = %q, want %q", got, data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("blob mode = %o, want 600", info.Mode().Perm())
	}

	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	assertNoStaging(t, dir)
}

func TestStoreEmptyBlob(t *testing.T) {
	t.Parallel()
	c, dir := newTestCache(t)
	digest := digestOf(nil)
	if err := c.Store(bytes.NewReader(nil), digest, 0); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(c.blobPath(digest))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("empty blob has %d bytes", len(data))
	}
	assertNoStaging(t, dir)
}

func TestStoreRejectsMismatch(t *testing.T) {
	t.Parallel()
	data := []byte("short")
	digest := digestOf(data)
	tests := []struct {
		name   string
		reader io.Reader
		digest string
		size   int64
	}{
		{name: "wrong digest", reader: bytes.NewReader(data), digest: strings.Repeat("0", 64), size: int64(len(data))},
		{name: "short input", reader: bytes.NewReader(data[:len(data)-1]), digest: digest, size: int64(len(data))},
		{name: "long input", reader: bytes.NewReader(append(append([]byte(nil), data...), 'x')), digest: digest, size: int64(len(data))},
		{name: "size too small", reader: bytes.NewReader(data), digest: digest, size: int64(len(data) - 1)},
		{name: "size too large", reader: bytes.NewReader(data), digest: digest, size: int64(len(data) + 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, dir := newTestCache(t)
			if err := c.Store(tt.reader, tt.digest, tt.size); err == nil {
				t.Fatal("Store accepted mismatched blob")
			}
			if _, err := os.Stat(c.blobPath(digest)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected blob was published: %v", err)
			}
			assertNoStaging(t, dir)
		})
	}
}

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestStoreReaderError(t *testing.T) {
	t.Parallel()
	c, dir := newTestCache(t)
	data := []byte("interrupted")
	digest := digestOf(data)
	errInjected := errors.New("GET https://host/blob?token=SECRET")
	err := c.Store(&failingReader{data: data[:3], err: errInjected}, digest, int64(len(data)))
	if !errors.Is(err, errInjected) {
		t.Fatalf("want reader error, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("reader error leaked sensitive input: %v", err)
	}
	if _, err := os.Stat(c.blobPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial blob was published: %v", err)
	}
	assertNoStaging(t, dir)
}

func TestStoreRejectsInvalidArguments(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("data")
	digest := digestOf(data)
	tests := []struct {
		name   string
		cache  *Cache
		reader io.Reader
		digest string
		size   int64
	}{
		{name: "nil cache", cache: nil, reader: bytes.NewReader(data), digest: digest, size: int64(len(data))},
		{name: "nil reader", cache: c, reader: nil, digest: digest, size: int64(len(data))},
		{name: "negative size", cache: c, reader: bytes.NewReader(data), digest: digest, size: -1},
		{name: "short digest", cache: c, reader: bytes.NewReader(data), digest: digest[:63], size: int64(len(data))},
		{name: "uppercase digest", cache: c, reader: bytes.NewReader(data), digest: strings.ToUpper(digest), size: int64(len(data))},
		{name: "non-hex digest", cache: c, reader: bytes.NewReader(data), digest: strings.Repeat("z", 64), size: int64(len(data))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cache.Store(tt.reader, tt.digest, tt.size); err == nil {
				t.Fatal("Store accepted invalid argument")
			}
		})
	}
}
