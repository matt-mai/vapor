package catalogue

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/cache"
)

// The header bound exists to stop a hostile archive from being walked forever.
// Walking the real limit costs a hundred thousand headers, so this test passes a
// small one: the check must still fire exactly at the limit, not one header early.
func TestSnapshotArchiveHeaderLimitInjectable(t *testing.T) {
	t.Parallel()
	const maxHeaders = 64
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	build := func(n int) []byte {
		var tarBuf bytes.Buffer
		writer := tar.NewWriter(&tarBuf)
		for range n {
			if writeErr := writer.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		if closeErr := writer.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		var gz bytes.Buffer
		gzipWriter := gzip.NewWriter(&gz)
		if _, writeErr := gzipWriter.Write(tarBuf.Bytes()); writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr := gzipWriter.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		return gz.Bytes()
	}
	if _, limitErr := snapshotArchiveWithHeaderLimit(build(maxHeaders), store, maxHeaders); limitErr != nil {
		t.Fatalf("archive at the limit rejected: %v", limitErr)
	}
	_, limitErr := snapshotArchiveWithHeaderLimit(build(maxHeaders+1), store, maxHeaders)
	if limitErr == nil || !strings.Contains(limitErr.Error(), "headers") {
		t.Fatalf("error = %v, want the header bound", limitErr)
	}
}
