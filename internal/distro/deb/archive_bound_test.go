package deb

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return compressed.Bytes()
}

func testArArchive(t *testing.T, members ...arMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(archiveMagic)
	for _, member := range members {
		fmt.Fprintf(&buf, "%-16s%-12s%-6s%-6s%-8s%-10s`\n",
			member.name, "0", "0", "0", "100644", fmt.Sprint(len(member.body)))
		buf.Write(member.body)
		if len(member.body)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// TestBoundedMemberReaderRejectsOversizedStream exercises the data bound with a
// small limit. Decoding a real 8 GiB payload would only prove the same branch at
// a cost of tens of seconds.
func TestBoundedMemberReaderRejectsOversizedStream(t *testing.T) {
	t.Parallel()
	stream, err := decompressMember(CompressionGzip, gzipBytes(t, bytes.Repeat([]byte("x"), 4096)), 1024)
	if err != nil {
		t.Fatalf("decompressMember: %v", err)
	}
	defer func() { _ = stream.Close() }()
	if _, err := io.Copy(io.Discard, stream); err == nil ||
		!strings.Contains(err.Error(), "exceeds the decompression bound") {
		t.Fatalf("error = %v, want a decompression bound error", err)
	}
}

// TestDecodeArchiveAppliesDataBound checks that DecodeArchive passes its limit
// to the data stream rather than buffering the payload first.
func TestDecodeArchiveAppliesDataBound(t *testing.T) {
	t.Parallel()
	compressed := gzipBytes(t, bytes.Repeat([]byte("y"), 4096))
	data := testArArchive(t,
		arMember{name: "debian-binary", body: []byte("2.0\n")},
		arMember{name: "control.tar.gz", body: gzipBytes(t, []byte("x"))},
		arMember{name: "data.tar.gz", body: compressed})
	archive, err := decodeArchive(data, 1024)
	if err != nil {
		t.Fatalf("decodeArchive: %v", err)
	}
	defer func() { _ = archive.Close() }()
	if _, err := io.Copy(io.Discard, archive.Data); err == nil ||
		!strings.Contains(err.Error(), "exceeds the decompression bound") {
		t.Fatalf("error = %v, want a decompression bound error", err)
	}
}
