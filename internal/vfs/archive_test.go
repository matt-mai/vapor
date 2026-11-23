package vfs_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/vfs"
)

func sampleTar(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	entries := []struct {
		name     string
		typeflag byte
		content  string
		link     string
	}{
		{name: "./bin/", typeflag: tar.TypeDir},
		{name: "./bin/tool", typeflag: tar.TypeReg, content: "tool"},
		{name: "./bin/alias", typeflag: tar.TypeLink, link: "./bin/tool"},
	}
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Mode: 0o755, Linkname: entry.link}
		if entry.typeflag == tar.TypeReg {
			header.Size = int64(len(entry.content))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if entry.typeflag == tar.TypeReg {
			if _, err := writer.Write([]byte(entry.content)); err != nil {
				t.Fatalf("write content: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buffer.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buffer.Bytes()
}

func zstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := zstd.NewWriter(&buffer, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buffer.Bytes()
}

func xzBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := xz.NewWriter(&buffer)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return buffer.Bytes()
}

func TestImportArchive_SupportedCompressions(t *testing.T) {
	raw := sampleTar(t)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "uncompressed", data: raw},
		{name: "gzip", data: gzipBytes(t, raw)},
		{name: "zstd", data: zstdBytes(t, raw)},
		{name: "xz", data: xzBytes(t, raw)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree, err := vfs.ImportArchive(test.data, vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			content, err := tree.Read("/bin/tool")
			if err != nil || string(content) != "tool" {
				t.Fatalf("content = %q, err = %v", content, err)
			}
			inodes := tree.Inodes()
			if inodes["/bin/tool"] != inodes["/bin/alias"] {
				t.Fatalf("hard link was not preserved: %v", inodes)
			}
		})
	}
}

func TestImportArchive_RejectsCorruptCompressedData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated gzip", data: []byte{0x1f, 0x8b, 0x08, 0x00}},
		{name: "truncated zstd", data: []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00}},
		{name: "truncated xz", data: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x00}},
		{name: "gzip of garbage", data: gzipBytes(t, []byte("not a tar archive at all"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := vfs.ImportArchive(test.data, vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "decompression failed") &&
				!strings.Contains(err.Error(), "tar import failed") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// TestImportArchive_ReportsTheDecoderCause guards the error wrapping: a corrupt
// archive is diagnosable only if the decoder's own message survives, and a
// decoder error describes the format rather than quoting payload bytes.
func TestImportArchive_ReportsTheDecoderCause(t *testing.T) {
	corrupt := gzipBytes(t, sampleTar(t))
	for index := 20; index < 40 && index < len(corrupt); index++ {
		corrupt[index] ^= 0xff
	}
	_, err := vfs.ImportArchive(corrupt, vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "tar import failed: flate: corrupt input") {
		t.Fatalf("error = %v, want the decoder cause", err)
	}
}

// metadataBomb is a gzip tar of many entries whose long names force a PAX extended
// header before each one. tar.Reader consumes those headers itself, so they never
// reach the entry or content counters that Limits otherwise applies.
func metadataBomb(t *testing.T, records int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressed)
	for i := range records {
		name := fmt.Sprintf("%s/%d", strings.Repeat("d", 400), i)
		if err := writer.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name, Format: tar.FormatPAX}); err != nil {
			t.Fatalf("write header: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buffer.Bytes()
}

func TestImportArchive_BoundsMetadataAsWellAsContent(t *testing.T) {
	// The archive holds no file content at all, so every byte it expands into is
	// metadata the entry and content bounds never see.
	data := metadataBomb(t, 2000)
	limits := vfs.DefaultLimits()
	limits.MaxStreamSize = 1 << 20
	_, err := vfs.ImportArchive(data, vfs.Origin{Package: "demo"}, limits)
	if err == nil || !strings.Contains(err.Error(), "decompressed stream bound") {
		t.Fatalf("error = %v, want the stream bound", err)
	}
}

// A tar end-of-archive marker can arrive before the compression trailer, so the
// decoder has not validated its checksum when the last entry is read. Draining the
// remainder is what makes a corrupt trailer fail instead of reporting success.
func TestImportArchive_ValidatesTheCompressionTrailer(t *testing.T) {
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressed)
	body := []byte("payload")
	if err := writer.WriteHeader(&tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("write content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	data := buffer.Bytes()
	// The trailer is the last eight bytes: CRC32 followed by ISIZE.
	data[len(data)-8] ^= 0xff
	_, err := vfs.ImportArchive(data, vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("error = %v, want a checksum failure", err)
	}
}

func TestImportArchive_AcceptsAnArchiveWithinTheStreamBound(t *testing.T) {
	// The same archive imports when the stream bound admits what it expands into,
	// so the bound rejects metadata volume rather than metadata itself.
	data := metadataBomb(t, 4)
	limits := vfs.DefaultLimits()
	limits.MaxStreamSize = 1 << 20
	if _, err := vfs.ImportArchive(data, vfs.Origin{Package: "demo"}, limits); err != nil {
		t.Fatalf("import: %v", err)
	}
}

func TestImportArchive_ReportsATruncatedStreamAsTheStreamBound(t *testing.T) {
	// A budget that runs out mid-entry must report the bound, not a decode failure:
	// the archive is well formed and only the bound ended the read.
	limits := vfs.DefaultLimits()
	limits.MaxStreamSize = 1024
	_, err := vfs.ImportArchive(gzipBytes(t, sampleTar(t)), vfs.Origin{Package: "demo"}, limits)
	if err == nil || !strings.Contains(err.Error(), "decompressed stream bound") {
		t.Fatalf("error = %v, want the stream bound", err)
	}
}

// Spending the budget exactly is not an overflow: the stream ended on its last
// byte, so a valid archive whose size equals the bound must import.
func TestImportTar_AcceptsAnArchiveThatExactlyFillsTheBound(t *testing.T) {
	data := sampleTar(t)
	limits := vfs.DefaultLimits()
	limits.MaxStreamSize = int64(len(data))
	if _, err := vfs.ImportTar(bytes.NewReader(data), vfs.Origin{Package: "demo"}, limits); err != nil {
		t.Fatalf("import: %v", err)
	}
	limits.MaxStreamSize = int64(len(data)) - 1
	if _, err := vfs.ImportTar(bytes.NewReader(data), vfs.Origin{Package: "demo"}, limits); err == nil ||
		!strings.Contains(err.Error(), "decompressed stream bound") {
		t.Fatalf("error = %v, want the stream bound", err)
	}
}

func TestImportTar_RequiresAStreamBound(t *testing.T) {
	limits := vfs.DefaultLimits()
	limits.MaxStreamSize = 0
	_, err := vfs.ImportTar(bytes.NewReader(sampleTar(t)), vfs.Origin{Package: "demo"}, limits)
	if err == nil || !strings.Contains(err.Error(), "must all be positive") {
		t.Fatalf("error = %v, want a positive-bound rejection", err)
	}
}

func TestImportArchive_AppliesLimitsAfterDecompression(t *testing.T) {
	// The compressed payload is tiny; the bound applies to what it expands into.
	raw := sampleTar(t)
	limits := vfs.DefaultLimits()
	limits.MaxEntries = 1
	_, err := vfs.ImportArchive(gzipBytes(t, raw), vfs.Origin{Package: "demo"}, limits)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 entries") {
		t.Fatalf("error = %v", err)
	}
}

func TestImportArchive_RejectsEscapingLinksAfterDecompression(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	header := &tar.Header{Name: "./link", Typeflag: tar.TypeSymlink, Linkname: "../../etc/shadow", Mode: 0o777}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	_, err := vfs.ImportArchive(zstdBytes(t, buffer.Bytes()), vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "escapes the image root") {
		t.Fatalf("error = %v", err)
	}
}

// TestImportArchive_RejectsAnXZDictionaryOverTheLimit covers the case a
// dictionary capacity cannot: the decoder library treats the setting as a floor
// and raises it to whatever a block declares, so the container is checked first.
func TestImportArchive_RejectsAnXZDictionaryOverTheLimit(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := xz.WriterConfig{DictCap: 128 << 20}.NewWriter(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(sampleTar(t)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = vfs.ImportArchive(buffer.Bytes(), vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "dictionary") {
		t.Fatalf("error = %v, want a dictionary rejection", err)
	}
}
