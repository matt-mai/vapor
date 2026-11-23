package oci_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/vfs"
)

func compressLayer(t *testing.T, level oci.CompressionLevel) ([]byte, oci.CompressedLayer) {
	t.Helper()
	var buffer bytes.Buffer
	result, err := oci.CompressLayer(context.Background(), &buffer, sampleTree(t), level)
	if err != nil {
		t.Fatalf("CompressLayer: %v", err)
	}
	return buffer.Bytes(), result
}

// TestCompressLayer_ByteStability checks that the compressed blob is stable for a
// given level, which is what lets a pushed digest be reproduced later.
func TestCompressLayer_ByteStability(t *testing.T) {
	first, result := compressLayer(t, oci.DefaultCompression)
	second, repeated := compressLayer(t, oci.DefaultCompression)
	if !bytes.Equal(first, second) || result != repeated {
		t.Fatalf("repeated compression differs: %+v vs %+v", repeated, result)
	}
	if result.Size != int64(len(first)) {
		t.Fatalf("size = %d, want %d", result.Size, len(first))
	}
	if !strings.HasPrefix(result.Digest, "sha256:") || len(result.Digest) != len("sha256:")+64 {
		t.Fatalf("digest = %q", result.Digest)
	}
}

// TestCompressLayer_LevelIndependentDiffID is the separation the design depends on:
// the uncompressed identity must be the same no matter how the blob is compressed.
func TestCompressLayer_LevelIndependentDiffID(t *testing.T) {
	uncompressed, plain := writeLayer(t, sampleTree(t))
	for _, level := range []oci.CompressionLevel{0, 1, 5, 9, oci.DefaultCompression} {
		blob, result := compressLayer(t, level)
		if result.Layer.DiffID != plain.DiffID || result.Layer.Size != plain.Size {
			t.Fatalf("level %v layer = %+v, want %+v", level, result.Layer, plain)
		}
		if result.Digest == plain.DiffID {
			t.Fatalf("level %v reused the uncompressed digest", level)
		}
		reader, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			t.Fatalf("level %v: %v", level, err)
		}
		decompressed, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("level %v: %v", level, err)
		}
		if !bytes.Equal(decompressed, uncompressed) {
			t.Fatalf("level %v decompressed to different bytes", level)
		}
	}
}

// TestCompressLayer_LevelsDiffer checks that the declared level reaches the encoder
// rather than always compressing at the library default.
func TestCompressLayer_LevelsDiffer(t *testing.T) {
	tree := vfs.New()
	if err := tree.File("/data", bytes.Repeat([]byte("compressible "), 4096),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: "demo"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	sizes := map[oci.CompressionLevel]int64{}
	for _, level := range []oci.CompressionLevel{1, 9} {
		var buffer bytes.Buffer
		result, err := oci.CompressLayer(context.Background(), &buffer, tree, level)
		if err != nil {
			t.Fatalf("level %v: %v", level, err)
		}
		sizes[level] = result.Size
	}
	if sizes[9] >= sizes[1] {
		t.Fatalf("level 9 = %d bytes, level 1 = %d: no compression was applied", sizes[9], sizes[1])
	}
}

// TestCompressLayer_HeaderIsNeutral pins the gzip header fields that would otherwise
// let host state into the blob: no name, comment, extra data or modification time.
func TestCompressLayer_HeaderIsNeutral(t *testing.T) {
	blob, _ := compressLayer(t, oci.DefaultCompression)
	reader, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	if reader.Name != "" || reader.Comment != "" || len(reader.Extra) != 0 {
		t.Fatalf("header = %q/%q/%x, want none", reader.Name, reader.Comment, reader.Extra)
	}
	if !reader.ModTime.IsZero() {
		t.Fatalf("mtime = %v, want unset", reader.ModTime)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestCompressLayer_Cancellation checks that a canceled context stops the work
// instead of producing a blob the caller will discard.
func TestCompressLayer_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buffer bytes.Buffer
	if _, err := oci.CompressLayer(ctx, &buffer, sampleTree(t), oci.DefaultCompression); !errors.Is(err,
		context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("wrote %d bytes after cancellation", buffer.Len())
	}
}

// TestCompressLayer_CancelDuringWrite covers the mid-stream path: a layer larger
// than one write must observe the cancellation rather than run to completion.
func TestCompressLayer_CancelDuringWrite(t *testing.T) {
	tree := vfs.New()
	if err := tree.File("/data", bytes.Repeat([]byte("x"), 1<<20),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: "demo"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	writer := &cancellingWriter{cancel: cancel, after: 1}
	if _, err := oci.CompressLayer(ctx, writer, tree, oci.DefaultCompression); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
}

// cancellingWriter cancels its context after a number of writes.
type cancellingWriter struct {
	cancel context.CancelFunc
	after  int
	writes int
}

func (w *cancellingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.after {
		w.cancel()
	}
	return len(p), nil
}

// TestCompressLayer_Errors covers the refusals and the failing destination.
func TestCompressLayer_Errors(t *testing.T) {
	var buffer bytes.Buffer
	tree := sampleTree(t)
	// A nil context must be refused, not silently replaced.
	var noContext context.Context
	if _, err := oci.CompressLayer(noContext, &buffer, tree, oci.DefaultCompression); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := oci.CompressLayer(context.Background(), nil, tree, oci.DefaultCompression); err == nil {
		t.Fatal("nil writer accepted")
	}
	if _, err := oci.CompressLayer(context.Background(), &buffer, nil, oci.DefaultCompression); err == nil {
		t.Fatal("nil tree accepted")
	}
	if _, err := oci.CompressLayer(context.Background(), &failWriter{left: 4}, tree,
		oci.DefaultCompression); err == nil {
		t.Fatal("write failure was swallowed")
	}
}
