package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/vfs"
)

// CompressionLevel is the gzip level declared for a layer blob. DefaultCompression
// asks the library to choose, which is a stable choice for a given library version
// but not a promise that the bytes match another level.
type CompressionLevel int

// DefaultCompression selects the library's default level.
const DefaultCompression CompressionLevel = -1

// CompressedLayer identifies one compressed layer. Layer holds the uncompressed
// identity, which is what a config's rootfs.diff_ids records; Digest and Size
// describe the blob a manifest descriptor points at.
type CompressedLayer struct {
	Layer  Descriptor
	Digest string
	Size   int64
}

// CompressLayer serializes the tree and compresses it in one pass, so the layer is
// never buffered in memory. The uncompressed identity is computed by the same
// serialization as WriteLayer and is therefore independent of the level; only the
// compressed digest and size change with it.
//
// The gzip header carries no modification time, file name or comment, so the blob
// depends on the tree and the level alone. Cancellation is checked before the
// first byte and on every write, so a large layer stops promptly rather than
// finishing work whose result nobody wants.
func CompressLayer(ctx context.Context, dst io.Writer, tree *vfs.Tree,
	level CompressionLevel) (CompressedLayer, error) {
	if ctx == nil {
		return CompressedLayer{}, errors.New("layer compression requires a context")
	}
	if err := ctx.Err(); err != nil {
		return CompressedLayer{}, err
	}
	if dst == nil {
		return CompressedLayer{}, errors.New("layer compression requires a writer")
	}
	// The tree is checked again before a byte is written: a refused tree must not
	// leave a partial blob behind, and compression is where an image is serialized.
	if tree == nil {
		return CompressedLayer{}, errors.New("layer compression requires a tree")
	}
	if err := tree.ConfineLinks(); err != nil {
		return CompressedLayer{}, err
	}
	compressed := sha256.New()
	counted := &countingWriter{writer: io.MultiWriter(dst, compressed)}
	guard := &contextWriter{ctx: ctx, writer: counted}
	archive, err := gzip.NewWriterLevel(guard, int(level))
	if err != nil {
		return CompressedLayer{}, fmt.Errorf("layer compression failed: %w", err)
	}
	layer, err := WriteLayer(archive, tree)
	if err != nil {
		return CompressedLayer{}, err
	}
	// Close writes the gzip trailer, which is part of the blob's digest and size.
	if err := archive.Close(); err != nil {
		return CompressedLayer{}, fmt.Errorf("layer compression failed: %w", err)
	}
	return CompressedLayer{
		Layer:  layer,
		Digest: "sha256:" + hex.EncodeToString(compressed.Sum(nil)),
		Size:   counted.written,
	}, nil
}

// contextWriter stops a write once its context is done, which turns a canceled
// build into a prompt error instead of a completed layer nobody consumes.
type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w *contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.writer.Write(p)
}
