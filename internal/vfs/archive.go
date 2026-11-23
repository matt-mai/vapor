package vfs

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/xzguard"
)

// archiveMagic lists the compression formats an artifact payload may use. Only
// the leading bytes matter: the format is detected, never inferred from a file
// name, so a mislabelled payload fails instead of being guessed at.
var archiveMagic = []struct {
	prefix []byte
	open   func([]byte) (io.ReadCloser, error)
}{
	{[]byte{0x1f, 0x8b}, openGzip},
	{[]byte{0x28, 0xb5, 0x2f, 0xfd}, openZstd},
	{[]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, openXZ},
}

// ImportArchive imports a tar archive that may be gzip, Zstandard or XZ
// compressed. Uncompressed archives are passed through unchanged.
//
// Decompression is bounded on both sides of the decoder: xzguard rejects a
// payload whose blocks declare more memory than xzguard.MaxDictionarySize, and
// every entry the archive yields is still subject to limits, so a compression
// bomb fails while it streams rather than after it is buffered.
func ImportArchive(data []byte, origin Origin, limits Limits) (*Tree, error) {
	reader, err := openArchive(data)
	if err != nil {
		return nil, err
	}
	// Every decoder reads from an in-memory reader, so Close only releases
	// buffers and cannot fail in a way the caller could act on.
	defer func() { _ = reader.Close() }()
	return ImportTar(reader, origin, limits)
}

func openArchive(data []byte) (io.ReadCloser, error) {
	for _, format := range archiveMagic {
		if bytes.HasPrefix(data, format.prefix) {
			reader, err := format.open(data)
			if err != nil {
				// Decoder errors describe the format, not the payload bytes, so the
				// cause is safe to report and is what makes a corrupt archive
				// diagnosable.
				return nil, fmt.Errorf("vfs archive decompression failed: %w", err)
			}
			return reader, nil
		}
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func openGzip(data []byte) (io.ReadCloser, error) {
	return gzip.NewReader(bytes.NewReader(data))
}

func openZstd(data []byte) (io.ReadCloser, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(xzguard.MaxDictionarySize),
		zstd.WithDecoderMaxMemory(xzguard.MaxDictionarySize))
	if err != nil {
		return nil, err
	}
	return decoder.IOReadCloser(), nil
}

func openXZ(data []byte) (io.ReadCloser, error) {
	// The library raises DictCap to whatever a block declares, so the container
	// is checked before a decoder exists.
	if err := xzguard.Check(data, xzguard.MaxDictionarySize); err != nil {
		return nil, err
	}
	reader, err := xz.ReaderConfig{DictCap: xzguard.MaxDictionarySize}.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.NopCloser(reader), nil
}
