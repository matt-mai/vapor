package deb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/xzguard"
)

// MaxControlArchiveSize bounds the decompressed control tarball, and the total
// logical bytes retained from it. The two are separate because a sparse member
// declares a size unrelated to the bytes it stores, so neither bound implies the
// other. Control tarballs carry metadata and maintainer scripts only; the largest
// Ubuntu packages stay well under 100 KiB, so this is a decompression-bomb guard.
const MaxControlArchiveSize int64 = 16 << 20

// MaxDataArchiveSize bounds the decompressed data tarball. The compressed member
// is already bounded by the verified package size, so this only rejects a
// decompression bomb; real archives expand roughly tenfold at most.
const MaxDataArchiveSize int64 = 8 << 30

const requiredArchiveMembers = 3

// MaxArchiveMembers allows one optional _gpgbuilder member after the required three.
const MaxArchiveMembers = requiredArchiveMembers + 1

// archiveMagic starts every ar archive.
const archiveMagic = "!<arch>\n"

// arHeaderSize is the fixed ar member header length.
const arHeaderSize = 60

// Compression identifies a supported DEB member compression.
type Compression string

// Supported DEB member compressions.
const (
	CompressionPlain Compression = "plain"
	CompressionGzip  Compression = "gz"
	CompressionXZ    Compression = "xz"
	CompressionZstd  Compression = "zst"
)

// errArchiveTooLarge reports a member that decompressed past its bound.
var errArchiveTooLarge = errors.New("package archive exceeds the decompression bound")

// Archive is one decoded DEB. Control holds the decompressed control tarball;
// Data streams the decompressed data tarball and must be closed.
type Archive struct {
	ControlFormat Compression
	DataFormat    Compression
	Control       []byte
	Data          io.ReadCloser
}

// Close releases the data stream.
func (a *Archive) Close() error {
	if a == nil || a.Data == nil {
		return nil
	}
	return a.Data.Close()
}

// DecodeArchive decodes a DEB into its control tarball and a bounded stream of
// its data tarball. It verifies nothing: callers pass bytes that already matched
// authenticated metadata, and nothing is written anywhere before that.
func DecodeArchive(data []byte) (*Archive, error) {
	return decodeArchive(data, MaxDataArchiveSize)
}

func decodeArchive(data []byte, dataLimit int64) (*Archive, error) {
	members, err := readArMembers(data)
	if err != nil {
		return nil, err
	}
	if len(members) < requiredArchiveMembers {
		return nil, errors.New("package is missing a required ar member")
	}
	if members[0].name != "debian-binary" {
		return nil, errors.New("package debian-binary member is not first")
	}
	if strings.TrimSpace(string(members[0].body)) != "2.0" {
		return nil, errors.New("package format version is not 2.0")
	}
	controlFormat, ok := memberCompression(members[1].name, "control.tar")
	if !ok {
		return nil, errors.New("package control member is missing or unsupported")
	}
	dataFormat, ok := memberCompression(members[2].name, "data.tar")
	if !ok {
		return nil, errors.New("package data member is missing or unsupported")
	}
	if len(members) == MaxArchiveMembers && members[requiredArchiveMembers].name != "_gpgbuilder" {
		return nil, errors.New("package has an unsupported trailing ar member")
	}
	control, err := readBoundedMember(controlFormat, members[1].body)
	if err != nil {
		return nil, err
	}
	stream, err := decompressMember(dataFormat, members[2].body, dataLimit)
	if err != nil {
		return nil, err
	}
	return &Archive{ControlFormat: controlFormat, DataFormat: dataFormat, Control: control, Data: stream}, nil
}

// arMember is one raw ar member.
type arMember struct {
	name string
	body []byte
}

func readArMembers(data []byte) ([]arMember, error) {
	if len(data) < len(archiveMagic) || string(data[:len(archiveMagic)]) != archiveMagic {
		return nil, errors.New("package is not an ar archive")
	}
	remaining := data[len(archiveMagic):]
	members := make([]arMember, 0, MaxArchiveMembers)
	for len(remaining) > 0 {
		if len(members) >= MaxArchiveMembers {
			return nil, fmt.Errorf("package has more than %d ar members", MaxArchiveMembers)
		}
		member, rest, err := readArMember(remaining)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
		remaining = rest
	}
	return members, nil
}

func readArMember(data []byte) (arMember, []byte, error) {
	if len(data) < arHeaderSize {
		return arMember{}, nil, errors.New("package ar member header is truncated")
	}
	header := data[:arHeaderSize]
	if string(header[58:]) != "`\n" {
		return arMember{}, nil, errors.New("package ar member header is malformed")
	}
	name, err := arMemberName(header[:16])
	if err != nil {
		return arMember{}, nil, err
	}
	size, err := arMemberSize(header[48:58])
	if err != nil {
		return arMember{}, nil, err
	}
	padded := size + size%2
	if len(data)-arHeaderSize < padded {
		return arMember{}, nil, errors.New("package ar member is truncated")
	}
	return arMember{name: name, body: data[arHeaderSize : arHeaderSize+size]},
		data[arHeaderSize+padded:], nil
}

func arMemberName(field []byte) (string, error) {
	name := strings.TrimSuffix(strings.TrimRight(string(field), " "), "/")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New("package ar member name is invalid")
	}
	return name, nil
}

func arMemberSize(field []byte) (int, error) {
	value := strings.TrimRight(string(field), " ")
	if value == "" || strings.TrimLeft(value, "0123456789") != "" {
		return 0, errors.New("package ar member size is invalid")
	}
	size, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("package ar member size is invalid")
	}
	return size, nil
}

// memberCompression matches a control or data member name and returns its
// compression. An unknown suffix is unsupported rather than guessed.
func memberCompression(name, prefix string) (Compression, bool) {
	if name == prefix {
		return CompressionPlain, true
	}
	suffix, found := strings.CutPrefix(name, prefix+".")
	if !found {
		return "", false
	}
	switch Compression(suffix) {
	case CompressionGzip, CompressionXZ, CompressionZstd:
		return Compression(suffix), true
	default:
		return "", false
	}
}

// readBoundedMember decompresses a small member fully, such as the control
// tarball, and fails if it exceeds the control bound.
func readBoundedMember(compression Compression, data []byte) ([]byte, error) {
	reader, err := decompressMember(compression, data, MaxControlArchiveSize)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	content, err := io.ReadAll(reader)
	if err != nil {
		if errors.Is(err, errArchiveTooLarge) {
			return nil, err
		}
		return nil, errors.New("package control archive decompression failed")
	}
	return content, nil
}

func decompressMember(compression Compression, data []byte, limit int64) (io.ReadCloser, error) {
	reader, err := memberReader(compression, data)
	if err != nil {
		return nil, err
	}
	return &boundedMemberReader{reader: reader, limit: limit}, nil
}

func memberReader(compression Compression, data []byte) (io.ReadCloser, error) {
	switch compression {
	case CompressionPlain:
		return io.NopCloser(bytes.NewReader(data)), nil
	case CompressionGzip:
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("package member decompression failed")
		}
		return reader, nil
	case CompressionXZ:
		if err := xzguard.Check(data, xzguard.MaxDictionarySize); err != nil {
			return nil, err
		}
		reader, err := xz.ReaderConfig{DictCap: xzguard.MaxDictionarySize}.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("package member decompression failed")
		}
		return io.NopCloser(reader), nil
	case CompressionZstd:
		decoder, err := zstd.NewReader(bytes.NewReader(data),
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxWindow(xzguard.MaxDictionarySize),
			zstd.WithDecoderMaxMemory(xzguard.MaxDictionarySize))
		if err != nil {
			return nil, errors.New("package member decompression failed")
		}
		return decoder.IOReadCloser(), nil
	default:
		return nil, fmt.Errorf("unsupported package member compression %q", compression)
	}
}

// boundedMemberReader fails once a member decompresses past its bound, so a
// bomb is rejected while it streams instead of after it is buffered.
type boundedMemberReader struct {
	reader io.ReadCloser
	read   int64
	limit  int64
}

func (r *boundedMemberReader) Read(data []byte) (int, error) {
	if r.read > r.limit {
		return 0, errArchiveTooLarge
	}
	n, err := r.reader.Read(data)
	r.read += int64(n)
	if r.read > r.limit {
		return n, errArchiveTooLarge
	}
	return n, err
}

func (r *boundedMemberReader) Close() error {
	return r.reader.Close()
}
