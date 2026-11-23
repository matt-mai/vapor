// Package xzguard bounds the memory an xz decoder allocates.
//
// github.com/ulikunitz/xz treats ReaderConfig.DictCap as a floor rather than a
// ceiling: a block header that declares a larger LZMA2 dictionary raises the
// value before the decoder allocates its dictionary (lzmafilter.go:68-79 in
// v0.5.17, and still true of the v0.6 line, which derives the window from the
// stream and offers no limit at all). A payload therefore chooses its own
// allocation, and bounding decompressed output does not bound it.
//
// Check reads the container instead: the stream footer, the index and every
// block header. A payload whose blocks ask for more than the caller allows is
// rejected before a decoder exists, so the allocation never happens. Nothing is
// decompressed.
package xzguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// MaxDictionarySize is the largest LZMA2 dictionary any caller accepts. Ubuntu's
// largest package index uses an 8 MiB dictionary and standard xz -9 output uses
// 64 MiB, so this admits ordinary archives while bounding what a hostile one can
// make a decoder allocate.
const MaxDictionarySize = 64 << 20

// Container sizes and flags from the xz file format specification.
const (
	streamHeaderLen = 12
	footerLen       = 12
	indexCRCLen     = 4
	blockCRCLen     = 4
	maxHeaderSize   = 1024

	lzmaFilterID  = 0x21
	lzmaFilterLen = 1

	compressedSizePresent   = 0x40
	uncompressedSizePresent = 0x80
	reservedBlockFlags      = 0x3C
	filterCountMask         = 0x03
)

var (
	errTruncated = errors.New("xz: payload is truncated")
	errCorrupt   = errors.New("xz: payload is corrupt")
)

var (
	headerMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	footerMagic = []byte{'Y', 'Z'}
)

// Check reports an error unless every block in the payload declares an LZMA2
// dictionary no larger than limit. It walks the container backwards from the
// footer, so it works whether or not the block headers carry sizes.
func Check(data []byte, limit int) error {
	if limit < 1 {
		return errors.New("xz: dictionary limit must be positive")
	}
	end := len(data)
	streams := 0
	for end > 0 {
		// Stream padding is a whole number of four zero bytes between streams
		// and, as the library tolerates it, after the last one. A footer always
		// ends with "YZ", so padding is never mistaken for one.
		if end >= 4 && isZero(data[end-4:end]) {
			end -= 4
			continue
		}
		start, err := checkStream(data[:end], limit)
		if err != nil {
			return err
		}
		streams++
		end = start
	}
	if streams == 0 {
		return errors.New("xz: payload holds no stream")
	}
	return nil
}

// checkStream validates one stream ending at the end of data and returns the
// offset where it begins.
func checkStream(data []byte, limit int) (int, error) {
	if len(data) < streamHeaderLen+footerLen+indexCRCLen {
		return 0, errTruncated
	}
	indexStart, flags, err := streamIndex(data[len(data)-footerLen:], len(data))
	if err != nil {
		return 0, err
	}
	blocks, err := readIndex(data[indexStart:len(data)-footerLen], indexStart)
	if err != nil {
		return 0, err
	}
	start, err := streamStart(data, indexStart, blocks, flags)
	if err != nil {
		return 0, err
	}
	offset := start + streamHeaderLen
	for i, size := range blocks {
		if err := checkBlock(data[offset:], limit, i); err != nil {
			return 0, err
		}
		// Alignment is proven by the next block's header checksum: a wrong
		// unpadded size lands on bytes that are not a valid header.
		offset += size + blockPadding(size)
	}
	if offset != indexStart {
		return 0, fmt.Errorf("%w: blocks end at offset %d, index starts at %d", errCorrupt, offset, indexStart)
	}
	return start, nil
}

// streamIndex validates the footer and returns where the index starts and which
// check the stream uses.
func streamIndex(footer []byte, end int) (int, byte, error) {
	if !bytes.Equal(footer[10:], footerMagic) {
		return 0, 0, errors.New("xz: stream footer magic is missing")
	}
	if crc32.ChecksumIEEE(footer[4:10]) != binary.LittleEndian.Uint32(footer[:4]) {
		return 0, 0, fmt.Errorf("%w: stream footer checksum does not match", errCorrupt)
	}
	// The backward size covers the whole index field: indicator, records,
	// padding and the trailing CRC.
	size := (int(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
	start := end - footerLen - size
	if start < streamHeaderLen {
		return 0, 0, errTruncated
	}
	return start, footer[9], nil
}

// streamStart validates the stream header against the index, which is the only
// statement about how many bytes the blocks occupy.
func streamStart(data []byte, indexStart int, blocks []int, flags byte) (int, error) {
	total := 0
	for _, size := range blocks {
		total += size + blockPadding(size)
	}
	start := indexStart - total - streamHeaderLen
	if start < 0 {
		return 0, errTruncated
	}
	header := data[start : start+streamHeaderLen]
	if !bytes.Equal(header[:6], headerMagic) {
		return 0, errors.New("xz: stream header magic is missing")
	}
	if crc32.ChecksumIEEE(header[6:8]) != binary.LittleEndian.Uint32(header[8:]) {
		return 0, fmt.Errorf("%w: stream header checksum does not match", errCorrupt)
	}
	if header[6] != 0 || header[7] != flags {
		return 0, fmt.Errorf("%w: stream header and footer flags disagree", errCorrupt)
	}
	return start, nil
}

// readIndex validates the whole index field and returns each block's unpadded
// size. The record's uncompressed size is not needed: the decoder checks it
// against the block it decodes.
func readIndex(field []byte, span int) ([]int, error) {
	if len(field) < 1+indexCRCLen {
		return nil, errTruncated
	}
	body, trail := field[:len(field)-indexCRCLen], field[len(field)-indexCRCLen:]
	if body[0] != 0 {
		return nil, errors.New("xz: index indicator is missing")
	}
	reader := &byteReader{data: body, pos: 1}
	count, err := readUvarint(reader)
	if err != nil {
		return nil, err
	}
	// Every record needs at least two bytes, so a count larger than the index
	// is a lie worth failing on before it becomes a loop bound.
	if count > uint64(len(body)) {
		return nil, fmt.Errorf("%w: index claims %d blocks in %d bytes", errCorrupt, count, len(body))
	}
	sizes := make([]int, 0, count)
	for range count {
		size, err := readUnpaddedSize(reader, span)
		if err != nil {
			return nil, err
		}
		if _, err := readUvarint(reader); err != nil {
			return nil, err
		}
		sizes = append(sizes, size)
	}
	padding := (4 - reader.pos%4) % 4
	if reader.pos+padding != len(body) {
		return nil, fmt.Errorf("%w: index is %d bytes, want %d", errCorrupt, reader.pos+padding, len(body))
	}
	if !isZero(body[reader.pos : reader.pos+padding]) {
		return nil, fmt.Errorf("%w: index padding is not zero", errCorrupt)
	}
	covered := body[:reader.pos+padding]
	if crc32.ChecksumIEEE(covered) != binary.LittleEndian.Uint32(trail) {
		return nil, fmt.Errorf("%w: index checksum does not match", errCorrupt)
	}
	return sizes, nil
}

// readUnpaddedSize reads a block size and keeps it within the bytes available,
// so a record cannot point outside the stream.
func readUnpaddedSize(reader *byteReader, span int) (int, error) {
	value, err := readUvarint(reader)
	if err != nil {
		return 0, err
	}
	if value == 0 || value >= uint64(span) { //nolint:gosec // span is the payload length, which is positive.
		return 0, fmt.Errorf("%w: block unpadded size %d is out of range", errCorrupt, value)
	}
	return int(value), nil //nolint:gosec // bounded by span just above.
}

// checkBlock validates one block header and enforces its dictionary size.
func checkBlock(data []byte, limit, index int) error {
	header, flags, err := blockHeader(data, index)
	if err != nil {
		return err
	}
	dictionary, err := filterDictionary(header[2:len(header)-blockCRCLen], flags, index)
	if err != nil {
		return err
	}
	if dictionary > int64(limit) {
		return fmt.Errorf("xz: block %d declares a %d MiB dictionary, over the %d MiB limit",
			index, dictionary>>20, int64(limit)>>20)
	}
	return nil
}

// blockHeader validates one block header and returns it with its flags.
func blockHeader(data []byte, index int) ([]byte, byte, error) {
	if len(data) == 0 {
		return nil, 0, errTruncated
	}
	if data[0] == 0 {
		return nil, 0, errors.New("xz: block header indicator is missing")
	}
	size := (int(data[0]) + 1) * 4
	if size > maxHeaderSize {
		return nil, 0, fmt.Errorf("%w: block %d header is %d bytes", errCorrupt, index, size)
	}
	if len(data) < size {
		return nil, 0, errTruncated
	}
	header := data[:size]
	if crc32.ChecksumIEEE(header[:size-blockCRCLen]) != binary.LittleEndian.Uint32(header[size-blockCRCLen:]) {
		return nil, 0, fmt.Errorf("%w: block %d header checksum does not match", errCorrupt, index)
	}
	flags := header[1]
	if flags&reservedBlockFlags != 0 {
		return nil, 0, fmt.Errorf("%w: block %d has reserved header flags set", errCorrupt, index)
	}
	if int(flags&filterCountMask)+1 != 1 {
		return nil, 0, fmt.Errorf("xz: block %d declares more than one filter", index)
	}
	return header, flags, nil
}

// filterDictionary reads the LZMA2 filter of a block header and returns the
// dictionary it declares.
func filterDictionary(body []byte, flags byte, index int) (int64, error) {
	reader := &byteReader{data: body}
	for _, present := range []byte{compressedSizePresent, uncompressedSizePresent} {
		if flags&present == 0 {
			continue
		}
		if _, err := readUvarint(reader); err != nil {
			return 0, err
		}
	}
	id, err := readUvarint(reader)
	if err != nil {
		return 0, err
	}
	if id != lzmaFilterID {
		return 0, fmt.Errorf("xz: block %d uses filter %#x, want LZMA2", index, id)
	}
	length, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	if int(length) != lzmaFilterLen {
		return 0, fmt.Errorf("%w: block %d filter property is %d bytes", errCorrupt, index, length)
	}
	property, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	dictionary, err := lzma.DecodeDictCap(property)
	if err != nil {
		return 0, fmt.Errorf("%w: block %d %v", errCorrupt, index, err)
	}
	return dictionary, nil
}

// blockPadding returns the number of zero bytes that pad a block of the given
// unpadded size to a four-byte boundary.
func blockPadding(unpadded int) int {
	return (4 - unpadded%4) % 4
}

func isZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// byteReader reads a slice and reports the position, which the index needs to
// locate its padding.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) ReadByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

// readUvarint decodes the variable-length integer the format uses, rejecting the
// overflow cases the decoder rejects.
func readUvarint(r *byteReader) (uint64, error) {
	var value uint64
	var shift uint
	for i := range 10 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b < 0x80 {
			if i == 9 && b > 1 {
				return 0, fmt.Errorf("%w: varint overflows 64 bits", errCorrupt)
			}
			return value | uint64(b)<<shift, nil
		}
		value |= uint64(b&0x7f) << shift
		shift += 7
	}
	return 0, fmt.Errorf("%w: varint overflows 64 bits", errCorrupt)
}
