package cache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// derivedSuffix marks an entry that holds the decoded text of an authenticated package
// index. The name before the suffix is the digest of the index the release names, so the
// entry is never trusted on its own: it is a pure function of bytes the release already
// authenticated, and the plain index digest and size are checked again on every read, so
// an entry written by another build, or edited since, cannot describe other packages.
const derivedSuffix = ".decoded"

// derivedHeader is the big-endian length of the payload that follows it. Without it a
// truncated entry would hand back a valid prefix, and a prefix of a package index parses
// as a shorter index instead of failing.
const derivedHeader = 8

// ReadDerived returns the decoded text recorded for an authenticated index. plainSHA256
// and plainSize are the digest and length the signed release gives the same index in
// plain form; an entry that does not reproduce both is refused, as is a missing, short,
// oversized or unreadable one. The caller then decodes the verified bytes itself: this
// store can only save work, never change an answer.
func (c *Cache) ReadDerived(digest, plainSHA256 string, plainSize, limit int64) ([]byte, bool) {
	if c == nil || c.dir == "" || checkDigest(digest) != nil || limit < 0 ||
		!plainDigestOK(plainSHA256, plainSize) {
		return nil, false
	}
	file, err := os.Open(c.derivedPath(digest))
	if err != nil {
		return nil, false
	}
	defer func() { _ = file.Close() }()
	size, err := derivedSize(file, limit)
	if err != nil || size != plainSize {
		return nil, false
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, false
	}
	if !plainMatches(data, plainSHA256) {
		return nil, false
	}
	return data, true
}

// StoreDerived records the decoded text of an authenticated index, but only when the
// signed release names it in plain form: a decode the release does not hash has nothing
// to be checked against, so it is not worth remembering. A failure is not an error a
// caller can act on, so it reports false and lets the decode be repeated next time.
func (c *Cache) StoreDerived(digest, plainSHA256 string, plainSize int64, data []byte) bool {
	if c == nil || c.dir == "" || checkDigest(digest) != nil ||
		!plainDigestOK(plainSHA256, plainSize) || int64(len(data)) != plainSize ||
		!plainMatches(data, plainSHA256) {
		return false
	}
	payload := make([]byte, derivedHeader+len(data))
	binary.BigEndian.PutUint64(payload, uint64(len(data)))
	copy(payload[derivedHeader:], data)
	return c.storeDerived(digest, payload) == nil
}

// plainDigestOK reports whether the release supplied something to check a decoded index
// against. A plain index is the only form a signed release file names by digest, so no
// other index can have one.
func plainDigestOK(plainSHA256 string, plainSize int64) bool {
	return validDigest(strings.ToLower(plainSHA256)) && plainSize >= 0 && plainSize <= maxDerivedSize
}

func plainMatches(data []byte, plainSHA256 string) bool {
	sum := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(sum[:]), plainSHA256)
}

func (c *Cache) storeDerived(digest string, payload []byte) error {
	dest := c.derivedPath(digest)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("create cache derived directory: %w", err)
	}
	ops := defaultStoreOps
	file, err := ops.createTemp(filepath.Dir(dest), stagingPrefix+"*")
	if err != nil {
		return fmt.Errorf("create cache derived temporary file: %w", err)
	}
	tempPath := file.Name()
	published := false
	defer func() {
		if !published {
			_ = ops.remove(tempPath)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return errors.Join(fmt.Errorf("write cache derived entry: %w", err), ops.close(file))
	}
	if err := ops.sync(file); err != nil {
		return errors.Join(fmt.Errorf("sync cache derived entry: %w", err), ops.close(file))
	}
	if err := ops.close(file); err != nil {
		return fmt.Errorf("close cache derived entry: %w", err)
	}
	if err := ops.rename(tempPath, dest); err != nil {
		return fmt.Errorf("publish cache derived entry: %w", err)
	}
	published = true
	return nil
}

// derivedSize reads the header and returns the payload length it declares, refusing an
// entry that is shorter than its own header or larger than the caller allows.
func derivedSize(file *os.File, limit int64) (int64, error) {
	var header [derivedHeader]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return 0, errors.New("derived entry has no length header")
	}
	// Refuse before narrowing: a length that does not fit the caller's bound is not a
	// record this cache can hand back, whatever the header claims.
	declared := int64(min(binary.BigEndian.Uint64(header[:]), math.MaxInt64))
	if declared > limit || declared > maxDerivedSize {
		return 0, errors.New("derived entry length is outside the allowed bound")
	}
	size := declared
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat cache derived entry: %w", err)
	}
	if info.Size() != derivedHeader+size {
		return 0, errors.New("derived entry does not match the length it declares")
	}
	return size, nil
}

// derivedPath keeps a decoded entry beside the index blob it came from, so one shard
// sweep keeps or removes both.
func (c *Cache) derivedPath(digest string) string {
	return c.blobPath(digest) + derivedSuffix
}

// maxDerivedSize bounds one decoded entry. It matches the largest index a caller can
// accept, so a decoded entry never holds more than decoding would have produced.
const maxDerivedSize int64 = 256 << 20

// isDerived reports whether a shard entry is a decoded form of the index it is named after.
func isDerived(name string) (string, bool) {
	digest, ok := cutSuffix(name, derivedSuffix)
	if !ok || !validDigest(digest) {
		return "", false
	}
	return digest, true
}

func cutSuffix(value, suffix string) (string, bool) {
	if len(value) <= len(suffix) || value[len(value)-len(suffix):] != suffix {
		return "", false
	}
	return value[:len(value)-len(suffix)], true
}
