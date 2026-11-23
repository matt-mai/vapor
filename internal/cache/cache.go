// Package cache stores verified content-addressed blobs.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
)

// Cache is a rooted content-addressed blob store. Blobs live under
// <dir>/sha256/<first two hex digits>/<sha256>.
type Cache struct {
	dir string
}

// New creates the cache directory if needed and returns a store rooted at dir.
func New(dir string) (*Cache, error) {
	if dir == "" {
		return nil, errors.New("cache directory must not be empty")
	}
	if err := os.MkdirAll(filepath.Join(dir, "sha256"), 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	return &Cache{dir: dir}, nil
}

// Store verifies and atomically publishes a blob. digest is the lowercase
// hexadecimal SHA256 of the blob and size is its exact byte length.
//
// The reader is read through at most size+1 bytes. A blob is published only
// after its length and digest match; failures leave any previous blob in place
// and remove the temporary file.
func (c *Cache) Store(r io.Reader, digest string, size int64) error {
	if c == nil || c.dir == "" {
		return errors.New("cache is not initialized")
	}
	if r == nil {
		return errors.New("blob reader must not be nil")
	}
	if err := checkDigest(digest); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("invalid blob size %d", size)
	}
	return c.store(r, digest, size, defaultStoreOps)
}

type storeOps struct {
	createTemp func(dir, pattern string) (*os.File, error)
	sync       func(*os.File) error
	close      func(*os.File) error
	rename     func(oldpath, newpath string) error
	remove     func(string) error
}

var defaultStoreOps = storeOps{
	createTemp: os.CreateTemp,
	sync:       (*os.File).Sync,
	close:      (*os.File).Close,
	rename:     os.Rename,
	remove:     os.Remove,
}

func (c *Cache) store(r io.Reader, digest string, size int64, ops storeOps) (err error) {
	dest := c.blobPath(digest)
	if mkdirErr := os.MkdirAll(filepath.Dir(dest), 0o700); mkdirErr != nil {
		return fmt.Errorf("create cache blob directory: %w", mkdirErr)
	}
	file, err := ops.createTemp(filepath.Dir(dest), ".vapor-blob-*")
	if err != nil {
		return fmt.Errorf("create cache temporary file: %w", err)
	}
	tempPath := file.Name()
	published := false
	defer func() {
		if published {
			return
		}
		if removeErr := ops.remove(tempPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove cache temporary file: %w", removeErr))
		}
	}()

	if writeErr := writeBlob(file, r, digest, size); writeErr != nil {
		return errors.Join(writeErr, closeBlob(ops, file))
	}
	if syncErr := ops.sync(file); syncErr != nil {
		return errors.Join(fmt.Errorf("sync cache blob: %w", syncErr), closeBlob(ops, file))
	}
	if closeErr := ops.close(file); closeErr != nil {
		return fmt.Errorf("close cache blob: %w", closeErr)
	}
	if renameErr := ops.rename(tempPath, dest); renameErr != nil {
		return fmt.Errorf("publish cache blob: %w", renameErr)
	}
	published = true
	return nil
}

// Read returns the verified bytes of one blob. Verification covers the bytes it returns,
// not a first pass over the file: a blob changed after it was checked must not be the
// bytes a caller parses.
func (c *Cache) Read(digest string, size int64) ([]byte, error) {
	if c == nil || c.dir == "" {
		return nil, errors.New("cache is not initialized")
	}
	if err := checkDigest(digest); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, errors.New("blob size must not be negative")
	}
	return c.read(digest, size)
}

func (c *Cache) read(digest string, size int64) ([]byte, error) {
	reader, err := c.open(digest, size)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, blobReadLimit(size)))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, err
	}
	return data, nil
}

// Verify reports whether the bytes stored for a digest are that blob. A name alone does
// not make a blob usable: a damaged or truncated file keeps its path, so a caller that
// is about to rely on it reads the content through the same check a reader performs.
func (c *Cache) Verify(digest string, size int64) error {
	reader, err := c.Open(digest, size)
	if err != nil {
		return err
	}
	return reader.Close()
}

// Has reports whether the cache holds a blob for the digest, without reading it.
func (c *Cache) Has(digest string) bool {
	if c == nil || c.dir == "" || checkDigest(digest) != nil {
		return false
	}
	_, err := os.Lstat(c.blobPath(digest))
	return err == nil
}

func (c *Cache) blobPath(digest string) string {
	return filepath.Join(c.dir, "sha256", digest[:2], digest)
}

func checkDigest(digest string) error {
	if !validDigest(digest) {
		return fmt.Errorf("invalid blob digest %q", digest)
	}
	return nil
}

func validDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	for _, char := range digest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func closeBlob(ops storeOps, file *os.File) error {
	if err := ops.close(file); err != nil {
		return fmt.Errorf("close cache blob: %w", err)
	}
	return nil
}

// Open returns a reader for the verified blob. Its digest is checked before the reader
// is returned, so no caller can stream bytes that turn out to be wrong only at the end
// of an upload. The bytes handed out are hashed again as they are read, so a blob
// replaced after it was opened fails the read instead of reaching the caller as verified
// content. The caller must close it.
func (c *Cache) Open(digest string, size int64) (io.ReadCloser, error) {
	if c == nil || c.dir == "" {
		return nil, errors.New("cache is not initialized")
	}
	if err := checkDigest(digest); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, errors.New("blob size must not be negative")
	}

	return c.open(digest, size)
}

func (c *Cache) open(digest string, size int64) (io.ReadCloser, error) {
	file, err := os.Open(c.blobPath(digest))
	if err != nil {
		return nil, fmt.Errorf("open cache blob %q: %w", digest, err)
	}
	if err := checkBlob(file, digest, size); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := verifyContent(file, digest, size); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.Join(fmt.Errorf("rewind cache blob %q: %w", digest, err), file.Close())
	}
	return &verifiedBlob{file: file, hash: sha256.New(), digest: digest, size: size}, nil
}

// verifyContent reads the whole blob once and compares it with its digest, leaving the
// file positioned at its end. Reading it twice is the price of handing out a byte only
// after the content is known to be right: a caller streaming into a registry upload
// session cannot take back what an end-of-file check rejects later.
func verifyContent(file *os.File, digest string, size int64) error {
	content := sha256.New()
	read, err := io.Copy(content, io.LimitReader(file, blobReadLimit(size)))
	if err != nil {
		return fmt.Errorf("read cache blob %q: %w", digest, err)
	}
	if read != size {
		return fmt.Errorf("cache blob %q is %d bytes, want %d", digest, read, size)
	}
	if hex.EncodeToString(content.Sum(nil)) != digest {
		return fmt.Errorf("cache blob %q failed SHA256 verification", digest)
	}
	return nil
}

// verifiedBlob re-hashes the bytes it hands out. The first pass proves the blob was
// right when it was opened; this one catches a file rewritten in place once the handle
// exists, which the first pass could not see.
type verifiedBlob struct {
	file   *os.File
	hash   hash.Hash
	digest string
	size   int64
	read   int64
}

func (b *verifiedBlob) Read(p []byte) (int, error) {
	n, err := b.file.Read(p)
	if n > 0 {
		b.hash.Write(p[:n])
		b.read += int64(n)
	}
	if b.read > b.size {
		return n, fmt.Errorf("cache blob %q is longer than %d bytes", b.digest, b.size)
	}
	if errors.Is(err, io.EOF) {
		return n, b.finish()
	}
	return n, err
}

func (b *verifiedBlob) finish() error {
	if b.read != b.size {
		return fmt.Errorf("cache blob %q is %d bytes, want %d", b.digest, b.read, b.size)
	}
	if hex.EncodeToString(b.hash.Sum(nil)) != b.digest {
		return fmt.Errorf("cache blob %q failed SHA256 verification", b.digest)
	}
	return io.EOF
}

func (b *verifiedBlob) Close() error { return b.file.Close() }

// checkBlob refuses a blob that is not a regular file of the recorded size, so a caller
// finds a truncated or extended entry before it reads anything.
func checkBlob(file *os.File, digest string, size int64) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat cache blob %q: %w", digest, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cache blob %q is not a regular file", digest)
	}
	if info.Size() != size {
		return fmt.Errorf("cache blob %q size is %d, want %d", digest, info.Size(), size)
	}
	return nil
}

func writeBlob(file *os.File, r io.Reader, digest string, size int64) error {
	content := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, content), io.LimitReader(r, blobReadLimit(size)))
	if err != nil {
		return &blobWriteError{cause: err}
	}
	if written != size {
		return fmt.Errorf("cache blob size %d does not match expected %d", written, size)
	}
	if actual := hex.EncodeToString(content.Sum(nil)); actual != digest {
		return fmt.Errorf("cache blob digest %s does not match expected %s", actual, digest)
	}
	return nil
}

func blobReadLimit(size int64) int64 {
	if size < math.MaxInt64 {
		return size + 1
	}
	return size
}

// Reader errors can contain credentialed URLs; expose the cause only through error inspection.
type blobWriteError struct{ cause error }

func (e *blobWriteError) Error() string {
	return "write cache blob: input/output failure (details redacted)"
}
func (e *blobWriteError) Unwrap() error { return e.cause }
