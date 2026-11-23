package locking

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// Bundle writes every blob a lockfile references into w as an uncompressed tar archive,
// and reports how many blobs it wrote and how many content bytes they hold. Only
// referenced blobs travel: moving a whole cache is neither small nor safe to share, and
// a build reads nothing else. A blob referenced twice is written once.
//
// Entries sit at the cache's own layout, so extracting the archive into a cache
// directory is all a receiving machine has to do. Headers carry no clock and no owner,
// so a bundle of one lock is the same bytes wherever it is made.
func Bundle(lockfile *lock.Lockfile, store *cache.Cache, w io.Writer) (int, int64, error) {
	if store == nil {
		return 0, 0, errors.New("bundle requires a cache")
	}
	blobs, err := Blobs(lockfile)
	if err != nil {
		return 0, 0, err
	}
	archive := tar.NewWriter(w)
	written := make(map[string]bool, len(blobs))
	count, bytes := 0, int64(0)
	for position := range blobs {
		blob := &blobs[position]
		if written[blob.Digest] {
			continue
		}
		written[blob.Digest] = true
		if err := writeBlob(archive, store, blob); err != nil {
			return 0, 0, err
		}
		count++
		bytes += blob.Size
	}
	if err := archive.Close(); err != nil {
		return 0, 0, fmt.Errorf("finish bundle: %w", err)
	}
	return count, bytes, nil
}

func writeBlob(archive *tar.Writer, store *cache.Cache, blob *Blob) error {
	header := &tar.Header{
		Typeflag: tar.TypeReg, Name: cacheEntryPath(blob.Digest), Mode: 0o600,
		Size: blob.Size, Format: tar.FormatPAX,
		ModTime: time.Time{}, AccessTime: time.Time{}, ChangeTime: time.Time{},
	}
	if err := archive.WriteHeader(header); err != nil {
		return fmt.Errorf("bundle %s: %w", blob.Label, err)
	}
	reader, err := store.Open(blob.Digest, blob.Size)
	if err != nil {
		return fmt.Errorf("bundle %s: %w", blob.Label, err)
	}
	defer func() { _ = reader.Close() }()
	// The cache verifies the bytes as it reads them, so a blob that no longer matches
	// its digest fails here instead of traveling as trusted content.
	if _, err := io.CopyN(archive, reader, blob.Size); err != nil {
		return fmt.Errorf("bundle %s: %w", blob.Label, err)
	}
	return nil
}

// Unbundle extracts a bundle into a cache and reports how many blobs were added and how
// many the cache already held.
//
// A bundle is not trusted input: an entry is accepted only at a cache path, and the
// cache keeps only bytes that match their own digest.
func Unbundle(store *cache.Cache, r io.Reader) (added, present int, err error) {
	if store == nil {
		return 0, 0, errors.New("unbundle requires a cache")
	}
	return unbundleEntries(store, tar.NewReader(r))
}

func unbundleEntries(store *cache.Cache, archive *tar.Reader) (int, int, error) {
	seen := make(map[string]bool)
	added, present := 0, 0
	for {
		digest, size, done, err := nextBundleEntry(archive, seen)
		if err != nil {
			return added, present, err
		}
		if done {
			return added, present, nil
		}
		held, err := takeEntry(store, archive, digest, size)
		if err != nil {
			return added, present, err
		}
		if held {
			present++
			continue
		}
		added++
	}
}

// nextBundleEntry reads the next entry and reports whether the archive ended.
func nextBundleEntry(archive *tar.Reader, seen map[string]bool) (string, int64, bool, error) {
	header, err := archive.Next()
	if errors.Is(err, io.EOF) {
		return "", 0, true, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("read bundle: %w", err)
	}
	digest, err := cacheEntryDigest(header)
	if err != nil {
		return "", 0, false, err
	}
	if seen[digest] {
		return "", 0, false, fmt.Errorf("bundle repeats %s", digest)
	}
	seen[digest] = true
	return digest, header.Size, false, nil
}

// takeEntry stores one bundle entry unless the cache holds that blob. A file at the
// blob's path is not enough: an interrupted write or a damaged disk keeps the name, and
// only the bundle still has the bytes that make the lock replayable.
func takeEntry(store *cache.Cache, archive io.Reader, digest string, size int64) (bool, error) {
	if store.Has(digest) && store.Verify(digest, size) == nil {
		return true, nil
	}
	if err := store.Store(archive, digest, size); err != nil {
		return false, fmt.Errorf("bundle %s: %w", digest, err)
	}
	return false, nil
}

func cacheEntryPath(digest string) string {
	return "sha256/" + digest[:2] + "/" + digest
}

// cacheEntryDigest reads the digest a bundle entry claims, and refuses a name that is not
// exactly the cache path of that digest.
func cacheEntryDigest(header *tar.Header) (string, error) {
	parts := strings.Split(header.Name, "/")
	if len(parts) != 3 || parts[0] != "sha256" || !validBundleDigest(parts[2]) ||
		parts[1] != parts[2][:2] {
		return "", fmt.Errorf("bundle entry %q is not a cache path", header.Name)
	}
	if header.Typeflag != tar.TypeReg {
		return "", fmt.Errorf("bundle entry %q is not a file", header.Name)
	}
	if header.Size < 0 {
		return "", fmt.Errorf("bundle entry %q has a negative size", header.Name)
	}
	return parts[2], nil
}

func validBundleDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, character := range digest {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
