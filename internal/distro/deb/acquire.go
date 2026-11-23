package deb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
)

// MaxIndexAcquisitionSize bounds compressed index bytes before verification.
// The allowance covers encoding overhead above the decompressed index bound.
const MaxIndexAcquisitionSize int64 = MaxIndexSize + (1 << 20)

// IndexFetcher retrieves one acquisition path relative to the repository suite.
type IndexFetcher interface {
	Fetch(ctx context.Context, path string) (io.ReadCloser, error)
}

// IndexStore is the verified content-addressed cache used for index reuse.
type IndexStore interface {
	Open(digest string, size int64) (io.ReadCloser, error)
	Store(reader io.Reader, digest string, size int64) error
}

// DerivedIndexStore remembers a decoded index beside the compressed blob it came from.
// Decoding is most of the cost of a repeat run: the Ubuntu universe index is 16 MB
// compressed and 77 MB of text, and xz spends several seconds on it every time.
//
// The entry is used only while the signed release names the decoded text in the plain
// Packages path, digest and size both, so an entry that says something else is refused
// and the verified compressed bytes are decoded again. Resolution is therefore the same
// cold or warm; the memo only saves the decode.
type DerivedIndexStore interface {
	ReadDerived(digest, plainSHA256 string, plainSize, limit int64) ([]byte, bool)
	StoreDerived(digest, plainSHA256 string, plainSize int64, data []byte) bool
}

// AcquireIndex returns a verified, decompressed package index. A valid cached
// blob is reused without fetching. Otherwise each acquisition path is tried in
// order; only bytes matching the authenticated SHA256 and size enter the cache.
func AcquireIndex(ctx context.Context, fetcher IndexFetcher, store IndexStore, index *Index) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("index acquisition context is nil")
	}
	if fetcher == nil || store == nil {
		return nil, errors.New("index acquisition requires a fetcher and store")
	}
	if index.Size < 0 || index.Size > MaxIndexAcquisitionSize {
		return nil, errors.New("index size is outside the acquisition bound")
	}
	digest := strings.ToLower(index.SHA256)
	if data, ok := readDecodedIndex(store, index, digest); ok {
		return data, nil
	}
	for _, path := range index.AcquirePaths {
		data, found, err := acquireIndexPath(ctx, fetcher, store, index, digest, path)
		if err != nil {
			return nil, err
		}
		if found {
			return data, nil
		}
	}
	return nil, errors.New("index acquisition failed")
}

// readDecodedIndex returns the index from the cache without decoding it again. The
// compressed blob stays the authority: a decoded entry is only used while the blob it
// was derived from still verifies, because a tampered blob must fail the run instead of
// being masked by a memo of the bytes it used to hold. Hashing the blob costs a fraction
// of decoding it.
func readDecodedIndex(store IndexStore, index *Index, digest string) ([]byte, bool) {
	if !blobVerifies(store, digest, index.Size) {
		return nil, false
	}
	// A plain index needs no decoding, so a memo of it would only duplicate the blob.
	derived, remembers := store.(DerivedIndexStore)
	if remembers && index.Format != IndexFormatPlain {
		if data, found := derived.ReadDerived(digest, index.PlainSHA256, index.PlainSize, MaxIndexSize); found {
			return data, true
		}
	}
	data, ok := readCachedIndex(store, index, digest)
	if !ok {
		return nil, false
	}
	if remembers {
		derived.StoreDerived(digest, index.PlainSHA256, index.PlainSize, data)
	}
	return data, true
}

// blobVerifies reads a cached blob to the end, which is what proves its digest. The bytes
// are discarded; only the fact that they hash correctly matters here.
func blobVerifies(store IndexStore, digest string, size int64) bool {
	reader, err := store.Open(digest, size)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return false
	}
	_, copyErr := io.Copy(io.Discard, reader)
	closeErr := reader.Close()
	return copyErr == nil && closeErr == nil
}

func acquireIndexPath(ctx context.Context, fetcher IndexFetcher, store IndexStore,
	index *Index, digest, path string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	compressed, err := fetchIndex(ctx, fetcher, path, index.Size)
	if err != nil {
		return nil, false, nil
	}
	data, err := VerifyIndex(index, compressed)
	if err != nil {
		return nil, false, nil
	}
	if err := store.Store(bytes.NewReader(compressed), digest, index.Size); err != nil {
		return nil, false, errors.New("index acquisition failed")
	}
	if derived, ok := store.(DerivedIndexStore); ok && index.Format != IndexFormatPlain {
		// Worth remembering for the next run, not worth failing this one.
		derived.StoreDerived(digest, index.PlainSHA256, index.PlainSize, data)
	}
	return data, true, nil
}

func readCachedIndex(store IndexStore, index *Index, digest string) ([]byte, bool) {
	reader, err := store.Open(digest, index.Size)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, false
	}
	if reader == nil {
		return nil, false
	}
	compressed, readErr := io.ReadAll(io.LimitReader(reader, index.Size+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(compressed)) != index.Size {
		return nil, false
	}
	data, err := VerifyIndex(index, compressed)
	if err != nil {
		return nil, false
	}
	return data, true
}

func fetchIndex(ctx context.Context, fetcher IndexFetcher, path string, size int64) ([]byte, error) {
	reader, err := fetcher.Fetch(ctx, path)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, err
	}
	if reader == nil {
		return nil, errors.New("index fetcher returned no data")
	}
	compressed, readErr := io.ReadAll(io.LimitReader(reader, size+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(compressed)) != size {
		return nil, errors.New("index size does not match authenticated metadata")
	}
	return compressed, nil
}
