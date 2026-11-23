package locking

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/verify"
)

// Audit verifies every recorded repository and payload blob in the cache using the
// default release matching.
func Audit(lockfile *lock.Lockfile, store BlobStore) (Stats, error) {
	return AuditWithPolicy(lockfile, store, nil)
}

// AuditWithPolicy is Audit under a provider's release matching rules, so a lock
// acquired with authenticated codenames is audited the same way.
func AuditWithPolicy(lockfile *lock.Lockfile, store BlobStore, policy verify.RepositoryPolicy) (Stats, error) {
	return audit(context.Background(), lockfile, store, policy)
}

func audit(ctx context.Context, lockfile *lock.Lockfile, store BlobStore, policy verify.RepositoryPolicy) (Stats, error) {
	if lockfile == nil {
		return Stats{}, errors.New("lock must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Stats{}, err
	}
	blobs, err := Blobs(lockfile)
	if err != nil {
		return Stats{}, fmt.Errorf("audit %w", err)
	}
	if err := verify.RepositoriesWithPolicy(lockfile, store, policy); err != nil {
		return Stats{}, fmt.Errorf("audit repository evidence: %w", err)
	}
	stats := Stats{Packages: len(lockfile.Packages)}
	for i := range blobs {
		if err := auditBlob(ctx, store, &blobs[i], &stats); err != nil {
			return Stats{}, err
		}
	}
	return stats, nil
}

func auditBlob(ctx context.Context, store BlobStore, blob *Blob, stats *Stats) error {
	if !blob.Read {
		return addBytes(&stats.VerifiedBytes, blob.Size)
	}
	if err := readBlob(ctx, store, blob.Digest, blob.Size, &stats.VerifiedBytes); err != nil {
		return fmt.Errorf("audit %s: %w", blob.Label, err)
	}
	return nil
}

type blobError struct {
	message string
	cause   error
}

func (e *blobError) Error() string { return e.message }

func (e *blobError) Unwrap() error { return e.cause }

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func readBlob(ctx context.Context, store BlobStore, digest string, size int64, total *int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reader, err := store.Open(digest, size)
	if err != nil {
		return &blobError{message: "open cached blob", cause: err}
	}
	bounded := io.LimitReader(contextReader{ctx: ctx, reader: reader}, size+1)
	read, copyErr := io.Copy(io.Discard, bounded)
	closeErr := reader.Close()
	if copyErr != nil {
		return &blobError{message: "read cached blob", cause: copyErr}
	}
	if closeErr != nil {
		return &blobError{message: "close cached blob", cause: closeErr}
	}
	if read != size {
		return fmt.Errorf("cached blob size %d does not match recorded size %d", read, size)
	}
	return addBytes(total, size)
}

func addBytes(total *int64, size int64) error {
	if size < 0 {
		return errors.New("recorded blob size is negative")
	}
	if *total > math.MaxInt64-size {
		return errors.New("verified byte count overflow")
	}
	*total += size
	return nil
}
