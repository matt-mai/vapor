// Package builder assembles images from locked inputs without network access.
//
// Inputs arrive as a verified cache, a spec and a lock. The builder has no
// acquisition client and no fetcher: assembly can only read blobs a previous
// `vaporize lock` already verified and stored, so a build cannot quietly download
// something a lock does not describe.
package builder

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/verify"
)

// BlobStore provides verified cached bytes and refuses a blob whose digest or size
// does not match. *cache.Cache implements it.
type BlobStore interface {
	Open(digest string, size int64) (io.ReadCloser, error)
}

// BlobWriter publishes bytes into the store under their digest. *cache.Cache
// implements it; a read-only store does not, and a build then keeps its layers in
// memory instead.
type BlobWriter interface {
	Store(reader io.Reader, digest string, size int64) error
}

// Inputs are the three things a build starts from. Nothing here fetches.
type Inputs struct {
	Spec     *spec.Spec
	Lockfile *lock.Lockfile
	Provider distro.Provider
	Blobs    BlobStore
	// Progress, when set, is told what assembly is working on. Platforms build
	// concurrently, so it must be safe for concurrent use.
	Progress Progress
}

// Input is one build of one specification, after its locked inputs were replayed.
type Input struct {
	spec     *spec.Spec
	lockfile *lock.Lockfile
	provider distro.Provider
	blobs    BlobStore
	progress Progress
	counts   stepCounts
}

// Open checks the lock against the spec and the provider. It reads cached
// catalogue roots only when needed to determine repository trust.
func Open(ctx context.Context, inputs *Inputs) (*Input, error) {
	if err := validate(ctx, inputs); err != nil {
		return nil, err
	}
	defaults, err := verify.ProviderDefaults(ctx, inputs.Provider, inputs.Spec,
		inputs.Lockfile.Catalogues, inputs.Lockfile.Repositories, inputs.Blobs)
	if err != nil {
		return nil, err
	}
	if err := lock.VerifyLockfileForProvider(inputs.Spec, inputs.Lockfile,
		inputs.Provider.Release(), defaults); err != nil {
		return nil, fmt.Errorf("build lock structure: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Input{
		spec: inputs.Spec, lockfile: inputs.Lockfile, provider: inputs.Provider,
		blobs: inputs.Blobs, progress: inputs.Progress,
	}, nil
}

func validate(ctx context.Context, inputs *Inputs) error {
	if ctx == nil {
		return errors.New("build context must not be nil")
	}
	if inputs == nil {
		return errors.New("build inputs must not be nil")
	}
	if inputs.Spec == nil || inputs.Lockfile == nil || inputs.Provider == nil || inputs.Blobs == nil {
		return errors.New("build requires a spec, lock, provider and blob store")
	}
	return ctx.Err()
}
