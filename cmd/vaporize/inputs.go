package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/ui"
	"github.com/matt-mai/vapor/internal/verify"
)

// resolveInputPaths fills the spec, lock and verified-cache paths from the argument and
// the flags, so every command that reads locked inputs resolves them the same way.
func resolveInputPaths(specPath, lockPath, cacheDir *string, args []string) error {
	if len(args) == 1 {
		if *specPath != "" {
			return errors.New("spec path supplied twice")
		}
		*specPath = args[0]
	}
	if *specPath == "" {
		*specPath = defaultSpecFile
	}
	if *lockPath == "" {
		*lockPath = defaultLockPath(*specPath)
	}
	if *cacheDir == "" {
		dir, err := defaultCacheDir()
		if err != nil {
			return err
		}
		*cacheDir = dir
	}
	return nil
}

// lockedInputs is what a command reads before it can build anything: the verified cache,
// the specification, the lock and the assembler opened over them.
type lockedInputs struct {
	store    *cache.Cache
	spec     *spec.Spec
	lock     *lock.Lockfile
	provider distro.Provider
	input    *builder.Input
}

// openLocked reads the specification, its lock and the verified cache, and opens the
// assembler over them. Nothing is verified here; that happens before any archive is read.
func openLocked(ctx context.Context, specPath, lockPath, cacheDir string,
	progress builder.Progress,
) (*lockedInputs, error) {
	store, err := cache.New(cacheDir)
	if err != nil {
		return nil, err
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		return nil, err
	}
	locked, err := lock.LoadLockfile(lockPath)
	if err != nil {
		return nil, err
	}
	provider, err := distro.Select(loaded.Distro, loaded.Release)
	if err != nil {
		return nil, err
	}
	input, err := builder.Open(ctx, &builder.Inputs{
		Spec: loaded, Lockfile: locked, Provider: provider, Blobs: store, Progress: progress,
	})
	if err != nil {
		return nil, err
	}
	return &lockedInputs{store: store, spec: loaded, lock: locked, provider: provider, input: input}, nil
}

// phaseReporter is how a command names one progress step, so shared work reports in the
// terms of the command that asked for it.
type phaseReporter func(reporter *ui.Reporter, number int, title, details string) error

// checkEvidence authenticates the locked repository evidence before assembly opens any
// package archive.
func checkEvidence(reporter *ui.Reporter, inputs *lockedInputs, report phaseReporter) error {
	if err := report(reporter, 1, "verify evidence", ""); err != nil {
		return err
	}
	policy := distro.RepositoryPolicy{Provider: inputs.provider, Repositories: inputs.spec.Contents.Repositories}
	if err := verify.RepositoriesWithPolicy(inputs.lock, inputs.store, policy); err != nil {
		return err
	}
	if err := report(reporter, 1, "verify evidence",
		fmt.Sprintf("%d repositories", len(inputs.lock.Repositories))); err != nil {
		return err
	}
	return reporter.CompletePhase()
}
