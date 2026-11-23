package lockinput

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/snapshot"
)

// Fetcher retrieves a path relative to a repository root.
type Fetcher interface {
	Fetch(ctx context.Context, name string) (io.ReadCloser, error)
}

// Request describes one lock-time acquisition.
type Request struct {
	Inputs   []lock.LocalInput
	Spec     *spec.Spec
	SpecDir  string
	Provider distro.Provider
	Cache    *cache.Cache
	// Repository returns a fetcher for a repository URL. Restricted selects
	// authenticated Pro access.
	Repository func(url string, restricted bool) (Fetcher, error)
	Artifacts  acquire.Fetcher
	Git        catalogue.GitRunner
	Now        time.Time
	// Progress observes each archive as it is verified and cached, so a command can
	// show what is being collected. It may be nil, and it must not block: it runs on
	// the collecting goroutine, once per archive.
	Progress func(acquire.Acquired, int64)
}

// Collect acquires catalogues, repositories, packages and artifacts.
func Collect(ctx context.Context, request *Request) (*locking.Evidence, error) {
	if err := validateRequest(ctx, request); err != nil {
		return nil, err
	}
	if request.Now.IsZero() {
		request.Now = time.Now()
	}
	snapped, err := snapshot.Snapshot(request.SpecDir, request.Spec, request.Cache)
	if err != nil {
		return nil, err
	}
	request.Inputs = snapped.Inputs
	evidence := &locking.Evidence{LocalInputs: snapped.Inputs}
	local := make(map[string]snapshot.Catalogue, len(snapped.Catalogues))
	for _, item := range snapped.Catalogues {
		local[item.Name] = item
	}
	catalogues, err := loadCatalogues(ctx, request, local, evidence)
	if err != nil {
		return nil, err
	}
	repositories, archives, err := acquireRepositories(ctx, request, catalogues)
	if err != nil {
		return nil, err
	}
	evidence.Packages, err = resolveWholePackages(request.Spec, archives)
	if err != nil {
		return nil, err
	}
	if acquireErr := acquireWholePackages(ctx, request, evidence.Packages, archives); acquireErr != nil {
		return nil, acquireErr
	}
	evidence.Slices, err = resolveSlicedPackages(ctx, request, catalogues, archives)
	if err != nil {
		return nil, err
	}
	artifacts, localPackages, err := acquireArtifacts(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := checkArtifactPackages(localPackages, evidence.Packages); err != nil {
		return nil, err
	}
	evidence.Artifacts = artifacts
	// Every suite is a candidate while resolving versions, but only the suite a
	// package or slice actually came from is an input of this build. Recording the
	// rest would leave repository entries nothing refers to.
	evidence.Repositories = referencedRepositories(repositories, evidence)
	return evidence, nil
}

func referencedRepositories(repositories []lock.Repository, evidence *locking.Evidence) []lock.Repository {
	used := make(map[string]bool, len(evidence.Packages)+len(evidence.Slices))
	for i := range evidence.Packages {
		used[evidence.Packages[i].Repository] = true
	}
	for i := range evidence.Slices {
		used[evidence.Slices[i].Repository] = true
	}
	kept := make([]lock.Repository, 0, len(repositories))
	for i := range repositories {
		if used[repositories[i].ID] {
			kept = append(kept, repositories[i])
		}
	}
	return kept
}

func validateRequest(ctx context.Context, request *Request) error {
	if ctx == nil || request == nil || request.Spec == nil {
		return errors.New("lock input request is incomplete")
	}
	if request.SpecDir == "" || request.Provider == nil || request.Cache == nil ||
		request.Repository == nil || request.Artifacts == nil {
		return errors.New("lock input request is incomplete")
	}
	return nil
}
