package lockinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

func acquireRepository(ctx context.Context, request *Request, state *repository) error {
	fetcher, err := request.Repository(state.record.URL, state.restricted)
	if err != nil {
		return err
	}
	release, raw, err := loadRelease(ctx, request, state, fetcher)
	if err != nil {
		return err
	}
	digestBytes := sha256.Sum256(raw)
	digest := hex.EncodeToString(digestBytes[:])
	if err := request.Cache.Store(bytes.NewReader(raw), digest, int64(len(raw))); err != nil {
		return err
	}
	state.record.Release = lock.RepositoryRelease{
		Format: release.Format, Path: path.Join("dists", state.record.Suite, "InRelease"),
		SHA256: digest, Size: int64(len(raw)), Signers: release.Signers,
	}
	if release.Metadata.ValidUntil != "" {
		validUntil := release.Metadata.ValidUntil
		state.record.Release.ValidUntil = &validUntil
	}
	return acquireIndexes(ctx, request, state, &release.Metadata, fetcher)
}

func loadRelease(ctx context.Context, request *Request, state *repository,
	fetcher Fetcher) (*deb.VerifiedRelease, []byte, error) {
	raw, err := fetchBytes(ctx, fetcher, path.Join("dists", state.record.Suite, "InRelease"), deb.MaxReleaseSize)
	if err != nil {
		return nil, nil, fmt.Errorf("repository %q: %w", state.record.Name, err)
	}
	release, err := deb.VerifyInRelease(raw, state.keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		return nil, nil, fmt.Errorf("repository %q: %w", state.record.Name, err)
	}
	policy := distro.RepositoryPolicy{Provider: request.Provider, Repositories: request.Spec.Contents.Repositories}
	expected := policy.ReleaseMatching(state.record.Name)
	expected.Suite, expected.Architecture = state.record.Suite, state.record.Architecture
	expected.Components = append(expected.Components, state.components...)
	if err := deb.CheckReleaseIdentity(&release.Metadata, expected); err != nil {
		return nil, nil, fmt.Errorf("repository %q: %w", state.record.Name, err)
	}
	freshness := deb.FreshnessIfPresent
	if specRepository := declaredRepository(request.Spec, state.record.Name); specRepository != nil &&
		specRepository.Freshness.ValidUntil != nil {
		freshness = deb.FreshnessPolicy(*specRepository.Freshness.ValidUntil)
	}
	if err := deb.CheckFreshness(&release.Metadata, freshness, request.Now); err != nil {
		return nil, nil, fmt.Errorf("repository %q: %w", state.record.Name, err)
	}
	return release, raw, nil
}

func acquireIndexes(ctx context.Context, request *Request, state *repository, release *deb.Release,
	fetcher Fetcher) error {
	fetcher = prefixFetcher{Fetcher: fetcher, prefix: path.Join("dists", state.record.Suite)}
	for _, component := range state.components {
		index, err := deb.SelectIndex(release, component, state.record.Architecture, state.byHash)
		if err != nil {
			return err
		}
		data, err := deb.AcquireIndex(ctx, fetcher, request.Cache, &index)
		if err != nil {
			return err
		}
		packages, err := deb.ParsePackages(data, &index, state.record.Suite)
		if err != nil {
			return err
		}
		state.packages = append(state.packages, packages...)
		state.record.Indexes = append(state.record.Indexes, lock.Index{
			Component: index.Component, Path: index.Path, SHA256: index.SHA256, Size: index.Size,
		})
	}
	return nil
}

type prefixFetcher struct {
	Fetcher
	prefix string
}

func (fetcher prefixFetcher) Fetch(ctx context.Context, name string) (io.ReadCloser, error) {
	return fetcher.Fetcher.Fetch(ctx, path.Join(fetcher.prefix, name))
}

func fetchBytes(ctx context.Context, fetcher Fetcher, name string, limit int64) ([]byte, error) {
	reader, err := fetcher.Fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("repository metadata exceeds its bound")
	}
	return data, nil
}
