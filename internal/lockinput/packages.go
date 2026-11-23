package lockinput

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/distro/deb/resolver"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func resolveWholePackages(specification *spec.Spec, archives map[string]*archiveSet) ([]lock.Package, error) {
	if len(specification.Contents.Packages) == 0 {
		return nil, nil
	}
	roots := make([]string, 0, len(specification.Contents.Packages))
	pins := make(map[string]string, len(specification.Contents.Packages))
	for _, request := range specification.Contents.Packages {
		roots = append(roots, request.Name)
		if request.Version != nil {
			pins[request.Name] = *request.Version
		}
	}
	var result []lock.Package
	for _, platform := range specification.Platforms {
		selected, err := solveWholePlatform(platform, roots, pins, archives)
		if err != nil {
			return nil, err
		}
		for i := range selected {
			candidate := &selected[i]
			result = append(result, lock.Package{
				Platform: platform, Name: candidate.Name, Version: candidate.Version,
				Architecture: candidate.Architecture, Source: candidate.Source,
				Repository: candidate.Repository,
				Content: lock.Content{
					Path: candidate.Filename, SHA256: candidate.SHA256, Size: candidate.Size,
				},
			})
		}
	}
	return result, nil
}

func solveWholePlatform(platform string, roots []string, pins map[string]string,
	archives map[string]*archiveSet) ([]resolver.Candidate, error) {
	var indexes []resolver.Index
	for _, set := range archives {
		// A negative priority keeps an archive out of the whole-package candidate
		// set; a slice can still pin a package to it.
		if set.platform != platform || set.archive.Priority < 0 {
			continue
		}
		for _, state := range set.repos {
			indexes = append(indexes, resolver.Index{
				Repository: state.record.ID, Priority: set.archive.Priority, Platform: platform,
				Architecture: state.record.Architecture, Packages: state.packages,
				Scope: state.scope,
			})
		}
	}
	if len(indexes) == 0 {
		return nil, fmt.Errorf("no repository candidates on %s", platform)
	}
	catalog, err := resolver.NewCatalog(indexes, pins)
	if err != nil {
		return nil, err
	}
	return resolver.Solve(catalog, roots)
}

func acquireWholePackages(ctx context.Context, request *Request, packages []lock.Package,
	archives map[string]*archiveSet) error {
	groups := make(map[fetcherKey][]acquire.Package)
	for i := range packages {
		pkg := &packages[i]
		source, ok := repositorySource(archives, pkg.Platform, pkg.Repository)
		if !ok {
			return fmt.Errorf("package %q has no bound repository", pkg.Name)
		}
		groups[source.fetcher] = append(groups[source.fetcher], acquire.Package{
			Platform: pkg.Platform, Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Architecture,
			URL:    strings.TrimSuffix(source.url, "/") + "/" + pkg.Content.Path,
			SHA256: pkg.Content.SHA256, Size: pkg.Content.Size,
		})
	}
	return acquireGroups(ctx, request, groups)
}

type fetcherKey struct {
	url        string
	restricted bool
}

type packageSource struct {
	url     string
	fetcher fetcherKey
}

func repositorySource(archives map[string]*archiveSet, platform, repositoryID string) (packageSource, bool) {
	for _, set := range archives {
		if set.platform != platform {
			continue
		}
		for _, repo := range set.repos {
			if repo.record.ID == repositoryID {
				return packageSource{
					url:     set.binding.URL,
					fetcher: fetcherKey{url: set.binding.URL, restricted: set.binding.Archive.Pro != ""},
				}, true
			}
		}
	}
	return packageSource{}, false
}

func acquireGroups(ctx context.Context, request *Request, groups map[fetcherKey][]acquire.Package) error {
	keys := make([]fetcherKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].url != keys[j].url {
			return keys[i].url < keys[j].url
		}
		return !keys[i].restricted && keys[j].restricted
	})
	for _, key := range keys {
		fetcher, err := request.Repository(key.url, key.restricted)
		if err != nil {
			return err
		}
		scoped := scopedFetcher{base: key.url, next: fetcher}
		if _, err := acquire.Packages(ctx, scoped, request.Cache, groups[key],
			request.Progress); err != nil {
			return fmt.Errorf("package index %q: %w", key.url, err)
		}
	}
	return nil
}

type scopedFetcher struct {
	base string
	next Fetcher
}

func (f scopedFetcher) Fetch(ctx context.Context, name string) (io.ReadCloser, error) {
	prefix := strings.TrimSuffix(f.base, "/") + "/"
	return f.next.Fetch(ctx, strings.TrimPrefix(name, prefix))
}
