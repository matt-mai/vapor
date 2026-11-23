package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

// ProviderDefaults resolves lock-time and build-time trust from the same provider
// and catalogue bindings. It reads only cached catalogue roots, not archives.
func ProviderDefaults(ctx context.Context, provider slicespkg.BindingProvider, specification *spec.Spec,
	catalogues []lock.Catalogue, repositories []lock.Repository, blobs BlobStore,
) (*lock.DefaultRepository, error) {
	defaults := &lock.DefaultRepository{
		Name: provider.Distro(), AllowedSuites: provider.AllowedSuites(),
		Keys: providerKeys(provider.DefaultTrust()), Archives: providerArchives(provider),
		RepositoryKeys: make(map[string][]lock.RepositoryKey),
		Bindings:       make(map[string]lock.ArchiveBinding), Covered: make(map[string]bool),
	}
	services, err := repositoryServices(ctx, provider, specification, catalogues, repositories, blobs,
		defaults)
	if err != nil {
		return nil, err
	}
	for name, service := range services {
		if service != "" {
			defaults.RepositoryKeys[name] = providerKeys(provider.ProTrust(service))
		}
	}
	return defaults, nil
}

// repositoryServices resolves every catalogue archive to the repository that serves
// it and records the Pro service the provider must vouch for. The same pass records
// the effective binding, so replay can check a slice against the archive it claims
// instead of only against a repository name.
func repositoryServices(ctx context.Context, provider slicespkg.BindingProvider, specification *spec.Spec,
	catalogues []lock.Catalogue, repositories []lock.Repository, blobs BlobStore,
	defaults *lock.DefaultRepository,
) (map[string]string, error) {
	active := activeProviderRepositories(specification.Contents.Repositories, repositories)
	services := make(map[string]string)
	for i := range specification.Contents.Catalogues {
		source := &specification.Contents.Catalogues[i]
		if err := resolveCatalogue(ctx, &resolution{
			provider: provider, specification: specification, source: source, catalogues: catalogues,
			repositories: repositories, blobs: blobs, active: active, defaults: defaults,
		}, services); err != nil {
			return nil, err
		}
	}
	return services, nil
}

// resolution carries what one catalogue needs to be resolved on every platform it
// binds.
type resolution struct {
	provider      slicespkg.BindingProvider
	specification *spec.Spec
	source        *contents.CatalogueSource
	catalogues    []lock.Catalogue
	repositories  []lock.Repository
	blobs         BlobStore
	active        map[string]string
	defaults      *lock.DefaultRepository
}

func resolveCatalogue(ctx context.Context, work *resolution, services map[string]string) error {
	for _, platform := range cataloguePlatforms(work.specification, work.source, work.active) {
		if err := ctx.Err(); err != nil {
			return err
		}
		metadata, err := lockedCatalogueRoot(work.catalogues, work.source.Name, work.blobs)
		if err != nil {
			return fmt.Errorf("catalogue %q trust: %w", work.source.Name, err)
		}
		bindings, err := slicespkg.BindArchives(metadata, work.source, work.specification.Contents.Repositories,
			work.provider, platform)
		if err != nil {
			return fmt.Errorf("catalogue %q trust: %w", work.source.Name, err)
		}
		if err := recordServices(bindings, work.active, services); err != nil {
			return err
		}
		recordBindings(work.source.Name, bindings, platform, work.defaults.Bindings)
		work.defaults.Covered[work.source.Name] = true
	}
	return nil
}

// cataloguePlatforms lists the platforms a catalogue has to be resolved on, which is
// every platform the image targets. A repository always covers the platforms it is
// declared for, so a bound archive binds the same way on each of them; an archive the
// provider serves is bound on the platform the lock used it on. Resolving every
// platform keeps the binding map complete enough that replay never has to guess.
func cataloguePlatforms(specification *spec.Spec, source *contents.CatalogueSource,
	active map[string]string,
) []string {
	platforms := slices.Clone(specification.Platforms)
	if platform := bindingPlatform(source, active); platform != "" {
		platforms = append(platforms, platform)
	}
	slices.Sort(platforms)
	return slices.Compact(platforms)
}

func activeProviderRepositories(declared []contents.Repository, records []lock.Repository) map[string]string {
	providerTrust := make(map[string]bool, len(declared))
	for i := range declared {
		repo := &declared[i]
		providerTrust[repo.Name] = len(repo.Trust.Keys) == 0
	}
	active := make(map[string]string)
	for i := range records {
		repo := &records[i]
		if providerTrust[repo.Name] {
			active[repo.Name] = repo.Platform
		}
	}
	return active
}

func bindingPlatform(source *contents.CatalogueSource, active map[string]string) string {
	platform := ""
	for _, name := range source.Archives {
		if candidate := active[name]; candidate != "" && (platform == "" || candidate < platform) {
			platform = candidate
		}
	}
	return platform
}

// recordBindings remembers what each archive resolved to. A platform whose binding
// differs from an earlier one is not recorded, because a binding that is not the same
// everywhere cannot be compared with a single repository record.
func recordBindings(name string, bindings []slicespkg.Binding, platform string,
	recorded map[string]lock.ArchiveBinding,
) {
	for i := range bindings {
		binding := &bindings[i]
		key := lock.BindingKey(name, binding.Archive.Name, platform)
		entry := lock.ArchiveBinding{
			Repository: binding.Repository,
			Suites:     append([]string(nil), binding.Archive.Suites...),
			Components: append([]string(nil), binding.Archive.Components...),
		}
		if previous, ok := recorded[key]; ok && (previous.Repository != entry.Repository ||
			!slices.Equal(previous.Suites, entry.Suites) ||
			!slices.Equal(previous.Components, entry.Components)) {
			delete(recorded, key)
			continue
		}
		recorded[key] = entry
	}
}

func recordServices(bindings []slicespkg.Binding, active, services map[string]string) error {
	for i := range bindings {
		binding := &bindings[i]
		name := binding.Repository
		if binding.ProviderDefault || active[name] == "" {
			continue
		}
		service := binding.Archive.Pro
		if previous, ok := services[name]; ok && previous != service {
			return fmt.Errorf("repository %q has conflicting catalogue trust; use separate repositories or explicit keys", name)
		}
		services[name] = service
	}
	return nil
}

func lockedCatalogueRoot(records []lock.Catalogue, name string, blobs BlobStore) (*slicespkg.Catalogue, error) {
	i := slices.IndexFunc(records, func(record lock.Catalogue) bool { return record.Name == name })
	if i < 0 {
		return nil, errors.New("missing locked catalogue")
	}
	tree, err := catalogue.LockedTree(&records[i])
	if err != nil {
		return nil, err
	}
	for _, entry := range tree.Entries() {
		if entry.Path == "chisel.yaml" && entry.Kind == catalogue.KindFile {
			data, err := readEvidence(blobs, "catalogue root", entry.SHA256, entry.Size, catalogue.MaxTreeFileSize)
			if err != nil {
				return nil, err
			}
			return slicespkg.ParseCatalogue(data)
		}
	}
	return nil, errors.New("missing regular chisel.yaml")
}

// providerArchives records the archives the provider serves itself, each with its own
// keys, so replay can check a lock record against the archive it names.
func providerArchives(provider slicespkg.BindingProvider) []lock.ProviderArchive {
	archives := provider.Archives()
	records := make([]lock.ProviderArchive, 0, len(archives))
	for i := range archives {
		archive := &archives[i]
		record := lock.ProviderArchive{
			Name: archive.Name, Endpoints: make(map[string]string, len(archive.Endpoints)),
			Suites:     append([]string(nil), archive.Suites...),
			Components: append([]string(nil), archive.Components...),
			Keys:       providerKeys(archive.Keys),
		}
		maps.Copy(record.Endpoints, archive.Endpoints)
		records = append(records, record)
	}
	return records
}

func providerKeys(snapshots []deb.KeySnapshot) []lock.RepositoryKey {
	var keys []lock.RepositoryKey
	for i := range snapshots {
		snapshot := &snapshots[i]
		sum := sha256.Sum256(snapshot.Data)
		digest := hex.EncodeToString(sum[:])
		for _, fingerprint := range snapshot.Fingerprints {
			keys = append(keys, lock.RepositoryKey{
				Fingerprint: fingerprint, SHA256: digest, Size: int64(len(snapshot.Data)),
			})
		}
	}
	return keys
}
