package lockinput

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

type repository struct {
	catalogue  string
	restricted bool
	record     lock.Repository
	components []string
	keys       []deb.PublicKey
	packages   []deb.Package
	byHash     deb.ByHashPolicy
	// scope names the packages a vendor repository may supply, so it cannot
	// replace an unrelated base package.
	scope []string
}

type archiveSet struct {
	platform string
	archive  slicespkg.Archive
	binding  slicespkg.Binding
	repos    []*repository
}

func acquireRepositories(ctx context.Context, request *Request,
	catalogues []*catalogueInput) ([]lock.Repository, map[string]*archiveSet, error) {
	required, err := requiredArchives(request, catalogues)
	if err != nil {
		return nil, nil, err
	}
	states, archives, err := buildRepositoryStates(request, catalogues, required)
	if err != nil {
		return nil, nil, err
	}
	if err := addSpecRepositories(request, states, archives); err != nil {
		return nil, nil, err
	}
	if err := addProviderArchive(request, states, archives); err != nil {
		return nil, nil, err
	}
	keys := slices.Sorted(maps.Keys(states))
	for _, key := range keys {
		if err := acquireRepository(ctx, request, states[key]); err != nil {
			return nil, nil, err
		}
	}
	return repositoryRecords(states, keys), archives, nil
}

func buildRepositoryStates(request *Request, catalogues []*catalogueInput,
	required map[string]bool) (map[string]*repository, map[string]*archiveSet, error) {
	states := make(map[string]*repository)
	archives := make(map[string]*archiveSet)
	for _, input := range catalogues {
		for _, platform := range request.Spec.Platforms {
			if err := buildCatalogueStates(request, input, platform, required, states, archives); err != nil {
				return nil, nil, err
			}
		}
	}
	return states, archives, nil
}

func buildCatalogueStates(request *Request, input *catalogueInput, platform string,
	required map[string]bool, states map[string]*repository, archives map[string]*archiveSet) error {
	names := slices.Sorted(maps.Keys(input.catalogue.Archives))
	for _, name := range names {
		key := archiveKey(input.name, name, platform)
		set, err := archiveStates(request, input, name, key, platform, required, states)
		if err != nil {
			return err
		}
		archives[key] = set
	}
	return nil
}

func archiveStates(request *Request, input *catalogueInput, name, key, platform string,
	required map[string]bool, states map[string]*repository) (*archiveSet, error) {
	binding, ok := input.bindings[platform+"\x00"+name]
	if !ok {
		if required[key] {
			return nil, fmt.Errorf("catalogue %q archive %q is not bound to a repository; "+
				"declare one under contents.repositories", input.name, name)
		}
		// An unbound archive is an optional subscription source: it is recorded so
		// versions can be resolved against it, but nothing is acquired.
		return &archiveSet{platform: platform, archive: input.catalogue.Archives[name]}, nil
	}
	set := &archiveSet{platform: platform, archive: binding.Archive, binding: binding}
	if skipArchive(request, &binding, key, required) {
		return set, nil
	}
	for _, suite := range binding.Archive.Suites {
		state, err := addRepositoryState(request, &binding, platform, suite, states)
		if err != nil {
			return nil, err
		}
		set.repos = append(set.repos, state)
	}
	return set, nil
}

func skipArchive(request *Request, binding *slicespkg.Binding, key string, required map[string]bool) bool {
	if binding.Archive.Pro == "" || required[key] {
		return false
	}
	// A negative priority marks an archive as out of the default candidate set:
	// only a slice pinned to it may use it.
	return binding.Archive.Priority < 0 || len(request.Spec.Contents.Packages) == 0
}

func addRepositoryState(request *Request, binding *slicespkg.Binding, platform, suite string,
	states map[string]*repository) (*repository, error) {
	repoKey := binding.Repository + "\x00" + platform + "\x00" + suite
	if state := states[repoKey]; state != nil {
		if binding.Catalogue != "" && !slices.Equal(state.components, binding.Archive.Components) {
			return nil, fmt.Errorf("catalogues %q and %q disagree on components for repository %q, platform %s, suite %q",
				state.catalogue, binding.Catalogue, binding.Repository, platform, suite)
		}
		return state, nil
	}
	state, err := newRepository(request, binding, suite)
	if err != nil {
		return nil, err
	}
	states[repoKey] = state
	return state, nil
}

// needsProviderArchive reports whether the specification left the source of its whole
// packages to the release: packages to resolve, no repository of its own, and a
// provider that serves reviewed archives.
func needsProviderArchive(request *Request) bool {
	return len(request.Spec.Contents.Packages) != 0 &&
		len(request.Spec.Contents.Repositories) == 0 &&
		len(request.Provider.Archives()) != 0
}

func providerArchiveBound(archives map[string]*archiveSet, platform, name string) bool {
	for _, set := range archives {
		if set.platform == platform && set.binding.ProviderDefault && set.binding.Repository == name {
			return true
		}
	}
	return false
}

func providerBinding(request *Request, platform string, archive *deb.SignedArchive) (slicespkg.Binding, error) {
	architecture, err := request.Provider.Architecture(platform)
	if err != nil {
		return slicespkg.Binding{}, err
	}
	url, ok := archive.Endpoint(platform)
	if !ok {
		return slicespkg.Binding{}, fmt.Errorf("archive %q has no endpoint for %s", archive.Name, platform)
	}
	return slicespkg.Binding{
		Archive: slicespkg.Archive{
			Name: archive.Name, Suites: archive.Suites, Components: archive.Components,
		},
		Repository: archive.Name, Platform: platform, Architecture: architecture,
		URL: url, DefaultTrust: archive.Keys, ProviderDefault: true,
	}, nil
}

// addProviderArchive binds the provider's own archives for whole packages when the
// specification declares no repositories of its own. A specification that declares one
// has said where its packages come from, so nothing is added behind it; an empty
// declaration is read as "the release's own archives", which is what a package-only
// image wants. Each archive keeps its own endpoint, suites and keys.
func addProviderArchive(request *Request, states map[string]*repository,
	archives map[string]*archiveSet) error {
	if !needsProviderArchive(request) {
		return nil
	}
	for _, platform := range request.Spec.Platforms {
		if err := addProviderPlatform(request, platform, states, archives); err != nil {
			return err
		}
	}
	return nil
}

// addProviderPlatform binds every provider archive the specification's source did not
// already name on this platform, each with its own endpoint, suites and keys.
func addProviderPlatform(request *Request, platform string, states map[string]*repository,
	archives map[string]*archiveSet) error {
	available := request.Provider.Archives()
	for i := range available {
		if providerArchiveBound(archives, platform, available[i].Name) {
			continue
		}
		binding, err := providerBinding(request, platform, &available[i])
		if err != nil {
			return err
		}
		set := &archiveSet{platform: platform, archive: binding.Archive, binding: binding}
		for _, suite := range binding.Archive.Suites {
			state, err := addRepositoryState(request, &binding, platform, suite, states)
			if err != nil {
				return err
			}
			set.repos = append(set.repos, state)
		}
		archives["provider\x00"+binding.Repository+"\x00"+platform] = set
	}
	return nil
}

func addSpecRepositories(request *Request, states map[string]*repository,
	archives map[string]*archiveSet) error {
	if len(request.Spec.Contents.Packages) == 0 {
		return nil
	}
	represented := make(map[string]bool)
	for _, set := range archives {
		for _, state := range set.repos {
			represented[state.record.ID] = true
		}
	}
	for i := range request.Spec.Contents.Repositories {
		if err := addSpecRepository(request, &request.Spec.Contents.Repositories[i],
			states, archives, represented); err != nil {
			return err
		}
	}
	return nil
}

func addSpecRepository(request *Request, declared *contents.Repository,
	states map[string]*repository, archives map[string]*archiveSet, represented map[string]bool) error {
	for _, platform := range declared.Platforms {
		binding, err := specBinding(request, declared, platform)
		if err != nil {
			return err
		}
		set := &archiveSet{platform: platform, archive: binding.Archive, binding: binding}
		if err := addSpecSuites(request, &binding, set, states, represented); err != nil {
			return err
		}
		if len(set.repos) != 0 {
			archives["spec\x00"+declared.Name+"\x00"+platform] = set
		}
	}
	return nil
}

func specBinding(request *Request, declared *contents.Repository, platform string) (slicespkg.Binding, error) {
	url, ok := repositoryEndpoint(declared, platform)
	if !ok {
		return slicespkg.Binding{}, fmt.Errorf("repository %q has no endpoint for %s", declared.Name, platform)
	}
	binding := slicespkg.Binding{
		Repository: declared.Name, Platform: platform, URL: url,
		Trust: declared.Trust.Keys,
		Archive: slicespkg.Archive{
			Name: declared.Name, Suites: declared.Suites, Components: declared.Components,
		},
		OwnIdentity: declared.Identity != nil,
		Packages:    slices.Clone(declared.Packages),
	}
	if len(binding.Trust) == 0 {
		binding.DefaultTrust = providerDefaultTrust(request.Provider, declared.Name)
	}
	// An explicitly declared repository chooses its own endpoint and keys, but not
	// which suites belong to this release: a correctly signed archive of another
	// release must not become reachable by declaring it. A repository with its own
	// identity is exempt, because its suites describe that identity.
	if declared.Identity == nil {
		for _, suite := range binding.Archive.Suites {
			if !servesSuite(request.Provider.AllowedSuites(), suite) {
				return slicespkg.Binding{}, fmt.Errorf("repository %q suite %q is not served by release %q",
					declared.Name, suite, request.Provider.Release())
			}
		}
	}
	return binding, nil
}

// providerDefaultTrust is the trust a declared repository gets when it names no keys
// of its own. A repository that names a provider archive gets that archive's keys, so
// declaring Debian's security archive does not hand it the main archive's key; any
// other name gets every reviewed key, which is what a mirror of the whole release
// needs.
func providerDefaultTrust(provider distro.Provider, name string) []deb.KeySnapshot {
	archives := provider.Archives()
	for i := range archives {
		if archives[i].Name == name {
			return archives[i].Keys
		}
	}
	return provider.DefaultTrust()
}

// servesSuite reports whether the provider lets this release read the suite. An empty
// list leaves the suites to the declaration.
func servesSuite(suites []string, suite string) bool {
	return len(suites) == 0 || slices.Contains(suites, suite)
}

func addSpecSuites(request *Request, binding *slicespkg.Binding, set *archiveSet,
	states map[string]*repository, represented map[string]bool) error {
	for _, suite := range binding.Archive.Suites {
		state, err := addRepositoryState(request, binding, binding.Platform, suite, states)
		if err != nil {
			return err
		}
		if !represented[state.record.ID] {
			set.repos = append(set.repos, state)
			represented[state.record.ID] = true
		}
	}
	return nil
}

func repositoryEndpoint(repository *contents.Repository, platform string) (string, bool) {
	for _, endpoint := range repository.Endpoints {
		if slices.Contains(endpoint.Platforms, platform) {
			return endpoint.URL, true
		}
	}
	return "", false
}

func repositoryRecords(states map[string]*repository, keys []string) []lock.Repository {
	records := make([]lock.Repository, 0, len(keys))
	for _, key := range keys {
		records = append(records, states[key].record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].Platform != records[j].Platform {
			return records[i].Platform < records[j].Platform
		}
		return records[i].Suite < records[j].Suite
	})
	return records
}

func archiveKey(catalogueName, archive, platform string) string {
	return catalogueName + "\x00" + archive + "\x00" + platform
}

func newRepository(request *Request, binding *slicespkg.Binding, suite string) (*repository, error) {
	architecture, err := request.Provider.Architecture(binding.Platform)
	if err != nil {
		return nil, err
	}
	specRepository := declaredRepository(request.Spec, binding.Repository)
	byHash := deb.ByHashPrefer
	if specRepository != nil && specRepository.ByHash != nil {
		byHash = deb.ByHashPolicy(*specRepository.ByHash)
	}
	state := &repository{
		record: lock.Repository{
			ID:   lock.RepositoryID(binding.Repository, binding.Platform, architecture, binding.URL, suite),
			Name: binding.Repository, Platform: binding.Platform, Architecture: architecture,
			URL: binding.URL, Suite: suite,
		},
		catalogue: binding.Catalogue, components: slices.Clone(binding.Archive.Components),
		byHash: byHash, restricted: binding.Archive.Pro != "", scope: slices.Clone(binding.Packages),
	}
	keys, err := repositoryTrust(request, binding)
	if err != nil {
		return nil, err
	}
	state.record.Trust.Keys = keys.records
	state.keys = keys.public
	return state, nil
}

func declaredRepository(specification *spec.Spec, name string) *contents.Repository {
	for i := range specification.Contents.Repositories {
		if specification.Contents.Repositories[i].Name == name {
			return &specification.Contents.Repositories[i]
		}
	}
	return nil
}
