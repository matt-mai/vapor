package slices

import (
	"errors"
	"fmt"
	stdslices "slices"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

// BindingProvider supplies the distribution defaults used when a catalogue
// archive has no explicit repository binding.
type BindingProvider interface {
	Distro() string
	Release() string
	Architecture(platform string) (string, error)
	// AllowedSuites lists every suite an image of this release may read, from any
	// endpoint. An empty list defers to the declaration.
	AllowedSuites() []string
	// ReleaseMatching carries the provider's release matching rules.
	ReleaseMatching() deb.ReleaseIdentity
	// Archives lists the archives the provider serves itself, each with the
	// endpoint, suites, components and keys that belong to it.
	Archives() []deb.SignedArchive
	DefaultTrust() []deb.KeySnapshot
	ProTrust(service string) []deb.KeySnapshot
}

// Binding connects one catalogue archive to a repository endpoint and trust
// policy for a single platform. Archive metadata is copied unchanged.
type Binding struct {
	Catalogue       string
	Archive         Archive
	Repository      string
	Platform        string
	Architecture    string
	URL             string
	Trust           []contents.TrustKey
	DefaultTrust    []deb.KeySnapshot
	ProviderDefault bool
	// OwnIdentity marks a repository that authenticates its own release metadata,
	// so the distribution's suite and codename rules do not judge it.
	OwnIdentity bool
	// Packages scopes what the repository may supply. Empty means the archive is
	// part of the image rather than an addition to it.
	Packages []string
}

// BindArchives resolves every catalogue archive that the image can use to an
// endpoint and trust policy. Explicit bindings select a declared repository; an
// unbound archive may use the provider default only when it carries the
// provider's name. An unbound Pro archive is left out only when the provider has
// keys for such a service, because then a subscription archive is optional and a
// user who wants its packages binds it. A provider without those keys cannot serve
// the archive at all, so for it the archive is refused instead of quietly dropped.
func BindArchives(catalogue *Catalogue, source *contents.CatalogueSource, repositories []contents.Repository,
	provider BindingProvider, platform string) ([]Binding, error) {
	if catalogue == nil || source == nil || provider == nil {
		return nil, errors.New("catalogue binding requires a catalogue, source and provider")
	}
	architecture, err := provider.Architecture(platform)
	if err != nil {
		return nil, fmt.Errorf("catalogue binding: %w", err)
	}
	declared, err := indexRepositories(repositories)
	if err != nil {
		return nil, err
	}
	if err := validateBoundArchives(catalogue, source); err != nil {
		return nil, err
	}
	names := archiveNames(catalogue)
	bindings := make([]Binding, 0, len(names))
	for _, name := range names {
		archive := catalogue.Archives[name]
		binding, bound, err := bindArchive(source, &archive, declared, provider, platform, architecture)
		if err != nil {
			return nil, err
		}
		if bound {
			bindings = append(bindings, binding)
		}
	}
	return bindings, nil
}

func bindArchive(source *contents.CatalogueSource, archive *Archive, repositories map[string]contents.Repository,
	provider BindingProvider, platform, architecture string,
) (Binding, bool, error) {
	if archive.Name == ubuntuArchive && provider.Distro() != ubuntuArchive {
		// The catalogue's Ubuntu maintenance defaults are Ubuntu knowledge, so a
		// catalogue naming an Ubuntu archive cannot describe another distribution.
		return Binding{}, false, fmt.Errorf("catalogue archive %q is Ubuntu; provider %q serves a different archive",
			archive.Name, provider.Distro())
	}
	if archive.Version != provider.Release() {
		return Binding{}, false, fmt.Errorf("catalogue archive %q version %q does not match provider release %q",
			archive.Name, archive.Version, provider.Release())
	}
	repositoryName, ok := source.Archives[archive.Name]
	if !ok {
		return bindProviderArchive(source, archive, provider, platform, architecture)
	}
	repository, ok := repositories[repositoryName]
	if !ok {
		return Binding{}, false, fmt.Errorf("catalogue archive %q binds unknown repository %q", archive.Name,
			repositoryName)
	}
	binding, err := bindRepository(source, archive, &repository, provider, platform, architecture)
	return binding, err == nil, err
}

func bindProviderArchive(source *contents.CatalogueSource, archive *Archive, provider BindingProvider,
	platform, architecture string,
) (Binding, bool, error) {
	if archive.Pro != "" {
		// A provider that knows the service treats it as optional. One that does not
		// has no way to serve the archive, and skipping it would leave the image
		// missing a source the catalogue declared as part of it.
		if len(provider.ProTrust(archive.Pro)) == 0 {
			return Binding{}, false, fmt.Errorf(
				"catalogue archive %q requires pro service %q, which provider %q has no keys for",
				archive.Name, archive.Pro, provider.Distro())
		}
		return Binding{}, false, nil
	}
	served := providerArchiveFor(provider, archive.Name)
	if served == nil {
		return Binding{}, false, fmt.Errorf("catalogue archive %q requires an explicit repository binding",
			archive.Name)
	}
	// An archive is bound whole or not at all, so a suite list mixing suites the
	// provider endpoint serves with suites it does not is refused. Debian's security
	// archive therefore needs its own archive entry and repository.
	for _, suite := range archive.Suites {
		if !servesSuite(served.Suites, suite) {
			return Binding{}, false, fmt.Errorf(
				"catalogue archive %q suite %q is not served by the provider archive", archive.Name, suite)
		}
	}
	url, ok := served.Endpoint(platform)
	if !ok {
		return Binding{}, false, fmt.Errorf("catalogue archive %q has no provider endpoint for %s",
			archive.Name, platform)
	}
	binding, err := newBinding(source.Name, archive, archive.Name, platform, architecture, url, nil,
		served.Keys, true)
	return binding, err == nil, err
}

// providerArchiveFor returns the archive the provider serves under this name. An
// archive the provider knows keeps its own keys, so a security archive is never
// verified with the main archive's key.
func providerArchiveFor(provider BindingProvider, name string) *deb.SignedArchive {
	archives := provider.Archives()
	for i := range archives {
		if archives[i].Name == name {
			return &archives[i]
		}
	}
	return nil
}

// providerDefaultTrust is the trust an explicitly bound repository gets when it names
// no keys. A repository named after a provider archive gets that archive's keys; any
// other name gets every reviewed key, which is what a mirror of the whole release
// needs.
func providerDefaultTrust(provider BindingProvider, name string) []deb.KeySnapshot {
	if served := providerArchiveFor(provider, name); served != nil {
		return served.Keys
	}
	return provider.DefaultTrust()
}

// servesSuite reports whether the provider endpoint serves the suite. A provider with
// no implicit suite list leaves the suites to the catalogue.
func servesSuite(suites []string, suite string) bool {
	return len(suites) == 0 || stdslices.Contains(suites, suite)
}

func bindRepository(source *contents.CatalogueSource, archive *Archive, repository *contents.Repository,
	provider BindingProvider, platform, architecture string) (Binding, error) {
	if !stdslices.Contains(repository.Platforms, platform) {
		return Binding{}, fmt.Errorf("repository %q does not cover platform %q", repository.Name, platform)
	}
	url, urlErr := repositoryURL(repository, platform)
	if urlErr != nil {
		return Binding{}, urlErr
	}
	if err := compatibleArchive(archive, repository); err != nil {
		return Binding{}, err
	}
	// An explicit binding chooses its own endpoint and keys, but not which suites
	// belong to this release: a correctly signed archive of another release must
	// not become reachable by declaring it. A repository answering to its own
	// identity instead of the release's is exempt, because its suites describe it.
	if repository.Identity == nil {
		for _, suite := range archive.Suites {
			if !servesSuite(provider.AllowedSuites(), suite) {
				return Binding{}, fmt.Errorf("repository %q suite %q is not served by release %q",
					repository.Name, suite, provider.Release())
			}
		}
	}
	if archive.Pro != "" && len(provider.ProTrust(archive.Pro)) == 0 {
		// A subscription archive the provider cannot vouch for is refused before
		// trust is chosen, so explicit keys cannot make it look supported.
		return Binding{}, fmt.Errorf("catalogue archive %q requires pro service %q, which provider %q has no keys for",
			archive.Name, archive.Pro, provider.Distro())
	}
	binding, err := trustBinding(source.Name, archive, repository, provider, platform, architecture, url)
	if err != nil {
		return Binding{}, err
	}
	binding.OwnIdentity = repository.Identity != nil
	binding.Packages = append([]string(nil), repository.Packages...)
	return binding, nil
}

func trustBinding(catalogue string, archive *Archive, repository *contents.Repository, provider BindingProvider,
	platform, architecture, url string,
) (Binding, error) {
	if len(repository.Trust.Keys) == 0 {
		trust := providerDefaultTrust(provider, repository.Name)
		if archive.Pro != "" {
			trust = provider.ProTrust(archive.Pro)
		}
		return newBinding(catalogue, archive, repository.Name, platform, architecture, url, nil, trust, false)
	}
	return newBinding(catalogue, archive, repository.Name, platform, architecture, url, repository.Trust.Keys,
		nil, false)
}

func newBinding(catalogue string, archive *Archive, repository, platform, architecture, url string,
	trust []contents.TrustKey, fallback []deb.KeySnapshot, providerDefault bool) (Binding, error) {
	if len(trust) == 0 && len(fallback) == 0 {
		return Binding{}, fmt.Errorf("catalogue archive %q has no trust policy", archive.Name)
	}
	return Binding{
		Catalogue:       catalogue,
		Archive:         *archive,
		Repository:      repository,
		Platform:        platform,
		Architecture:    architecture,
		URL:             url,
		Trust:           append([]contents.TrustKey(nil), trust...),
		DefaultTrust:    cloneSnapshots(fallback),
		ProviderDefault: providerDefault,
	}, nil
}

func validateBoundArchives(catalogue *Catalogue, source *contents.CatalogueSource) error {
	names := make([]string, 0, len(source.Archives))
	for name := range source.Archives {
		names = append(names, name)
	}
	stdslices.Sort(names)
	for _, name := range names {
		if _, ok := catalogue.Archives[name]; !ok {
			return fmt.Errorf("catalogue binds unknown archive %q", name)
		}
	}
	return nil
}

func archiveNames(catalogue *Catalogue) []string {
	names := make([]string, 0, len(catalogue.Archives))
	for name := range catalogue.Archives {
		names = append(names, name)
	}
	stdslices.Sort(names)
	return names
}

func indexRepositories(repositories []contents.Repository) (map[string]contents.Repository, error) {
	index := make(map[string]contents.Repository, len(repositories))
	for i := range repositories {
		repository := &repositories[i]
		if _, ok := index[repository.Name]; ok {
			return nil, fmt.Errorf("duplicate repository %q", repository.Name)
		}
		index[repository.Name] = *repository
	}
	return index, nil
}

func repositoryURL(repository *contents.Repository, platform string) (string, error) {
	for i := range repository.Endpoints {
		endpoint := &repository.Endpoints[i]
		if stdslices.Contains(endpoint.Platforms, platform) {
			return endpoint.URL, nil
		}
	}
	return "", fmt.Errorf("repository %q has no endpoint for platform %q", repository.Name, platform)
}

func compatibleArchive(archive *Archive, repository *contents.Repository) error {
	if !stdslices.Equal(archive.Suites, repository.Suites) {
		return fmt.Errorf("repository %q suites do not match catalogue archive %q", repository.Name, archive.Name)
	}
	if !stdslices.Equal(archive.Components, repository.Components) {
		return fmt.Errorf("repository %q components do not match catalogue archive %q", repository.Name,
			archive.Name)
	}
	return nil
}

func cloneSnapshots(snapshots []deb.KeySnapshot) []deb.KeySnapshot {
	cloned := make([]deb.KeySnapshot, len(snapshots))
	for i := range snapshots {
		snapshot := &snapshots[i]
		cloned[i] = deb.KeySnapshot{
			Fingerprints: append([]string(nil), snapshot.Fingerprints...),
			Data:         append([]byte(nil), snapshot.Data...),
		}
	}
	return cloned
}
