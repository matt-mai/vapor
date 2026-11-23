package slices_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/debian"
	"github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

func TestBindArchivesDefaultUbuntuMapping(t *testing.T) {
	t.Parallel()
	catalogue := &slices.Catalogue{Archives: map[string]slices.Archive{
		"ubuntu": {
			Name:       "ubuntu",
			Version:    "26.04",
			Suites:     []string{"resolute", "resolute-security", "resolute-updates"},
			Components: []string{"main", "universe"},
			Priority:   10,
		},
	}}
	source := &contents.CatalogueSource{Name: "upstream"}
	bindings, err := slices.BindArchives(catalogue, source, nil, ubuntu.New("26.04"), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
	binding := bindings[0]
	if binding.Catalogue != "upstream" || binding.Repository != "ubuntu" || !binding.ProviderDefault ||
		binding.Platform != deb.PlatformAMD64 || binding.Architecture != "amd64" ||
		binding.URL != "https://archive.ubuntu.com/ubuntu" {
		t.Fatalf("unexpected binding: %#v", binding)
	}
	if len(binding.Trust) != 0 || len(binding.DefaultTrust) != 1 ||
		binding.DefaultTrust[0].Fingerprints[0] != "F6ECB3762474EDA9D21B7022871920D1991BC93C" {
		t.Fatalf("unexpected trust: %#v", binding)
	}
	if len(binding.Archive.Suites) != 3 || binding.Archive.Suites[1] != "resolute-security" ||
		binding.Archive.Priority != 10 {
		t.Fatalf("archive metadata changed: %#v", binding.Archive)
	}
}

func TestBindArchivesExplicitBinding(t *testing.T) {
	t.Parallel()
	catalogue := catalogueFixture()
	source := &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu": "mirror"}}
	repositories := []contents.Repository{{
		Name:       "mirror",
		Platforms:  []string{deb.PlatformAMD64, deb.PlatformARM64},
		Endpoints:  []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://mirror.example/amd64"}, {Platforms: []string{deb.PlatformARM64}, URL: "https://mirror.example/arm64"}},
		Suites:     []string{"resolute", "resolute-security", "resolute-updates"},
		Components: []string{"main", "universe"},
		Trust: contents.Trust{Keys: []contents.TrustKey{{
			Path:         "keys/mirror.asc",
			Fingerprints: []string{strings.Repeat("A", 40)},
		}}},
	}}
	bindings, err := slices.BindArchives(catalogue, source, repositories, ubuntu.New("26.04"), deb.PlatformARM64)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindings[0]
	if binding.Repository != "mirror" || binding.ProviderDefault ||
		binding.URL != "https://mirror.example/arm64" || binding.Architecture != "arm64" {
		t.Fatalf("unexpected binding: %#v", binding)
	}
	if len(binding.Trust) != 1 || binding.Trust[0].Path != "keys/mirror.asc" || len(binding.DefaultTrust) != 0 {
		t.Fatalf("unexpected trust: %#v", binding.Trust)
	}
}

func TestBindArchivesExplicitBindingDefaultsTrust(t *testing.T) {
	t.Parallel()
	catalogue := catalogueFixture()
	source := &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu": "mirror"}}
	repositories := []contents.Repository{{
		Name:       "mirror",
		Platforms:  []string{deb.PlatformAMD64},
		Endpoints:  []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://mirror.example"}},
		Suites:     []string{"resolute", "resolute-security", "resolute-updates"},
		Components: []string{"main", "universe"},
	}}
	bindings, err := slices.BindArchives(catalogue, source, repositories, ubuntu.New("26.04"), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings[0].Trust) != 0 || len(bindings[0].DefaultTrust) != 1 {
		t.Fatalf("default trust not applied: %#v", bindings[0])
	}
}

func TestBindArchivesProDefaultsTrust(t *testing.T) {
	t.Parallel()
	catalogue := proCatalogueFixture()
	source := &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu-esm-apps": "mirror"}}
	repositories := []contents.Repository{withoutTrust(contents.Repository{
		Name: "mirror", Platforms: []string{deb.PlatformAMD64},
		Endpoints: []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://mirror.example"}},
		Suites:    []string{"resolute-apps-security"}, Components: []string{"main"},
	})}
	bindings, err := slices.BindArchives(catalogue, source, repositories, ubuntu.New("26.04"), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	var binding *slices.Binding
	for i := range bindings {
		if bindings[i].Archive.Name == "ubuntu-esm-apps" {
			binding = &bindings[i]
		}
	}
	if binding == nil {
		t.Fatalf("Pro archive was not bound: %#v", bindings)
	}
	if len(binding.Trust) != 0 || len(binding.DefaultTrust) != 1 ||
		binding.DefaultTrust[0].Fingerprints[0] != "E8A443CE358113D187BEE0E6AB01A101DB53907B" {
		t.Fatalf("unexpected trust: %#v", binding)
	}
}

// baseRepository is the mirror Ubuntu's tests bind explicitly.
func baseRepository() contents.Repository {
	return contents.Repository{
		Name:       "mirror",
		Platforms:  []string{deb.PlatformAMD64},
		Endpoints:  []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://mirror.example"}},
		Suites:     []string{"resolute", "resolute-security", "resolute-updates"},
		Components: []string{"main", "universe"},
		Trust: contents.Trust{Keys: []contents.TrustKey{{
			Path: "keys/mirror.asc", Fingerprints: []string{strings.Repeat("A", 40)},
		}}},
	}
}

func TestBindArchivesRejections(t *testing.T) {
	t.Parallel()
	baseRepository := baseRepository()
	tests := []struct {
		name      string
		catalogue *slices.Catalogue
		source    *contents.CatalogueSource
		repos     []contents.Repository
		platform  string
		provider  slices.BindingProvider
		wantErr   string
	}{
		{
			name:      "missing repository",
			catalogue: catalogueFixture(),
			source:    &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu": "missing"}},
			platform:  deb.PlatformAMD64, provider: ubuntu.New("26.04"), wantErr: "binds unknown repository",
		},
		{
			name:      "unknown archive",
			catalogue: catalogueFixture(),
			source:    &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"other": "mirror"}},
			repos:     []contents.Repository{baseRepository},
			platform:  deb.PlatformAMD64, provider: ubuntu.New("26.04"), wantErr: "unknown archive",
		},
		{
			name: "release mismatch",
			catalogue: &slices.Catalogue{Archives: map[string]slices.Archive{
				"ubuntu": {Name: "ubuntu", Version: "24.04", Suites: []string{"resolute"}, Components: []string{"main"}},
			}},
			source:   &contents.CatalogueSource{Name: "upstream"},
			platform: deb.PlatformAMD64, provider: ubuntu.New("26.04"), wantErr: "does not match provider release",
		},
		{
			name:      "unbound custom archive",
			catalogue: &slices.Catalogue{Archives: map[string]slices.Archive{"third-party": {Name: "third-party", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}}}},
			source:    &contents.CatalogueSource{Name: "upstream"},
			platform:  deb.PlatformAMD64, provider: ubuntu.New("26.04"), wantErr: "requires an explicit repository binding",
		},

		{
			name:      "suite mismatch",
			catalogue: catalogueFixture(),
			source:    &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu": "mirror"}},
			repos:     []contents.Repository{withSuites(baseRepository, []string{"resolute"})},
			platform:  deb.PlatformAMD64, provider: ubuntu.New("26.04"), wantErr: "suites do not match",
		},
		{
			name:      "component mismatch",
			catalogue: catalogueFixture(),
			source:    &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu": "mirror"}},
			repos:     []contents.Repository{withComponents(baseRepository, []string{"main"})},
			platform:  deb.PlatformAMD64, provider: ubuntu.New("26.04"), wantErr: "components do not match",
		},
		{
			name:      "unsupported platform",
			catalogue: catalogueFixture(),
			source:    &contents.CatalogueSource{Name: "upstream"},
			platform:  "linux/386", provider: ubuntu.New("26.04"), wantErr: "unsupported platform",
		},
		{
			name:      "platform outside scope",
			catalogue: catalogueFixture(),
			source:    &contents.CatalogueSource{Name: "custom", Archives: map[string]string{"ubuntu": "mirror"}},
			repos:     []contents.Repository{baseRepository},
			platform:  deb.PlatformARM64, provider: ubuntu.New("26.04"), wantErr: "does not cover platform",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := slices.BindArchives(tt.catalogue, tt.source, tt.repos, tt.provider, tt.platform)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestBindArchivesSkipsUnboundProArchives(t *testing.T) {
	t.Parallel()
	catalogue := &slices.Catalogue{Archives: map[string]slices.Archive{
		"ubuntu":          {Name: "ubuntu", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}, Priority: 10},
		"ubuntu-esm-apps": {Name: "ubuntu-esm-apps", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}, Pro: "esm-apps", Priority: 16},
	}}
	bindings, err := slices.BindArchives(catalogue, &contents.CatalogueSource{Name: "upstream"}, nil,
		ubuntu.New("26.04"), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Archive.Name != "ubuntu" {
		t.Fatalf("bindings = %#v, want only the public archive", bindings)
	}
}

func TestBindArchivesDeterministicOrder(t *testing.T) {
	t.Parallel()
	catalogue := &slices.Catalogue{Archives: map[string]slices.Archive{
		"zeta":   {Name: "zeta", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}, Priority: 2},
		"ubuntu": {Name: "ubuntu", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}, Priority: 1},
	}}
	repository := contents.Repository{
		Name:       "zeta-mirror",
		Platforms:  []string{deb.PlatformAMD64},
		Endpoints:  []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://zeta.example"}},
		Suites:     []string{"resolute"},
		Components: []string{"main"},
		Trust:      contents.Trust{Keys: []contents.TrustKey{{Path: "keys/zeta.asc", Fingerprints: []string{strings.Repeat("A", 40)}}}},
	}
	bindings, err := slices.BindArchives(catalogue, &contents.CatalogueSource{
		Name:     "upstream",
		Archives: map[string]string{"zeta": "zeta-mirror"},
	}, []contents.Repository{repository}, stubProvider{name: "ubuntu", endpoints: map[string]string{"ubuntu": "https://ubuntu"}},
		deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if bindings[0].Archive.Name != "ubuntu" || bindings[1].Archive.Name != "zeta" {
		t.Fatalf("binding order = %q, %q", bindings[0].Archive.Name, bindings[1].Archive.Name)
	}
}

func catalogueFixture() *slices.Catalogue {
	return &slices.Catalogue{Archives: map[string]slices.Archive{
		"ubuntu": {
			Name:       "ubuntu",
			Version:    "26.04",
			Suites:     []string{"resolute", "resolute-security", "resolute-updates"},
			Components: []string{"main", "universe"},
			Priority:   10,
		},
	}}
}

// Ubuntu has keys for its subscription archives, so an unbound Pro archive stays
// optional: it is skipped, and a user who wants its packages binds it.
func TestBindArchivesLeavesUnboundProOptional(t *testing.T) {
	t.Parallel()
	bindings, err := slices.BindArchives(proCatalogueFixture(), &contents.CatalogueSource{Name: "custom"},
		nil, ubuntu.New("26.04"), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range bindings {
		if binding.Archive.Pro != "" {
			t.Fatalf("unbound Pro archive was bound: %#v", binding)
		}
	}
}

// A Debian catalogue that declares a subscription archive describes a source the
// image cannot get from the default endpoint. Debian has no such service, so skipping
// it would leave the image quietly missing an archive the catalogue says it needs.
func TestBindArchivesRejectsUnboundProWithoutProviderKeys(t *testing.T) {
	t.Parallel()
	catalogue := debianCatalogue()
	main := catalogue.Archives["debian"]
	main.Pro = "esm-apps"
	catalogue.Archives["debian"] = main
	_, err := slices.BindArchives(catalogue, &contents.CatalogueSource{Name: "debian"}, nil,
		debianProvider(t), deb.PlatformAMD64)
	if err == nil || !strings.Contains(err.Error(), `requires pro service "esm-apps", which provider "debian"`) {
		t.Fatalf("err = %v", err)
	}
}

func proCatalogueFixture() *slices.Catalogue {
	catalogue := catalogueFixture()
	catalogue.Archives["ubuntu-esm-apps"] = slices.Archive{
		Name: "ubuntu-esm-apps", Version: "26.04", Suites: []string{"resolute-apps-security"},
		Components: []string{"main"}, Pro: "esm-apps",
	}
	return catalogue
}

func withSuites(repository contents.Repository, suites []string) contents.Repository {
	repository.Suites = suites
	return repository
}

func withComponents(repository contents.Repository, components []string) contents.Repository {
	repository.Components = components
	return repository
}

func withoutTrust(repository contents.Repository) contents.Repository {
	repository.Trust = contents.Trust{}
	return repository
}

type stubProvider struct {
	name      string
	endpoints map[string]string
	suites    []string
	implied   []string
}

func (p stubProvider) ImplicitSuites() []string { return p.suites }

// Archives keeps the stub's single archive aligned with its endpoint,
// suites and default key, so existing fixtures bind the same way.
func (p stubProvider) Archives() []deb.SignedArchive {
	return []deb.SignedArchive{{
		Name:      p.name,
		Endpoints: map[string]string{"linux/amd64": p.endpoints[p.name], "linux/arm64": p.endpoints[p.name]},
		Suites:    p.suites, Components: []string{"main"},
		Keys: []deb.KeySnapshot{{Fingerprints: []string{strings.Repeat("B", 40)}, Data: []byte("key")}},
	}}
}

func (p stubProvider) AllowedSuites() []string { return p.implied }

func (p stubProvider) Distro() string                      { return p.name }
func (p stubProvider) Release() string                     { return "26.04" }
func (p stubProvider) Architecture(string) (string, error) { return "amd64", nil }
func (p stubProvider) ReleaseMatching() deb.ReleaseIdentity {
	return deb.ReleaseIdentity{}
}
func (p stubProvider) DefaultTrust() []deb.KeySnapshot {
	return []deb.KeySnapshot{{Fingerprints: []string{strings.Repeat("B", 40)}, Data: []byte("key")}}
}
func (p stubProvider) ProTrust(string) []deb.KeySnapshot {
	return []deb.KeySnapshot{{Fingerprints: []string{strings.Repeat("C", 40)}, Data: []byte("pro")}}
}

// plainProvider is a provider that vouches for no Pro service, so a catalogue naming
// one cannot be bound without the provider's keys.
type plainProvider struct{ stubProvider }

func (p plainProvider) ProTrust(string) []deb.KeySnapshot { return nil }

func debianProvider(t *testing.T) *debian.Provider {
	t.Helper()
	provider, err := debian.New("trixie")
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func debianCatalogue() *slices.Catalogue {
	return &slices.Catalogue{Archives: map[string]slices.Archive{
		"debian": {
			Name: "debian", Version: "trixie",
			Suites:     []string{"trixie", "trixie-updates"},
			Components: []string{"main"}, Priority: 10,
		},
	}}
}

func debianRepository(trusted bool) contents.Repository {
	repository := contents.Repository{
		Name:       "debian-security",
		Platforms:  []string{deb.PlatformAMD64, deb.PlatformARM64},
		Endpoints:  []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64, deb.PlatformARM64}, URL: "https://security.debian.org/debian-security"}},
		Suites:     []string{"trixie-security"},
		Components: []string{"main"},
	}
	if trusted {
		repository.Trust = contents.Trust{Keys: []contents.TrustKey{{
			Path: "keys/security.asc", Fingerprints: []string{strings.Repeat("D", 40)},
		}}}
	}
	return repository
}

// Debian's security archive lives on another host, so it is its own catalogue archive
// with its own repository. The main archive keeps its implicit provider binding, and
// that binding is unaffected by the security archive's declared repository.
func TestBindArchivesDebianKeepsMainImplicit(t *testing.T) {
	t.Parallel()
	catalogue := debianCatalogue()
	catalogue.Archives["debian-security"] = slices.Archive{
		Name: "debian-security", Version: "trixie",
		Suites: []string{"trixie-security"}, Components: []string{"main"}, Priority: 10,
	}
	source := &contents.CatalogueSource{Name: "debian", Archives: map[string]string{
		"debian-security": "debian-security",
	}}
	bindings, err := slices.BindArchives(catalogue, source,
		[]contents.Repository{debianRepository(true)}, debianProvider(t), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("bindings = %#v", bindings)
	}
	main, security := bindings[0], bindings[1]
	if main.Archive.Name != "debian" || !main.ProviderDefault || main.URL != "https://deb.debian.org/debian" {
		t.Fatalf("main binding = %#v", main)
	}
	if len(main.Archive.Suites) != 2 || main.Archive.Suites[0] != "trixie" ||
		main.Archive.Suites[1] != "trixie-updates" {
		t.Fatalf("main suites = %v", main.Archive.Suites)
	}
	if security.Archive.Name != "debian-security" || security.ProviderDefault ||
		security.URL != "https://security.debian.org/debian-security" {
		t.Fatalf("security binding = %#v", security)
	}
}

// A Debian archive that lists a suite the main endpoint does not serve cannot be bound
// implicitly: another host signs it.
func TestBindArchivesDebianRejectsForeignSuite(t *testing.T) {
	t.Parallel()
	catalogue := debianCatalogue()
	main := catalogue.Archives["debian"]
	main.Suites = []string{"trixie", "trixie-security"}
	catalogue.Archives["debian"] = main
	_, err := slices.BindArchives(catalogue, &contents.CatalogueSource{Name: "debian"},
		nil, debianProvider(t), deb.PlatformAMD64)
	if err == nil || !strings.Contains(err.Error(), "is not served by the provider archive") {
		t.Fatalf("err = %v", err)
	}
}

// An explicit repository chooses its own endpoint and keys, but not which suites the
// release may read: a bookworm archive stays unreachable from a trixie image no matter
// how it is declared.
func TestBindArchivesDebianRejectsForeignSuiteInExplicitBinding(t *testing.T) {
	t.Parallel()
	catalogue := debianCatalogue()
	catalogue.Archives["debian-old"] = slices.Archive{
		Name: "debian-old", Version: "trixie",
		Suites: []string{"bookworm"}, Components: []string{"main"}, Priority: 10,
	}
	repository := debianRepository(true)
	repository.Name = "debian-old"
	repository.Endpoints = []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://old.example"}}
	repository.Suites = []string{"bookworm"}
	source := &contents.CatalogueSource{Name: "debian", Archives: map[string]string{
		"debian-old": "debian-old",
	}}
	_, err := slices.BindArchives(catalogue, source, []contents.Repository{repository},
		debianProvider(t), deb.PlatformAMD64)
	if err == nil || !strings.Contains(err.Error(), `suite "bookworm" is not served by release "trixie"`) {
		t.Fatalf("err = %v", err)
	}
}

// The security suite is a suite of the release, so an explicit repository may carry it
// even though the provider endpoint does not serve it.
func TestBindArchivesDebianAllowsSecuritySuiteInExplicitBinding(t *testing.T) {
	t.Parallel()
	catalogue := debianCatalogue()
	catalogue.Archives["debian-security"] = slices.Archive{
		Name: "debian-security", Version: "trixie",
		Suites: []string{"trixie-security"}, Components: []string{"main"}, Priority: 10,
	}
	source := &contents.CatalogueSource{Name: "debian", Archives: map[string]string{
		"debian-security": "debian-security",
	}}
	bindings, err := slices.BindArchives(catalogue, source,
		[]contents.Repository{debianRepository(true)}, debianProvider(t), deb.PlatformAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("bindings = %#v", bindings)
	}
}

// A catalogue naming an Ubuntu archive describes Ubuntu, so a Debian provider refuses
// it instead of applying Ubuntu's default lifecycle dates to a Debian image.
func TestBindArchivesRejectsUbuntuArchiveForOtherProvider(t *testing.T) {
	t.Parallel()
	_, err := slices.BindArchives(catalogueFixture(), &contents.CatalogueSource{Name: "custom"},
		nil, debianProvider(t), deb.PlatformAMD64)
	if err == nil || !strings.Contains(err.Error(), "is Ubuntu") {
		t.Fatalf("err = %v", err)
	}
}

// A Pro archive the provider has no keys for is refused even when the repository
// carries explicit keys, because the provider cannot say whether the service exists.
func TestBindArchivesRejectsProWithoutProviderKeys(t *testing.T) {
	t.Parallel()
	catalogue := proCatalogueFixture()
	source := &contents.CatalogueSource{Name: "upstream", Archives: map[string]string{
		"ubuntu": "mirror", "ubuntu-esm-apps": "esm",
	}}
	mirror := withSuites(baseRepository(), []string{"resolute", "resolute-security", "resolute-updates"})
	esm := contents.Repository{
		Name: "esm", Platforms: []string{deb.PlatformAMD64},
		Endpoints: []contents.Endpoint{{Platforms: []string{deb.PlatformAMD64}, URL: "https://esm.example"}},
		Suites:    []string{"resolute-apps-security"}, Components: []string{"main"},
		Trust: contents.Trust{Keys: []contents.TrustKey{{
			Path: "keys/esm.asc", Fingerprints: []string{strings.Repeat("E", 40)},
		}}},
	}
	_, err := slices.BindArchives(catalogue, source, []contents.Repository{mirror, esm},
		plainProvider{name: "ubuntu", endpoints: map[string]string{"ubuntu": "https://ubuntu"}},
		deb.PlatformAMD64)
	if err == nil || !strings.Contains(err.Error(), "which provider") {
		t.Fatalf("err = %v", err)
	}
}

// A Pro archive on another archive name cannot borrow the provider's endpoint at all;
// whichever way it is unreachable, the refusal happens before a binding is chosen.
func TestBindArchivesRejectsUnboundProOutsideTheProviderArchive(t *testing.T) {
	t.Parallel()
	catalogue := debianCatalogue()
	catalogue.Archives["debian-security"] = slices.Archive{
		Name: "debian-security", Version: "trixie", Suites: []string{"trixie-security"},
		Components: []string{"main"}, Pro: "esm-infra",
	}
	_, err := slices.BindArchives(catalogue, &contents.CatalogueSource{Name: "debian"}, nil,
		debianProvider(t), deb.PlatformAMD64)
	if err == nil || !strings.Contains(err.Error(), `requires pro service "esm-infra"`) {
		t.Fatalf("err = %v", err)
	}
}
