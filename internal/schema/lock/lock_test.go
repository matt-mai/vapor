package lock

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

func TestVerifyLockfile_ValidMinimal(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, minimalSpec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	lock := &Lockfile{
		Version:    1,
		SpecDigest: digest,
		Provider:   Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:  []string{"linux/amd64"},
	}
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err != nil {
		t.Fatalf("valid minimal lock rejected: %v", err)
	}
}

func TestVerifyLockfile_ValidMultiPlatform(t *testing.T) {
	t.Parallel()
	spec, lock := validMultiPlatformLock(t)
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err != nil {
		t.Fatalf("valid multi-platform lock rejected: %v", err)
	}
}

func TestVerifyLockfile_TransitiveSlice(t *testing.T) {
	t.Parallel()
	spec, lock := validMultiPlatformLock(t)
	lock.Slices = append(lock.Slices, Slice{
		Platform:         "linux/amd64",
		Package:          "libc6",
		Version:          "2.39-0ubuntu8",
		Architecture:     "amd64",
		Catalogue:        "custom",
		Archive:          "ubuntu",
		Repository:       lock.Repositories[0].ID,
		Content:          Content{Path: "pool/main/g/glibc/libc6_2.39_amd64.deb", SHA256: strings.Repeat("5", 64), Size: 2048},
		Closure:          []string{"lib"},
		DefinitionDigest: "sha256:" + strings.Repeat("6", 64),
	})
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err != nil {
		t.Fatalf("transitive slice rejected: %v", err)
	}
}

func TestVerifyLockfile_UnrequestedSlice(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, minimalSpec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	lock := &Lockfile{
		Version:    1,
		SpecDigest: digest,
		Provider:   Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:  []string{"linux/amd64"},
		Slices:     []Slice{{Platform: "linux/amd64", Package: "base-files"}},
	}
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err == nil {
		t.Fatal("unrequested slice accepted")
	}
}

func TestVerifyLockfile_Nil(t *testing.T) {
	t.Parallel()
	if err := VerifyLockfileForProvider(nil, &Lockfile{}, "26.04", nil); err == nil {
		t.Fatal("nil spec accepted")
	}
	spec, err := loadText(t, minimalSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLockfileForProvider(spec, nil, spec.Release, nil); err == nil {
		t.Fatal("nil lock accepted")
	}
}

func TestLockRepositoryID_Vector(t *testing.T) {
	t.Parallel()
	got := RepositoryID("mirror", "linux/amd64", "amd64", "https://archive.example.com/ubuntu", "resolute")
	want := "sha256:7a61186f27a8e2b419587158089216c97ff0b4c233b46f93d11f5fabba4e1f34"
	if got != want {
		t.Fatalf("repository ID = %s, want %s", got, want)
	}
}

func TestVerifyLockfile_Rejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Lockfile)
	}{
		{"version", func(lock *Lockfile) { lock.Version = 2 }},
		{"spec digest", func(lock *Lockfile) { lock.SpecDigest = strings.Repeat("0", 64) }},
		{"provider", func(lock *Lockfile) { lock.Provider.Release = "24.04" }},
		{"platform order", func(lock *Lockfile) { lock.Platforms[0], lock.Platforms[1] = lock.Platforms[1], lock.Platforms[0] }},
		{"missing local input", func(lock *Lockfile) { lock.LocalInputs = nil }},
		{"extra local input", func(lock *Lockfile) {
			lock.LocalInputs = append(lock.LocalInputs, LocalInput{Role: "ca", Path: "ca.pem", SHA256: strings.Repeat("9", 64), Size: 1})
		}},
		{"local input role", func(lock *Lockfile) { lock.LocalInputs[0].Role = "ca" }},
		{"local input path", func(lock *Lockfile) { lock.LocalInputs[0].Path = "keys/other.asc" }},
		{"missing catalogue", func(lock *Lockfile) { lock.Catalogues = nil }},
		{"unknown catalogue", func(lock *Lockfile) { lock.Catalogues[0].Name = "other" }},
		{"catalogue selector", func(lock *Lockfile) { lock.Catalogues[0].Source.Selector.Branch = new("other") }},
		{"catalogue commit", func(lock *Lockfile) { lock.Catalogues[0].Source.Commit = "abc123" }},
		{"catalogue archive", func(lock *Lockfile) { lock.Catalogues[0].Archive = nil }},
		{"catalogue source type", func(lock *Lockfile) { lock.Catalogues[0].Source.Type = "local" }},
		{"missing repository", func(lock *Lockfile) { lock.Repositories = nil }},
		{"repository ID", func(lock *Lockfile) { lock.Repositories[0].ID = "sha256:" + strings.Repeat("9", 64) }},
		{"repository architecture", func(lock *Lockfile) { lock.Repositories[0].Architecture = "arm64" }},
		{"repository URL", func(lock *Lockfile) { lock.Repositories[0].URL = "https://other.example.com/ubuntu" }},
		{"repository suite", func(lock *Lockfile) { lock.Repositories[0].Suite = "other" }},
		{"requirement trust", func(lock *Lockfile) { lock.Repositories[0].Trust.Keys = nil }},
		{"trust key path", func(lock *Lockfile) { lock.Repositories[0].Trust.Keys[0].Path = "keys/other.asc" }},
		{"trust key bytes", func(lock *Lockfile) { lock.Repositories[0].Trust.Keys[0].SHA256 = strings.Repeat("9", 64) }},
		{"release signer", func(lock *Lockfile) {
			lock.Repositories[0].Release.Signers = append(lock.Repositories[0].Release.Signers, strings.Repeat("B", 40))
		}},
		{"release format", func(lock *Lockfile) { lock.Repositories[0].Release.Format = "release-gpg" }},
		{"release signature", func(lock *Lockfile) {
			lock.Repositories[0].Release.Signature = &Content{Path: "dists/resolute/InRelease.gpg", SHA256: strings.Repeat("9", 64), Size: 1}
		}},
		{"release valid until", func(lock *Lockfile) { lock.Repositories[0].Release.ValidUntil = new(" ") }},
		{"empty indexes", func(lock *Lockfile) { lock.Repositories[0].Indexes = nil }},
		{"index component", func(lock *Lockfile) { lock.Repositories[0].Indexes[0].Component = "extra" }},
		{"index hash", func(lock *Lockfile) { lock.Repositories[0].Indexes[0].SHA256 = "bad" }},
		{"unreferenced repository", func(lock *Lockfile) {
			extra := lock.Repositories[0]
			extra.Suite = "resolute-updates"
			extra.ID = RepositoryID(extra.Name, extra.Platform, extra.Architecture, extra.URL, extra.Suite)
			lock.Repositories = append(lock.Repositories, extra)
		}},
		{"missing platform package", func(lock *Lockfile) { lock.Packages = lock.Packages[:1] }},
		{"package pin", func(lock *Lockfile) { lock.Packages[0].Version = "9.9" }},
		{"package pin outside the range", func(lock *Lockfile) { lock.Packages[0].Version = "4.0-1" }},
		{"package architecture", func(lock *Lockfile) { lock.Packages[0].Architecture = "arm64" }},
		{"package repository", func(lock *Lockfile) { lock.Packages[0].Repository = "sha256:" + strings.Repeat("9", 64) }},
		{"duplicate package", func(lock *Lockfile) { lock.Packages = append(lock.Packages, lock.Packages[0]) }},
		{"whole and sliced package", func(lock *Lockfile) { lock.Packages[0].Name = "base-files" }},
		{"missing platform slice", func(lock *Lockfile) { lock.Slices = lock.Slices[:1] }},
		{"slice selected", func(lock *Lockfile) { lock.Slices[0].Selected = append(lock.Slices[0].Selected, "extra") }},
		{"slice closure", func(lock *Lockfile) { lock.Slices[0].Closure = []string{"copyright", "etc", "lib"} }},
		{"slice catalogue", func(lock *Lockfile) { lock.Slices[0].Catalogue = "missing" }},
		{"slice definition digest", func(lock *Lockfile) { lock.Slices[0].DefinitionDigest = "sha256:short" }},
		{"slice archive", func(lock *Lockfile) { lock.Slices[0].Archive = "" }},
		{"slice archive binding", func(lock *Lockfile) { lock.Slices[0].Archive = "other" }},
		{"duplicate slice", func(lock *Lockfile) { lock.Slices = append(lock.Slices, lock.Slices[0]) }},
		{"missing artifact", func(lock *Lockfile) { lock.Artifacts = nil }},
		{"artifact hash", func(lock *Lockfile) { lock.Artifacts[0].SHA256 = strings.Repeat("9", 64) }},
		{"artifact URL", func(lock *Lockfile) { lock.Artifacts[0].URL = "https://example.com/other" }},
		{"artifact path", func(lock *Lockfile) { lock.Artifacts[0].Path = "files/server" }},
		{"artifact size", func(lock *Lockfile) { lock.Artifacts[0].Size = -1 }},
		{"artifact dest", func(lock *Lockfile) { lock.Artifacts[0].Dest = "/usr/bin/other" }},
		{"artifact unpack", func(lock *Lockfile) { lock.Artifacts[0].Unpack = new(contents.ArtifactUnpackArchive) }},
		{"artifact mode", func(lock *Lockfile) { lock.Artifacts[0].Mode = nil }},
		{"artifact sbom", func(lock *Lockfile) { lock.Artifacts[0].SBOM.Name = "other" }},
		{"artifact uid", func(lock *Lockfile) { lock.Artifacts[0].UID = -1 }},
		{"duplicate artifact platform", func(lock *Lockfile) { lock.Artifacts[1].Platform = "linux/amd64" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec, lock := validMultiPlatformLock(t)
			tt.mutate(lock)
			if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err == nil {
				t.Fatal("invalid lock accepted")
			}
		})
	}
}

// A slice must name the repository its archive was bound to, in that archive's suites
// and components. Authenticating the package against the index proves where it came
// from, not that the catalogue allowed it there, so the record is compared with the
// binding rebuilt from the verified catalogue.
func TestCheckEffectiveBinding(t *testing.T) {
	t.Parallel()
	slice := &Slice{Platform: "linux/amd64", Catalogue: "debian", Archive: "debian-security"}
	repository := &Repository{
		Name: "security", Platform: "linux/amd64", Architecture: "amd64", Suite: "trixie-security",
		Indexes: []Index{{Component: "main"}},
	}
	provider := &DefaultRepository{Covered: map[string]bool{"debian": true}, Bindings: map[string]ArchiveBinding{
		BindingKey("debian", "debian-security", "linux/amd64"): {
			Repository: "security", Suites: []string{"trixie-security"}, Components: []string{"main"},
		},
	}}
	if err := checkEffectiveBinding(slice, repository, provider, 0); err != nil {
		t.Fatalf("matching binding refused: %v", err)
	}
	// Debian's security metadata signs the main component as updates/main, which is
	// still the archive's main.
	signed := *repository
	signed.Indexes = []Index{{Component: "updates/main"}}
	prefixed := &DefaultRepository{Covered: map[string]bool{"debian": true}, Bindings: map[string]ArchiveBinding{
		BindingKey("debian", "debian-security", "linux/amd64"): {
			Repository: "security", Suites: []string{"trixie-security"}, Components: []string{"updates/main"},
		},
	}}
	if err := checkEffectiveBinding(slice, &signed, prefixed, 0); err != nil {
		t.Fatalf("prefixed component refused: %v", err)
	}
	for name, check := range map[string]func() error{
		"another repository": func() error {
			altered := *repository
			altered.Name = "main"
			return checkEffectiveBinding(slice, &altered, provider, 0)
		},
		"another suite": func() error {
			altered := *repository
			altered.Suite = "trixie"
			return checkEffectiveBinding(slice, &altered, provider, 0)
		},
		"another component": func() error {
			altered := *repository
			altered.Indexes = []Index{{Component: "contrib"}}
			return checkEffectiveBinding(slice, &altered, provider, 0)
		},
	} {
		if err := check(); err == nil {
			t.Fatalf("%s: accepted a repository the archive was not bound to", name)
		}
	}
	// Another catalogue's binding does not stand in for the slice's own, and a slice
	// whose bindings were never rebuilt is refused rather than assumed correct.
	otherCatalogue := &DefaultRepository{Covered: map[string]bool{"other": true}, Bindings: map[string]ArchiveBinding{
		BindingKey("other", "debian-security", "linux/amd64"): {
			Repository: "security", Suites: []string{"trixie-security"}, Components: []string{"main"},
		},
	}}
	for name, check := range map[string]func() error{
		"binding of another catalogue": func() error {
			return checkEffectiveBinding(slice, repository, otherCatalogue, 0)
		},
		"no binding": func() error {
			return checkEffectiveBinding(slice, repository, &DefaultRepository{Covered: map[string]bool{"debian": true}}, 0)
		},
		"archive not bound on this platform": func() error {
			return checkEffectiveBinding(slice, repository, &DefaultRepository{Covered: map[string]bool{"debian": true},
				Bindings: map[string]ArchiveBinding{
					BindingKey("debian", "debian-security", "linux/arm64"): {Repository: "security"},
				}}, 0)
		},
		"no provider": func() error { return checkEffectiveBinding(slice, repository, nil, 0) },
	} {
		if err := check(); err == nil {
			t.Fatalf("%s: accepted an unbound slice", name)
		}
	}
}

// A provider archive needs no catalogue binding, so it stays usable beside bound
// archives; anything else must be bound.
func TestVerifySliceCatalogueProviderArchive(t *testing.T) {
	t.Parallel()
	provider := &DefaultRepository{Name: "debian", Covered: map[string]bool{"custom": true},
		Bindings: map[string]ArchiveBinding{
			BindingKey("custom", "extra", "linux/amd64"):  {Repository: "security"},
			BindingKey("custom", "debian", "linux/amd64"): {Repository: "debian"},
		}}
	declared := map[string]contents.CatalogueSource{
		"custom": {Name: "custom", Archives: map[string]string{"extra": "security"}},
	}
	catalogues := map[string]*Catalogue{"custom": {Name: "custom"}}
	repositories := map[string]*Repository{
		"one": {Name: "security", Platform: "linux/amd64", Architecture: "amd64", Suite: "main"},
		"two": {Name: "debian", Platform: "linux/amd64", Architecture: "amd64", Suite: "main"},
	}
	for key, binding := range provider.Bindings {
		binding.Suites = []string{"main"}
		provider.Bindings[key] = binding
	}
	slice := func(archive, repository string) *Slice {
		return &Slice{Catalogue: "custom", Archive: archive, Repository: repository,
			Platform: "linux/amd64", Architecture: "amd64"}
	}
	if err := verifySliceCatalogue(slice("extra", "one"), declared, catalogues, repositories, provider, 0); err != nil {
		t.Fatalf("bound archive: %v", err)
	}
	if err := verifySliceCatalogue(slice("debian", "two"), declared, catalogues, repositories, provider, 0); err != nil {
		t.Fatalf("provider archive: %v", err)
	}
	for name, tc := range map[string]struct {
		slice    *Slice
		provider *DefaultRepository
		want     string
	}{
		"wrong binding":   {slice: slice("extra", "two"), provider: provider, want: "does not match catalogue archive binding"},
		"unbound archive": {slice: slice("other", "one"), provider: provider, want: "archive is not bound by the catalogue"},
		"no provider":     {slice: slice("debian", "two"), provider: nil, want: "archive is not bound by the catalogue"},
	} {
		err := verifySliceCatalogue(tc.slice, declared, catalogues, repositories, tc.provider, 0)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// Replay applies the provider endpoint's own suites to a lock that uses the implicit
// repository, so a whole-package-only Debian lock cannot record the security suite at
// the main endpoint just because the release allows that suite elsewhere.
func TestVerifyLockfileRejectsImplicitSecurityRepository(t *testing.T) {
	t.Parallel()
	const debianSpec = `version: 1
name: debian-whole
image: example.invalid/debian-whole
distro: debian
release: trixie
platforms: [linux/amd64]
contents:
  packages:
    - name: openssl
`
	loaded, err := loadText(t, debianSpec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := loaded.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("A", 40)
	key := RepositoryKey{Fingerprint: fingerprint, SHA256: strings.Repeat("b", 64), Size: 10}
	endpoint := "https://deb.example.com/debian"
	provider := &DefaultRepository{
		Name:          "debian",
		AllowedSuites: []string{"trixie", "trixie-updates", "trixie-security"},
		Keys:          []RepositoryKey{key},
		Archives: []ProviderArchive{{
			Name: "debian", Endpoints: map[string]string{"linux/amd64": endpoint},
			Suites: []string{"trixie", "trixie-updates"}, Components: []string{"main"},
			Keys: []RepositoryKey{key},
		}},
	}
	build := func(name, suite string) *Lockfile {
		repository := Repository{
			Name: name, Platform: "linux/amd64", Architecture: "amd64", URL: endpoint, Suite: suite,
			Trust: RepositoryTrust{Keys: []RepositoryKey{key}},
			Release: RepositoryRelease{
				Format: "inrelease", Path: "dists/" + suite + "/InRelease",
				SHA256: strings.Repeat("d", 64), Size: 100, Signers: []string{fingerprint},
			},
			Indexes: []Index{{Component: "main", Path: "main/binary-amd64/Packages.xz",
				SHA256: strings.Repeat("e", 64), Size: 200}},
		}
		repository.ID = RepositoryID(repository.Name, repository.Platform, repository.Architecture,
			repository.URL, repository.Suite)
		return &Lockfile{
			Version: 1, SpecDigest: digest, Provider: Provider{Distro: "debian", Release: "trixie"},
			Platforms:    []string{"linux/amd64"},
			Repositories: []Repository{repository},
			Packages: []Package{{
				Platform: "linux/amd64", Name: "openssl", Version: "3.5-1", Architecture: "amd64", Repository: repository.ID,
				Content: Content{Path: "pool/main/o/openssl/openssl_3.5-1_amd64.deb",
					SHA256: strings.Repeat("1", 64), Size: 1000},
			}},
		}
	}
	err = VerifyLockfileForProvider(loaded, build("debian", "trixie-security"), "trixie", provider)
	if err == nil || !strings.Contains(err.Error(), "suite is not served by the provider archive") {
		t.Fatalf("implicit security repository: err = %v", err)
	}
	// The same package in the same suite is fine once the spec declares the repository.
	declared := strings.Replace(debianSpec, "  packages:\n", `  repositories:
    - name: security
      suites: [trixie-security]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: `+endpoint+`
  packages:
`, 1)
	declaredSpec, err := loadText(t, declared)
	if err != nil {
		t.Fatal(err)
	}
	declaredDigest, err := declaredSpec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	explicit := build("security", "trixie-security")
	explicit.SpecDigest = declaredDigest
	if err := VerifyLockfileForProvider(declaredSpec, explicit, "trixie", provider); err != nil {
		t.Fatalf("declared security repository: %v", err)
	}
}

// A lock is a file on disk, so the scope a repository was granted has to be applied on
// replay as well: editing a lock must not hand a vendor a name it may not supply.
func TestCheckRepositoryNameScope(t *testing.T) {
	t.Parallel()
	loaded, err := loadText(t, minimalSpec+`platforms: [linux/amd64]
contents:
  packages:
    - name: nginx
  repositories:
    - name: vendor
      suites: [stable]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: https://vendor.example.com/debian
      identity: own
      packages: [nginx]
      trust:
        keys:
          - path: keys/vendor.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
    - name: base
      suites: [trixie]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: https://base.example.com/debian
      trust:
        keys:
          - path: keys/base.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
`)
	if err != nil {
		t.Fatal(err)
	}
	repositories := map[string]*Repository{
		"vendor-id": {ID: "vendor-id", Name: "vendor", Platform: "linux/amd64", Architecture: "amd64"},
		"base-id":   {ID: "base-id", Name: "base", Platform: "linux/amd64", Architecture: "amd64"},
		"other-id":  {ID: "other-id", Name: "other", Platform: "linux/amd64", Architecture: "amd64"},
	}
	for name, tc := range map[string]struct {
		pkg, repository string
		refused         bool
	}{
		"declared name":         {pkg: "nginx", repository: "vendor-id"},
		"undeclared name":       {pkg: "apt", repository: "vendor-id", refused: true},
		"unscoped repository":   {pkg: "apt", repository: "base-id"},
		"undeclared repository": {pkg: "apt", repository: "other-id"},
		"dangling reference":    {pkg: "nginx", repository: "missing-id", refused: true},
	} {
		err := checkRepositoryNameScope(tc.pkg, tc.repository, loaded, repositories, "lock packages[0]")
		if tc.refused && err == nil {
			t.Fatalf("%s: accepted a package outside the repository scope", name)
		}
		if !tc.refused && err != nil {
			t.Fatalf("%s: refused a package the repository may supply: %v", name, err)
		}
	}
}

// The slice selector can reach a name the specification never listed, so replay has to
// apply the same scope to a slice's real package name.
func TestVerifyLockSliceRespectsRepositoryScope(t *testing.T) {
	t.Parallel()
	loaded, err := loadText(t, minimalSpec+`platforms: [linux/amd64]
contents:
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
      archives: {ubuntu: base, extra: vendor}
  slices:
    - package: base-files
      catalogue: custom
      slice: release-info
  repositories:
    - name: vendor
      suites: [stable]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: https://vendor.example.com/debian
      identity: own
      packages: [nginx]
      trust:
        keys:
          - path: keys/vendor.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
    - name: base
      suites: [trixie]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: https://base.example.com/debian
      trust:
        keys:
          - path: keys/base.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
`)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]contents.CatalogueSource{
		"custom": {Name: "custom", Archives: map[string]string{"ubuntu": "base", "extra": "vendor"}},
	}
	catalogues := map[string]*Catalogue{"custom": {Name: "custom"}}
	repositories := map[string]*Repository{
		"base-id": {ID: "base-id", Name: "base", Platform: "linux/amd64", Architecture: "amd64",
			Suite: "trixie", Indexes: []Index{{Component: "main"}}},
		"vendor-id": {ID: "vendor-id", Name: "vendor", Platform: "linux/amd64", Architecture: "amd64",
			Suite: "stable", Indexes: []Index{{Component: "main"}}},
	}
	provider := &DefaultRepository{Name: "ubuntu", Covered: map[string]bool{"custom": true},
		Bindings: map[string]ArchiveBinding{
			BindingKey("custom", "ubuntu", "linux/amd64"): {
				Repository: "base", Suites: []string{"trixie"}, Components: []string{"main"},
			},
			BindingKey("custom", "extra", "linux/amd64"): {
				Repository: "vendor", Suites: []string{"stable"}, Components: []string{"main"},
			},
		}}
	expected, err := sliceExpectations(loaded)
	if err != nil {
		t.Fatal(err)
	}
	build := func(pkg, archive, repository string) *Slice {
		return &Slice{
			Platform: "linux/amd64", Package: pkg, Version: "1.0", Architecture: "all",
			Catalogue: "custom", Archive: archive, Repository: repository,
			Content:          Content{Path: "pool/main/b/base-files/base-files_1.0_all.deb", SHA256: strings.Repeat("2", 64), Size: 300},
			Selected:         []string{"release-info"},
			Closure:          []string{"release-info"},
			DefinitionDigest: "sha256:" + strings.Repeat("3", 64),
		}
	}
	verify := func(slice *Slice) error {
		_, err := verifyLockSlice(slice, loaded, declared, catalogues, repositories, expected, provider, 0)
		return err
	}
	if refused := verify(build("base-files", "ubuntu", "base-id")); refused != nil {
		t.Fatalf("unscoped repository refused its own package: %v", refused)
	}
	if refused := verify(build("apt", "extra", "vendor-id")); refused == nil ||
		!strings.Contains(refused.Error(), `is not scoped to supply "apt"`) {
		t.Fatalf("err = %v, want the vendor scope enforced on a slice", refused)
	}
}

// A dependency-only package has no request to compare its CPE with, so a record that
// states one attributes the package to an identity the specification never declared.
// A scanner reading the attestation document would then file it under a name the
// specification did not choose.
func TestVerifyLockfile_DependencyCPE(t *testing.T) {
	t.Parallel()
	spec, lock := validMultiPlatformLock(t)
	lock.Packages = append(lock.Packages, Package{
		Platform:     "linux/amd64",
		Name:         "libssl3t64",
		Version:      "3.0-1",
		Architecture: "amd64",
		Repository:   lock.Repositories[0].ID,
		CPE:          nodeCPEForLock,
		Content: Content{Path: "pool/main/o/openssl/libssl3t64_3.0-1_amd64.deb",
			SHA256: strings.Repeat("8", 64), Size: 900},
	})
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err == nil {
		t.Fatal("a dependency cpe the specification never declared was accepted")
	}
}

// The same for a slice pulled in only as a dependency.
func TestVerifyLockfile_DependencySliceCPE(t *testing.T) {
	t.Parallel()
	spec, lock := validMultiPlatformLock(t)
	lock.Slices = append(lock.Slices, Slice{
		Platform:         "linux/amd64",
		Package:          "libc6",
		Version:          "2.39-0ubuntu8",
		Architecture:     "amd64",
		Catalogue:        "custom",
		Archive:          "ubuntu",
		Repository:       lock.Repositories[0].ID,
		CPE:              nodeCPEForLock,
		Content:          Content{Path: "pool/main/g/glibc/libc6_2.39_amd64.deb", SHA256: strings.Repeat("5", 64), Size: 2048},
		Closure:          []string{"lib"},
		DefinitionDigest: "sha256:" + strings.Repeat("6", 64),
	})
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err == nil {
		t.Fatal("a dependency slice cpe the specification never declared was accepted")
	}
}

// A direct record that matches its declaration is still accepted, so the comparison is
// not a blanket refusal.
func TestVerifyLockfile_DeclaredCPEIsAccepted(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, contentsFixtureWithCPE)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	_, lock := validMultiPlatformLock(t)
	lock.SpecDigest = digest
	for position := range lock.Packages {
		lock.Packages[position].CPE = nodeCPEForLock
	}
	if err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults()); err != nil {
		t.Fatalf("declared cpe rejected: %v", err)
	}
}
