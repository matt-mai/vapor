package lock

import (
	"strings"
	"testing"

	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func TestProviderRepositoryTrust(t *testing.T) {
	t.Parallel()
	key := RepositoryKey{
		Fingerprint: strings.Repeat("A", 40), SHA256: strings.Repeat("b", 64), Size: 10,
	}
	provider := &DefaultRepository{
		Keys:     []RepositoryKey{key},
		Archives: []ProviderArchive{{Name: "ubuntu", Keys: []RepositoryKey{key}}},
	}
	repository := &Repository{Name: "ubuntu", Trust: RepositoryTrust{Keys: []RepositoryKey{key}}}
	if _, err := verifyProviderRepositoryTrust(repository, provider, 0); err != nil {
		t.Fatal(err)
	}
	for name, altered := range map[string]RepositoryKey{
		"unknown key": {Fingerprint: strings.Repeat("C", 40), SHA256: key.SHA256, Size: key.Size},
		"wrong hash":  {Fingerprint: key.Fingerprint, SHA256: strings.Repeat("c", 64), Size: key.Size},
		"path":        {Path: "keys/key.asc", Fingerprint: key.Fingerprint, SHA256: key.SHA256, Size: key.Size},
	} {
		repository := &Repository{Name: "ubuntu", Trust: RepositoryTrust{Keys: []RepositoryKey{altered}}}
		if _, err := verifyProviderRepositoryTrust(repository, provider, 0); err == nil {
			t.Fatalf("%s: accepted invalid provider trust", name)
		}
	}
}

func TestDefaultRepositoryScopeAndTrust(t *testing.T) {
	t.Parallel()
	key := RepositoryKey{
		Fingerprint: strings.Repeat("A", 40), SHA256: strings.Repeat("b", 64), Size: 10,
	}
	repository := Repository{
		Name: "ubuntu", Platform: "linux/amd64", Architecture: "amd64", URL: "https://archive.example.com/ubuntu",
		Suite: "resolute", Trust: RepositoryTrust{Keys: []RepositoryKey{key}},
	}
	provider := &DefaultRepository{
		Name: "ubuntu",
		Archives: []ProviderArchive{{
			Name: "ubuntu", Endpoints: map[string]string{"linux/amd64": repository.URL},
			Keys: []RepositoryKey{key},
		}},
	}
	spec := &schemaSpec.Spec{Platforms: []string{"linux/amd64"}}
	if err := checkDefaultRepositoryScope(&repository, provider, spec, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDefaultRepositoryTrust(&repository, provider, 0); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"URL": func() error {
			altered := repository
			altered.URL = "https://other.example.com/ubuntu"
			return checkDefaultRepositoryScope(&altered, provider, spec, 0)
		},
		"platform": func() error {
			altered := repository
			altered.Platform, altered.Architecture = "linux/arm64", "arm64"
			return checkDefaultRepositoryScope(&altered, provider, spec, 0)
		},
		"suite outside the endpoint": func() error {
			altered := repository
			altered.Suite = "resolute-security"
			scoped := *provider
			scoped.Archives = []ProviderArchive{{
				Name: "ubuntu", Endpoints: provider.Archives[0].Endpoints,
				Suites: []string{"resolute", "resolute-updates"}, Keys: provider.Archives[0].Keys,
			}}
			return checkDefaultRepositoryScope(&altered, &scoped, spec, 0)
		},
		"key hash": func() error {
			altered := repository
			altered.Trust.Keys = []RepositoryKey{{Fingerprint: key.Fingerprint, SHA256: strings.Repeat("c", 64),
				Size: key.Size}}
			_, err := verifyDefaultRepositoryTrust(&altered, provider, 0)
			return err
		},
		"key path": func() error {
			altered := repository
			altered.Trust.Keys = []RepositoryKey{{Path: "keys/other.asc", Fingerprint: key.Fingerprint,
				SHA256: key.SHA256, Size: key.Size}}
			_, err := verifyDefaultRepositoryTrust(&altered, provider, 0)
			return err
		},
		"key count": func() error {
			altered := repository
			altered.Trust.Keys = nil
			_, err := verifyDefaultRepositoryTrust(&altered, provider, 0)
			return err
		},
	} {
		if err := check(); err == nil {
			t.Fatalf("%s: accepted invalid default repository", name)
		}
	}
}

// Declaring a repository's own endpoint and keys does not widen which suites the
// release may read: a correctly signed archive of another release stays out, both for
// the provider archive and for a repository the specification declares itself.
func TestVerifyLockfileAppliesProviderSuitesToDeclaredRepositories(t *testing.T) {
	t.Parallel()
	key := RepositoryKey{
		Fingerprint: strings.Repeat("A", 40), SHA256: strings.Repeat("b", 64), Size: 10,
	}
	repository := Repository{
		Name: "debian-security", Platform: "linux/amd64", Architecture: "amd64",
		URL: "https://security.example.com/debian-security", Suite: "trixie-security",
		Trust: RepositoryTrust{Keys: []RepositoryKey{key}},
	}
	provider := &DefaultRepository{
		Name:          "debian",
		AllowedSuites: []string{"trixie", "trixie-updates", "trixie-security"},
		Archives: []ProviderArchive{{
			Name: "debian", Endpoints: map[string]string{"linux/amd64": "https://deb.example.com/debian"},
			Suites: []string{"trixie", "trixie-updates"}, Keys: []RepositoryKey{key},
		}},
	}
	if err := checkProviderSuite(&repository, provider, 0); err != nil {
		t.Fatalf("security suite refused: %v", err)
	}
	for name, scope := range map[string]*DefaultRepository{
		"another release": {Name: "other", AllowedSuites: []string{"bookworm", "bookworm-updates"}},
		"no suites":       {Name: "other"},
	} {
		want := name == "another release"
		err := checkProviderSuite(&repository, scope, 0)
		if want && (err == nil || !strings.Contains(err.Error(), "suite is not served by the provider archive")) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if !want && err != nil {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if err := checkProviderSuite(&repository, nil, 0); err != nil {
		t.Fatalf("no provider: %v", err)
	}
}

// Debian serves its security suite from another host, so a lock may record it only at
// a repository the specification declared. Replay keeps the provider endpoint's suites
// separate from the suites the release may read, or it would accept a security
// repository riding the implicit main endpoint.
func TestVerifyLockfileRejectsImplicitSecuritySuite(t *testing.T) {
	t.Parallel()
	key := RepositoryKey{
		Fingerprint: strings.Repeat("A", 40), SHA256: strings.Repeat("b", 64), Size: 10,
	}
	provider := &DefaultRepository{
		Name:          "debian",
		AllowedSuites: []string{"trixie", "trixie-updates", "trixie-security"},
		Archives: []ProviderArchive{{
			Name: "debian", Endpoints: map[string]string{"linux/amd64": "https://deb.example.com/debian"},
			Suites: []string{"trixie", "trixie-updates"}, Keys: []RepositoryKey{key},
		}},
	}
	security := &Repository{
		Name: "debian", Platform: "linux/amd64", Architecture: "amd64", URL: "https://deb.example.com/debian",
		Suite: "trixie-security", Trust: RepositoryTrust{Keys: []RepositoryKey{key}},
	}
	spec := &schemaSpec.Spec{Platforms: []string{"linux/amd64"}}
	err := checkDefaultRepositoryScope(security, provider, spec, 0)
	if err == nil || !strings.Contains(err.Error(), "suite is not served by the provider archive") {
		t.Fatalf("implicit security suite: err = %v", err)
	}
	// The same suite at a declared repository is what the release allows.
	if err := checkProviderSuite(security, provider, 0); err != nil {
		t.Fatalf("declared security suite refused: %v", err)
	}
	for _, suite := range provider.Archives[0].Suites {
		implicit := *security
		implicit.Suite = suite
		if err := checkDefaultRepositoryScope(&implicit, provider, spec, 0); err != nil {
			t.Fatalf("implicit suite %q refused: %v", suite, err)
		}
	}
}
