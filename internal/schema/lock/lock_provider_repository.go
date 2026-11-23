package lock

// Verification of a provider archive: the repositories an image reads when the
// specification does not declare them itself.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func checkDefaultRepositoryScope(repository *Repository, provider *DefaultRepository,
	spec *schemaSpec.Spec, i int) error {
	native, ok := nativeArchitecture(repository.Platform)
	if !ok || !slices.Contains(spec.Platforms, repository.Platform) {
		return fmt.Errorf("lock repositories[%d]: platform is not a spec platform", i)
	}
	if repository.Architecture != native {
		return fmt.Errorf("lock repositories[%d]: architecture is not native for its platform", i)
	}
	archive, ok := provider.archive(repository.Name)
	if !ok {
		return fmt.Errorf("lock repositories[%d]: unknown repository", i)
	}
	endpoint, ok := archive.Endpoints[repository.Platform]
	if !ok || repository.URL != endpoint {
		return fmt.Errorf("lock repositories[%d]: URL does not match the provider endpoint", i)
	}
	if len(archive.Suites) != 0 && !slices.Contains(archive.Suites, repository.Suite) {
		return fmt.Errorf("lock repositories[%d]: suite is not served by the provider archive", i)
	}
	if err := base.ValidateInputURL(repository.URL, false); err != nil {
		return fmt.Errorf("lock repositories[%d]: %w", i, err)
	}
	return nil
}

// verifyProviderRepositoryTrust checks a repository the specification declared
// without keys against the keys the provider vouches for it: a Pro service's keys by
// name, or the provider's declared archives, which must agree exactly.
func verifyProviderRepositoryTrust(repository *Repository, provider *DefaultRepository,
	i int) (map[string]bool, error) {
	if provider == nil {
		return nil, fmt.Errorf("lock repositories[%d]: no provider trust is configured", i)
	}
	keys, err := providerKeysFor(repository.Name, provider, i)
	if err != nil {
		return nil, err
	}
	return matchProviderKeys(repository, keys, "a provider key", i)
}

// verifyDefaultRepositoryTrust checks a repository the provider supplies itself
// against the keys of the archive it names, so a suite record cannot be signed by a
// key that belongs to another archive.
func verifyDefaultRepositoryTrust(repository *Repository, provider *DefaultRepository,
	i int) (map[string]bool, error) {
	archive, ok := provider.archive(repository.Name)
	if !ok {
		return nil, fmt.Errorf("lock repositories[%d]: unknown repository", i)
	}
	return matchProviderKeys(repository, archive.Keys, "the provider defaults", i)
}

func providerKeysFor(name string, provider *DefaultRepository, i int) ([]RepositoryKey, error) {
	if keys, scoped := provider.RepositoryKeys[name]; scoped {
		if len(keys) == 0 {
			return nil, fmt.Errorf("lock repositories[%d]: no provider trust is configured", i)
		}
		return keys, nil
	}
	// A repository named after a provider archive is verified with that archive's
	// keys, as acquisition bound it; only an unrecognized name falls back to every
	// reviewed key, which is what a mirror of the whole release needs.
	if archive, ok := provider.archive(name); ok {
		return archive.Keys, nil
	}
	if len(provider.Keys) == 0 {
		return nil, fmt.Errorf("lock repositories[%d]: no provider trust is configured", i)
	}
	return provider.Keys, nil
}

func matchProviderKeys(repository *Repository, keys []RepositoryKey, source string, i int) (map[string]bool, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("lock repositories[%d]: no provider trust is configured", i)
	}
	if len(repository.Trust.Keys) != len(keys) {
		return nil, fmt.Errorf("lock repositories[%d]: trust does not match %s", i, source)
	}
	want := make(map[string]RepositoryKey, len(keys))
	for _, key := range keys {
		want[strings.ToUpper(key.Fingerprint)] = key
	}
	trusted := make(map[string]bool, len(repository.Trust.Keys))
	for j := range repository.Trust.Keys {
		key := &repository.Trust.Keys[j]
		expected, ok := want[strings.ToUpper(key.Fingerprint)]
		if !ok || key.Path != "" || key.SHA256 != expected.SHA256 || key.Size != expected.Size {
			return nil, fmt.Errorf("lock repositories[%d]: trust does not match %s", i, source)
		}
		fingerprint := strings.ToUpper(key.Fingerprint)
		if trusted[fingerprint] {
			return nil, fmt.Errorf("lock repositories[%d]: duplicate trusted fingerprint", i)
		}
		trusted[fingerprint] = true
	}
	return trusted, nil
}
