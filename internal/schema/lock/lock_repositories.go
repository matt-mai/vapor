package lock

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func verifyLockRepositories(spec *schemaSpec.Spec, lock *Lockfile,
	local map[lockInputKey]LocalInput, provider *DefaultRepository) (map[string]*Repository, error) {
	declared := declaredRepositories(spec)
	repositories := make(map[string]*Repository)
	keys := make(map[string]bool)
	for i := range lock.Repositories {
		repository := &lock.Repositories[i]
		specRepository, declaredRepository := declared[repository.Name]
		isDefault := false
		if !declaredRepository && provider != nil {
			_, isDefault = provider.archive(repository.Name)
		}
		if !declaredRepository && !isDefault {
			return nil, fmt.Errorf("lock repositories[%d]: unknown repository", i)
		}
		key := repository.Name + "\x00" + repository.Platform + "\x00" + repository.Suite
		if err := verifyRepository(repository, specRepository, provider, local, spec, repositories, keys, key, i); err != nil {
			return nil, err
		}
		repositories[repository.ID] = repository
	}
	return repositories, nil
}
func declaredRepositories(spec *schemaSpec.Spec) map[string]*contents.Repository {
	declared := make(map[string]*contents.Repository)
	for i := range spec.Contents.Repositories {
		declared[spec.Contents.Repositories[i].Name] = &spec.Contents.Repositories[i]
	}
	return declared
}
func verifyRepository(repository *Repository, specRepository *contents.Repository, provider *DefaultRepository,
	local map[lockInputKey]LocalInput, spec *schemaSpec.Spec, repositories map[string]*Repository, keys map[string]bool,
	key string, i int) error {
	if err := checkLockDerived("lock repository ID", repository.ID); err != nil {
		return fmt.Errorf("lock repositories[%d]: %w", i, err)
	}
	if _, seen := repositories[repository.ID]; seen {
		return fmt.Errorf("lock repositories[%d]: duplicate ID", i)
	}
	if keys[key] {
		return fmt.Errorf("lock repositories[%d]: duplicate name, platform and suite", i)
	}
	if err := verifyRepositoryScope(repository, specRepository, provider, spec, i); err != nil {
		return err
	}
	if err := verifyRepositoryIdentity(repository, specRepository, i); err != nil {
		return err
	}
	if repository.ID != RepositoryID(repository.Name, repository.Platform, repository.Architecture, repository.URL,
		repository.Suite) {
		return fmt.Errorf("lock repositories[%d]: ID does not match its payload", i)
	}
	trusted, err := verifyRepositoryTrust(repository, specRepository, provider, local, i)
	if err != nil {
		return err
	}
	if err := verifyLockRepositoryRelease(&repository.Release, repository.Suite, trusted); err != nil {
		return fmt.Errorf("lock repositories[%d]: %w", i, err)
	}
	if err := verifyLockIndexes(repository.Indexes, specRepository); err != nil {
		return fmt.Errorf("lock repositories[%d]: %w", i, err)
	}
	keys[key] = true
	return nil
}
func verifyRepositoryScope(repository *Repository, specRepository *contents.Repository,
	provider *DefaultRepository, spec *schemaSpec.Spec, i int) error {
	if specRepository != nil {
		if err := checkRepositoryScope(repository, specRepository, spec, i); err != nil {
			return err
		}
		if specRepository.Identity != nil {
			// A repository with its own identity names a suite of its own, so the
			// base release has no say over which suites it may read.
			return nil
		}
		return checkProviderSuite(repository, provider, i)
	}
	return checkDefaultRepositoryScope(repository, provider, spec, i)
}

// verifyRepositoryIdentity checks that a repository's recorded identity is the one the
// specification declares. The flag decides which vendor's name its packages are
// published under, so a lock that disagrees with the specification would attribute them
// to the wrong vendor.
func verifyRepositoryIdentity(repository *Repository, specRepository *contents.Repository, i int) error {
	declared := ""
	if specRepository != nil && specRepository.Identity != nil {
		declared = *specRepository.Identity
	}
	if repository.Identity != declared {
		return fmt.Errorf("lock repositories[%d]: identity does not match the specification", i)
	}
	return nil
}

// checkProviderSuite applies the release rule to a repository the specification
// declares itself. Declaring an endpoint and keys does not widen which suites the
// release may read, so a correctly signed archive of another release stays out.
func checkProviderSuite(repository *Repository, provider *DefaultRepository, i int) error {
	// No provider, or one that leaves the suites to the specification, as Ubuntu does.
	if provider == nil || len(provider.AllowedSuites) == 0 ||
		slices.Contains(provider.AllowedSuites, repository.Suite) {
		return nil
	}
	return fmt.Errorf("lock repositories[%d]: suite is not served by the provider archive", i)
}
func verifyRepositoryTrust(repository *Repository, specRepository *contents.Repository,
	provider *DefaultRepository, local map[lockInputKey]LocalInput, i int) (map[string]bool, error) {
	if specRepository == nil {
		return verifyDefaultRepositoryTrust(repository, provider, i)
	}
	if len(specRepository.Trust.Keys) == 0 {
		return verifyProviderRepositoryTrust(repository, provider, i)
	}
	trusted, err := verifyLockRepositoryTrust(repository, specRepository, local)
	if err != nil {
		return nil, fmt.Errorf("lock repositories[%d]: %w", i, err)
	}
	return trusted, nil
}
func checkRepositoryScope(repository *Repository, specRepository *contents.Repository, spec *schemaSpec.Spec, i int) error {
	native, ok := nativeArchitecture(repository.Platform)
	if !ok || !slices.Contains(spec.Platforms, repository.Platform) {
		return fmt.Errorf("lock repositories[%d]: platform is not a spec platform", i)
	}
	if repository.Architecture != native {
		return fmt.Errorf("lock repositories[%d]: architecture is not native for its platform", i)
	}
	if !slices.Contains(specRepository.Platforms, repository.Platform) {
		return fmt.Errorf("lock repositories[%d]: platform is outside the repository scope", i)
	}
	if !slices.Contains(specRepository.Suites, repository.Suite) {
		return fmt.Errorf("lock repositories[%d]: suite is not declared", i)
	}
	endpoint, ok := repositoryEndpoint(specRepository, repository.Platform)
	if !ok || repository.URL != endpoint {
		return fmt.Errorf("lock repositories[%d]: URL does not match the platform endpoint", i)
	}
	if err := base.ValidateInputURL(repository.URL, false); err != nil {
		return fmt.Errorf("lock repositories[%d]: %w", i, err)
	}
	return nil
}
func verifyLockRepositoryTrust(repository *Repository, specRepository *contents.Repository,
	local map[lockInputKey]LocalInput) (map[string]bool, error) {
	if len(repository.Trust.Keys) == 0 {
		return nil, errors.New("trust requires at least one key")
	}
	trusted := make(map[string]bool)
	for i := range repository.Trust.Keys {
		if err := verifyLockTrustKey(&repository.Trust.Keys[i], local, trusted); err != nil {
			return nil, err
		}
	}
	if err := verifyTrustCoverage(repository.Trust.Keys, specRepository.Trust.Keys); err != nil {
		return nil, err
	}
	return trusted, nil
}
func verifyLockTrustKey(key *RepositoryKey, local map[lockInputKey]LocalInput, trusted map[string]bool) error {
	if err := base.RequirePattern("trusted full fingerprint", key.Fingerprint,
		`^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`); err != nil {
		return err
	}
	canonical := strings.ToUpper(key.Fingerprint)
	if trusted[canonical] {
		return errors.New("duplicate trusted fingerprint")
	}
	if key.Path != "" {
		if err := base.ValidateLocalPath(key.Path); err != nil {
			return err
		}
		input, ok := local[lockInputKey{role: trustKeyRole, path: key.Path}]
		if !ok || input.SHA256 != key.SHA256 || input.Size != key.Size {
			return errors.New("trust key does not match a trust-key local input")
		}
	}
	if err := checkLockHash("trust key", key.SHA256); err != nil {
		return err
	}
	if err := checkLockSize("trust key", key.Size); err != nil {
		return err
	}
	trusted[canonical] = true
	return nil
}
func verifyTrustCoverage(keys []RepositoryKey, specKeys []contents.TrustKey) error {
	configured := make(map[string]string)
	for _, key := range specKeys {
		for _, fingerprint := range key.Fingerprints {
			configured[strings.ToUpper(fingerprint)] = key.Path
		}
	}
	if len(configured) == 0 {
		return nil
	}
	if len(configured) != len(keys) {
		return errors.New("trust keys do not exactly cover the configured fingerprints")
	}
	for fingerprint, keyPath := range configured {
		if !trustKeyMatches(keys, fingerprint, keyPath) {
			return errors.New("trust keys do not cover a configured fingerprint and path")
		}
	}
	return nil
}
func trustKeyMatches(keys []RepositoryKey, fingerprint, keyPath string) bool {
	for _, key := range keys {
		if strings.EqualFold(key.Fingerprint, fingerprint) && key.Path == keyPath {
			return true
		}
	}
	return false
}

// checkRepositoryNameScope keeps a package inside the authority its repository was
// granted. The scope is applied where candidates are chosen, but a lock is a file on
// disk: replay has to refuse a name the repository may not supply, or the check could
// be bypassed by editing the lock. A repository the specification does not declare,
// and a declared one with no scope, may supply any name.
func checkRepositoryNameScope(name, repositoryID string, spec *schemaSpec.Spec,
	repositories map[string]*Repository, location string) error {
	repository, ok := repositories[repositoryID]
	if !ok {
		return fmt.Errorf("%s: dangling repository reference", location)
	}
	for i := range spec.Contents.Repositories {
		declared := &spec.Contents.Repositories[i]
		if declared.Name != repository.Name {
			continue
		}
		if len(declared.Packages) == 0 || slices.Contains(declared.Packages, name) {
			return nil
		}
		return fmt.Errorf("%s: repository %q is not scoped to supply %q", location, repository.Name, name)
	}
	return nil
}
