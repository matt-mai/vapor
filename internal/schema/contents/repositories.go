package contents

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
)

func validateRepositories(repositories []Repository, platforms []string) error {
	seen := make(map[string]bool)
	for i := range repositories {
		repository := &repositories[i]
		if seen[repository.Name] {
			return errors.New("duplicate repository name")
		}
		seen[repository.Name] = true
		if err := validateRepository(repository, platforms); err != nil {
			return fmt.Errorf("contents.repositories[%d]: %w", i, err)
		}
	}
	return nil
}

func validateRepository(repository *Repository, platforms []string) error {
	if err := base.ValidateInputName(repository.Name); err != nil {
		return err
	}
	if err := base.ValidateScope(repository.Platforms, platforms); err != nil {
		return err
	}
	if err := validateEndpoints(repository.Endpoints, repository.Platforms); err != nil {
		return err
	}
	if err := base.ValidateTokens("repository suites", repository.Suites); err != nil {
		return err
	}
	if repository.SuiteMatch != nil && *repository.SuiteMatch != SuiteMatchCodename {
		return errors.New("repository suite-match must be codename when set")
	}
	if err := base.ValidateTokens("repository components", repository.Components); err != nil {
		return err
	}
	if err := validateOwnIdentity(repository); err != nil {
		return err
	}
	if repository.ByHash == nil || !slices.Contains([]string{"prefer", "require", "disable"}, *repository.ByHash) {
		return errors.New("repository by-hash must be prefer, require or disable")
	}
	if repository.Freshness.ValidUntil == nil || !slices.Contains([]string{"if-present", "require"},
		*repository.Freshness.ValidUntil) {
		return errors.New("repository freshness.valid-until must be if-present or require")
	}
	return validateTrust(repository.Trust)
}

// validateOwnIdentity keeps own identity an explicit opt-in with its own keys and an
// explicit scope, so declaring a vendor archive cannot widen what it may supply. A
// repository that names its own release cannot borrow the base release's keys as a
// default, because nothing ties those keys to the archive it describes.
func validateOwnIdentity(repository *Repository) error {
	if repository.Identity == nil {
		if len(repository.Packages) != 0 {
			return errors.New("repository packages requires identity: own")
		}
		return nil
	}
	if *repository.Identity != RepositoryIdentityOwn {
		return errors.New("repository identity must be own when set")
	}
	if len(repository.Trust.Keys) == 0 {
		return errors.New("repository with its own identity requires trust keys")
	}
	return validateRepositoryPackages(repository.Packages)
}

func validateRepositoryPackages(packages []string) error {
	seen := make(map[string]bool, len(packages))
	for _, name := range packages {
		if err := base.ValidatePackageVersion(name, nil); err != nil {
			return fmt.Errorf("repository packages: %w", err)
		}
		if seen[name] {
			return errors.New("repository packages has a duplicate name")
		}
		seen[name] = true
	}
	return nil
}

func validateEndpoints(endpoints []Endpoint, platforms []string) error {
	seen := make(map[string]bool)
	for i, endpoint := range endpoints {
		if err := base.ValidateInputURL(endpoint.URL, false); err != nil {
			return fmt.Errorf("repository endpoint[%d]: %w", i, err)
		}
		if err := base.ClaimPlatforms(endpoint.Platforms, platforms, seen); err != nil {
			return fmt.Errorf("repository endpoint[%d]: %w", i, err)
		}
	}
	if len(seen) != len(platforms) {
		return errors.New("repository endpoints must cover every intended platform")
	}
	return nil
}

func validateTrust(trust Trust) error {
	paths, fingerprints := make(map[string]bool), make(map[string]bool)
	for _, key := range trust.Keys {
		if err := validateTrustKey(key, paths, fingerprints); err != nil {
			return err
		}
	}
	return nil
}

func validateTrustKey(key TrustKey, paths, fingerprints map[string]bool) error {
	if err := base.ValidateLocalPath(key.Path); err != nil {
		return fmt.Errorf("repository trust key: %w", err)
	}
	if paths[key.Path] || len(key.Fingerprints) == 0 {
		return errors.New("trust key paths must be unique and each needs full fingerprints")
	}
	paths[key.Path] = true
	for _, fingerprint := range key.Fingerprints {
		if err := base.RequirePattern("trusted full fingerprint", fingerprint,
			`^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`); err != nil {
			return err
		}
		canonical := strings.ToUpper(fingerprint)
		if fingerprints[canonical] {
			return errors.New("duplicate trusted fingerprint")
		}
		fingerprints[canonical] = true
	}
	return nil
}
