package lock

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

func verifyLockRepositoryRelease(release *RepositoryRelease, suite string, trusted map[string]bool) error {
	if err := checkReleaseIdentity(release, suite); err != nil {
		return err
	}
	if err := checkReleaseValidUntil(release.ValidUntil); err != nil {
		return err
	}
	if err := checkReleaseSigners(release.Signers, trusted); err != nil {
		return err
	}
	if release.Format == "inrelease" {
		if release.Signature != nil {
			return errors.New("inrelease must not have a detached signature")
		}
		return nil
	}
	if release.Signature == nil {
		return errors.New("release-gpg requires a detached signature")
	}
	if release.Signature.Path != "dists/"+suite+"/Release.gpg" {
		return errors.New("release signature path does not match suite")
	}
	if err := checkLockHash("release signature", release.Signature.SHA256); err != nil {
		return err
	}
	return checkLockSize("release signature", release.Signature.Size)
}
func checkReleaseIdentity(release *RepositoryRelease, suite string) error {
	if release.Format != "inrelease" && release.Format != "release-gpg" {
		return errors.New("release format must be inrelease or release-gpg")
	}
	if err := validateLockPath(release.Path); err != nil {
		return fmt.Errorf("release path: %w", err)
	}
	wantPath := "dists/" + suite + "/InRelease"
	if release.Format == "release-gpg" {
		wantPath = "dists/" + suite + "/Release"
	}
	if release.Path != wantPath {
		return errors.New("release path does not match suite and format")
	}
	if err := checkLockHash("release", release.SHA256); err != nil {
		return err
	}
	return checkLockSize("release", release.Size)
}
func checkReleaseValidUntil(value *string) error {
	if value == nil {
		return nil
	}
	if *value == "" || strings.TrimSpace(*value) != *value || strings.ContainsFunc(*value, unicode.IsControl) {
		return errors.New("release valid-until must be a nonblank single-line string")
	}
	return nil
}
func checkReleaseSigners(signers []string, trusted map[string]bool) error {
	if len(signers) == 0 {
		return errors.New("release requires at least one signer")
	}
	seen := make(map[string]bool)
	for _, signer := range signers {
		canonical := strings.ToUpper(signer)
		if !trusted[canonical] {
			return errors.New("release signer is not a trusted key")
		}
		if seen[canonical] {
			return errors.New("duplicate release signer")
		}
		seen[canonical] = true
	}
	return nil
}
func verifyLockIndexes(indexes []Index, specRepository *contents.Repository) error {
	if len(indexes) == 0 {
		return errors.New("indexes must not be empty")
	}
	seen := make(map[string]bool)
	for i := range indexes {
		if err := verifyLockIndex(&indexes[i], specRepository, seen); err != nil {
			return err
		}
	}
	return nil
}
func verifyLockIndex(index *Index, specRepository *contents.Repository, seen map[string]bool) error {
	if seen[index.Component] {
		return errors.New("duplicate index component")
	}
	if specRepository != nil && !slices.Contains(specRepository.Components, index.Component) {
		return errors.New("index component is not declared")
	}
	if err := validateLockPath(index.Path); err != nil {
		return fmt.Errorf("index path: %w", err)
	}
	if err := checkLockHash("index", index.SHA256); err != nil {
		return err
	}
	if err := checkLockSize("index", index.Size); err != nil {
		return err
	}
	seen[index.Component] = true
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
