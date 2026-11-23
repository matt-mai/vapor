package lock

import (
	"errors"
	"fmt"
	"slices"

	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

const (
	trustKeyRole    = "trust-key"
	architectureAll = "all"
	platformAMD64   = "linux/amd64"
	platformARM64   = "linux/arm64"
)

// DefaultRepository describes the repositories the provider supplies itself.
// Archives lists them, each with its own endpoint, suites and keys, so a lock record
// is checked against the archive it claims: Debian's security archive is verified
// with the security key, not with the main archive's. AllowedSuites is every suite an
// image of this release may read from a declared repository; an empty list leaves
// that choice to the spec. RepositoryKeys overrides the keys of a declared repository
// by name, for Pro services.
type DefaultRepository struct {
	Name          string
	AllowedSuites []string
	// Keys is every reviewed key, across all archives, for a declared repository
	// whose name matches no provider archive.
	Keys           []RepositoryKey
	Archives       []ProviderArchive
	RepositoryKeys map[string][]RepositoryKey
	// Bindings holds the effective binding of every catalogue archive on every
	// platform, rebuilt from the verified catalogue bytes.
	Bindings map[string]ArchiveBinding
	// Covered names the catalogues the rebuild actually read. A provider that
	// covered fewer catalogues than the specification declares has an incomplete
	// binding map, so replay refuses the slices instead of trusting a partial one.
	Covered map[string]bool
}

// ProviderArchive is one repository the provider supplies with no declaration: its
// endpoints per platform, the suites it serves and the keys that sign them.
type ProviderArchive struct {
	Name       string
	Endpoints  map[string]string
	Suites     []string
	Components []string
	Keys       []RepositoryKey
}

// archive returns the provider archive a repository name names.
func (p *DefaultRepository) archive(name string) (*ProviderArchive, bool) {
	for i := range p.Archives {
		if p.Archives[i].Name == name {
			return &p.Archives[i], true
		}
	}
	return nil, false
}

// ArchiveBinding is the repository one catalogue archive was resolved to, with the
// suites and components that archive declares. It is what a slice's record has to
// agree with, so authenticating a package against some index is not enough.
type ArchiveBinding struct {
	Repository string
	Suites     []string
	Components []string
}

// BindingKey identifies one catalogue archive on one platform. The catalogue is part
// of the key because two catalogues may declare the same archive name and bind it to
// different repositories.
func BindingKey(catalogue, archive, platform string) string {
	return catalogue + "\x00" + archive + "\x00" + platform
}

// VerifyLockfileForProvider additionally accepts one provider-owned repository
// that does not appear in the spec repository list.
func VerifyLockfileForProvider(spec *schemaSpec.Spec, lock *Lockfile, release string,
	provider *DefaultRepository) error {
	if lock == nil {
		return errors.New("lock must not be nil")
	}
	normalized, err := lockSpecForRelease(spec, release)
	if err != nil {
		return err
	}
	digest, err := normalized.SpecDigest()
	if err != nil {
		return fmt.Errorf("lock spec digest: %w", err)
	}
	if headerErr := verifyLockHeader(normalized, lock, digest); headerErr != nil {
		return headerErr
	}
	local, err := verifyLockLocalInputs(normalized, lock)
	if err != nil {
		return err
	}
	catalogues, err := verifyLockCatalogues(normalized, lock)
	if err != nil {
		return err
	}
	repositories, err := verifyLockRepositories(normalized, lock, local, provider)
	if err != nil {
		return err
	}
	packages, err := verifyLockPackages(normalized, lock, repositories)
	if err != nil {
		return err
	}
	slicesByKey, err := verifyLockSlices(normalized, lock, repositories, catalogues, packages, provider)
	if err != nil {
		return err
	}
	if err := verifyLockRepositoryReferences(repositories, packages, slicesByKey); err != nil {
		return err
	}
	return verifyLockArtifacts(normalized, lock)
}

func lockSpecForRelease(spec *schemaSpec.Spec, release string) (*schemaSpec.Spec, error) {
	if spec == nil {
		return nil, errors.New("spec must not be nil")
	}
	if release == "" {
		return nil, errors.New("canonical release must not be empty")
	}
	normalized, err := schemaSpec.CopySpec(spec)
	if err != nil {
		return nil, fmt.Errorf("lock spec snapshot: %w", err)
	}
	normalized.Release = release
	schemaSpec.ApplyDefaults(normalized)
	if err := schemaSpec.ValidateSpec(normalized); err != nil {
		return nil, fmt.Errorf("lock spec: %w", err)
	}
	return normalized, nil
}

func verifyLockHeader(spec *schemaSpec.Spec, lock *Lockfile, digest string) error {
	if lock.Version != 1 {
		return errors.New("lock version must be 1")
	}
	if lock.SpecDigest != digest {
		return errors.New("lock spec digest does not match the spec")
	}
	if lock.Provider.Distro != spec.Distro || lock.Provider.Release != spec.Release {
		return errors.New("lock provider does not match the spec")
	}
	if !slices.Equal(lock.Platforms, spec.Platforms) {
		return errors.New("lock platforms must match the spec platforms in order")
	}
	return nil
}
