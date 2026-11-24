package lock

import (
	"fmt"
	"slices"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

type lockPackageKey struct {
	platform string
	name     string
}

func verifyLockPackages(spec *schemaSpec.Spec, lock *Lockfile,
	repositories map[string]*Repository) (map[lockPackageKey]*Package, error) {
	packages := make(map[lockPackageKey]*Package)
	for i := range lock.Packages {
		pkg := &lock.Packages[i]
		if err := verifyLockPackage(pkg, spec, repositories, i); err != nil {
			return nil, err
		}
		key := lockPackageKey{platform: pkg.Platform, name: pkg.Name}
		if _, ok := packages[key]; ok {
			return nil, fmt.Errorf("lock packages[%d]: duplicate platform and name", i)
		}
		packages[key] = pkg
	}
	return packages, verifyLockPackageRequests(spec, packages)
}

func verifyLockPackage(pkg *Package, spec *schemaSpec.Spec, repositories map[string]*Repository, i int) error {
	native, ok := nativeArchitecture(pkg.Platform)
	if !ok || !slices.Contains(spec.Platforms, pkg.Platform) {
		return fmt.Errorf("lock packages[%d]: platform is not a spec platform", i)
	}
	if pkg.Architecture != architectureAll && pkg.Architecture != native {
		return fmt.Errorf("lock packages[%d]: architecture is not all or native", i)
	}
	version := pkg.Version
	if err := base.ValidatePackageVersion(pkg.Name, &version); err != nil {
		return fmt.Errorf("lock packages[%d]: %w", i, err)
	}
	if err := verifyLocksource(pkg.Source, fmt.Sprintf("lock packages[%d]", i)); err != nil {
		return err
	}
	if err := contents.ValidateDeclaredCPE(pkg.CPE); err != nil {
		return fmt.Errorf("lock packages[%d]: %w", i, err)
	}
	return verifyLockPackageRepository(pkg, spec, repositories, i)
}

// verifyLocksource checks the optional source package name. It is the same grammar as
// a package name because it is one.
func verifyLocksource(source, location string) error {
	if source == "" {
		return nil
	}
	if err := base.RequirePattern("source package name", source, `^[a-z0-9][a-z0-9+.-]*$`); err != nil {
		return fmt.Errorf("%s: %w", location, err)
	}
	return nil
}

func verifyLockPackageRepository(pkg *Package, spec *schemaSpec.Spec, repositories map[string]*Repository, i int) error {
	repository, ok := repositories[pkg.Repository]
	if !ok {
		return fmt.Errorf("lock packages[%d]: dangling repository reference", i)
	}
	if repository.Platform != pkg.Platform ||
		(pkg.Architecture != architectureAll && pkg.Architecture != repository.Architecture) {
		return fmt.Errorf("lock packages[%d]: repository platform or architecture mismatch", i)
	}
	if err := verifyLockContent("package", pkg.Content); err != nil {
		return fmt.Errorf("lock packages[%d]: %w", i, err)
	}
	return checkRepositoryNameScope(pkg.Name, pkg.Repository, spec, repositories,
		fmt.Sprintf("lock packages[%d]", i))
}

func verifyLockPackageRequests(spec *schemaSpec.Spec, packages map[lockPackageKey]*Package) error {
	// One request per package name is already enforced by the specification decoder, so
	// there is one CPE per name to compare the lock against.
	declared := make(map[string]string, len(spec.Contents.Packages))
	for _, request := range spec.Contents.Packages {
		declared[request.Name] = request.CPE
	}
	for _, request := range spec.Contents.Packages {
		for _, platform := range spec.Platforms {
			pkg, ok := packages[lockPackageKey{platform: platform, name: request.Name}]
			if !ok {
				return fmt.Errorf("lock packages: missing direct package %q on %s", request.Name, platform)
			}
			if err := verifyLockPackageRequest(request, pkg, platform); err != nil {
				return err
			}
		}
	}
	return verifyPackageCPEs(declared, packages)
}

// verifyPackageCPEs compares every record with the CPE the requests for its package
// declared, which a dependency has none of.
func verifyPackageCPEs(declared map[string]string, packages map[lockPackageKey]*Package) error {
	for key, pkg := range packages {
		if pkg.CPE != declared[key.name] {
			return fmt.Errorf("lock packages: package %q cpe does not match the specification on %s",
				key.name, key.platform)
		}
	}
	return nil
}

// verifyLockPackageRequest checks one platform's record against the request that asked
// for it: the version it satisfies and the identity the specification declared.
func verifyLockPackageRequest(request contents.PackageRequest, pkg *Package, platform string) error {
	if request.Version != nil && !satisfies(*request.Version, pkg.Version) {
		return fmt.Errorf("lock packages: direct package %q version %q does not satisfy %q on %s",
			request.Name, pkg.Version, *request.Version, platform)
	}
	if pkg.CPE != request.CPE {
		return fmt.Errorf("lock packages: package %q cpe does not match the specification on %s",
			request.Name, platform)
	}
	return nil
}

// satisfies reports whether a locked version is inside a spec's version
// expression. A recorded version that does not parse is not a satisfying one.
func satisfies(expression, version string) bool {
	constraint, err := deb.ParseConstraint(expression)
	if err != nil {
		return false
	}
	parsed, err := deb.ParseVersion(version)
	if err != nil {
		return false
	}
	return constraint.Allows(parsed)
}
