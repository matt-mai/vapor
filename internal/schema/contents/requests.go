package contents

import (
	"errors"
	"fmt"
	"slices"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/base"
)

// Validate checks declared repositories, catalogues, requests and artifacts.
func Validate(contents *Contents, platforms []string) error {
	if err := validateRepositories(contents.Repositories, platforms); err != nil {
		return err
	}
	if err := validateCatalogues(contents); err != nil {
		return err
	}
	if err := validateRequests(contents); err != nil {
		return err
	}
	return validateArtifacts(contents.Artifacts, platforms)
}

func validateRequests(contents *Contents) error {
	whole, err := validateWholePackages(contents.Packages)
	if err != nil {
		return err
	}
	seen, pins := make(map[string]bool), make(map[string]string)
	cpes := make(map[string]string)
	for i, request := range contents.Slices {
		if whole[request.Package] {
			return errors.New("whole-package/slice overlap is not allowed")
		}
		key := request.Package + "/" + request.Slice
		if seen[key] {
			return errors.New("duplicate slice request")
		}
		seen[key] = true
		if err := validateSlice(request, contents.Catalogues, pins); err != nil {
			return fmt.Errorf("contents.slices[%d]: %w", i, err)
		}
		if err := agreeOnCPE(cpes, request.Package, request.CPE); err != nil {
			return fmt.Errorf("contents.slices[%d]: %w", i, err)
		}
	}
	return nil
}

// agreeOnCPE holds every request for one package to the same declared CPE, including the
// requests that declare none. One package is one element in the attestation document, so
// a name only some of its requests state would attribute the package to an identity the
// others never asked for; an omission beside a declaration is the same disagreement as
// two different names.
func agreeOnCPE(declared map[string]string, name, cpe string) error {
	first, seen := declared[name]
	if !seen {
		declared[name] = cpe
		return nil
	}
	if first != cpe {
		return fmt.Errorf("requests for %q declare different CPEs", name)
	}
	return nil
}

// validateWholePackages checks the whole-package requests and returns the names they
// claim, which a slice request may not take as well.
func validateWholePackages(packages []PackageRequest) (map[string]bool, error) {
	whole := make(map[string]bool, len(packages))
	for i, request := range packages {
		if whole[request.Name] {
			return nil, errors.New("duplicate whole package request")
		}
		whole[request.Name] = true
		if err := validateWholePackage(request); err != nil {
			return nil, fmt.Errorf("contents.packages[%d]: %w", i, err)
		}
	}
	return whole, nil
}

func validateWholePackage(request PackageRequest) error {
	if err := validatePackageRequest(request.Name, request.Version); err != nil {
		return err
	}
	return ValidateDeclaredCPE(request.CPE)
}

func validateSlice(request SliceRequest, catalogues []CatalogueSource, pins map[string]string) error {
	if err := validatePackageRequest(request.Package, request.Version); err != nil {
		return err
	}
	if err := ValidateDeclaredCPE(request.CPE); err != nil {
		return err
	}
	if err := base.RequirePattern("slice name", request.Slice, `^[a-z](?:-?[a-z0-9]){2,}$`); err != nil {
		return err
	}
	if request.Catalogue == nil || !slices.ContainsFunc(catalogues,
		func(source CatalogueSource) bool { return source.Name == *request.Catalogue }) {
		return errors.New("slice requires an unambiguous declared catalogue")
	}
	if request.Version != nil {
		pins[request.Package] = deb.JoinExpressions(pins[request.Package], *request.Version)
	}
	return nil
}

// validatePackageRequest checks a package name and, when present, its version
// expression against the distribution's grammar, since only the distribution
// knows what one of its versions looks like.
func validatePackageRequest(name string, version *string) error {
	if err := base.ValidatePackageVersion(name, version); err != nil || version == nil {
		return err
	}
	if _, err := deb.ParseConstraint(*version); err != nil {
		return fmt.Errorf("package %q: %w", name, err)
	}
	return nil
}
