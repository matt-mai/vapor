package lock

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

type lockSliceKey struct {
	platform string
	pkg      string
}

type sliceExpectation struct {
	names     []string
	catalogue string
	version   string
	cpe       string
}

func verifyLockSlices(spec *schemaSpec.Spec, lock *Lockfile, repositories map[string]*Repository,
	catalogues map[string]*Catalogue, packages map[lockPackageKey]*Package,
	provider *DefaultRepository) (map[lockSliceKey]*Slice, error) {
	declaredCatalogues := make(map[string]contents.CatalogueSource)
	for i := range spec.Contents.Catalogues {
		declaredCatalogues[spec.Contents.Catalogues[i].Name] = spec.Contents.Catalogues[i]
	}
	expected, err := sliceExpectations(spec)
	if err != nil {
		return nil, err
	}
	if len(expected) == 0 && len(lock.Slices) != 0 {
		return nil, errors.New("lock slices: no sliced packages were requested")
	}
	slicesByKey := make(map[lockSliceKey]*Slice)
	for i := range lock.Slices {
		slice := &lock.Slices[i]
		key, err := verifyLockSlice(slice, spec, declaredCatalogues, catalogues, repositories, expected, provider, i)
		if err != nil {
			return nil, err
		}
		if _, ok := slicesByKey[key]; ok {
			return nil, fmt.Errorf("lock slices[%d]: duplicate platform and package", i)
		}
		if _, ok := packages[lockPackageKey{platform: slice.Platform, name: slice.Package}]; ok {
			return nil, fmt.Errorf("lock slices[%d]: package %q is also selected whole", i, slice.Package)
		}
		slicesByKey[key] = slice
	}
	return slicesByKey, verifyLockSliceRequests(spec, expected, slicesByKey)
}

func verifyLockSlice(slice *Slice, spec *schemaSpec.Spec, declaredCatalogues map[string]contents.CatalogueSource,
	catalogues map[string]*Catalogue, repositories map[string]*Repository,
	expected map[string]sliceExpectation, provider *DefaultRepository, i int) (lockSliceKey, error) {
	native, ok := nativeArchitecture(slice.Platform)
	if !ok || !slices.Contains(spec.Platforms, slice.Platform) {
		return lockSliceKey{}, fmt.Errorf("lock slices[%d]: platform is not a spec platform", i)
	}
	if slice.Architecture != architectureAll && slice.Architecture != native {
		return lockSliceKey{}, fmt.Errorf("lock slices[%d]: architecture is not all or native", i)
	}
	if err := verifyLockSliceRecord(slice, i); err != nil {
		return lockSliceKey{}, err
	}
	if err := verifySliceCatalogue(slice, declaredCatalogues, catalogues, repositories, provider, i); err != nil {
		return lockSliceKey{}, err
	}
	if err := checkRepositoryNameScope(slice.Package, slice.Repository, spec, repositories,
		fmt.Sprintf("lock slices[%d]", i)); err != nil {
		return lockSliceKey{}, err
	}
	if err := verifySliceExpectation(slice, expected, i); err != nil {
		return lockSliceKey{}, err
	}
	return lockSliceKey{platform: slice.Platform, pkg: slice.Package}, nil
}

// verifyLockSliceRecord checks what a slice record must state on its own, before anything
// about the specification it was locked from is considered.
func verifyLockSliceRecord(slice *Slice, i int) error {
	version := slice.Version
	if err := base.ValidatePackageVersion(slice.Package, &version); err != nil {
		return fmt.Errorf("lock slices[%d]: %w", i, err)
	}
	if err := verifyLockContent("slice", slice.Content); err != nil {
		return fmt.Errorf("lock slices[%d]: %w", i, err)
	}
	if err := verifyLocksource(slice.Source, fmt.Sprintf("lock slices[%d]", i)); err != nil {
		return err
	}
	if err := contents.ValidateDeclaredCPE(slice.CPE); err != nil {
		return fmt.Errorf("lock slices[%d]: %w", i, err)
	}
	if err := verifyLockSliceNames(slice.Selected, slice.Closure); err != nil {
		return fmt.Errorf("lock slices[%d]: %w", i, err)
	}
	if err := checkLockDerived("lock slice definition digest", slice.DefinitionDigest); err != nil {
		return fmt.Errorf("lock slices[%d]: %w", i, err)
	}
	return nil
}

func verifySliceCatalogue(slice *Slice, declaredCatalogues map[string]contents.CatalogueSource,
	catalogues map[string]*Catalogue, repositories map[string]*Repository,
	provider *DefaultRepository, i int) error {
	if _, exists := catalogues[slice.Catalogue]; !exists {
		return fmt.Errorf("lock slices[%d]: dangling catalogue reference", i)
	}
	if err := validateLockArchive(slice.Archive); err != nil {
		return fmt.Errorf("lock slices[%d]: %w", i, err)
	}
	repository, ok := repositories[slice.Repository]
	if !ok {
		return fmt.Errorf("lock slices[%d]: dangling repository reference", i)
	}
	declared := declaredCatalogues[slice.Catalogue]
	bound, isBound := declared.Archives[slice.Archive]
	if isBound && repository.Name != bound {
		return fmt.Errorf("lock slices[%d]: repository does not match catalogue archive binding", i)
	}
	// A provider archive stays usable beside bound ones: it needs no declaration
	// because the provider supplies its endpoint and trust.
	if !isBound && len(declared.Archives) != 0 && (provider == nil || repository.Name != provider.Name) {
		return fmt.Errorf("lock slices[%d]: archive is not bound by the catalogue", i)
	}
	if repository.Platform != slice.Platform || (slice.Architecture != architectureAll &&
		slice.Architecture != repository.Architecture) {
		return fmt.Errorf("lock slices[%d]: repository platform or architecture mismatch", i)
	}
	return checkEffectiveBinding(slice, repository, provider, i)
}

// checkEffectiveBinding compares the slice's repository with the binding the verified
// catalogue declares for its archive: the same repository, and the archive's own
// suites and components. Authenticating a package against an index proves where it came
// from, not that the catalogue allowed that source, so the agreement is checked on its
// own. Slices are refused when the caller could not rebuild the bindings at all: a
// check that silently passes because nothing was rebuilt protects nothing.
func checkEffectiveBinding(slice *Slice, repository *Repository, provider *DefaultRepository, i int) error {
	if provider == nil {
		return fmt.Errorf("lock slices[%d]: no provider bindings are configured", i)
	}
	if !provider.Covered[slice.Catalogue] {
		return fmt.Errorf("lock slices[%d]: catalogue %q has no verified binding", i, slice.Catalogue)
	}
	binding, ok := provider.Bindings[BindingKey(slice.Catalogue, slice.Archive, slice.Platform)]
	if !ok {
		return fmt.Errorf("lock slices[%d]: archive %q on %s has no effective binding", i, slice.Archive,
			slice.Platform)
	}
	if repository.Name != binding.Repository {
		return fmt.Errorf("lock slices[%d]: repository %q is not the archive's binding %q", i,
			repository.Name, binding.Repository)
	}
	if !slices.Contains(binding.Suites, repository.Suite) {
		return fmt.Errorf("lock slices[%d]: repository suite %q is not a suite of archive %q", i,
			repository.Suite, slice.Archive)
	}
	components := make([]string, len(repository.Indexes))
	for j := range repository.Indexes {
		components[j] = repository.Indexes[j].Component
	}
	for _, component := range components {
		if !listsComponent(binding.Components, component) {
			return fmt.Errorf("lock slices[%d]: repository component %q is not a component of archive %q", i,
				component, slice.Archive)
		}
	}
	return nil
}

// listsComponent reports whether a component is declared, allowing the updates/ prefix
// Debian security metadata uses for its main component.
func listsComponent(components []string, component string) bool {
	if slices.Contains(components, component) {
		return true
	}
	for _, declared := range components {
		prefix, name, ok := strings.Cut(declared, "/")
		if ok && prefix != "" && !strings.Contains(name, "/") && name == component {
			return true
		}
	}
	return false
}

func verifySliceExpectation(slice *Slice, expected map[string]sliceExpectation, i int) error {
	want, ok := expected[slice.Package]
	if !ok {
		if len(slice.Selected) != 0 {
			return fmt.Errorf("lock slices[%d]: unrequested package has selected slices", i)
		}
		return nil
	}
	if slice.Catalogue != want.catalogue || !slices.Equal(slice.Selected, want.names) {
		return fmt.Errorf("lock slices[%d]: selected definitions do not match the spec requests", i)
	}
	if slice.CPE != want.cpe {
		return fmt.Errorf("lock slices[%d]: cpe does not match the specification", i)
	}
	return nil
}

func verifyLockSliceRequests(spec *schemaSpec.Spec, expected map[string]sliceExpectation,
	slicesByKey map[lockSliceKey]*Slice) error {
	for name, want := range expected {
		for _, platform := range spec.Platforms {
			slice, ok := slicesByKey[lockSliceKey{platform: platform, pkg: name}]
			if !ok {
				return fmt.Errorf("lock slices: missing direct slice package %q on %s", name, platform)
			}
			if want.version != "" && !satisfies(want.version, slice.Version) {
				return fmt.Errorf("lock slices: package %q version %q does not satisfy %q on %s",
					name, slice.Version, want.version, platform)
			}
		}
	}
	return nil
}

func sliceExpectations(spec *schemaSpec.Spec) (map[string]sliceExpectation, error) {
	expected := make(map[string]sliceExpectation)
	for _, request := range spec.Contents.Slices {
		want, seen := expected[request.Package]
		want, err := mergeSliceExpectation(want, request, seen)
		if err != nil {
			return nil, err
		}
		expected[request.Package] = want
	}
	return expected, nil
}

// mergeSliceExpectation folds one slice request into what the package's earlier requests
// already asked for. Two requests for one package have to agree on the catalogue and the
// declared CPE, because one package is one element in the document.
func mergeSliceExpectation(want sliceExpectation, request contents.SliceRequest,
	seen bool) (sliceExpectation, error) {
	if request.Catalogue == nil {
		return want, errors.New("lock slices: spec slice request has no catalogue")
	}
	if !seen {
		want = sliceExpectation{catalogue: *request.Catalogue}
	} else if want.catalogue != *request.Catalogue {
		return want, errors.New("lock slices: requests for one package use multiple catalogues")
	}
	want.names = append(want.names, request.Slice)
	if request.Version != nil {
		want.version = deb.JoinExpressions(want.version, *request.Version)
	}
	if request.CPE != "" {
		if want.cpe != "" && want.cpe != request.CPE {
			return want, fmt.Errorf("lock slices: requests for %q declare different CPEs",
				request.Package)
		}
		want.cpe = request.CPE
	}
	return want, nil
}

func verifyLockSliceNames(selected, closure []string) error {
	if _, err := sliceNameSet(selected, "selected slice"); err != nil {
		return err
	}
	if len(closure) == 0 {
		return errors.New("closure must not be empty")
	}
	closureSeen, err := sliceNameSet(closure, "closure slice")
	if err != nil {
		return err
	}
	for _, name := range selected {
		if !closureSeen[name] {
			return errors.New("closure does not contain every selected slice")
		}
	}
	return nil
}

func sliceNameSet(names []string, kind string) (map[string]bool, error) {
	seen := make(map[string]bool)
	for _, name := range names {
		if err := base.RequirePattern("slice name", name, `^[a-z](?:-?[a-z0-9]){2,}$`); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate %s", kind)
		}
		seen[name] = true
	}
	return seen, nil
}

func verifyLockRepositoryReferences(repositories map[string]*Repository, packages map[lockPackageKey]*Package,
	slicesByKey map[lockSliceKey]*Slice) error {
	used := make(map[string]bool)
	for _, pkg := range packages {
		used[pkg.Repository] = true
	}
	for _, slice := range slicesByKey {
		used[slice.Repository] = true
	}
	for id := range repositories {
		if !used[id] {
			return fmt.Errorf("lock repository %s is not referenced by a package or slice", id)
		}
	}
	return nil
}
