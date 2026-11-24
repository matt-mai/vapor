package lockinput

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func selectSlicedPackages(request *Request, input *catalogueInput, platform string,
	byPackage map[string][]contents.SliceRequest, archives map[string]*archiveSet) ([]sliceSelection, error) {
	architecture, err := request.Provider.Architecture(platform)
	if err != nil {
		return nil, err
	}
	roots, pins := sliceRoots(input, byPackage)
	closure, err := slicespkg.SelectSlices(input.packages, roots, nil, architecture)
	if err != nil {
		return nil, err
	}
	selected, err := slicespkg.SelectPackageOrigins(input.packages, input.catalogue, closure, roots,
		sliceVersions(input, platform, archives), pins)
	if err != nil {
		return nil, err
	}
	result := make([]sliceSelection, 0, len(selected))
	for i := range selected {
		result = append(result, sliceSelection{
			platform: platform, catalogue: input.name, selection: selected[i],
		})
	}
	return result, nil
}

func sliceRoots(input *catalogueInput, byPackage map[string][]contents.SliceRequest) (
	[]slicespkg.SliceKey, map[string]string) {
	var roots []slicespkg.SliceKey
	pins := make(map[string]string)
	for name, requests := range byPackage {
		if _, ok := input.packages[name]; !ok {
			continue
		}
		for _, sliceRequest := range requests {
			roots = append(roots, slicespkg.SliceKey{Package: name, Slice: sliceRequest.Slice})
			if sliceRequest.Version != nil {
				pins[name] = deb.JoinExpressions(pins[name], *sliceRequest.Version)
			}
		}
	}
	return roots, pins
}

func sliceVersions(input *catalogueInput, platform string,
	archives map[string]*archiveSet) map[string][]slicespkg.PackageVersion {
	versions := make(map[string][]slicespkg.PackageVersion)
	for _, archiveName := range slices.Sorted(maps.Keys(input.catalogue.Archives)) {
		set := archives[archiveKey(input.name, archiveName, platform)]
		for _, state := range set.repos {
			for i := range state.packages {
				pkg := &state.packages[i]
				// A slice closure reaches names the spec never listed, so the scope
				// has to be applied here too: otherwise a vendor scoped to one name
				// could supply a dependency of a slice it was not granted.
				if len(state.scope) != 0 && !slices.Contains(state.scope, pkg.Name) {
					continue
				}
				versions[pkg.Name] = append(versions[pkg.Name], slicespkg.PackageVersion{
					Archive: archiveName, Suite: pkg.Origin.Suite, Component: pkg.Origin.Component, Version: pkg.Version,
				})
			}
		}
	}
	return versions
}

type sliceSelection struct {
	platform  string
	catalogue string
	selection slicespkg.PackageSelection
}

func resolveSlicedPackages(ctx context.Context, request *Request, catalogues []*catalogueInput,
	archives map[string]*archiveSet) ([]lock.Slice, error) {
	selections, err := selectAllSlices(request, catalogues, archives)
	if err != nil {
		return nil, err
	}
	payloads, err := slicePayloads(selections, archives)
	if err != nil {
		return nil, err
	}
	if err := acquireGroups(ctx, request, payloads); err != nil {
		return nil, err
	}
	return lockSlices(selections, archives, specCPEs(request.Spec))
}

// specCPEs maps a package to the CPE its slice requests declare. A package's requests
// share one CPE, which the lock verification enforces.
func specCPEs(specification *spec.Spec) map[string]string {
	cpes := make(map[string]string)
	for _, request := range specification.Contents.Slices {
		if request.CPE != "" {
			cpes[request.Package] = request.CPE
		}
	}
	return cpes
}

// selectAllSlices resolves every slice request against repository metadata alone, so a
// caller that only wants the selection pays no payload download.
func selectAllSlices(request *Request, catalogues []*catalogueInput,
	archives map[string]*archiveSet) ([]sliceSelection, error) {
	if len(request.Spec.Contents.Slices) == 0 {
		return nil, nil
	}
	var selections []sliceSelection
	for _, input := range catalogues {
		byPackage := sliceRequestsByPackage(request.Spec, input.name)
		for _, platform := range request.Spec.Platforms {
			selected, err := selectSlicedPackages(request, input, platform, byPackage, archives)
			if err != nil {
				return nil, err
			}
			selections = append(selections, selected...)
		}
	}
	return selections, nil
}

func lockSlices(selections []sliceSelection, archives map[string]*archiveSet,
	cpes map[string]string) ([]lock.Slice, error) {
	result := make([]lock.Slice, 0, len(selections))
	for i := range selections {
		item := &selections[i]
		set := archives[archiveKey(item.catalogue, item.selection.Archive, item.platform)]
		if set == nil {
			return nil, fmt.Errorf("archive %q is not bound", item.selection.Archive)
		}
		pkg, err := slicePackage(set, &item.selection)
		if err != nil {
			return nil, err
		}
		result = append(result, lock.Slice{
			Platform: item.platform, Package: item.selection.RealName, Version: item.selection.Version,
			Architecture: pkg.Architecture, Source: pkg.Source, Catalogue: item.catalogue,
			Archive:    item.selection.Archive,
			Repository: repositoryForSuite(set, item.selection.Suite),
			CPE:        cpes[item.selection.RealName],
			Content:    lock.Content{Path: pkg.Filename, SHA256: pkg.SHA256, Size: pkg.Size},
			Selected:   item.selection.Selected, Closure: item.selection.Closure,
			DefinitionDigest: item.selection.DefinitionDigest,
		})
	}
	return result, nil
}

func repositoryForSuite(set *archiveSet, suite string) string {
	for _, repo := range set.repos {
		if repo.record.Suite == suite {
			return repo.record.ID
		}
	}
	return ""
}

func slicePackage(set *archiveSet, selection *slicespkg.PackageSelection) (deb.Package, error) {
	for _, repo := range set.repos {
		if repo.record.Suite != selection.Suite {
			continue
		}
		for i := range repo.packages {
			pkg := &repo.packages[i]
			if pkg.Name == selection.RealName && pkg.Version == selection.Version && pkg.Origin.Component == selection.Component {
				return *pkg, nil
			}
		}
	}
	return deb.Package{}, fmt.Errorf("package %q version %q has no acquired payload", selection.RealName,
		selection.Version)
}

func slicePayloads(selections []sliceSelection,
	archives map[string]*archiveSet) (map[fetcherKey][]acquire.Package, error) {
	payloads := make(map[fetcherKey][]acquire.Package)
	seen := make(map[string]bool)
	for i := range selections {
		item := &selections[i]
		set := archives[archiveKey(item.catalogue, item.selection.Archive, item.platform)]
		if set == nil {
			return nil, fmt.Errorf("archive %q is not bound", item.selection.Archive)
		}
		pkg, err := slicePackage(set, &item.selection)
		if err != nil {
			return nil, err
		}
		identity := item.platform + "\x00" + pkg.Name
		if seen[identity] {
			continue
		}
		seen[identity] = true
		fetcher := fetcherKey{url: set.binding.URL, restricted: set.binding.Archive.Pro != ""}
		payloads[fetcher] = append(payloads[fetcher], acquire.Package{
			Platform: item.platform, Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Architecture,
			URL:    strings.TrimSuffix(set.binding.URL, "/") + "/" + pkg.Filename,
			SHA256: pkg.SHA256, Size: pkg.Size,
		})
	}
	return payloads, nil
}

func requiredArchives(request *Request, catalogues []*catalogueInput) (map[string]bool, error) {
	whole := make([]string, 0, len(request.Spec.Contents.Packages))
	for _, pkg := range request.Spec.Contents.Packages {
		whole = append(whole, pkg.Name)
	}
	required := make(map[string]bool)
	for _, input := range catalogues {
		byPackage := sliceRequestsByPackage(request.Spec, input.name)
		if err := catalogueRequiredArchives(request, input, byPackage, whole, required); err != nil {
			return nil, err
		}
	}
	return required, nil
}

func sliceRequestsByPackage(specification *spec.Spec, catalogue string) map[string][]contents.SliceRequest {
	byPackage := make(map[string][]contents.SliceRequest)
	for _, sliceRequest := range specification.Contents.Slices {
		if sliceRequest.Catalogue == nil || *sliceRequest.Catalogue != catalogue {
			continue
		}
		byPackage[sliceRequest.Package] = append(byPackage[sliceRequest.Package], sliceRequest)
	}
	return byPackage
}

func catalogueRequiredArchives(request *Request, input *catalogueInput,
	byPackage map[string][]contents.SliceRequest, whole []string, required map[string]bool) error {
	roots, _ := sliceRoots(input, byPackage)
	for _, platform := range request.Spec.Platforms {
		if len(roots) == 0 {
			break
		}
		selected, err := selectedArchives(request, input, roots, whole, platform)
		if err != nil {
			return err
		}
		for _, key := range selected {
			required[archiveKey(input.name, input.packages[key.Package].Archive, platform)] = true
		}
	}
	return nil
}

func selectedArchives(request *Request, input *catalogueInput,
	roots []slicespkg.SliceKey, whole []string, platform string) ([]slicespkg.SliceKey, error) {
	architecture, err := request.Provider.Architecture(platform)
	if err != nil {
		return nil, err
	}
	return slicespkg.SelectSlices(input.packages, roots, whole, architecture)
}
