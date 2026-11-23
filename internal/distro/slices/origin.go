package slices

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	pathpkg "path"
	"slices"
	"sort"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

const definitionDomain = "vapor.lock.slice-definitions.v1"

// PackageVersion is one package version available from a catalogue archive.
type PackageVersion struct {
	Archive   string
	Suite     string
	Component string
	Version   string
}

// PackageSelection records the origin and identity of one selected package.
type PackageSelection struct {
	Package          string
	RealName         string
	Version          string
	Archive          string
	Suite            string
	Component        string
	Selected         []string
	Closure          []string
	DefinitionDigest string
}

// DefinitionDigest returns the selected-definition closure identity of an SDF.
func DefinitionDigest(definitionPath, digest string, size int64, sliceNames []string) (string, error) {
	if definitionPath == "" || pathpkg.IsAbs(definitionPath) || pathpkg.Clean(definitionPath) != definitionPath {
		return "", fmt.Errorf("definition path %q is not a clean relative path", definitionPath)
	}
	if len(digest) != 64 || !isLowerHex(digest) {
		return "", fmt.Errorf("definition digest %q is not a lowercase SHA256", digest)
	}
	if size < 0 {
		return "", fmt.Errorf("definition size %d is negative", size)
	}
	if len(sliceNames) == 0 {
		return "", errors.New("definition closure is empty")
	}
	seen := make(map[string]bool, len(sliceNames))
	for _, name := range sliceNames {
		if !sliceNamePattern.MatchString(name) {
			return "", fmt.Errorf("definition closure has invalid slice name %q", name)
		}
		if seen[name] {
			return "", fmt.Errorf("definition closure repeats slice %q", name)
		}
		seen[name] = true
	}
	payload := struct {
		Path   string   `json:"path"`
		SHA256 string   `json:"sha256"`
		Size   int64    `json:"size"`
		Slices []string `json:"slices"`
	}{definitionPath, digest, size, sliceNames}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode slice definition: %w", err)
	}
	sum := sha256.Sum256(append([]byte(definitionDomain+"\x00"), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// SelectPackageOrigins chooses archive origins and definition identities for a
// dependency-first slice closure.
func SelectPackageOrigins(packages map[string]*Package, catalogue *Catalogue, closure,
	requests []SliceKey, versions map[string][]PackageVersion, pins map[string]string,
) ([]PackageSelection, error) {
	if packages == nil {
		return nil, errors.New("packages must not be nil")
	}
	if catalogue == nil {
		return nil, errors.New("catalogue must not be nil")
	}
	order, grouped, err := groupClosure(packages, closure)
	if err != nil {
		return nil, err
	}
	direct, err := directSelections(packages, requests, grouped)
	if err != nil {
		return nil, err
	}
	result := make([]PackageSelection, 0, len(order))
	for _, name := range order {
		pkg := packages[name]
		origin, err := selectOrigin(pkg, catalogue, versions[pkg.RealName], pins[pkg.Name])
		if err != nil {
			return nil, err
		}
		identity, err := DefinitionDigest(pkg.Path, pkg.SHA256, pkg.Size, grouped[name])
		if err != nil {
			return nil, fmt.Errorf("package %q definition: %w", name, err)
		}
		selected := direct[name]
		if selected == nil {
			selected = []string{}
		}
		result = append(result, PackageSelection{
			Package:          name,
			RealName:         pkg.RealName,
			Version:          origin.Version,
			Archive:          origin.Archive,
			Suite:            origin.Suite,
			Component:        origin.Component,
			Selected:         selected,
			Closure:          grouped[name],
			DefinitionDigest: identity,
		})
	}
	return result, nil
}

func groupClosure(packages map[string]*Package, closure []SliceKey) ([]string, map[string][]string, error) {
	order := make([]string, 0)
	grouped := make(map[string][]string)
	for _, key := range closure {
		if _, ok := packages[key.Package]; !ok {
			return nil, nil, fmt.Errorf("slices of package %q not found", key.Package)
		}
		if _, ok := grouped[key.Package]; !ok {
			order = append(order, key.Package)
		}
		grouped[key.Package] = append(grouped[key.Package], key.Slice)
	}
	return order, grouped, nil
}

func directSelections(packages map[string]*Package, requests []SliceKey,
	grouped map[string][]string,
) (map[string][]string, error) {
	direct := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for _, key := range requests {
		if _, ok := packages[key.Package]; !ok {
			return nil, fmt.Errorf("slices of package %q not found", key.Package)
		}
		if !containsString(grouped[key.Package], key.Slice) {
			return nil, fmt.Errorf("slice %s is not part of the selected closure", key)
		}
		if seen[key.Package] == nil {
			seen[key.Package] = make(map[string]bool)
		}
		if seen[key.Package][key.Slice] {
			continue
		}
		seen[key.Package][key.Slice] = true
		direct[key.Package] = append(direct[key.Package], key.Slice)
	}
	return direct, nil
}

func selectOrigin(pkg *Package, catalogue *Catalogue, versions []PackageVersion,
	pin string,
) (PackageVersion, error) {
	if pkg.Store != "" {
		store, ok := catalogue.Stores[pkg.Store]
		if !ok {
			return PackageVersion{}, fmt.Errorf("package %q uses undeclared store %q", pkg.Name, pkg.Store)
		}
		return PackageVersion{}, fmt.Errorf(
			"package %q from store %q (kind %q, track %q) is not supported",
			pkg.Name, pkg.Store, store.Kind, pkg.DefaultTrack)
	}
	archive, candidates, err := chooseArchive(pkg, catalogue, versions)
	if err != nil {
		return PackageVersion{}, err
	}
	if pin != "" {
		constraint, err := deb.ParseConstraint(pin)
		if err != nil {
			return PackageVersion{}, fmt.Errorf("package %q version constraint %q: %w", pkg.Name, pin, err)
		}
		candidates = filterVersions(candidates, func(candidate PackageVersion) bool {
			version, err := deb.ParseVersion(candidate.Version)
			return err == nil && constraint.Allows(version)
		})
		if len(candidates) == 0 {
			return PackageVersion{}, fmt.Errorf("no version of package %q in archive %q satisfies %q",
				pkg.Name, archive.Name, pin)
		}
	}
	return newestVersion(&archive, candidates)
}

func chooseArchive(pkg *Package, catalogue *Catalogue, versions []PackageVersion) (Archive, []PackageVersion, error) {
	if pkg.Archive != "" {
		return pinnedArchive(pkg, catalogue, versions)
	}
	name, ok := bestArchive(catalogue, versions)
	if !ok {
		return Archive{}, nil, fmt.Errorf("package %q has no candidate in an eligible archive", pkg.Name)
	}
	archive := catalogue.Archives[name]
	candidates := filterVersions(versions, func(candidate PackageVersion) bool {
		return candidate.Archive == name
	})
	return archive, candidates, nil
}

func pinnedArchive(pkg *Package, catalogue *Catalogue, versions []PackageVersion) (Archive, []PackageVersion, error) {
	archive, ok := catalogue.Archives[pkg.Archive]
	if !ok {
		return Archive{}, nil, fmt.Errorf("archive %q is not declared", pkg.Archive)
	}
	candidates := filterVersions(versions, func(candidate PackageVersion) bool {
		return candidate.Archive == pkg.Archive
	})
	if len(candidates) == 0 {
		return Archive{}, nil, fmt.Errorf("package %q is not available in pinned archive %q",
			pkg.Name, pkg.Archive)
	}
	return archive, candidates, nil
}

func bestArchive(catalogue *Catalogue, versions []PackageVersion) (string, bool) {
	best := ""
	for name := range catalogue.Archives {
		archive := catalogue.Archives[name]
		if archive.Priority < 0 || !hasArchiveVersion(versions, name) {
			continue
		}
		if best == "" || archive.Priority > catalogue.Archives[best].Priority ||
			(archive.Priority == catalogue.Archives[best].Priority && name < best) {
			best = name
		}
	}
	return best, best != ""
}

func hasArchiveVersion(versions []PackageVersion, archive string) bool {
	for _, candidate := range versions {
		if candidate.Archive == archive {
			return true
		}
	}
	return false
}

func newestVersion(archive *Archive, candidates []PackageVersion) (PackageVersion, error) {
	ranked := make([]rankedVersion, 0, len(candidates))
	for _, candidate := range candidates {
		position, err := archivePosition(archive, candidate)
		if err != nil {
			return PackageVersion{}, err
		}
		ranked = append(ranked, position)
	}
	sort.Slice(ranked, func(i, j int) bool { return rankedVersionLess(&ranked[i], &ranked[j]) })
	return ranked[0].candidate, nil
}

type rankedVersion struct {
	candidate PackageVersion
	version   deb.Version
	suite     int
	component int
}

func archivePosition(archive *Archive, candidate PackageVersion) (rankedVersion, error) {
	suite, ok := indexOf(archive.Suites, candidate.Suite)
	if !ok {
		return rankedVersion{}, fmt.Errorf("archive %q has unknown suite %q", archive.Name, candidate.Suite)
	}
	component, ok := indexOf(archive.Components, candidate.Component)
	if !ok {
		return rankedVersion{}, fmt.Errorf("archive %q has unknown component %q", archive.Name, candidate.Component)
	}
	version, err := deb.ParseVersion(candidate.Version)
	if err != nil {
		return rankedVersion{}, fmt.Errorf("archive %q has an invalid version %q: %w",
			archive.Name, candidate.Version, err)
	}
	return rankedVersion{candidate, version, suite, component}, nil
}

func rankedVersionLess(left, right *rankedVersion) bool {
	if comparison := left.version.Compare(right.version); comparison != 0 {
		return comparison > 0
	}
	if left.suite != right.suite {
		return left.suite < right.suite
	}
	if left.component != right.component {
		return left.component < right.component
	}
	return left.candidate.Version < right.candidate.Version
}

func filterVersions(versions []PackageVersion, keep func(PackageVersion) bool) []PackageVersion {
	result := make([]PackageVersion, 0, len(versions))
	for _, candidate := range versions {
		if keep(candidate) {
			result = append(result, candidate)
		}
	}
	return result
}

func indexOf(values []string, value string) (int, bool) {
	for i, candidate := range values {
		if candidate == value {
			return i, true
		}
	}
	return 0, false
}

func containsString(values []string, value string) bool {
	return slices.Contains(values, value)
}
