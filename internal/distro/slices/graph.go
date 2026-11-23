package slices

import (
	"fmt"
	"sort"
	"strings"
)

// ValidatePackages checks catalogue-wide dependency, path and preference
// consistency. It does not select slices or resolve paths against archives.
func ValidatePackages(packages map[string]*Package) error {
	paths := collectPaths(packages)
	prefers, err := buildPrefers(packages)
	if err != nil {
		return err
	}
	if err := validateEssentials(packages); err != nil {
		return err
	}
	if err := validateExactConflicts(paths, prefers); err != nil {
		return err
	}
	if err := validatePreferTargets(paths, prefers); err != nil {
		return err
	}
	return validateOverlappingConflicts(paths)
}

type contentOccurrence struct {
	key  SliceKey
	info PathInfo
}

func collectPaths(packages map[string]*Package) map[string][]contentOccurrence {
	paths := make(map[string][]contentOccurrence)
	for _, record := range allSlices(packages) {
		for _, path := range sortedKeys(record.slice.Contents) {
			info := record.slice.Contents[path]
			paths[path] = append(paths[path], contentOccurrence{key: record.key, info: info})
		}
	}
	for path := range paths {
		sort.Slice(paths[path], func(i, j int) bool {
			a, b := paths[path][i].key, paths[path][j].key
			if a.Package != b.Package {
				return a.Package < b.Package
			}
			return a.Slice < b.Slice
		})
	}
	return paths
}

func validateExactConflicts(paths map[string][]contentOccurrence, prefers *preferGraph) error {
	for _, path := range sortedKeys(paths) {
		occurrences := paths[path]
		for i := range occurrences {
			for j := i + 1; j < len(occurrences); j++ {
				if err := exactConflict(path, &occurrences[i], &occurrences[j], prefers); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func exactConflict(path string, a, b *contentOccurrence, prefers *preferGraph) error {
	if a.key.Package != b.key.Package {
		resolved, err := prefers.resolve(path, a.key.Package, b.key.Package)
		if err != nil {
			return err
		}
		if resolved {
			return nil
		}
	}
	if a.info.SameContent(&b.info) && !extractedAcrossPackages(a, b) {
		return nil
	}
	first, second := slicesPair(a.key, b.key)
	return fmt.Errorf("slices %s and %s conflict on %s", first, second, path)
}

func bothExtracted(a, b *PathInfo) bool {
	return (a.Kind == PathCopy || a.Kind == PathGlob) && (b.Kind == PathCopy || b.Kind == PathGlob)
}

func extractedAcrossPackages(a, b *contentOccurrence) bool {
	return a.key.Package != b.key.Package &&
		(a.info.Kind == PathCopy || a.info.Kind == PathGlob ||
			b.info.Kind == PathCopy || b.info.Kind == PathGlob)
}

func slicesPair(a, b SliceKey) (SliceKey, SliceKey) {
	if a.Package > b.Package || (a.Package == b.Package && a.Slice > b.Slice) {
		return b, a
	}
	return a, b
}

func validateOverlappingConflicts(paths map[string][]contentOccurrence) error {
	names := sortedKeys(paths)
	for i := range names {
		if !hasGlob(names[i]) {
			continue
		}
		for j := range names {
			if i == j || !globIntersects(names[i], names[j]) {
				continue
			}
			if err := overlapConflict(names[i], names[j], paths[names[i]], paths[names[j]]); err != nil {
				return err
			}
		}
	}
	return nil
}

func overlapConflict(pathA, pathB string, aList, bList []contentOccurrence) error {
	first, second := pathA, pathB
	if first > second {
		first, second = second, first
	}
	for i := range aList {
		for j := range bList {
			a, b := aList[i], bList[j]
			if a.key.Package == b.key.Package && bothExtracted(&a.info, &b.info) {
				continue
			}
			sa, sb := slicesPair(a.key, b.key)
			return fmt.Errorf("slices %s and %s conflict on %s and %s", sa, sb, first, second)
		}
	}
	return nil
}

func hasGlob(path string) bool {
	return strings.ContainsAny(path, "*?")
}
