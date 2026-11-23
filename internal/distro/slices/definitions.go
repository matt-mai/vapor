package slices

import (
	"fmt"
	"maps"
	"slices"
)

// NamedPackageDefinitions identifies the catalogue that supplied a set of packages.
type NamedPackageDefinitions struct {
	Catalogue string
	Packages  map[string]*Package
}

// MergePackageDefinitions combines catalogues that define disjoint package names.
func MergePackageDefinitions(catalogues []NamedPackageDefinitions) (map[string]*Package, error) {
	packages := make(map[string]*Package)
	owners := make(map[string]string)
	for _, catalogue := range catalogues {
		for _, name := range slices.Sorted(maps.Keys(catalogue.Packages)) {
			if owner, ok := owners[name]; ok {
				return nil, fmt.Errorf("catalogue package %q is defined by both %q and %q", name, owner, catalogue.Catalogue)
			}
			owners[name] = catalogue.Catalogue
			packages[name] = catalogue.Packages[name]
		}
	}
	return packages, nil
}
