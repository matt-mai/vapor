package slices

import (
	"fmt"
)

type preferGraph struct {
	edges   map[string]map[string]string
	samples map[string]string
}

func buildPrefers(packages map[string]*Package) (*preferGraph, error) {
	graph := &preferGraph{
		edges:   make(map[string]map[string]string),
		samples: make(map[string]string),
	}
	for _, record := range allSlices(packages) {
		for _, path := range sortedKeys(record.slice.Contents) {
			info := record.slice.Contents[path]
			if info.Prefer != "" {
				if err := graph.addPreference(packages, record.key, path, info.Prefer); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := graph.checkCycles(); err != nil {
		return nil, err
	}
	return graph, nil
}

func (g *preferGraph) addPreference(packages map[string]*Package, key SliceKey, path, target string) error {
	if _, ok := packages[target]; !ok {
		return fmt.Errorf("slice %s path %s 'prefer' refers to undefined package %q", key, path, target)
	}
	if target == key.Package {
		return fmt.Errorf("package %q cannot prefer itself for %s", key.Package, path)
	}
	if g.edges[path] == nil {
		g.edges[path] = make(map[string]string)
	}
	edges := g.edges[path]
	if existing, ok := edges[key.Package]; ok && existing != target {
		first, second := sortNames(existing, target)
		return fmt.Errorf("package %q has conflicting prefers for %s: %q != %q",
			key.Package, path, first, second)
	}
	for source, existing := range edges {
		if existing == target && source != key.Package {
			first, second := sortNames(source, key.Package)
			return fmt.Errorf("packages %q and %q cannot both prefer %q for %s",
				first, second, target, path)
		}
	}
	edges[key.Package] = target
	if _, ok := g.samples[path]; !ok {
		g.samples[path] = key.Package
	}
	return nil
}

func (g *preferGraph) checkCycles() error {
	for _, path := range sortedKeys(g.edges) {
		check := &preferCycleCheck{path: path, edges: g.edges[path], state: make(map[string]uint8)}
		for _, pkg := range sortedKeys(g.edges[path]) {
			if check.state[pkg] == 0 {
				if err := check.visit(pkg); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type preferCycleCheck struct {
	path  string
	edges map[string]string
	state map[string]uint8
}

func (check *preferCycleCheck) visit(pkg string) error {
	check.state[pkg] = 1
	next, ok := check.edges[pkg]
	if ok {
		switch check.state[next] {
		case 1:
			return fmt.Errorf("package %q is part of a prefer loop on %s", next, check.path)
		case 0:
			if err := check.visit(next); err != nil {
				return err
			}
		}
	}
	check.state[pkg] = 2
	return nil
}

func (g *preferGraph) resolve(path, first, second string) (bool, error) {
	firstToSecond := g.reaches(path, first, second)
	secondToFirst := g.reaches(path, second, first)
	switch {
	case firstToSecond && secondToFirst:
		return false, fmt.Errorf("package %q is part of a prefer loop on %s", first, path)
	case firstToSecond || secondToFirst:
		return true, nil
	}
	sample, ok := g.samples[path]
	if !ok {
		return false, nil
	}
	conflict := first
	if conflict == sample {
		conflict = second
	}
	a, b := sortNames(conflict, sample)
	return false, fmt.Errorf("package %q and %q conflict on %s without prefer relationship", a, b, path)
}

// preferred returns the package that wins a path among two selected providers.
// A preference only decides between packages that both declare the path; it
// never selects a package that the image does not already contain.
func (g *preferGraph) preferred(path, first, second string) (string, error) {
	if first == second {
		return first, nil
	}
	firstToSecond := g.reaches(path, first, second)
	secondToFirst := g.reaches(path, second, first)
	switch {
	case firstToSecond && secondToFirst:
		return "", fmt.Errorf("package %q is part of a prefer loop on %s", first, path)
	case firstToSecond:
		return second, nil
	case secondToFirst:
		return first, nil
	}
	// No preference reaches either package, so the caller decides whether the
	// declarations may still be shared.
	return "", nil
}

// selectionPreferences resolves exact-path preferences among the selected
// slices. It returns the package that provides each contested path. A preference
// only decides between selected packages that both declare the path; it never
// adds a package to the selection, and a path nobody prefers keeps the ordinary
// collision rules.
//
// The traversal uses the catalogue's preference graph, so a chain that runs
// through a provider the image does not contain still decides between the two that
// it does. Only the competing providers are restricted to the selection.
func selectionPreferences(selected []Slice, architecture string,
	catalogue map[string]*Package) (map[string]string, error) {
	graph := &preferGraph{edges: make(map[string]map[string]string)}
	if catalogue != nil {
		built, err := buildPrefers(catalogue)
		if err != nil {
			return nil, err
		}
		graph = built
	}
	claims := &selectionClaims{
		graph:    graph,
		declared: make(map[string][]string),
	}
	for i := range selected {
		claims.collect(&selected[i], architecture)
	}
	preferred := make(map[string]string)
	for _, path := range sortedKeys(claims.declared) {
		if len(claims.declared[path]) < 2 {
			continue
		}
		// A path is contested when any package in the catalogue prefers a provider
		// for it, not only when a selected declaration carries the preference: the
		// preference may live in a slice the image does not select, and application
		// order must not decide the winner in that case either.
		if len(claims.graph.edges[path]) == 0 {
			continue
		}
		winner, err := claims.decide(path)
		if err != nil {
			return nil, err
		}
		preferred[path] = winner
	}
	return preferred, nil
}

// selectionClaims records which selected packages declare which paths.
type selectionClaims struct {
	graph    *preferGraph
	declared map[string][]string
}

func (c *selectionClaims) collect(slice *Slice, architecture string) {
	for _, path := range sortedKeys(slice.Contents) {
		info := slice.Contents[path]
		if hasGlob(path) || !architectureIncluded(info.Arch, architecture) {
			continue
		}
		c.declared[path] = appendPackage(c.declared[path], slice.Package)
		if info.Prefer == "" {
			continue
		}
		// The selected declaration's own preference joins the catalogue graph, so a
		// chain through an unselected provider is still traversable.
		if c.graph.edges[path] == nil {
			c.graph.edges[path] = make(map[string]string)
		}
		c.graph.edges[path][slice.Package] = info.Prefer
	}
}

// decide returns the package that provides a contested path. A path that some
// package prefers must be decided by the preference chain, never by application
// order.
func (c *selectionClaims) decide(path string) (string, error) {
	packages := c.declared[path]
	winner := packages[0]
	for _, other := range packages[1:] {
		chosen, err := c.graph.preferred(path, winner, other)
		if err != nil {
			return "", err
		}
		if chosen == "" {
			first, second := sortNames(winner, other)
			return "", fmt.Errorf("package %q and %q conflict on %s without prefer relationship",
				first, second, path)
		}
		winner = chosen
	}
	return winner, nil
}

// appendPackage adds a package to a sorted unique list.
func appendPackage(packages []string, pkg string) []string {
	if len(packages) > 0 && packages[len(packages)-1] == pkg {
		return packages
	}
	return append(packages, pkg)
}

func (g *preferGraph) reaches(path, from, to string) bool {
	current := from
	for range len(g.edges[path]) {
		next, ok := g.edges[path][current]
		if !ok {
			return false
		}
		if next == to {
			return true
		}
		current = next
	}
	return false
}

func sortNames(first, second string) (string, string) {
	if first > second {
		return second, first
	}
	return first, second
}

func validatePreferTargets(paths map[string][]contentOccurrence, prefers *preferGraph) error {
	for _, path := range sortedKeys(prefers.edges) {
		for _, source := range sortedKeys(prefers.edges[path]) {
			target := prefers.edges[path][source]
			if !pathHasPackage(paths[path], target) {
				return fmt.Errorf("package %s prefers package %q which does not contain path %s",
					source, target, path)
			}
		}
	}
	return nil
}

func pathHasPackage(occurrences []contentOccurrence, pkg string) bool {
	for i := range occurrences {
		if occurrences[i].key.Package == pkg {
			return true
		}
	}
	return false
}
