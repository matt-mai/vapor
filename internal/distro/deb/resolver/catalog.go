// Package resolver selects whole packages and their slice closures for one
// platform. Selection is pure: it never fetches indexes or package archives.
package resolver

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

const architectureAll = "all"

// Index is one authenticated, decoded package index for a target platform.
// Priority is the configured source priority; higher values win.
type Index struct {
	Repository   string
	Priority     int
	Platform     string
	Architecture string
	Packages     []deb.Package
	// Scope names the packages this index may supply. A vendor archive is scoped
	// to what it was declared for, so adding it cannot replace an unrelated base
	// package. Empty means every package in the index is eligible.
	Scope []string
}

// Candidate is one package record with its source and parsed relations.
type Candidate struct {
	deb.Package
	Repository    string
	Priority      int
	ParsedVersion deb.Version
	PreDepends    []deb.RelationClause
	Depends       []deb.RelationClause
	Provides      []deb.Relation
	Conflicts     []deb.Relation
	Breaks        []deb.Relation
}

// Catalog is the deterministic candidate universe for one platform.
type Catalog struct {
	platform     string
	architecture string
	packages     map[string][]Candidate
	providers    map[string][]Candidate
}

// NewCatalog ranks every package in the indexes and applies the user's version
// constraints. A constraint keeps every candidate it allows and is only valid
// for a real package name. Candidates for one name stay ranked so the solver can
// backtrack; only one version may be selected in a final result.
func NewCatalog(indexes []Index, pins map[string]string) (*Catalog, error) {
	platform, architecture, err := catalogHeader(indexes)
	if err != nil {
		return nil, err
	}
	packages := make(map[string][]Candidate)
	for i := range indexes {
		if err := addIndex(packages, &indexes[i], platform, architecture); err != nil {
			return nil, err
		}
	}
	for name := range packages {
		slices.SortFunc(packages[name], func(a, b Candidate) int { return compareCandidates(&a, &b) })
	}
	if err := applyPins(packages, pins); err != nil {
		return nil, err
	}
	providers := buildProviders(packages)
	return &Catalog{
		platform:     platform,
		architecture: architecture,
		packages:     packages,
		providers:    providers,
	}, nil
}

func catalogHeader(indexes []Index) (string, string, error) {
	if len(indexes) == 0 {
		return "", "", errors.New("candidate catalog requires at least one package index")
	}
	platform, architecture := indexes[0].Platform, indexes[0].Architecture
	if platform == "" || architecture == "" || architecture == architectureAll {
		return "", "", errors.New("candidate catalog requires a platform and native architecture")
	}
	return platform, architecture, nil
}

func addIndex(packages map[string][]Candidate, index *Index, platform, architecture string) error {
	if index.Repository == "" {
		return errors.New("candidate index has no repository name")
	}
	if index.Platform != platform || index.Architecture != architecture {
		return errors.New("candidate indexes must share one platform and native architecture")
	}
	for i := range index.Packages {
		pkg := &index.Packages[i]
		if !inScope(index.Scope, pkg.Name) {
			continue
		}
		candidate, err := newCandidate(pkg, index.Repository, index.Priority, architecture)
		if err != nil {
			return fmt.Errorf("repository %q: %w", index.Repository, err)
		}
		packages[pkg.Name] = append(packages[pkg.Name], candidate)
	}
	return nil
}

// inScope reports whether an index may supply the name. An empty scope admits every
// name, which is what a base archive needs.
func inScope(scope []string, name string) bool {
	return len(scope) == 0 || slices.Contains(scope, name)
}

func buildProviders(packages map[string][]Candidate) map[string][]Candidate {
	providers := make(map[string][]Candidate)
	for _, candidates := range packages {
		for i := range candidates {
			candidate := &candidates[i]
			seen := make(map[string]bool, len(candidate.Provides))
			for _, provide := range candidate.Provides {
				if seen[provide.Name] {
					continue
				}
				seen[provide.Name] = true
				providers[provide.Name] = append(providers[provide.Name], *candidate)
			}
		}
	}
	for name := range providers {
		slices.SortFunc(providers[name], func(a, b Candidate) int { return compareCandidates(&a, &b) })
	}
	return providers
}

func newCandidate(pkg *deb.Package, repository string, priority int, native string) (Candidate, error) {
	if pkg.Architecture != native && pkg.Architecture != architectureAll {
		return Candidate{}, fmt.Errorf("candidate %q has unsupported architecture %q", pkg.Name, pkg.Architecture)
	}
	if pkg.Origin.Suite == "" || pkg.Origin.Component == "" {
		return Candidate{}, fmt.Errorf("candidate %q has an incomplete origin", pkg.Name)
	}
	version, err := deb.ParseVersion(pkg.Version)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate %q has an invalid version: %w", pkg.Name, err)
	}
	preDepends, err := parseClauses(pkg.Relations.PreDepends, native, deb.ParseDependencyList)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate %q has invalid pre-depends: %w", pkg.Name, err)
	}
	depends, err := parseClauses(pkg.Relations.Depends, native, deb.ParseDependencyList)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate %q has invalid depends: %w", pkg.Name, err)
	}
	provides, err := parseRelations(pkg.Relations.Provides, native, deb.ParseProvidesList)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate %q has invalid provides: %w", pkg.Name, err)
	}
	conflicts, err := parseRelations(pkg.Relations.Conflicts, native, deb.ParseConflictList)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate %q has invalid conflicts: %w", pkg.Name, err)
	}
	breaks, err := parseRelations(pkg.Relations.Breaks, native, deb.ParseConflictList)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate %q has invalid breaks: %w", pkg.Name, err)
	}
	return Candidate{
		Package:       *pkg,
		Repository:    repository,
		Priority:      priority,
		ParsedVersion: version,
		PreDepends:    preDepends,
		Depends:       depends,
		Provides:      provides,
		Conflicts:     conflicts,
		Breaks:        breaks,
	}, nil
}

func parseClauses(values []string, native string,
	parse func(string, string) ([]deb.RelationClause, error)) ([]deb.RelationClause, error) {
	var clauses []deb.RelationClause
	for _, value := range values {
		parsed, err := parse(value, native)
		if err != nil {
			return nil, err
		}
		clauses = append(clauses, parsed...)
	}
	return clauses, nil
}

func parseRelations(values []string, native string,
	parse func(string, string) ([]deb.RelationClause, error)) ([]deb.Relation, error) {
	clauses, err := parseClauses(values, native, parse)
	if err != nil {
		return nil, err
	}
	relations := make([]deb.Relation, 0, len(clauses))
	for _, clause := range clauses {
		if len(clause) != 1 {
			return nil, errors.New("relation clause has alternatives")
		}
		relations = append(relations, clause[0])
	}
	return relations, nil
}

func applyPins(packages map[string][]Candidate, pins map[string]string) error {
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		pin := pins[name]
		constraint, err := deb.ParseConstraint(pin)
		if err != nil {
			return fmt.Errorf("version constraint for %q: %w", name, err)
		}
		var matched []Candidate
		for i := range packages[name] {
			if constraint.Allows(packages[name][i].ParsedVersion) {
				matched = append(matched, packages[name][i])
			}
		}
		if len(matched) == 0 {
			return fmt.Errorf("version constraint %q for %q matches no candidate", pin, name)
		}
		packages[name] = matched
	}
	return nil
}

func compareCandidates(a, b *Candidate) int {
	if a.Priority != b.Priority {
		return cmp.Compare(b.Priority, a.Priority)
	}
	if diff := a.ParsedVersion.Compare(b.ParsedVersion); diff != 0 {
		return -diff
	}
	if diff := strings.Compare(a.Repository, b.Repository); diff != 0 {
		return diff
	}
	if diff := strings.Compare(a.Origin.Suite, b.Origin.Suite); diff != 0 {
		return diff
	}
	if diff := strings.Compare(a.Origin.Component, b.Origin.Component); diff != 0 {
		return diff
	}
	if a.Architecture != b.Architecture {
		if a.Architecture == architectureAll {
			return 1
		}
		if b.Architecture == architectureAll {
			return -1
		}
		return strings.Compare(a.Architecture, b.Architecture)
	}
	if diff := strings.Compare(a.Filename, b.Filename); diff != 0 {
		return diff
	}
	return strings.Compare(a.SHA256, b.SHA256)
}

// Candidates returns real package candidates ranked best first.
func (c *Catalog) Candidates(name string) []Candidate { return slices.Clone(c.packages[name]) }

// Providers returns packages providing a virtual name, ranked best first.
func (c *Catalog) Providers(name string) []Candidate { return slices.Clone(c.providers[name]) }
