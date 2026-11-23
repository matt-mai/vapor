package resolver

import (
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func (solver *solver) satisfies(clause deb.RelationClause) bool {
	for _, name := range solver.order {
		if !solver.spendWork() {
			return true
		}
		candidate := solver.selected[name]
		for i := range clause {
			matched, ok := solver.candidateSatisfies(&clause[i], &candidate)
			if !ok {
				return true
			}
			if matched {
				return true
			}
		}
	}
	return false
}
func (solver *solver) conflict(candidate *Candidate) error {
	for _, name := range solver.order {
		if !solver.spendWork() {
			return nil
		}
		other := solver.selected[name]
		if other.Name == candidate.Name {
			continue
		}
		conflict, err := solver.conflictsWith(candidate, &other)
		if err != nil {
			return err
		}
		if conflict || solver.aborted {
			return nil
		}
	}
	return nil
}
func (solver *solver) conflictsWith(a, b *Candidate) (bool, error) {
	for _, pair := range [][2]*Candidate{{a, b}, {b, a}} {
		conflict, err := solver.conflictBetween(pair[0], pair[1])
		if err != nil {
			return false, err
		}
		if conflict {
			return true, nil
		}
	}
	return false, nil
}
func (solver *solver) conflictBetween(a, b *Candidate) (bool, error) {
	for i := range a.Conflicts {
		matched, ok := solver.candidateSatisfies(&a.Conflicts[i], b)
		if !ok {
			return false, nil
		}
		if matched {
			return true, fmt.Errorf("%s conflicts with %s", formatCandidate(a), formatCandidate(b))
		}
	}
	for i := range a.Breaks {
		matched, ok := solver.candidateSatisfies(&a.Breaks[i], b)
		if !ok {
			return false, nil
		}
		if matched {
			return true, fmt.Errorf("%s breaks %s", formatCandidate(a), formatCandidate(b))
		}
	}
	return false, nil
}

// architectureMatches reports whether a candidate can meet the relation's
// qualifier.
//
// ":any" asks for a package that declares itself usable by another architecture,
// which is what Multi-Arch: allowed means; a package that says nothing, or says
// "same", is only usable by its own architecture and cannot satisfy it. The bare
// native qualifier needs the candidate to be available for that architecture, and
// a qualifier for a foreign one cannot be met from this catalog at all.
func (solver *solver) architectureMatches(relation *deb.Relation, candidate *Candidate) bool {
	switch relation.Architecture {
	case "":
		return true
	case "any":
		return candidate.MultiArch == "allowed"
	case solver.catalog.architecture:
		return candidate.Architecture == solver.catalog.architecture ||
			candidate.Architecture == architectureAll
	default:
		return false
	}
}
func (solver *solver) candidateSatisfies(relation *deb.Relation, candidate *Candidate) (bool, bool) {
	if !solver.spendWork() {
		return false, false
	}
	if !solver.architectureMatches(relation, candidate) {
		return false, true
	}
	if candidate.Name == relation.Name {
		return versionSatisfies(relation, candidate.ParsedVersion), true
	}
	return solver.providesSatisfies(relation, candidate)
}

// providesSatisfies matches a virtual name, so an unversioned relation accepts an
// unversioned provider and a versioned one only a provider that pins the version.
// A provider's own qualifier is judged here because it describes what the candidate
// offers: "virtual:arm64" is a different offer from "virtual", not a hint about the
// relation asking for it.
func (solver *solver) providesSatisfies(relation *deb.Relation, candidate *Candidate) (bool, bool) {
	for i := range candidate.Provides {
		if !solver.spendWork() {
			return false, false
		}
		provides := &candidate.Provides[i]
		if provides.Name != relation.Name || !solver.architectureMatches(provides, candidate) {
			continue
		}
		if relation.Operator == "" {
			return true, true
		}
		if provides.Operator == deb.RelationEqual && versionSatisfies(relation, provides.Version) {
			return true, true
		}
	}
	return false, true
}
