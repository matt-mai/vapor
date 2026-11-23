package resolver

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

const (
	// maxSolverSteps bounds candidate selections and alternative attempts.
	maxSolverSteps = 100000
	// maxSolverWork bounds total candidate inspections, requirement checks and
	// conflict comparisons so scanning a large index cannot run unbounded.
	maxSolverWork = 10000000
	// maxSolverPending bounds requirements held by the search state.
	maxSolverPending = 100000
)

var (
	errStepLimit    = errors.New("dependency resolution exceeded its step limit")
	errWorkLimit    = errors.New("dependency resolution exceeded its work limit")
	errPendingLimit = errors.New("dependency resolution exceeded its pending requirement limit")
)

// Solve expands Pre-Depends and Depends from the requested package names and
// returns one selected version per package name. Alternatives are tried in
// declared order and candidates in catalog order; incompatible constraints,
// Conflicts and Breaks cause backtracking. Replaces is never used for
// selection. The result is sorted by package name.
func Solve(catalog *Catalog, roots []string) ([]Candidate, error) {
	return solveWithBudget(catalog, roots, maxSolverWork)
}

// solveWithBudget is Solve with an explicit work budget. Reaching the real limit
// takes ten million charged checks, so the only way to test the limit without
// spending a minute under the race detector is to pass a small budget.
func solveWithBudget(catalog *Catalog, roots []string, maxWork int) ([]Candidate, error) {
	names := slices.Clone(roots)
	slices.Sort(names)
	names = slices.Compact(names)
	solver := &solver{catalog: catalog, selected: make(map[string]Candidate, len(names)), maxWork: maxWork}
	for _, name := range names {
		if len(catalog.packages[name]) == 0 {
			return nil, fmt.Errorf("dependency resolution failed: package %q has no candidates", name)
		}
		solver.pending = append(solver.pending, requirement{
			clause: deb.RelationClause{{Name: name}},
			root:   name,
		})
	}
	if !solver.resolve(0) {
		if solver.aborted {
			return nil, fmt.Errorf("dependency resolution failed: %w", solver.abortErr)
		}
		if solver.failure != nil {
			return nil, fmt.Errorf("dependency resolution failed: %w", solver.failure)
		}
		return nil, errors.New("dependency resolution failed")
	}
	packages := make([]Candidate, 0, len(solver.selected))
	for name := range solver.selected {
		packages = append(packages, solver.selected[name])
	}
	slices.SortFunc(packages, func(a, b Candidate) int {
		return strings.Compare(a.Name, b.Name)
	})
	return packages, nil
}

type requirement struct {
	clause deb.RelationClause
	// root is set for explicit package requests, which only a real package of
	// that name may satisfy.
	root string
}
type candidateKey struct {
	repository   string
	name         string
	version      string
	architecture string
	filename     string
	sha256       string
}

// solver mutates one search state and rewinds it on backtracking instead of
// copying the selected map for every branch.
type solver struct {
	catalog  *Catalog
	selected map[string]Candidate
	// order lists the selected names in selection order. Scanning it instead of
	// the map keeps the work charged by satisfies and conflict identical between
	// runs: a build near the work limit would otherwise fail for no reason the
	// input explains.
	order   []string
	pending []requirement
	// next indexes the first pending requirement not yet processed.
	next int

	maxWork      int
	steps        int
	work         int
	aborted      bool
	abortErr     error
	failureDepth int
	failure      error
}

func (solver *solver) resolve(depth int) bool {
	for solver.next < len(solver.pending) {
		if solver.aborted {
			return false
		}
		if !solver.spendWork() {
			return false
		}
		next := solver.pending[solver.next]
		solver.next++
		if solver.requirementSatisfied(next) {
			continue
		}
		if solver.aborted {
			return false
		}
		return solver.choose(next, depth)
	}
	return !solver.aborted
}
func (solver *solver) requirementSatisfied(next requirement) bool {
	if next.root != "" {
		_, selected := solver.selected[next.root]
		return selected
	}
	return solver.satisfies(next.clause)
}
func (solver *solver) choose(next requirement, depth int) bool {
	savedNext, savedLen := solver.next, len(solver.pending)
	attempted := make(map[candidateKey]struct{})
	matched := false
	for i := range next.clause {
		relationMatched, found := solver.tryRelation(&next.clause[i], next.root, attempted, depth, savedNext, savedLen)
		matched = matched || relationMatched
		if found {
			return true
		}
		if solver.aborted {
			return false
		}
	}
	if !matched {
		solver.fail(depth, fmt.Errorf("no candidate satisfies %s", formatClause(next.clause)))
	}
	return false
}
func (solver *solver) tryRelation(relation *deb.Relation, root string,
	attempted map[candidateKey]struct{}, depth, savedNext, savedLen int) (bool, bool) {
	matched, found := solver.tryList(solver.catalog.packages[relation.Name], relation, true,
		attempted, depth, savedNext, savedLen)
	if found {
		return true, true
	}
	if root != "" || solver.aborted {
		return matched, false
	}
	providers := solver.catalog.providers[relation.Name]
	providerMatched, found := solver.tryList(providers, relation, false, attempted, depth, savedNext, savedLen)
	return matched || providerMatched, found
}
func (solver *solver) tryList(list []Candidate, relation *deb.Relation, direct bool,
	attempted map[candidateKey]struct{}, depth, savedNext, savedLen int) (bool, bool) {
	matched := false
	for j := range list {
		if !solver.spendWork() {
			return matched, false
		}
		candidateMatched, found, ok := solver.tryCandidate(&list[j], relation, direct,
			attempted, depth, savedNext, savedLen)
		matched = matched || candidateMatched
		if !ok {
			return matched, false
		}
		if found {
			return true, true
		}
	}
	return matched, false
}
func (solver *solver) tryCandidate(candidate *Candidate, relation *deb.Relation, direct bool,
	attempted map[candidateKey]struct{}, depth, savedNext, savedLen int) (bool, bool, bool) {
	if !direct && candidate.Name == relation.Name {
		return false, false, true
	}
	matched, ok := solver.candidateSatisfies(relation, candidate)
	if !ok {
		return false, false, false
	}
	if !matched {
		return false, false, true
	}
	if solver.attempt(candidate, attempted, depth) {
		return true, true, true
	}
	if solver.aborted {
		return true, false, false
	}
	solver.next, solver.pending = savedNext, solver.pending[:savedLen]
	return true, false, true
}
func (solver *solver) attempt(candidate *Candidate, attempted map[candidateKey]struct{}, depth int) bool {
	key := candidateKey{
		repository:   candidate.Repository,
		name:         candidate.Name,
		version:      candidate.Version,
		architecture: candidate.Architecture,
		filename:     candidate.Filename,
		sha256:       candidate.SHA256,
	}
	if _, seen := attempted[key]; seen {
		return false
	}
	solver.steps++
	if solver.steps > maxSolverSteps {
		solver.abort(errStepLimit)
		return false
	}
	attempted[key] = struct{}{}
	if _, exists := solver.selected[candidate.Name]; exists {
		solver.fail(depth+1, fmt.Errorf("only one version of %q may be selected", candidate.Name))
		return false
	}
	conflict := solver.conflict(candidate)
	if solver.aborted {
		return false
	}
	if conflict != nil {
		solver.fail(depth+1, conflict)
		return false
	}
	added := len(candidate.PreDepends) + len(candidate.Depends)
	if len(solver.pending)+added > maxSolverPending {
		solver.abort(errPendingLimit)
		return false
	}
	solver.selected[candidate.Name] = *candidate
	solver.order = append(solver.order, candidate.Name)
	for _, clause := range candidate.PreDepends {
		solver.pending = append(solver.pending, requirement{clause: clause})
	}
	for _, clause := range candidate.Depends {
		solver.pending = append(solver.pending, requirement{clause: clause})
	}
	if solver.resolve(depth + 1) {
		return true
	}
	delete(solver.selected, candidate.Name)
	solver.order = solver.order[:len(solver.order)-1]
	return false
}
func (solver *solver) spendWork() bool {
	if solver.aborted {
		return false
	}
	solver.work++
	if solver.work > solver.maxWork {
		solver.abort(errWorkLimit)
		return false
	}
	return true
}
func (solver *solver) abort(err error) {
	if !solver.aborted {
		solver.aborted = true
		solver.abortErr = err
	}
}
func (solver *solver) fail(depth int, err error) {
	if solver.failure == nil || depth > solver.failureDepth {
		solver.failure = err
		solver.failureDepth = depth
	}
}
