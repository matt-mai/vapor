package resolver

import (
	"errors"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// conflictCatalog returns aa whose Conflicts list is usable, with count entries that
// cannot match bb's single provide, and optionally one that does. Matching them all
// is the scan the work budget has to bound: nothing is selected for the packages
// themselves, so the charge comes from the conflict comparison alone.
func conflictCatalog(t *testing.T, count int, realConflict bool) *Catalog {
	t.Helper()
	origin := deb.PackageOrigin{Suite: "resolute", Component: "main"}
	aa := deb.Package{Name: "aa", Version: "1.0", Architecture: "amd64", Origin: origin}
	bb := deb.Package{Name: "bb", Version: "1.0", Architecture: "amd64", Origin: origin,
		Relations: deb.Relations{Provides: []string{"virtual (= 2.0)"}}}
	for range count {
		aa.Relations.Conflicts = append(aa.Relations.Conflicts, "virtual (= 1.0)")
	}
	if realConflict {
		aa.Relations.Conflicts = append(aa.Relations.Conflicts, "virtual (= 2.0)")
	}
	index := Index{Repository: "mirror", Platform: "linux/amd64", Architecture: "amd64",
		Packages: []deb.Package{aa, bb}}
	catalog, err := NewCatalog([]Index{index}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

// Conflict matching must charge the work budget, or an index full of conflicting
// relations can be scanned for free. Each relation costs two units: one to walk the
// Conflicts list and one to match the relation against the provider. A budget above
// the relation count but below twice it finishes only when the matching charge is
// missing, so this pins the charge that scales with the lists rather than the one
// per selected package.
func TestSolveConflictMatchingChargesWork(t *testing.T) {
	const count = 64
	if _, err := solveWithBudget(conflictCatalog(t, count, false), []string{"aa", "bb"},
		count+count/2); !errors.Is(err, errWorkLimit) {
		t.Fatalf("error = %v, want the work limit", err)
	}
}

// A budget wide enough to finish the scan must still surface the conflict, so the
// charge above is not passing because matching never reaches a verdict.
func TestSolveConflictMatchingReachesAVerdict(t *testing.T) {
	const count = 64
	_, err := solveWithBudget(conflictCatalog(t, count, true), []string{"aa", "bb"}, maxSolverWork)
	if err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("error = %v, want the conflict", err)
	}
}

// The work a graph costs must not depend on map iteration order: a build sitting
// at the limit would otherwise fail on one run and succeed on the next. The
// smallest budget that finishes is therefore the same on every attempt.
func TestSolveWorkCostIsDeterministic(t *testing.T) {
	catalog := chainCatalog(t)
	smallest := 0
	for budget := 1; budget <= 1000; budget++ {
		if _, err := solveWithBudget(catalog, []string{"root"}, budget); err == nil {
			smallest = budget
			break
		}
	}
	if smallest == 0 {
		t.Fatal("no budget below 1000 finished the graph")
	}
	for range 50 {
		if _, err := solveWithBudget(catalog, []string{"root"}, smallest); err != nil {
			t.Fatalf("budget %d finished once and failed now: %v", smallest, err)
		}
	}
}

// chainCatalog builds a graph wide enough for map order to matter when scanning
// the selected packages for dependencies and conflicts.
func chainCatalog(t *testing.T) *Catalog {
	t.Helper()
	origin := deb.PackageOrigin{Suite: "resolute", Component: "main"}
	packages := []deb.Package{{Name: "root", Version: "1.0", Architecture: "amd64", Origin: origin,
		Relations: deb.Relations{Depends: []string{"dep1, dep2, dep3, dep4, dep5, dep6"}}}}
	for i := 1; i <= 6; i++ {
		packages = append(packages, deb.Package{
			Name: "dep" + string(rune('0'+i)), Version: "1.0", Architecture: "amd64", Origin: origin,
			Relations: deb.Relations{
				Depends:  []string{"shared1 | shared2"},
				Provides: []string{"placeholder"},
			},
		})
	}
	for _, name := range []string{"shared1", "shared2"} {
		packages = append(packages, deb.Package{Name: name, Version: "1.0", Architecture: "amd64", Origin: origin})
	}
	index := Index{Repository: "mirror", Platform: "linux/amd64", Architecture: "amd64", Packages: packages}
	catalog, err := NewCatalog([]Index{index}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}
