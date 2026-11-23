package resolver_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/deb/resolver"
)

func solve(t *testing.T, indexes []resolver.Index, roots ...string) []resolver.Candidate {
	t.Helper()
	catalog, err := resolver.NewCatalog(indexes, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := resolver.Solve(catalog, roots)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func solveNames(t *testing.T, indexes []resolver.Index, roots ...string) []string {
	t.Helper()
	selected := solve(t, indexes, roots...)
	names := make([]string, len(selected))
	for i := range selected {
		names[i] = selected[i].Name
	}
	return names
}

func depends(pkg deb.Package, values ...string) deb.Package {
	pkg.Relations.Depends = values
	return pkg
}

func preDepends(pkg deb.Package, values ...string) deb.Package {
	pkg.Relations.PreDepends = values
	return pkg
}

func conflicts(pkg deb.Package, values ...string) deb.Package {
	pkg.Relations.Conflicts = values
	return pkg
}

func TestSolveExpandsTransitiveDependencies(t *testing.T) {
	app := depends(preDepends(testPackage("app", "1.0", "amd64"), "pre"), "lib | backup")
	lib := depends(testPackage("lib", "1.0", "amd64"), "deep")
	catalog := []resolver.Index{testIndex("mirror", 0,
		app, lib, testPackage("pre", "1.0", "amd64"),
		testPackage("deep", "1.0", "amd64"), testPackage("backup", "1.0", "amd64"))}
	got := solveNames(t, catalog, "app")
	want := []string{"app", "deep", "lib", "pre"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selection = %v, want %v", got, want)
	}
}

func TestSolveTriesAlternativesInDeclaredOrder(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "libb | libc")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("libb", "1.0", "amd64"), testPackage("libc", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,libb" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveBacktracksToLaterAlternative(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib | compat", "base")
	lib := depends(testPackage("lib", "1.0", "amd64"), "boom")
	boom := conflicts(testPackage("boom", "1.0", "amd64"), "base")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, lib, boom,
		testPackage("base", "1.0", "amd64"), testPackage("compat", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,base,compat" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveBacktracksToOlderVersion(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib", "core")
	libNew := conflicts(testPackage("lib", "2.0", "amd64"), "core")
	libOld := testPackage("lib", "1.0", "amd64")
	got := solve(t, []resolver.Index{testIndex("mirror", 0, app, libNew, libOld,
		testPackage("core", "1.0", "amd64"))}, "app")
	for _, candidate := range got {
		if candidate.Name == "lib" && candidate.Version != "1.0" {
			t.Fatalf("selected lib %s, want 1.0", candidate.Version)
		}
	}
}

func TestSolveBacktracksToAnotherVirtualProvider(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "virtual", "core")
	first := conflicts(testPackage("prov-a", "2.0", "amd64", "virtual"), "core")
	second := testPackage("prov-b", "1.0", "amd64", "virtual")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, first, second,
		testPackage("core", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,core,prov-b" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveUsesSelectedPackageConflicts(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "base", "libb | libc")
	base := conflicts(testPackage("base", "1.0", "amd64"), "libb")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, base,
		testPackage("libb", "1.0", "amd64"), testPackage("libc", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,base,libc" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveTreatsBreaksAsConflict(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "libb | libc", "core")
	broken := testPackage("libb", "1.0", "amd64")
	broken.Relations.Breaks = []string{"core"}
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, broken,
		testPackage("libc", "1.0", "amd64"), testPackage("core", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,core,libc" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveVersionedRequirementsNeedVersionedProvides(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "virt (= 2.0)")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("plain", "3.0", "amd64", "virt"),
		testPackage("wrong", "4.0", "amd64", "virt (= 3.0)"),
		testPackage("matching", "1.0", "amd64", "virt (= 2.0)"))}, "app")
	if strings.Join(got, ",") != "app,matching" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveUnversionedRequirementAcceptsUnversionedProvider(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "virt")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("provider", "1.0", "amd64", "virt"))}, "app")
	if strings.Join(got, ",") != "app,provider" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolvePrefersRealPackageOverProvider(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "foo")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("foo", "0.5", "amd64"), testPackage("bar", "9.0", "amd64", "foo"))}, "app")
	if strings.Join(got, ",") != "app,foo" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveHandlesCycles(t *testing.T) {
	first := depends(testPackage("cycle-a", "1.0", "amd64"), "cycle-b")
	second := depends(testPackage("cycle-b", "1.0", "amd64"), "cycle-a")
	self := depends(testPackage("self", "1.0", "amd64"), "self")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, first, second, self)}, "cycle-a", "self")
	if strings.Join(got, ",") != "cycle-a,cycle-b,self" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveRejectsTwoVersionsOfOnePackage(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib (= 1.0)", "lib (= 2.0)")
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, app,
		testPackage("lib", "1.0", "amd64"), testPackage("lib", "2.0", "amd64"))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Solve(catalog, []string{"app"}); err == nil {
		t.Fatal("expected one-version conflict")
	}
}

func TestSolveRejectsUnsatisfiablePinnedDependencies(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib (>= 2.0)")
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, app,
		testPackage("lib", "1.0", "amd64"))}, map[string]string{"app": "= 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Solve(catalog, []string{"app"}); err == nil {
		t.Fatal("expected unsatisfiable dependency")
	}
}

func TestSolveNeverSelectsReplaces(t *testing.T) {
	app := testPackage("app", "1.0", "amd64")
	app.Relations.Replaces = []string{"other"}
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("other", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveMissingRootFails(t *testing.T) {
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0,
		testPackage("foo", "1.0", "amd64"))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Solve(catalog, []string{"nope"}); err == nil {
		t.Fatal("expected missing root error")
	}
}

func TestSolveEmptyRoots(t *testing.T) {
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := resolver.Solve(catalog, nil)
	if err != nil || len(selected) != 0 {
		t.Fatalf("Solve(nil) = %v, %v", selected, err)
	}
}

func TestSolveStableAcrossShuffledIndexes(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib | compat", "base")
	lib := depends(testPackage("lib", "1.0", "amd64"), "boom")
	boom := conflicts(testPackage("boom", "1.0", "amd64"), "base")
	compat := testPackage("compat", "1.0", "amd64")
	base := testPackage("base", "1.0", "amd64")
	first := []resolver.Index{
		testIndex("alpha", 0, app, lib, boom),
		testIndex("zeta", 0, compat, base),
	}
	second := []resolver.Index{
		testIndex("zeta", 0, base, compat),
		testIndex("alpha", 0, boom, lib, app),
	}
	firstSelected := solve(t, first, "app")
	secondSelected := solve(t, second, "app")
	if len(firstSelected) != len(secondSelected) {
		t.Fatalf("selection sizes differ: %d vs %d", len(firstSelected), len(secondSelected))
	}
	for i := range firstSelected {
		if firstSelected[i].Name != secondSelected[i].Name || firstSelected[i].Version != secondSelected[i].Version ||
			firstSelected[i].Repository != secondSelected[i].Repository {
			t.Fatalf("selection differs: %+v vs %+v", firstSelected, secondSelected)
		}
	}
}

func TestSolveSelectsArchitectureAllDependency(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "shared")
	got := solve(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("shared", "1.0", "all"))}, "app")
	if len(got) != 2 || got[1].Name != "shared" || got[1].Architecture != "all" {
		t.Fatalf("selection = %+v", got)
	}
}

func TestSolveRepeatedAlternativesStayBounded(t *testing.T) {
	const (
		alternatives = 2000
		providers    = 100
	)
	app := depends(testPackage("app", "1.0", "amd64"), "virtual")
	app.Relations.PreDepends = []string{"core"}
	var clause strings.Builder
	for range alternatives {
		clause.WriteString("virtual | ")
	}
	clause.WriteString("good")
	app.Relations.Depends = []string{clause.String()}

	packages := make([]deb.Package, 0, 3+providers)
	packages = append(packages, app, testPackage("core", "1.0", "amd64"),
		testPackage("good", "1.0", "amd64"))
	for i := range providers {
		provider := testPackage(fmt.Sprintf("provider%03d", i), "1.0", "amd64")
		provider.Relations.Provides = []string{"virtual"}
		provider.Relations.Conflicts = []string{"core"}
		packages = append(packages, provider)
	}
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, packages...)}, "app")
	if len(got) != 3 || got[2] != "good" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveBoundsMemoryForRepeatedAlternatives(t *testing.T) {
	app := testPackage("app", "1.0", "amd64")
	app.Relations.PreDepends = []string{"core"}
	var clause strings.Builder
	for range 2000 {
		clause.WriteString("virtual | ")
	}
	clause.WriteString("missing")
	app.Relations.Depends = []string{clause.String()}

	packages := make([]deb.Package, 0, 2+100)
	packages = append(packages, app, testPackage("core", "1.0", "amd64"))
	for i := range 100 {
		provider := testPackage(fmt.Sprintf("provider%03d", i), "1.0", "amd64")
		provider.Relations.Provides = []string{"virtual"}
		provider.Relations.Conflicts = []string{"core"}
		packages = append(packages, provider)
	}
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, packages...)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := resolver.Solve(catalog, []string{"app"}); err == nil {
		t.Fatal("Solve succeeded with an unsatisfiable alternative")
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
		t.Fatalf("Solve allocated %d bytes", allocated)
	}
}

func TestSolveRootsRequireRealPackage(t *testing.T) {
	aa := testPackage("aa", "1.0", "amd64")
	aa.Relations.Provides = []string{"bb"}
	bb := depends(testPackage("bb", "1.0", "amd64"), "cc")
	cc := testPackage("cc", "1.0", "amd64")
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, aa, bb, cc)},
		map[string]string{"bb": "= 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.Solve(catalog, []string{"aa", "bb"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "aa" || got[1].Name != "bb" || got[2].Name != "cc" {
		t.Fatalf("selection = %+v", got)
	}
}

func TestSolveVersionedProviderUsesAnyMatchingProvide(t *testing.T) {
	provider := testPackage("provider", "3.0", "amd64")
	provider.Relations.Provides = []string{"virtual (= 1.0)", "virtual (= 2.0)"}
	app := depends(testPackage("app", "1.0", "amd64"), "virtual (= 2.0)")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, provider)}, "app")
	if len(got) != 2 || got[1] != "provider" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveVersionedConflictUsesMatchingProvide(t *testing.T) {
	provider := testPackage("provider", "3.0", "amd64")
	provider.Relations.Provides = []string{"virtual (= 1.0)", "virtual (= 2.0)"}
	app := depends(testPackage("app", "1.0", "amd64"), "virtual (= 2.0)")
	blocker := testPackage("blocker", "1.0", "amd64")
	blocker.Relations.Conflicts = []string{"virtual (= 2.0)"}
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, app, provider, blocker)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Solve(catalog, []string{"app", "blocker"}); err == nil {
		t.Fatal("conflicting versioned provider was accepted")
	}
}

func TestSolveSkipsForeignArchitectureAlternative(t *testing.T) {
	// crossbuild-essential-arm64 in the real archive depends on
	// "gcc-aarch64-linux-gnu (>= 4:14.2) | gcc:arm64": the foreign qualifier is a
	// fallback next to a satisfiable cross compiler, so it must be skipped, not
	// treated as an unsatisfiable graph.
	app := depends(testPackage("app", "1.0", "amd64"),
		"gcc-aarch64-linux-gnu (>= 4:14.2) | gcc:arm64")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("gcc-aarch64-linux-gnu", "4:14.2", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,gcc-aarch64-linux-gnu" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveRejectsOnlyForeignArchitectureAlternatives(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "gcc:arm64 | gcc:s390x")
	_, err := resolver.Solve(mustCatalog(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("gcc", "1.0", "amd64"))}), []string{"app"})
	if err == nil {
		t.Fatal("expected an unsatisfiable error")
	}
	if !strings.Contains(err.Error(), "no candidate satisfies app") &&
		!strings.Contains(err.Error(), "gcc:arm64") {
		t.Fatalf("error = %v", err)
	}
}

func TestSolveMatchesExplicitNativeQualifier(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib:amd64")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("lib", "1.0", "amd64"))}, "app")
	if strings.Join(got, ",") != "app,lib" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveIgnoresForeignQualifiedProvider(t *testing.T) {
	// A provider entry describes what the candidate offers, so a foreign qualifier on
	// the entry is unavailable here even when the relation asks for the native
	// architecture without any qualifier of its own.
	app := depends(testPackage("app", "1.0", "amd64"), "virtual")
	foreign := testPackage("foreign", "1.0", "amd64", "virtual:arm64")
	native := testPackage("native", "1.0", "amd64", "virtual")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, foreign, native)}, "app")
	if strings.Join(got, ",") != "app,native" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveForeignQualifiedProviderDoesNotSatisfy(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "virtual")
	foreign := testPackage("foreign", "1.0", "amd64", "virtual:arm64")
	_, err := resolver.Solve(mustCatalog(t, []resolver.Index{testIndex("mirror", 0, app, foreign)}),
		[]string{"app"})
	if err == nil || !strings.Contains(err.Error(), "no candidate satisfies virtual") {
		t.Fatalf("error = %v", err)
	}
}

func TestSolveForeignQualifiedProviderDoesNotConflict(t *testing.T) {
	// Neither a conflict nor a break may fire on a provider entry that offers a
	// foreign architecture: nothing here provides "virtual".
	clashing := conflicts(testPackage("clashing", "1.0", "amd64"), "virtual")
	foreign := testPackage("foreign", "1.0", "amd64", "virtual:arm64")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, clashing, foreign)}, "clashing", "foreign")
	if strings.Join(got, ",") != "clashing,foreign" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveNativeQualifiedProviderSatisfiesNativeRelation(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "virtual")
	provider := testPackage("provider", "1.0", "amd64", "virtual:amd64")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, provider)}, "app")
	if strings.Join(got, ",") != "app,provider" {
		t.Fatalf("selection = %v", got)
	}
}

func mustCatalog(t *testing.T, indexes []resolver.Index) *resolver.Catalog {
	t.Helper()
	catalog, err := resolver.NewCatalog(indexes, nil)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

// ":any" asks for a package other architectures can use, which only Multi-Arch:
// allowed declares. A package without it is usable by its own architecture alone,
// and accepting it would silently satisfy a dependency that cannot be done.
func TestSolveAnyQualifierNeedsMultiArchAllowed(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib:any")
	plain := testPackage("lib", "1.0", "amd64")
	if _, err := resolver.Solve(mustCatalog(t, []resolver.Index{testIndex("mirror", 0, app, plain)}),
		[]string{"app"}); err == nil || !strings.Contains(err.Error(), "no candidate satisfies lib:any") {
		t.Fatalf("error = %v, want an unsatisfiable lib:any", err)
	}
	allowed := plain
	allowed.MultiArch = "allowed"
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app, allowed)}, "app")
	if strings.Join(got, ",") != "app,lib" {
		t.Fatalf("selection = %v", got)
	}
}

func TestSolveAnyQualifierRejectsSame(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib:any")
	same := testPackage("lib", "1.0", "amd64")
	same.MultiArch = "same"
	if _, err := resolver.Solve(mustCatalog(t, []resolver.Index{testIndex("mirror", 0, app, same)}),
		[]string{"app"}); err == nil {
		t.Fatal(":any accepted Multi-Arch: same")
	}
}

// The native qualifier names the architecture, so an Architecture: all package
// answers it as well.
func TestSolveNativeQualifierAcceptsArchitectureAll(t *testing.T) {
	app := depends(testPackage("app", "1.0", "amd64"), "lib:amd64")
	got := solveNames(t, []resolver.Index{testIndex("mirror", 0, app,
		testPackage("lib", "1.0", "all"))}, "app")
	if strings.Join(got, ",") != "app,lib" {
		t.Fatalf("selection = %v", got)
	}
}
