package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/deb/resolver"
)

func testPackage(name, version, architecture string, provides ...string) deb.Package {
	return deb.Package{
		Name:         name,
		Version:      version,
		Architecture: architecture,
		Origin:       deb.PackageOrigin{Suite: "resolute", Component: "main"},
		Filename:     "pool/main/" + name + "_" + version + "_" + architecture + ".deb",
		SHA256:       strings.Repeat("a", 64),
		Relations:    deb.Relations{Provides: provides},
	}
}

func testIndex(repository string, priority int, packages ...deb.Package) resolver.Index {
	return resolver.Index{
		Repository:   repository,
		Priority:     priority,
		Platform:     "linux/amd64",
		Architecture: "amd64",
		Packages:     packages,
	}
}

func versionOrder(t *testing.T, catalog *resolver.Catalog, name string) []string {
	t.Helper()
	candidates := catalog.Candidates(name)
	versions := make([]string, 0, len(candidates))
	for i := range candidates {
		versions = append(versions, candidates[i].Repository+" "+candidates[i].Version)
	}
	return versions
}

func TestCatalogRanksByPriorityBeforeVersion(t *testing.T) {
	catalog, err := resolver.NewCatalog([]resolver.Index{
		testIndex("low", 0, testPackage("foo", "2.0", "amd64")),
		testIndex("high", 10, testPackage("foo", "1.0", "amd64")),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := versionOrder(t, catalog, "foo")
	want := []string{"high 1.0", "low 2.0"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestCatalogRanksNewestVersionAtEqualPriority(t *testing.T) {
	catalog, err := resolver.NewCatalog([]resolver.Index{
		testIndex("mirror", 0,
			testPackage("foo", "1.0", "amd64"),
			testPackage("foo", "1:0.5", "amd64"),
			testPackage("foo", "2.0~rc1", "amd64"),
			testPackage("foo", "2.0", "amd64")),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := versionOrder(t, catalog, "foo")
	want := []string{"mirror 1:0.5", "mirror 2.0", "mirror 2.0~rc1", "mirror 1.0"}
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestCatalogSourceIdentityBreaksVersionTies(t *testing.T) {
	catalog, err := resolver.NewCatalog([]resolver.Index{
		testIndex("zeta", 0, testPackage("foo", "1.0", "amd64")),
		testIndex("alpha", 0, testPackage("foo", "1.0", "amd64")),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := versionOrder(t, catalog, "foo")
	want := []string{"alpha 1.0", "zeta 1.0"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestCatalogSuiteAndComponentBreakSourceTies(t *testing.T) {
	updates := testPackage("foo", "1.0", "amd64")
	updates.Origin = deb.PackageOrigin{Suite: "resolute-updates", Component: "main"}
	universe := testPackage("foo", "1.0", "amd64")
	universe.Origin = deb.PackageOrigin{Suite: "resolute", Component: "universe"}
	security := testPackage("foo", "1.0", "amd64")
	security.Origin = deb.PackageOrigin{Suite: "resolute-security", Component: "main"}
	catalog, err := resolver.NewCatalog([]resolver.Index{
		testIndex("mirror", 0, updates, universe, security),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates := catalog.Candidates("foo")
	if len(candidates) != 3 {
		t.Fatalf("len(candidates) = %d", len(candidates))
	}
	if candidates[0].Origin.Suite != "resolute" || candidates[0].Origin.Component != "universe" {
		t.Fatalf("first candidate origin = %+v", candidates[0].Origin)
	}
	if candidates[1].Origin.Suite != "resolute-security" || candidates[2].Origin.Suite != "resolute-updates" {
		t.Fatalf("suite order = %q, %q", candidates[1].Origin.Suite, candidates[2].Origin.Suite)
	}
}

func TestCatalogPrefersNativeArchitectureOverAll(t *testing.T) {
	all := testPackage("foo", "1.0", "all")
	native := testPackage("foo", "1.0", "amd64")
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, all, native)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates := catalog.Candidates("foo")
	if candidates[0].Architecture != "amd64" || candidates[1].Architecture != "all" {
		t.Fatalf("architecture order = %q, %q", candidates[0].Architecture, candidates[1].Architecture)
	}
	reversed, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, native, all)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reversed.Candidates("foo")[0].Architecture != "amd64" {
		t.Fatal("index order changed architecture preference")
	}
}

func TestCatalogShuffledIndexes(t *testing.T) {
	foo := testPackage("foo", "1.0", "amd64")
	bar := testPackage("bar", "2.0", "amd64")
	first, err := resolver.NewCatalog([]resolver.Index{
		testIndex("a", 0, foo, bar),
		testIndex("b", 0, foo, bar),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.NewCatalog([]resolver.Index{
		testIndex("b", 0, bar, foo),
		testIndex("a", 0, bar, foo),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"foo", "bar"} {
		one, two := versionOrder(t, first, name), versionOrder(t, second, name)
		if len(one) != 2 || !strings.HasPrefix(one[0], "a ") || !strings.HasPrefix(one[1], "b ") {
			t.Fatalf("%s order = %v", name, one)
		}
		for i := range one {
			if one[i] != two[i] {
				t.Fatalf("%s order differs: %v vs %v", name, one, two)
			}
		}
	}
}

func TestCatalogAppliesExactPins(t *testing.T) {
	indexes := []resolver.Index{
		testIndex("mirror", 0,
			testPackage("foo", "1.0", "amd64"),
			testPackage("foo", "2.0", "amd64"),
			testPackage("bar", "1.0", "amd64")),
	}
	catalog, err := resolver.NewCatalog(indexes, map[string]string{"foo": "= 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := versionOrder(t, catalog, "foo"); len(got) != 1 || got[0] != "mirror 1.0" {
		t.Fatalf("pinned order = %v", got)
	}
	if got := versionOrder(t, catalog, "bar"); len(got) != 1 {
		t.Fatalf("unrelated package order = %v", got)
	}
}

func TestCatalogAppliesRangeConstraint(t *testing.T) {
	indexes := []resolver.Index{
		testIndex("mirror", 0,
			testPackage("foo", "2.9", "amd64"),
			testPackage("foo", "3.0.1-1", "amd64"),
			testPackage("foo", "3.4", "amd64"),
			testPackage("foo", "4.0", "amd64")),
	}
	for constraint, want := range map[string][]string{
		"~> 3.0":        {"mirror 3.4", "mirror 3.0.1-1"},
		">= 3.0, < 3.5": {"mirror 3.4", "mirror 3.0.1-1"},
		"= 3.0.1":       {"mirror 3.0.1-1"},
		"> 3.0.1":       {"mirror 4.0", "mirror 3.4"},
		"!= 3.4":        {"mirror 4.0", "mirror 3.0.1-1", "mirror 2.9"},
	} {
		catalog, err := resolver.NewCatalog(indexes, map[string]string{"foo": constraint})
		if err != nil {
			t.Fatalf("%q: %v", constraint, err)
		}
		if got := versionOrder(t, catalog, "foo"); !slices.Equal(got, want) {
			t.Fatalf("%q order = %v, want %v", constraint, got, want)
		}
	}
}

func TestCatalogPinsCompareVersionsNotIndexStrings(t *testing.T) {
	indexes := []resolver.Index{testIndex("mirror", 0, testPackage("foo", "1.0", "amd64"))}
	if _, err := resolver.NewCatalog(indexes, map[string]string{"foo": "= 1.0-1"}); err == nil {
		t.Fatal("expected a revision in the constraint to exclude 1.0")
	}
	catalog, err := resolver.NewCatalog(indexes, map[string]string{"foo": "= 1.0"})
	if err != nil {
		t.Fatalf("a revision-free constraint should allow 1.0: %v", err)
	}
	if got := versionOrder(t, catalog, "foo"); len(got) != 1 {
		t.Fatalf("pinned order = %v", got)
	}
}

func TestCatalogRejectsMissedAndInvalidPins(t *testing.T) {
	indexes := []resolver.Index{testIndex("mirror", 0, testPackage("foo", "1.0", "amd64"))}
	for name, pins := range map[string]map[string]string{
		"missing version": {"foo": ">= 9.0"},
		"missing package": {"nope": "= 1.0"},
		"invalid version": {"foo": "not-a-version"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolver.NewCatalog(indexes, pins); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCatalogPinsFilterProviderCandidates(t *testing.T) {
	indexes := []resolver.Index{
		testIndex("mirror", 0,
			testPackage("a", "1.0", "amd64", "virtual (= 1.0)"),
			testPackage("a", "2.0", "amd64", "virtual (= 2.0)")),
	}
	catalog, err := resolver.NewCatalog(indexes, map[string]string{"a": "= 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	providers := catalog.Providers("virtual")
	if len(providers) != 1 || providers[0].Name != "a" || providers[0].Version != "1.0" {
		t.Fatalf("providers = %+v", providers)
	}
}

func TestCatalogVirtualProviders(t *testing.T) {
	indexes := []resolver.Index{
		testIndex("mirror", 0,
			testPackage("a", "1.0", "amd64", "mail-transport-agent (= 3.0)", "default-mta"),
			testPackage("b", "2.0", "amd64", "mail-transport-agent (= 1.0)"),
			testPackage("c", "3.0", "amd64", "default-mta", "default-mta")),
	}
	catalog, err := resolver.NewCatalog(indexes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Candidates("mail-transport-agent") != nil {
		t.Fatal("virtual name must not be a real package")
	}
	providers := catalog.Providers("mail-transport-agent")
	if len(providers) != 2 || providers[0].Name != "b" || providers[1].Name != "a" {
		t.Fatalf("providers = %+v", providers)
	}
	versioned := providers[1].Provides[0]
	if versioned.Name != "mail-transport-agent" || versioned.Operator != deb.RelationEqual ||
		versioned.Version != (deb.Version{Upstream: "3.0"}) {
		t.Fatalf("versioned provide = %+v", versioned)
	}
	defaultMTA := catalog.Providers("default-mta")
	if len(defaultMTA) != 2 || defaultMTA[0].Name != "c" || defaultMTA[1].Name != "a" {
		t.Fatalf("default-mta providers = %+v", defaultMTA)
	}
	if catalog.Providers("unknown") != nil {
		t.Fatal("unknown virtual name has providers")
	}
}

func TestCatalogParsesRelations(t *testing.T) {
	pkg := testPackage("foo", "1.0", "amd64", "virtual:any (= 1:2.0-1)")
	pkg.Relations.PreDepends = []string{"libc6 (>= 2.34)"}
	pkg.Relations.Depends = []string{"libfoo | libbar (= 1.0)"}
	pkg.Relations.Conflicts = []string{"old (<< 1.0)"}
	pkg.Relations.Breaks = []string{"broken (<= 2.0)"}
	catalog, err := resolver.NewCatalog([]resolver.Index{testIndex("mirror", 0, pkg)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate := catalog.Candidates("foo")[0]
	if len(candidate.PreDepends) != 1 || candidate.PreDepends[0][0].Name != "libc6" ||
		candidate.PreDepends[0][0].Operator != deb.RelationGreaterOrEqual {
		t.Fatalf("pre-depends = %+v", candidate.PreDepends)
	}
	if len(candidate.Depends) != 1 || len(candidate.Depends[0]) != 2 ||
		candidate.Depends[0][1].Operator != deb.RelationEqual {
		t.Fatalf("depends = %+v", candidate.Depends)
	}
	if len(candidate.Conflicts) != 1 || candidate.Conflicts[0].Operator != deb.RelationLess ||
		len(candidate.Breaks) != 1 {
		t.Fatalf("conflict fields = %+v %+v", candidate.Conflicts, candidate.Breaks)
	}
	if len(candidate.Provides) != 1 || candidate.Provides[0].Architecture != "any" ||
		candidate.Provides[0].Version != (deb.Version{Epoch: 1, Upstream: "2.0", Revision: "1"}) {
		t.Fatalf("provides = %+v", candidate.Provides)
	}
}

func TestCatalogRejectsInvalidInput(t *testing.T) {
	base := testIndex("mirror", 0, testPackage("foo", "1.0", "amd64"))
	mismatchedPlatform := base
	mismatchedPlatform.Platform = "linux/arm64"
	mismatchedArchitecture := base
	mismatchedArchitecture.Architecture = "arm64"
	missingRepository := base
	missingRepository.Repository = ""
	missingPlatform := base
	missingPlatform.Platform = ""
	allNative := base
	allNative.Architecture = "all"
	foreign := testIndex("mirror", 0, testPackage("foo", "1.0", "i386"))
	badVersion := testIndex("mirror", 0, testPackage("foo", "v1", "amd64"))
	badDepends := testIndex("mirror", 0, testPackage("foo", "1.0", "amd64"))
	badDepends.Packages[0].Relations.Depends = []string{"foo (< 1.0)"}
	badProvides := testIndex("mirror", 0, testPackage("foo", "1.0", "amd64"))
	badProvides.Packages[0].Relations.Provides = []string{"foo (>= 1.0)"}
	missingOrigin := testIndex("mirror", 0, testPackage("foo", "1.0", "amd64"))
	missingOrigin.Packages[0].Origin = deb.PackageOrigin{}
	for name, indexes := range map[string][]resolver.Index{
		"no indexes":                nil,
		"mismatched platform":       {base, mismatchedPlatform},
		"mismatched arch":           {base, mismatchedArchitecture},
		"missing repository":        {missingRepository},
		"missing platform":          {missingPlatform},
		"all as native arch":        {allNative},
		"foreign architecture":      {foreign},
		"invalid version":           {badVersion},
		"invalid depends":           {badDepends},
		"invalid provides":          {badProvides},
		"incomplete package origin": {missingOrigin},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolver.NewCatalog(indexes, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
