package slices_test

import (
	"maps"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func selectFixture(t *testing.T, packages map[string]*slices.Package, requests []slices.SliceKey,
	versions map[string][]slices.PackageVersion, pins map[string]string,
) []slices.PackageSelection {
	t.Helper()
	if pins == nil {
		pins = map[string]string{}
	}
	closure, err := slices.SelectSlices(packages, requests, nil, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/chisel-v3/catalogue/chisel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := slices.ParseCatalogue(data)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := slices.SelectPackageOrigins(packages, catalogue, closure, requests, versions, pins)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func TestDefinitionDigestVector(t *testing.T) {
	want := "sha256:5418709558c1bbf7d5be441a9bbac1ea5439ed9a0c62454d23ffd2b892e33557"
	got, err := slices.DefinitionDigest("slices/base-files.yaml",
		strings.Repeat("a", 64), 120, []string{"copyright", "etc", "lib", "release-info"})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	for _, test := range []struct {
		name   string
		path   string
		digest string
		size   int64
		slices []string
	}{
		{name: "absolute path", path: "/slices/a.yaml", digest: strings.Repeat("a", 64), slices: []string{"abc"}},
		{name: "short digest", path: "slices/a.yaml", digest: "abc", slices: []string{"abc"}},
		{name: "negative size", path: "slices/a.yaml", digest: strings.Repeat("a", 64), size: -1, slices: []string{"abc"}},
		{name: "empty closure", path: "slices/a.yaml", digest: strings.Repeat("a", 64)},
		{name: "invalid slice", path: "slices/a.yaml", digest: strings.Repeat("a", 64), slices: []string{"A"}},
		{name: "repeated slice", path: "slices/a.yaml", digest: strings.Repeat("a", 64), slices: []string{"abc", "abc"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := slices.DefinitionDigest(test.path, test.digest, test.size, test.slices); err == nil {
				t.Fatal("definition digest succeeded")
			}
		})
	}
}

func TestSelectPackageOriginsRecord(t *testing.T) {
	packages := fixturePackages(t)
	selected := selectFixture(t, packages,
		[]slices.SliceKey{{Package: "base-files", Slice: "etc"}},
		map[string][]slices.PackageVersion{"base-files": {
			{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10"},
		}}, nil)
	if len(selected) != 1 {
		t.Fatalf("selections = %d", len(selected))
	}
	got := selected[0]
	if got.Package != "base-files" || got.RealName != "base-files" || got.Version != "13ubuntu10" ||
		got.Archive != "ubuntu" || got.Suite != "resolute" || got.Component != "main" {
		t.Fatalf("origin = %+v", got)
	}
	wantSelected := []string{"etc"}
	wantClosure := []string{"copyright", "etc"}
	if strings.Join(got.Selected, ",") != strings.Join(wantSelected, ",") ||
		strings.Join(got.Closure, ",") != strings.Join(wantClosure, ",") {
		t.Fatalf("selection = %+v", got)
	}
	pkg := packages["base-files"]
	wantDigest, err := slices.DefinitionDigest(pkg.Path, pkg.SHA256, pkg.Size, wantClosure)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefinitionDigest != wantDigest {
		t.Fatalf("digest = %q, want %q", got.DefinitionDigest, wantDigest)
	}
}

func TestSelectPackageOriginsArchiveRanking(t *testing.T) {
	packages := fixturePackages(t)
	request := []slices.SliceKey{{Package: "base-files", Slice: "etc"}}
	for _, test := range []struct {
		name       string
		candidates []slices.PackageVersion
		archive    string
		suite      string
		component  string
		version    string
	}{
		{
			name: "archive priority before version",
			candidates: []slices.PackageVersion{
				{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "9.0"},
				{Archive: "ubuntu-esm-apps", Suite: "resolute-apps-security", Component: "main", Version: "1.0"},
			},
			archive: "ubuntu-esm-apps", suite: "resolute-apps-security", component: "main", version: "1.0",
		},
		{
			name: "newest version within archive",
			candidates: []slices.PackageVersion{
				{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "2.0"},
				{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "1.9"},
			},
			archive: "ubuntu", suite: "resolute", component: "main", version: "2.0",
		},
		{
			name: "ordered suite tie",
			candidates: []slices.PackageVersion{
				{Archive: "ubuntu", Suite: "resolute-security", Component: "main", Version: "1.0"},
				{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "1.0"},
			},
			archive: "ubuntu", suite: "resolute", component: "main", version: "1.0",
		},
		{
			name: "ordered component tie",
			candidates: []slices.PackageVersion{
				{Archive: "ubuntu", Suite: "resolute", Component: "universe", Version: "1.0"},
				{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "1.0"},
			},
			archive: "ubuntu", suite: "resolute", component: "main", version: "1.0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := selectFixture(t, packages, request,
				map[string][]slices.PackageVersion{"base-files": test.candidates}, nil)
			got := selected[0]
			if got.Archive != test.archive || got.Suite != test.suite ||
				got.Component != test.component || got.Version != test.version {
				t.Fatalf("origin = %+v, want %s/%s/%s/%s",
					got, test.archive, test.suite, test.component, test.version)
			}
		})
	}
}

func TestSelectPackageOriginsPinnedArchiveAndNegativePriority(t *testing.T) {
	packages := fixturePackages(t)
	request := []slices.SliceKey{{Package: "fixture", Slice: "runtime"}}
	selected := selectFixture(t, packages, request, map[string][]slices.PackageVersion{
		"fixture": {
			{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "9.0"},
			{Archive: "pinned-only", Suite: "resolute", Component: "main", Version: "1.0"},
		},
		"base-files": {
			{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10"},
		},
	}, nil)
	var fixture *slices.PackageSelection
	for i := range selected {
		if selected[i].Package == "fixture" {
			fixture = &selected[i]
		}
	}
	if fixture == nil || fixture.Archive != "pinned-only" || fixture.Version != "1.0" {
		t.Fatalf("fixture origin = %+v", selected)
	}
	if _, err := slices.SelectPackageOrigins(packages, fixtureCatalogue(t),
		[]slices.SliceKey{{Package: "fixture", Slice: "runtime"}},
		request, map[string][]slices.PackageVersion{
			"fixture": {{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "9.0"}},
			"base-files": {
				{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10"},
			},
		}, nil); err == nil || !strings.Contains(err.Error(), `pinned archive "pinned-only"`) {
		t.Fatalf("pinned archive fallback error = %v", err)
	}
	demo := &slices.Package{
		Name: "demo", RealName: "demo", Path: "slices/demo.yaml",
		SHA256: strings.Repeat("a", 64), Size: 1,
		Slices: map[string]slices.Slice{"runtime": {Name: "runtime"}},
	}
	if _, err := slices.SelectPackageOrigins(map[string]*slices.Package{"demo": demo}, fixtureCatalogue(t),
		[]slices.SliceKey{{Package: "demo", Slice: "runtime"}},
		[]slices.SliceKey{{Package: "demo", Slice: "runtime"}},
		map[string][]slices.PackageVersion{"demo": {
			{Archive: "pinned-only", Suite: "resolute", Component: "main", Version: "1.0"},
		}}, nil); err == nil || !strings.Contains(err.Error(), "eligible archive") {
		t.Fatalf("negative archive error = %v", err)
	}
}

func TestSelectPackageOriginsExactPinDoesNotSwitchArchive(t *testing.T) {
	packages := fixturePackages(t)
	request := []slices.SliceKey{{Package: "base-files", Slice: "etc"}}
	_, err := slices.SelectPackageOrigins(packages, fixtureCatalogue(t),
		[]slices.SliceKey{{Package: "base-files", Slice: "copyright"},
			{Package: "base-files", Slice: "etc"}},
		request, map[string][]slices.PackageVersion{"base-files": {
			{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "1.0"},
			{Archive: "ubuntu-esm-apps", Suite: "resolute-apps-security", Component: "main", Version: "2.0"},
		}}, map[string]string{"base-files": "= 1.0"})
	if err == nil || !strings.Contains(err.Error(), "ubuntu-esm-apps") {
		t.Fatalf("error = %v", err)
	}
	selected := selectFixture(t, packages, request, map[string][]slices.PackageVersion{"base-files": {
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "1.0-0"},
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "1.0"},
	}}, map[string]string{"base-files": "= 1.0"})
	if selected[0].Version != "1.0" {
		t.Fatalf("pinned version = %q", selected[0].Version)
	}
}

// A constraint selects among versions the archive offers instead of demanding one
// exact string, so an archive that publishes several builds can satisfy it.
func TestSelectPackageOriginsConstraint(t *testing.T) {
	packages := fixturePackages(t)
	request := []slices.SliceKey{{Package: "base-files", Slice: "etc"}}
	versions := map[string][]slices.PackageVersion{"base-files": {
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu9"},
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10.1"},
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu11"},
	}}
	selected := selectFixture(t, packages, request, versions, map[string]string{"base-files": "~> 13"})
	if selected[0].Version != "13ubuntu11" {
		t.Fatalf("pessimistic version = %q", selected[0].Version)
	}
	selected = selectFixture(t, packages, request, versions, map[string]string{"base-files": "> 13ubuntu9, < 13ubuntu11"})
	if selected[0].Version != "13ubuntu10.1" {
		t.Fatalf("bounded version = %q", selected[0].Version)
	}
	selected = selectFixture(t, packages, request, versions, map[string]string{"base-files": "= 13ubuntu10.1"})
	if selected[0].Version != "13ubuntu10.1" {
		t.Fatalf("exact upstream version = %q", selected[0].Version)
	}
	if _, err := slices.SelectPackageOrigins(packages, fixtureCatalogue(t),
		[]slices.SliceKey{{Package: "base-files", Slice: "etc"}}, request, versions,
		map[string]string{"base-files": "= 13ubuntu10"}); err == nil {
		t.Fatal("upstream equality should not accept a longer upstream")
	}
	selected = selectFixture(t, packages, request, versions, map[string]string{"base-files": "< 13ubuntu10.1"})
	if selected[0].Version != "13ubuntu9" {
		t.Fatalf("ordering version = %q", selected[0].Version)
	}
}

func TestSelectPackageOriginsStoreSelection(t *testing.T) {
	packages := fixturePackages(t)
	base := map[string][]slices.PackageVersion{"base-files": {
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10"},
	}}
	if _, err := slices.SelectPackageOrigins(packages, fixtureCatalogue(t),
		[]slices.SliceKey{{Package: "base-files", Slice: "release-info"}, {Package: "bin-demo", Slice: "bins"}},
		[]slices.SliceKey{{Package: "bin-demo", Slice: "bins"}}, base, nil); err == nil ||
		!strings.Contains(err.Error(), `store "bin"`) || !strings.Contains(err.Error(), `track "1"`) ||
		!strings.Contains(err.Error(), `"bin-demo"`) {
		t.Fatalf("store error = %v", err)
	}
	if _, err := slices.SelectPackageOrigins(packages, fixtureCatalogue(t),
		[]slices.SliceKey{{Package: "base-files", Slice: "etc"}},
		[]slices.SliceKey{{Package: "base-files", Slice: "etc"}}, base, nil); err != nil {
		t.Fatalf("unselected store failed: %v", err)
	}
}

func TestSelectPackageOriginsDefinitionDrift(t *testing.T) {
	packages := fixturePackages(t)
	request := []slices.SliceKey{{Package: "base-files", Slice: "etc"}}
	versions := map[string][]slices.PackageVersion{"base-files": {
		{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10"},
	}}
	base := selectFixture(t, packages, request, versions, nil)[0].DefinitionDigest
	changed := parseFixtureWith(t, map[string]string{
		"slices/base-files.yaml": fixtureFile(t, "slices/base-files.yaml") +
			"  drift:\n    contents:\n      /usr/share/drift: {text: \"drift\\n\"}\n",
	})
	if got := selectFixture(t, changed, request, versions, nil)[0].DefinitionDigest; got == base {
		t.Fatal("unselected definition drift did not change digest")
	}
	unrelated := parseFixtureWith(t, map[string]string{
		"slices/provider.yaml": fixtureFile(t, "slices/provider.yaml") + "\n# unrelated drift\n",
	})
	if got := selectFixture(t, unrelated, request, versions, nil)[0].DefinitionDigest; got != base {
		t.Fatalf("unrelated drift changed digest: %q", got)
	}
}

func fixtureCatalogue(t *testing.T) *slices.Catalogue {
	t.Helper()
	data, err := os.ReadFile("testdata/chisel-v3/catalogue/chisel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := slices.ParseCatalogue(data)
	if err != nil {
		t.Fatal(err)
	}
	return catalogue
}

func fixtureFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/chisel-v3/catalogue/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func parseFixtureWith(t *testing.T, overrides map[string]string) map[string]*slices.Package {
	t.Helper()
	files := map[string]string{
		"chisel.yaml":            fixtureFile(t, "chisel.yaml"),
		"slices/base-files.yaml": fixtureFile(t, "slices/base-files.yaml"),
		"slices/fixture.yaml":    fixtureFile(t, "slices/fixture.yaml"),
		"slices/provider.yaml":   fixtureFile(t, "slices/provider.yaml"),
		"bin-slices/demo.yaml":   fixtureFile(t, "bin-slices/demo.yaml"),
	}
	maps.Copy(files, overrides)
	root := fstest.MapFS{}
	for name, content := range files {
		root[name] = &fstest.MapFile{Data: []byte(content)}
	}
	catalogue, err := slices.ParseCatalogue([]byte(files["chisel.yaml"]))
	if err != nil {
		t.Fatal(err)
	}
	packages, err := slices.ParsePackages(root, catalogue)
	if err != nil {
		t.Fatal(err)
	}
	return packages
}

func TestSelectPackageOriginsRejectsInvalidSelectedEvidence(t *testing.T) {
	packages := fixturePackages(t)
	request := []slices.SliceKey{{Package: "base-files", Slice: "etc"}}
	for _, test := range []struct {
		name      string
		candidate slices.PackageVersion
		wantPart  string
	}{
		{
			name:      "unknown suite",
			candidate: slices.PackageVersion{Archive: "ubuntu", Suite: "unknown", Component: "main", Version: "1.0"},
			wantPart:  `unknown suite "unknown"`,
		},
		{
			name:      "unknown component",
			candidate: slices.PackageVersion{Archive: "ubuntu", Suite: "resolute", Component: "unknown", Version: "1.0"},
			wantPart:  `unknown component "unknown"`,
		},
		{
			name:      "invalid version",
			candidate: slices.PackageVersion{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "not-a-version"},
			wantPart:  "invalid version",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := slices.SelectPackageOrigins(packages, fixtureCatalogue(t),
				[]slices.SliceKey{{Package: "base-files", Slice: "copyright"},
					{Package: "base-files", Slice: "etc"}},
				request, map[string][]slices.PackageVersion{"base-files": {test.candidate}}, nil)
			if err == nil || !strings.Contains(err.Error(), test.wantPart) {
				t.Fatalf("error = %v, want %q", err, test.wantPart)
			}
		})
	}
	selected := selectFixture(t, packages, request, map[string][]slices.PackageVersion{
		"base-files": {{Archive: "ubuntu", Suite: "resolute", Component: "main", Version: "13ubuntu10"}},
		"provider": {{
			Archive: "ubuntu-esm-apps", Suite: "resolute-apps-security",
			Component: "main", Version: "invalid",
		}},
	}, nil)
	if len(selected) != 1 {
		t.Fatalf("selected unrequested evidence: %+v", selected)
	}
}
