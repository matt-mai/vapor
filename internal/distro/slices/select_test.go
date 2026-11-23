package slices_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func fixturePackages(t *testing.T) map[string]*slices.Package {
	t.Helper()
	root := os.DirFS("testdata/chisel-v3/catalogue")
	data, err := os.ReadFile("testdata/chisel-v3/catalogue/chisel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := slices.ParseCatalogue(data)
	if err != nil {
		t.Fatal(err)
	}
	packages, err := slices.ParsePackages(root, catalogue)
	if err != nil {
		t.Fatal(err)
	}
	if err := slices.ValidatePackages(packages); err != nil {
		t.Fatal(err)
	}
	return packages
}

func sliceNames(keys []slices.SliceKey) []string {
	names := make([]string, len(keys))
	for i, key := range keys {
		names[i] = key.String()
	}
	return names
}

func TestSelectSlicesStarterClosure(t *testing.T) {
	data, err := os.ReadFile("testdata/chisel-v3/expectations.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		StarterSelection     string              `json:"starterSelection"`
		StarterClosureByArch map[string][]string `json:"starterClosureByArch"`
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	packageName, sliceName, ok := strings.Cut(evidence.StarterSelection, "_")
	if !ok {
		t.Fatalf("invalid starter selection %q", evidence.StarterSelection)
	}
	root := slices.SliceKey{Package: packageName, Slice: sliceName}
	packages := fixturePackages(t)
	for architecture, want := range evidence.StarterClosureByArch {
		t.Run(architecture, func(t *testing.T) {
			got, err := slices.SelectSlices(packages, []slices.SliceKey{root}, nil, architecture)
			if err != nil {
				t.Fatal(err)
			}
			if names := sliceNames(got); strings.Join(names, ",") != strings.Join(want, ",") {
				t.Fatalf("closure = %v, want %v", names, want)
			}
		})
	}
}

func TestSelectSlicesArchitectureFilter(t *testing.T) {
	packages := fixturePackages(t)
	root := slices.SliceKey{Package: "fixture", Slice: "runtime"}
	for _, test := range []struct {
		architecture string
		support      bool
	}{
		{architecture: "amd64", support: true},
		{architecture: "arm64", support: true},
		{architecture: "ppc64el"},
	} {
		t.Run(test.architecture, func(t *testing.T) {
			got, err := slices.SelectSlices(packages, []slices.SliceKey{root}, nil, test.architecture)
			if err != nil {
				t.Fatal(err)
			}
			names := sliceNames(got)
			joined := strings.Join(names, ",")
			if strings.Contains(joined, "fixture_support") != test.support {
				t.Fatalf("support closure = %v", names)
			}
			if names[len(names)-1] != "fixture_runtime" {
				t.Fatalf("runtime is not last: %v", names)
			}
		})
	}
}

func TestSelectSlicesOmitsPackageSelfAndIsOrderIndependent(t *testing.T) {
	packages := fixturePackages(t)
	etc := slices.SliceKey{Package: "base-files", Slice: "etc"}
	releaseInfo := slices.SliceKey{Package: "base-files", Slice: "release-info"}
	first, err := slices.SelectSlices(packages, []slices.SliceKey{etc}, nil, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sliceNames(first), ","); got != "base-files_copyright,base-files_etc" {
		t.Fatalf("closure = %q", got)
	}
	second, err := slices.SelectSlices(packages, []slices.SliceKey{releaseInfo, etc}, nil, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	third, err := slices.SelectSlices(packages, []slices.SliceKey{etc, releaseInfo}, nil, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(sliceNames(second), ",") != strings.Join(sliceNames(third), ",") {
		t.Fatalf("request order changed closure: %v vs %v", sliceNames(second), sliceNames(third))
	}
}

func TestSelectSlicesRejectsWholeOverlap(t *testing.T) {
	packages := fixturePackages(t)
	_, err := slices.SelectSlices(packages,
		[]slices.SliceKey{{Package: "fixture", Slice: "runtime"}}, []string{"base-files"}, "amd64")
	if err == nil || !strings.Contains(err.Error(), "base-files") ||
		!strings.Contains(err.Error(), "both whole and sliced") {
		t.Fatalf("error = %v", err)
	}
}

func TestSelectSlicesRejectsTransitiveWholeOverlap(t *testing.T) {
	packages, err := parseSDFs(t, map[string]string{
		"slices/app.yaml":        "package: app\nslices:\n  main:\n    essential:\n      base-files_etc:\n",
		"slices/base-files.yaml": "package: base-files\nslices:\n  etc: {}\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = slices.SelectSlices(packages,
		[]slices.SliceKey{{Package: "app", Slice: "main"}}, []string{"base-files"}, "amd64")
	if err == nil || !strings.Contains(err.Error(), "base-files") ||
		!strings.Contains(err.Error(), "both whole and sliced") {
		t.Fatalf("error = %v", err)
	}
}

func TestSelectSlicesErrors(t *testing.T) {
	if _, err := slices.SelectSlices(nil, nil, nil, "amd64"); err == nil {
		t.Fatal("nil packages succeeded")
	}
	for _, test := range []struct {
		name     string
		files    map[string]string
		root     slices.SliceKey
		wantPart string
	}{
		{
			name:     "unknown package",
			files:    map[string]string{"slices/demo.yaml": packageSDF()},
			root:     slices.SliceKey{Package: "missing", Slice: "runtime"},
			wantPart: `slices of package "missing" not found`,
		},
		{
			name:     "unknown slice",
			files:    map[string]string{"slices/demo.yaml": packageSDF()},
			root:     slices.SliceKey{Package: "demo", Slice: "missing"},
			wantPart: "slice demo_missing not found",
		},
		{
			name: "missing essential",
			files: map[string]string{
				"slices/demo.yaml": "package: demo\nessential:\n  other_alpha:\nslices:\n  runtime: {}\n",
			},
			root:     slices.SliceKey{Package: "demo", Slice: "runtime"},
			wantPart: "requires other_alpha",
		},
		{
			name: "essential loop",
			files: map[string]string{
				"slices/demo.yaml":  "package: demo\nslices:\n  runtime:\n    essential:\n      other_alpha:\n",
				"slices/other.yaml": "package: other\nslices:\n  alpha:\n    essential:\n      demo_runtime:\n",
			},
			root:     slices.SliceKey{Package: "demo", Slice: "runtime"},
			wantPart: "essential loop detected",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			packages, err := parseSDFs(t, test.files)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := slices.SelectSlices(packages, []slices.SliceKey{test.root}, nil, "amd64"); err == nil ||
				!strings.Contains(err.Error(), test.wantPart) {
				t.Fatalf("error = %v, want %q", err, test.wantPart)
			}
		})
	}
}
