package slices_test

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func testCatalogue() *slices.Catalogue {
	return &slices.Catalogue{
		Archives: map[string]slices.Archive{
			"main":       {Name: "main"},
			"restricted": {Name: "restricted", Pro: "esm-apps"},
		},
		Stores: map[string]slices.Store{
			"bin": {Name: "bin", Kind: "bin", Version: "26.04", DefaultPrefix: "bin-"},
		},
	}
}

func parseSDFs(t *testing.T, files map[string]string) (map[string]*slices.Package, error) {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(data)}
	}
	return slices.ParsePackages(fsys, testCatalogue())
}

func packageSDF() string {
	return "package: demo\nslices:\n  runtime:\n    contents:\n      /demo: {}\n"
}

func TestParsePackagesFixture(t *testing.T) {
	root := os.DirFS("testdata/chisel-v3/catalogue")
	rootData, err := os.ReadFile("testdata/chisel-v3/catalogue/chisel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := slices.ParseCatalogue(rootData)
	if err != nil {
		t.Fatal(err)
	}
	packages, err := slices.ParsePackages(root, catalogue)
	if err != nil {
		t.Fatal(err)
	}
	if err := slices.ValidatePackages(packages); err != nil {
		t.Fatalf("ValidatePackages() = %v", err)
	}
	if len(packages) != 4 {
		t.Fatalf("packages = %d, want 4", len(packages))
	}
	fixture := packages["fixture"]
	if fixture == nil || fixture.Archive != "pinned-only" {
		t.Fatalf("fixture package = %+v", fixture)
	}
	runtime := fixture.Slices["runtime"]
	if _, ok := runtime.Essential[slices.SliceKey{Package: "fixture", Slice: "support"}]; !ok {
		t.Fatal("runtime essential is missing support")
	}
	if info := runtime.Contents["/usr/share/fixture/output"]; info.Kind != slices.PathText ||
		info.Info != "before\n" || !info.Mutable || info.Mode != 0o644 {
		t.Fatalf("output info = %+v", info)
	}
	if info := runtime.Contents["/usr/lib/fixture/*.so*"]; info.Kind != slices.PathGlob ||
		len(info.Arch) != 1 || info.Arch[0] != "amd64" {
		t.Fatalf("glob info = %+v", info)
	}
	if info := runtime.Contents["/usr/share/fixture/preferred"]; info.Prefer != "provider" {
		t.Fatalf("prefer info = %+v", info)
	}
	if info := fixture.Slices["manifest"].Contents["/var/lib/chisel/**"]; info.Kind != slices.PathGenerate ||
		info.Generate != slices.GenerateManifest {
		t.Fatalf("generate info = %+v", info)
	}
	demo := packages["bin-demo"]
	if demo == nil || demo.RealName != "demo" || demo.Store != "bin" || demo.DefaultTrack != "1" {
		t.Fatalf("store package = %+v", demo)
	}
}

func TestParsePackagesRejectsInterpolation(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"package", "package: ${PACKAGE}\nslices:\n  runtime: {}\n"},
		{"slice", "package: demo\nslices:\n  ${SLICE}: {}\n"},
		{"hint", "package: demo\nslices:\n  runtime:\n    hint: ${HINT}\n"},
		{"content path", "package: demo\nslices:\n  runtime:\n    contents:\n      /${PATH}: {}\n"},
		{"copy source", "package: demo\nslices:\n  runtime:\n    contents:\n      /demo: {copy: \"${SOURCE}\"}\n"},
		{"essential arch", "package: demo\nessential:\n  other_alpha: {arch: [\"${ARCH}\"]}\nslices:\n  runtime: {}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSDFs(t, map[string]string{"slices/demo.yaml": test.data})
			if err == nil || !strings.Contains(err.Error(), "interpolation") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestParsePackagesAllowsInterpolationInContent(t *testing.T) {
	_, err := parseSDFs(t, map[string]string{"slices/demo.yaml": `package: demo
slices:
  runtime:
    mutate: echo ${HOME}
    contents:
      /demo: {text: "${HOME}"}
`})
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePackagesDiscovery(t *testing.T) {
	t.Run("nested and optional bin-slices", func(t *testing.T) {
		packages, err := parseSDFs(t, map[string]string{
			"slices/nested/demo.yaml": "package: demo\nslices:\n  runtime: {}\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		if packages["demo"] == nil || packages["demo"].Path != "slices/nested/demo.yaml" {
			t.Fatalf("packages = %+v", packages)
		}
	})
	t.Run("missing slices", func(t *testing.T) {
		_, err := parseSDFs(t, map[string]string{"bin-slices/demo.yaml": packageSDF()})
		if err == nil || !strings.Contains(err.Error(), "read slices directory failed") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("slices is a file", func(t *testing.T) {
		_, err := parseSDFs(t, map[string]string{"slices": packageSDF()})
		if err == nil || !strings.Contains(err.Error(), "read slices directory failed") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("bin-slices is a file", func(t *testing.T) {
		_, err := parseSDFs(t, map[string]string{
			"slices/demo.yaml": packageSDF(),
			"bin-slices":       "not a directory",
		})
		if err == nil || !strings.Contains(err.Error(), "read bin-slices directory failed") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("invalid filename", func(t *testing.T) {
		_, err := parseSDFs(t, map[string]string{"slices/Invalid.yaml": packageSDF()})
		if err == nil || !strings.Contains(err.Error(), "invalid slice definition filename") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate package", func(t *testing.T) {
		_, err := parseSDFs(t, map[string]string{
			"slices/demo.yaml":      packageSDF(),
			"slices/more/demo.yaml": packageSDF(),
		})
		if err == nil || !strings.Contains(err.Error(), "defined more than once") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("store prefix collision", func(t *testing.T) {
		_, err := parseSDFs(t, map[string]string{
			"slices/bin-demo.yaml": "package: bin-demo\nslices:\n  runtime: {}\n",
			"bin-slices/demo.yaml": "package: demo\nstore: bin\ndefault-track: \"1\"\nslices:\n  runtime: {}\n",
		})
		if err == nil || !strings.Contains(err.Error(), "defined more than once") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestParsePackagesDocumentErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "slice definition is empty"},
		{"multiple documents", "package: demo\nslices: {}\n---\npackage: demo\n", "one YAML document"},
		{"package mismatch", "package: other\nslices: {}\n", "does not match filename"},
		{"unknown field", "package: demo\nformat: v3\nslices: {}\n", "field format not found"},
		{"duplicate field", "package: demo\npackage: demo\nslices: {}\n", "already defined"},
		{"legacy essential list", "package: demo\nessential: [base-files_release-info]\nslices: {}\n", "essential must be a map"},
		{"essential scalar", "package: demo\nslices:\n  runtime:\n    essential:\n      other_alpha: true\n", "essential value must be a map"},
		{"essential unknown field", "package: demo\nslices:\n  runtime:\n    essential:\n      other_alpha: {track: stable}\n", "unknown field"},
		{"v3 essential", "package: demo\nv3-essential: {}\nslices: {}\n", "field v3-essential not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSDFs(t, map[string]string{"slices/demo.yaml": test.data})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParsePackagesTargets(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			"undefined archive",
			"package: demo\narchive: absent\nslices: {}\n",
			"undefined archive",
		},
		{
			"undefined store",
			"package: demo\nstore: absent\ndefault-track: \"1\"\nslices: {}\n",
			"undefined store",
		},
		{
			"store without track",
			"package: demo\nstore: bin\nslices: {}\n",
			"requires default-track",
		},
		{
			"store and archive",
			"package: demo\nstore: bin\narchive: main\ndefault-track: \"1\"\nslices: {}\n",
			"both archive and store",
		},
		{
			"track without store",
			"package: demo\ndefault-track: \"1\"\nslices: {}\n",
			"without a store",
		},
		{
			"track with slash",
			"package: demo\nstore: bin\ndefault-track: \"1/edge\"\nslices: {}\n",
			"must not contain /",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSDFs(t, map[string]string{"slices/demo.yaml": test.data})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParsePackagesHintsAndNames(t *testing.T) {
	hint40 := strings.Repeat("a", 40)
	hint41 := strings.Repeat("a", 41)
	tests := []struct {
		name string
		data string
		want string
	}{
		{"40 byte hint", "package: demo\nslices:\n  runtime:\n    hint: " + hint40 + "\n", ""},
		{"41 byte hint", "package: demo\nslices:\n  runtime:\n    hint: " + hint41 + "\n", "hint exceeds"},
		{"non-printable hint", "package: demo\nslices:\n  runtime:\n    hint: \"a\\tb\"\n", "non-printable"},
		{"short slice name", "package: demo\nslices:\n  ab: {}\n", "invalid slice name"},
		{"uppercase slice name", "package: demo\nslices:\n  Runtime: {}\n", "invalid slice name"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSDFs(t, map[string]string{"slices/demo.yaml": test.data})
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParsePackagesEssentials(t *testing.T) {
	t.Run("essential architectures preserved", func(t *testing.T) {
		packages, err := parseSDFs(t, map[string]string{
			"slices/demo.yaml": `package: demo
essential:
  other_alpha: {arch: [amd64, amd64, imaginary]}
slices:
  runtime: {}
`,
			"slices/other.yaml": "package: other\nslices:\n  alpha: {}\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		info := packages["demo"].Slices["runtime"].Essential[slices.SliceKey{Package: "other", Slice: "alpha"}]
		if got := strings.Join(info.Arch, ","); got != "amd64,amd64,imaginary" {
			t.Fatalf("arch = %q", got)
		}
	})
	t.Run("package and slice merge", func(t *testing.T) {
		packages, err := parseSDFs(t, map[string]string{
			"slices/demo.yaml": `package: demo
essential:
  other_alpha: {arch: ppc64el}
  demo_runtime:
slices:
  runtime:
    essential:
      other_beta:
`,
			"slices/other.yaml": "package: other\nslices:\n  alpha: {}\n  beta: {}\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		essential := packages["demo"].Slices["runtime"].Essential
		if _, ok := essential[slices.SliceKey{Package: "demo", Slice: "runtime"}]; ok {
			t.Fatal("package essential self was not omitted")
		}
		if info := essential[slices.SliceKey{Package: "other", Slice: "alpha"}]; len(info.Arch) != 1 || info.Arch[0] != "ppc64el" {
			t.Fatalf("alpha info = %+v", info)
		}
		if _, ok := essential[slices.SliceKey{Package: "other", Slice: "beta"}]; !ok {
			t.Fatal("slice essential beta is missing")
		}
	})
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			"slice self",
			"package: demo\nslices:\n  runtime:\n    essential:\n      demo_runtime:\n",
			"cannot be essential to itself",
		},
		{
			"duplicate ref",
			"package: demo\nessential:\n  other_alpha:\nslices:\n  runtime:\n    essential:\n      other_alpha:\n",
			"repeats other_alpha",
		},
		{
			"invalid ref",
			"package: demo\nslices:\n  runtime:\n    essential:\n      Missing_slice:\n",
			"invalid essential slice reference",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSDFs(t, map[string]string{
				"slices/demo.yaml":  test.data,
				"slices/other.yaml": "package: other\nslices:\n  alpha: {}\n",
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
