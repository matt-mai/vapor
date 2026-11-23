package slices

import (
	"os"
	"testing"
	"testing/fstest"
)

func TestCheckPackagesValidFixture(t *testing.T) {
	t.Parallel()
	root := os.DirFS("testdata/chisel-v3/catalogue")
	data, err := os.ReadFile("testdata/chisel-v3/catalogue/chisel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := ParseCatalogue(data)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := CheckPackages(root, catalogue, CheckDiagnosticLimit); len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", diagnostics)
	}
}

func TestCheckPackagesStoreBackedPackageOffline(t *testing.T) {
	t.Parallel()
	catalogue := &Catalogue{
		Archives: map[string]Archive{},
		Stores: map[string]Store{"bin": {
			Name: "bin", Kind: "bin", Version: "26.04", DefaultPrefix: "bin-",
		}},
	}
	valid := fstest.MapFS{
		"slices/demo.yaml": &fstest.MapFile{Data: []byte(
			"package: demo\nstore: bin\ndefault-track: 1\nslices:\n  runtime: {}\n")},
	}
	if diagnostics := CheckPackages(valid, catalogue, CheckDiagnosticLimit); len(diagnostics) != 0 {
		t.Fatalf("store-backed diagnostics = %v", diagnostics)
	}
	invalid := fstest.MapFS{
		"slices/demo.yaml": &fstest.MapFile{Data: []byte(
			"package: demo\nstore: missing\ndefault-track: 1\nslices:\n  runtime: {}\n")},
	}
	if diagnostics := CheckPackages(invalid, catalogue, CheckDiagnosticLimit); len(diagnostics) != 1 {
		t.Fatalf("invalid store diagnostics = %v", diagnostics)
	}
}

func TestCheckPackagesCollectsIndependentFileErrors(t *testing.T) {
	t.Parallel()
	catalogue := &Catalogue{Archives: map[string]Archive{"ubuntu": {Name: "ubuntu", Version: "26.04"}}}
	fsys := fstest.MapFS{
		"slices/bad.yaml":   &fstest.MapFile{Data: []byte("package: bad\narchive: missing\n")},
		"slices/worse.yaml": &fstest.MapFile{Data: []byte("package: worse\nunknown: 1\n")},
	}
	diagnostics := CheckPackages(fsys, catalogue, CheckDiagnosticLimit)
	if len(diagnostics) != 2 {
		t.Fatalf("diagnostics = %v", diagnostics)
	}
	limited := CheckPackages(fsys, catalogue, 1)
	if len(limited) != 2 || limited[1].Error() != "1 more diagnostics omitted" {
		t.Fatalf("limited = %v", limited)
	}
}

func TestCheckPackagesBoundsRetainedDiagnostics(t *testing.T) {
	t.Parallel()
	catalogue := &Catalogue{Archives: map[string]Archive{"ubuntu": {Name: "ubuntu", Version: "26.04"}}}
	fsys := fstest.MapFS{}
	for _, name := range []string{"a", "b", "c", "d"} {
		fsys["slices/"+name+".yaml"] = &fstest.MapFile{Data: []byte("package: " + name + "\narchive: missing\n")}
	}
	limited := CheckPackages(fsys, catalogue, 2)
	if len(limited) != 3 || limited[2].Error() != "2 more diagnostics omitted" {
		t.Fatalf("limited = %v", limited)
	}
}
