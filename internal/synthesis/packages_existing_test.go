package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

func TestPackageDatabase_PreservesContinuationLines(t *testing.T) {
	tree := treeOwning(t, "base-files")
	if err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
	}); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if !strings.Contains(content, "Description: Debian base system miscellaneous files\n This package contains") {
		t.Fatalf("description was reformatted:\n%s", content)
	}
}

func TestPackageDatabase_KeepsUncoveredRecords(t *testing.T) {
	existing := "Package: artifact-tool\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n"
	tree := treeWithFile(t, synthesis.StatusPath, existing)
	if err := tree.File("/usr/lib/base-files", []byte("x"), vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Package: "base-files", Path: "base-files.deb"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
	}); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if !strings.Contains(content, "Package: artifact-tool\nVersion: 1.0\n") {
		t.Fatalf("existing record was dropped:\n%s", content)
	}
	if strings.Contains(content, "Status:") {
		t.Fatalf("a carried-over record reintroduced a status:\n%s", content)
	}
	if !strings.Contains(content, "Package: base-files") {
		t.Fatalf("generated record is missing:\n%s", content)
	}
}

// An image of whole packages keeps a carried-over record's status, because the
// database it lands in declares statuses too.
func TestPackageDatabase_KeepsCarriedOverStatusInAWholePackageImage(t *testing.T) {
	existing := "Package: artifact-tool\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n"
	tree := treeWithFile(t, synthesis.StatusPath, existing)
	if err := tree.File("/usr/lib/openssl", []byte("x"), vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Package: "openssl", Path: "openssl.deb"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
		packageState("openssl", "3.0.13", synthesis.StatusInstalled, opensslControl),
	}); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if !strings.Contains(content, "Package: artifact-tool\nStatus: install ok installed\n") {
		t.Fatalf("a carried-over status was dropped from a whole-package image:\n%s", content)
	}
}

func TestPackageDatabase_RejectsMalformedExistingStatus(t *testing.T) {
	tree := treeWithFile(t, synthesis.StatusPath, "Status: install ok installed\n\n")
	err := synthesis.PackageDatabase(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "without a package name") {
		t.Fatalf("error %v does not reject the record", err)
	}
}
