package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

// ownedTree builds a tree holding one file per package, so a list can be checked
// against the package that really carried each path.
func ownedTree(t *testing.T, files map[string]string) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for name, pkg := range files {
		if err := tree.File(name, []byte("x"), vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Package: pkg, Path: "pool/" + pkg + ".deb"}}); err != nil {
			t.Fatalf("File %s: %v", name, err)
		}
	}
	return tree
}

func TestFileLists_NamesEveryOwnedPath(t *testing.T) {
	tree := ownedTree(t, map[string]string{
		"/etc/os-release":    "base-files",
		"/usr/bin/openssl":   "openssl",
		"/usr/lib/libssl.so": "openssl",
	})
	if err := synthesis.FileLists(tree, []synthesis.PackageState{
		packageState("openssl", "3.0.13", synthesis.StatusInstalled, baseFilesControl),
		packageState("base-files", "26.04", synthesis.StatusUnpacked, libc6Control),
	}); err != nil {
		t.Fatalf("FileLists: %v", err)
	}
	if list := readFile(t, tree, synthesis.InfoDir+"/openssl.list"); list != "/usr/bin/openssl\n/usr/lib/libssl.so\n" {
		t.Fatalf("openssl list = %q", list)
	}
	if list := readFile(t, tree, synthesis.InfoDir+"/base-files.list"); list != "/etc/os-release\n" {
		t.Fatalf("base-files list = %q", list)
	}
}

// dpkg qualifies the file only for a package that can be installed twice, so
// qualifying any other package makes it look for a file nothing wrote and warn
// about the missing list.
func TestFileLists_QualifiesOnlyMultiArchSame(t *testing.T) {
	const samePackage = `Package: libacl1
Version: 2.3.2
Architecture: amd64
Multi-Arch: same
Description: access control list shared library
`
	const foreignPackage = `Package: busybox-static
Version: 1.36
Architecture: amd64
Multi-Arch: foreign
Description: Standalone rescue shell
`
	tree := ownedTree(t, map[string]string{"/usr/lib/libacl.so": "libacl1"})
	if err := synthesis.FileLists(tree, []synthesis.PackageState{
		packageState("libacl1", "2.3.2", synthesis.StatusInstalled, samePackage),
		packageState("busybox-static", "1.36", synthesis.StatusInstalled, foreignPackage),
	}); err != nil {
		t.Fatalf("FileLists: %v", err)
	}
	if !strings.Contains(readFile(t, tree, synthesis.InfoDir+"/libacl1:amd64.list"), "/usr/lib/libacl.so") {
		t.Fatal("the multi-arch qualified list is missing the package's file")
	}
	for _, unwanted := range []string{synthesis.InfoDir + "/libacl1.list",
		synthesis.InfoDir + "/busybox-static:amd64.list"} {
		if _, ok := tree.Lookup(unwanted); ok {
			t.Fatalf("%s was written for a package dpkg does not qualify", unwanted)
		}
	}
}

// A package whose content left no regular file is not in the image, so it gets
// neither a list nor a status record: the record would claim a package whose files
// are absent and make a scanner report an advisory for code the image cannot run.
func TestFileLists_IgnoresPackageWithoutFiles(t *testing.T) {
	tree := vfs.New()
	if err := tree.Dir("/usr/lib/ssl", vfs.Attrs{Mode: 0o755,
		Origin: vfs.Origin{Package: "openssl", Path: "openssl.deb"}}); err != nil {
		t.Fatalf("dir: %v", err)
	}
	packages := []synthesis.PackageState{
		packageState("openssl", "3.0.13", synthesis.StatusUnpacked, "Package: openssl\nVersion: 3.0.13\n"),
	}
	if err := synthesis.FileLists(tree, packages); err != nil {
		t.Fatalf("FileLists: %v", err)
	}
	if _, ok := tree.Lookup(synthesis.InfoDir + "/openssl.list"); ok {
		t.Fatal("a package without files got a file list")
	}
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	if _, ok := tree.Lookup(synthesis.StatusPath); ok {
		t.Fatal("a package without files got a status record")
	}
}

// A path that only exists as someone's parent directory was never in a package,
// so no list may claim it.
func TestFileLists_IgnoresImplicitDirectories(t *testing.T) {
	tree := ownedTree(t, map[string]string{"/usr/lib/openssl/engine.so": "openssl"})
	if err := synthesis.FileLists(tree, []synthesis.PackageState{
		packageState("openssl", "3.0.13", synthesis.StatusInstalled, baseFilesControl),
	}); err != nil {
		t.Fatalf("FileLists: %v", err)
	}
	if list := readFile(t, tree, synthesis.InfoDir+"/openssl.list"); list != "/usr/lib/openssl/engine.so\n" {
		t.Fatalf("list = %q", list)
	}
}

func TestFileLists_RejectsInvalidInput(t *testing.T) {
	if err := synthesis.FileLists(nil, nil); err == nil {
		t.Fatal("expected an error for a nil tree")
	}
	tree := vfs.New()
	if err := synthesis.FileLists(tree, []synthesis.PackageState{
		packageState("", "1", synthesis.StatusInstalled, baseFilesControl),
	}); err == nil || !strings.Contains(err.Error(), "no name") {
		t.Fatalf("error %v does not reject a nameless package", err)
	}
	if err := synthesis.FileLists(tree, []synthesis.PackageState{
		packageState("demo", "1", synthesis.StatusInstalled, "Package: demo\nbroken line\n"),
	}); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("error %v does not reject an unusable control stanza", err)
	}
}
