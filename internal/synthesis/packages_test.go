package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

const baseFilesControl = `Package: base-files
Version: 13ubuntu10.5
Architecture: amd64
Essential: yes
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Installed-Size: 426
Section: admin
Priority: required
Description: Debian base system miscellaneous files
 This package contains the basic filesystem hierarchy of a Debian system.
`

const libc6Control = `Package: libc6
Version: 2.39-0ubuntu8.5
Architecture: amd64
Installed-Size: 13000
Description: GNU C Library
`

const opensslControl = `Package: openssl
Version: 3.0.13
Architecture: amd64
Depends: libc6 (>= 2.38)
Description: Secure Sockets Layer toolkit
`

func packageState(name, version string, status synthesis.PackageStatus, control string) synthesis.PackageState {
	return synthesis.PackageState{
		Name:         name,
		Version:      version,
		Architecture: "amd64",
		Status:       status,
		Control:      []byte(control),
	}
}

// treeOwning creates a tree and gives each named package one file, because a
// record follows the files: a package that contributed nothing gets no record.
func treeOwning(t *testing.T, names ...string) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for _, name := range names {
		if err := tree.File("/usr/lib/"+name, []byte(name),
			vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: name, Path: name + ".deb"}}); err != nil {
			t.Fatalf("file for %s: %v", name, err)
		}
	}
	return tree
}

func TestPackageDatabase_WritesEveryPackage(t *testing.T) {
	tree := treeOwning(t, "base-files", "libc6")
	packages := []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
		packageState("libc6", "2.39-0ubuntu8.5", synthesis.StatusSliced, libc6Control),
	}
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	for _, want := range []string{
		"Package: base-files\nVersion: 13ubuntu10.5\n",
		"Package: libc6\nVersion: 2.39-0ubuntu8.5\n",
		"Installed-Size: 426\n",
		"Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n",
		"Priority: required\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("status is missing %q:\n%s", want, content)
		}
	}
}

// A record with no Status field reads as not-installed to dpkg, so a package
// manager sees no broken package to repair and no upgrade it cannot perform. The
// tradeoff is that dpkg cannot tell that a package is installed either, which is
// why this only applies once a slice is in the image.
func TestPackageDatabase_OmitsStatusWhenAnyPackageIsSliced(t *testing.T) {
	tree := treeOwning(t, "base-files", "openssl")
	if err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
		packageState("openssl", "3.0.13", synthesis.StatusInstalled, opensslControl),
	}); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if strings.Contains(content, "Status:") {
		t.Fatalf("a database holding a slice wrote a Status field:\n%s", content)
	}
	if strings.Count(content, "Package: ") != 2 {
		t.Fatalf("records were lost:\n%s", content)
	}
}

// An image of whole packages only describes itself fully: dpkg and a package
// manager both read it normally.
func TestPackageDatabase_DescribesWholePackages(t *testing.T) {
	tree := treeOwning(t, "openssl")
	if err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
		packageState("openssl", "3.0.13", synthesis.StatusInstalled, opensslControl),
	}); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if !strings.Contains(content, "Package: openssl\nStatus: install ok installed\n") {
		t.Fatalf("a whole package was not described as installed:\n%s", content)
	}
}

// The database's Status is synthesized from the package state, so a control stanza
// that carries its own would appear twice and a consumer could read the
// contradictory value instead.
func TestPackageDatabase_DropsInputStatusFields(t *testing.T) {
	for _, field := range []string{"Status", "status", "STATUS"} {
		tree := treeOwning(t, "demo")
		control := "Package: demo\n" + field + ": deinstall ok config-files\nVersion: 1\n"
		if err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
			packageState("demo", "1", synthesis.StatusInstalled, control),
		}); err != nil {
			t.Fatalf("%s: PackageDatabase: %v", field, err)
		}
		content := readFile(t, tree, synthesis.StatusPath)
		if strings.Count(strings.ToLower(content), "status:") != 1 {
			t.Fatalf("%s: status appears more than once:\n%s", field, content)
		}
		if !strings.Contains(content, "Status: install ok installed") {
			t.Fatalf("%s: synthesized status missing:\n%s", field, content)
		}
	}
}

func TestPackageDatabase_OrdersPackagesByName(t *testing.T) {
	tree := treeOwning(t, "base-files", "libc6")
	packages := []synthesis.PackageState{
		packageState("libc6", "2.39-0ubuntu8.5", synthesis.StatusSliced, libc6Control),
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
	}
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if strings.Index(content, "Package: base-files") > strings.Index(content, "Package: libc6") {
		t.Fatalf("status is not sorted:\n%s", content)
	}
}

func TestPackageDatabase_WholePackageWinsOverSlice(t *testing.T) {
	tree := treeOwning(t, "base-files")
	packages := []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
		packageState("base-files", "13ubuntu10.5", synthesis.StatusInstalled, baseFilesControl),
	}
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	content := readFile(t, tree, synthesis.StatusPath)
	if count := strings.Count(content, "Package: base-files"); count != 1 {
		t.Fatalf("status has %d base-files records:\n%s", count, content)
	}
	if !strings.Contains(content, "Status: install ok installed\n") {
		t.Fatalf("whole package did not win:\n%s", content)
	}
}

func TestPackageDatabase_RejectsVersionDisagreement(t *testing.T) {
	tree := treeOwning(t, "base-files")
	newer := strings.Replace(baseFilesControl, "13ubuntu10.5", "13ubuntu10.6", 1)
	packages := []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
		packageState("base-files", "13ubuntu10.6", synthesis.StatusSliced, newer),
	}
	err := synthesis.PackageDatabase(tree, packages)
	if err == nil || !strings.Contains(err.Error(), "recorded at versions") {
		t.Fatalf("error %v does not report the disagreement", err)
	}
}

func TestPackageDatabase_RejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		pkg  synthesis.PackageState
		want string
	}{
		{"no status", packageState("base-files", "13ubuntu10.5", "", baseFilesControl), "has no status"},
		{"unknown status", packageState("base-files", "13ubuntu10.5", "install ok half-configured", baseFilesControl), "has an invalid status"},
		{"no name", packageState("", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl), "has no name"},
		{"no control", packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, ""), "has no control stanza"},
		{"wrong package", packageState("libc6", "2.39-0ubuntu8.5", synthesis.StatusSliced, baseFilesControl), "declares Package \"base-files\""},
		{"wrong version", packageState("base-files", "13ubuntu10.6", synthesis.StatusSliced, baseFilesControl), "declares Version"},
		{"no version field", packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, "Package: base-files\n"), "has no Version field"},
		{"wrong architecture", synthesis.PackageState{Name: "base-files", Version: "13ubuntu10.5", Architecture: "arm64", Status: synthesis.StatusSliced, Control: []byte(baseFilesControl)}, "declares Architecture"},
		{"malformed", packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, "not a field\n"), "is malformed"},
		{"duplicate field", packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, "Package: base-files\nPackage: base-files\n"), "is malformed"},
		{"continuation first", packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, " leading\nPackage: base-files\n"), "is malformed"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := synthesis.PackageDatabase(vfs.New(), []synthesis.PackageState{testCase.pkg})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %v does not contain %q", err, testCase.want)
			}
		})
	}
}

// An existing status file comes from selected packages and artifacts, so it is
// untrusted input and is bounded before it is parsed.
func TestPackageDatabase_RejectsAnOversizedStatusFile(t *testing.T) {
	tree := vfs.New()
	content := []byte("Package: demo\n" + strings.Repeat("x", synthesis.MaxStatusFileSize))
	if err := tree.File(synthesis.StatusPath, content, vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("file: %v", err)
	}
	err := synthesis.PackageDatabase(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("error = %v", err)
	}
}

func TestPackageDatabase_RequiresTree(t *testing.T) {
	err := synthesis.PackageDatabase(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires an image tree") {
		t.Fatalf("error %v does not mention the tree", err)
	}
}

func TestPackageDatabase_EmptyIsNoop(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.PackageDatabase(tree, nil); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	if _, ok := tree.Lookup(synthesis.StatusPath); ok {
		t.Fatal("empty database wrote a status file")
	}
}

func TestPackageDatabase_ReplacesCoveredRecords(t *testing.T) {
	existing := "Package: base-files\nStatus: install ok installed\nVersion: 13ubuntu10.4\nArchitecture: amd64\n\n"
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
	if count := strings.Count(content, "Package: base-files"); count != 1 {
		t.Fatalf("status has %d base-files records:\n%s", count, content)
	}
	if strings.Contains(content, "13ubuntu10.4") {
		t.Fatalf("stale version survived:\n%s", content)
	}
}

// TestPackageDatabase_FailsOnUnreadableStatus guards against silently dropping
// records the image already carries.
func TestPackageDatabase_FailsOnUnreadableStatus(t *testing.T) {
	tree := treeOwning(t, "base-files")
	if err := tree.Dir(synthesis.StatusPath, vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	err := synthesis.PackageDatabase(tree, []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("error %v does not report the unreadable status file", err)
	}
}

func TestPackageDatabase_IsIdempotent(t *testing.T) {
	packages := []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
	}
	tree := treeOwning(t, "base-files")
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	first := readFile(t, tree, synthesis.StatusPath)
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	if second := readFile(t, tree, synthesis.StatusPath); second != first {
		t.Fatalf("repeated synthesis changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestPackageDatabase_IsDeterministic(t *testing.T) {
	packages := []synthesis.PackageState{
		packageState("libc6", "2.39-0ubuntu8.5", synthesis.StatusSliced, libc6Control),
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, baseFilesControl),
	}
	var previous string
	for range 5 {
		tree := treeOwning(t, "base-files", "libc6")
		if err := synthesis.PackageDatabase(tree, packages); err != nil {
			t.Fatalf("PackageDatabase: %v", err)
		}
		content := readFile(t, tree, synthesis.StatusPath)
		if previous != "" && content != previous {
			t.Fatal("status output is not deterministic")
		}
		previous = content
	}
}

// A sliced package ships part of its package, so the relations of the whole
// package describe files that are not in the image. A package manager treats such
// a record as a broken database and refuses every later operation.
// A sliced record keeps its relations, exactly as Canonical's chisel-wrapper
// writes them. Stripping them would make the record describe a package the archive
// never published, which is what a package manager reads as a phantom upgrade when
// it compares the installed record against the archive's own version.
func TestPackageDatabase_KeepsRelationsForSlicedPackages(t *testing.T) {
	tree := treeOwning(t, "base-files")
	control := `Package: base-files
Version: 13ubuntu10.5
Architecture: amd64
Pre-Depends: awk
Depends: libc6 (>= 2.38),
         mawk
Recommends: bash-completion
Section: admin
Description: Debian base system miscellaneous files
`
	packages := []synthesis.PackageState{
		packageState("base-files", "13ubuntu10.5", synthesis.StatusSliced, control),
	}
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	data, err := tree.Read(synthesis.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{"Pre-Depends: awk", "Recommends: bash-completion",
		"Section: admin", "Description: Debian base system miscellaneous files"} {
		if !strings.Contains(string(data), kept) {
			t.Fatalf("sliced record lost %q:\n%s", kept, data)
		}
	}
	if strings.Contains(string(data), "Status:") {
		t.Fatalf("sliced record carried a Status field:\n%s", data)
	}
}

// A whole package really does ship every file, so its relations stay: a scanner
// and a package manager both need to know what it depends on.
func TestPackageDatabase_KeepsRelationsForWholePackages(t *testing.T) {
	tree := treeOwning(t, "openssl")
	control := `Package: openssl
Version: 3.0.13
Architecture: amd64
Depends: libc6 (>= 2.38)
Description: Secure Sockets Layer toolkit
`
	packages := []synthesis.PackageState{
		packageState("openssl", "3.0.13", synthesis.StatusInstalled, control),
	}
	if err := synthesis.PackageDatabase(tree, packages); err != nil {
		t.Fatalf("PackageDatabase: %v", err)
	}
	data, err := tree.Read(synthesis.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Depends: libc6 (>= 2.38)") {
		t.Fatalf("whole package lost its relations:\n%s", data)
	}
}
