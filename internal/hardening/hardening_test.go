package hardening_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/hardening"
	"github.com/matt-mai/vapor/internal/schema/policy"
	"github.com/matt-mai/vapor/internal/vfs"
)

var packageOrigin = vfs.Origin{Package: "pkg", Slice: "pkg_slice", Path: "slices/pkg.yaml"}

func enabled() policy.Hardening {
	yes := true
	return policy.Hardening{StripDocs: &yes, StripShells: &yes, StripAptDpkg: &yes, RemoveSUIDSGID: &yes}
}

func disabled() policy.Hardening {
	no := false
	return policy.Hardening{StripDocs: &no, StripShells: &no, StripAptDpkg: &no, RemoveSUIDSGID: &no}
}

// mergedTree builds a tree whose /bin, /sbin and /lib are links into /usr.
func mergedTree(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/share/doc"} {
		if err := tree.Dir(dir, vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
			t.Fatalf("Dir %s: %v", dir, err)
		}
	}
	for _, link := range []struct{ path, target string }{
		{"/bin", "usr/bin"},
		{"/sbin", "usr/sbin"},
		{"/lib", "usr/lib"},
	} {
		if err := tree.Symlink(link.path, link.target, vfs.Attrs{Origin: packageOrigin}); err != nil {
			t.Fatalf("Symlink %s: %v", link.path, err)
		}
	}
	return tree
}

func addFile(t *testing.T, tree *vfs.Tree, p string, mode fs.FileMode, origin vfs.Origin) {
	t.Helper()
	if err := tree.File(p, []byte("x"), vfs.Attrs{Mode: mode, Origin: origin}); err != nil {
		t.Fatalf("File %s: %v", p, err)
	}
}

func exists(tree *vfs.Tree, p string) bool {
	_, ok := tree.Lookup(p)
	return ok
}

func TestApply_RemovesEnabledInventories(t *testing.T) {
	tree := mergedTree(t)
	addFile(t, tree, "/usr/bin/dash", 0o755, packageOrigin)
	addFile(t, tree, "/usr/bin/busybox", 0o755, packageOrigin)
	addFile(t, tree, "/usr/bin/myshell", 0o755, packageOrigin)
	addFile(t, tree, "/usr/bin/apt-get", 0o755, packageOrigin)
	addFile(t, tree, "/usr/bin/dpkg-reconfigure", 0o755, packageOrigin)
	if err := tree.Symlink("/usr/bin/ash", "busybox", vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, p := range []string{"/usr/bin/dash", "/usr/bin/ash", "/usr/bin/apt-get"} {
		if exists(tree, p) {
			t.Fatalf("%s was not removed", p)
		}
	}
	for _, p := range []string{"/usr/bin/busybox", "/usr/bin/myshell", "/usr/bin/dpkg-reconfigure"} {
		if !exists(tree, p) {
			t.Fatalf("%s was removed", p)
		}
	}
}

func TestApply_UnmergedUsrAndAbsentPaths(t *testing.T) {
	tree := vfs.New()
	addFile(t, tree, "/bin/dash", 0o755, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if exists(tree, "/bin/dash") {
		t.Fatal("/bin/dash was not removed")
	}

	tree = vfs.New()
	addFile(t, tree, "/usr/bin/bash", 0o755, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if exists(tree, "/usr/bin/bash") {
		t.Fatal("/usr/bin/bash was not removed")
	}
}

func TestApply_LeavesADirectoryAtAnInventoryPath(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/bin/sh", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/bin/sh/keep", 0o644, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !exists(tree, "/usr/bin/sh/keep") {
		t.Fatal("a directory at an inventory path was removed")
	}
}

func TestApply_DocumentationAndCopyright(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/app", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/doc/app/copyright", 0o644, packageOrigin)
	addFile(t, tree, "/usr/share/doc/app/README", 0o644, packageOrigin)
	addFile(t, tree, "/usr/share/doc/app/sub/copyright", 0o644, packageOrigin)
	if err := tree.Dir("/usr/share/man/man1", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/man/man1/app.1", 0o644, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !exists(tree, "/usr/share/doc/app/copyright") {
		t.Fatal("copyright notice was removed")
	}
	for _, p := range []string{"/usr/share/doc/app/README", "/usr/share/doc/app/sub/copyright", "/usr/share/man/man1/app.1", "/usr/share/man/man1"} {
		if exists(tree, p) {
			t.Fatalf("%s was not removed", p)
		}
	}
	if !exists(tree, "/usr/share/doc/app") {
		t.Fatal("directory holding a copyright notice was removed")
	}
}

// A notice is often a link into another documentation directory. Removing the
// target would leave the notice dangling without any error, so the target has to
// survive with it.
func TestApply_KeepsTheTargetOfACopyrightLink(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/app", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/doc/upstream/NOTICE", 0o644, packageOrigin)
	if err := tree.Symlink("/usr/share/doc/app/copyright", "../upstream/NOTICE",
		vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, p := range []string{"/usr/share/doc/app/copyright", "/usr/share/doc/upstream/NOTICE"} {
		if !exists(tree, p) {
			t.Fatalf("%s was removed", p)
		}
	}
}

// A chain of links keeps every hop, because removing an intermediate link breaks
// the notice just as surely as removing its target.
func TestApply_KeepsACopyrightLinkChain(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/app", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/LICENSE", 0o644, packageOrigin)
	if err := tree.Symlink("/usr/share/doc/NOTICE", "/usr/share/LICENSE", vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := tree.Symlink("/usr/share/doc/app/copyright", "../NOTICE", vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, p := range []string{"/usr/share/doc/app/copyright", "/usr/share/doc/NOTICE", "/usr/share/LICENSE"} {
		if !exists(tree, p) {
			t.Fatalf("%s was removed", p)
		}
	}
}

// A notice whose target the image never had stays a dangling link: hardening is not
// allowed to invent content, and the link validator accepts a missing target.
func TestApply_KeepsADanglingCopyrightLink(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/app", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if err := tree.Symlink("/usr/share/doc/app/copyright", "/usr/share/doc/gone/NOTICE",
		vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !exists(tree, "/usr/share/doc/app/copyright") {
		t.Fatal("dangling copyright link was removed")
	}
}

func TestApply_KeepsAnImplicitDirectoryThatBecomesEmpty(t *testing.T) {
	tree := vfs.New()
	addFile(t, tree, "/usr/share/doc/gone/README", 0o644, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if exists(tree, "/usr/share/doc/gone/README") {
		t.Fatal("documentation was not removed")
	}
	if !exists(tree, "/usr/share/doc/gone") {
		t.Fatal("implicit directory was removed")
	}
}

func TestApply_ConflictsWithDeclaredEntries(t *testing.T) {
	declared := vfs.Origin{Path: "filesystem.paths"}
	tests := []struct {
		name  string
		build func(*testing.T, *vfs.Tree)
		want  string
	}{
		{
			name: "declared shell",
			build: func(t *testing.T, tree *vfs.Tree) {
				addFile(t, tree, "/usr/bin/dash", 0o755, packageOrigin)
				if err := tree.Declare("/usr/bin/dash", vfs.File, vfs.Attrs{Mode: 0o755, Origin: declared}, ""); err != nil {
					t.Fatalf("Declare: %v", err)
				}
			},
			want: "hardening.strip-shells: /usr/bin/dash is declared in filesystem.paths",
		},
		{
			name: "declared documentation file",
			build: func(t *testing.T, tree *vfs.Tree) {
				if err := tree.Declare("/usr/share/doc/app/README", vfs.File, vfs.Attrs{Mode: 0o644, Origin: declared}, ""); err != nil {
					t.Fatalf("Declare: %v", err)
				}
			},
			want: "hardening.strip-docs: /usr/share/doc/app/README is declared in filesystem.paths",
		},
		{
			name: "declared documentation directory",
			build: func(t *testing.T, tree *vfs.Tree) {
				if err := tree.Declare("/usr/share/man/man1", vfs.Dir, vfs.Attrs{Mode: 0o755, Origin: declared}, ""); err != nil {
					t.Fatalf("Declare: %v", err)
				}
			},
			want: "hardening.strip-docs: /usr/share/man/man1 is declared in filesystem.paths",
		},
		{
			name: "declared directory emptied out",
			build: func(t *testing.T, tree *vfs.Tree) {
				addFile(t, tree, "/usr/share/doc/app/README", 0o644, packageOrigin)
				if err := tree.Declare("/usr/share/doc/app", vfs.Dir, vfs.Attrs{Mode: 0o755, Origin: declared}, ""); err != nil {
					t.Fatalf("Declare: %v", err)
				}
			},
			want: "hardening.strip-docs: /usr/share/doc/app is declared in filesystem.paths",
		},
		{
			name: "synthesized path",
			build: func(t *testing.T, tree *vfs.Tree) {
				addFile(t, tree, "/usr/share/doc/app/README", 0o644,
					vfs.Origin{Path: "filesystem.packages"})
			},
			want: "hardening.strip-docs: /usr/share/doc/app/README was written by filesystem.packages",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := mergedTree(t)
			tc.build(t, tree)
			before := tree.Entries()
			err := hardening.Apply(tree, enabled())
			if err == nil {
				t.Fatal("expected a conflict")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "disable") {
				t.Fatalf("error lacks guidance: %q", err)
			}
			if after := tree.Entries(); len(after) != len(before) {
				t.Fatalf("failed apply changed the tree: %d -> %d entries", len(before), len(after))
			}
		})
	}
}

func TestApply_DeclaredDirectoryWithProtectedContentIsNotAConflict(t *testing.T) {
	declared := vfs.Origin{Path: "filesystem.paths"}
	tree := mergedTree(t)
	addFile(t, tree, "/usr/share/doc/app/copyright", 0o644, packageOrigin)
	addFile(t, tree, "/usr/share/doc/app/README", 0o644, packageOrigin)
	if err := tree.Declare("/usr/share/doc/app", vfs.Dir, vfs.Attrs{Mode: 0o755, Origin: declared}, ""); err != nil {
		t.Fatalf("Declare: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !exists(tree, "/usr/share/doc/app/copyright") || exists(tree, "/usr/share/doc/app/README") {
		t.Fatal("documentation removal was not applied around the declaration")
	}
}

func TestApply_DisabledPassesAreIndependent(t *testing.T) {
	tree := mergedTree(t)
	addFile(t, tree, "/usr/bin/dash", 0o755, packageOrigin)
	addFile(t, tree, "/usr/share/doc/app/README", 0o644, packageOrigin)
	flags := enabled()
	no := false
	flags.StripDocs = &no
	if err := hardening.Apply(tree, flags); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !exists(tree, "/usr/share/doc/app/README") {
		t.Fatal("strip-docs: false did not keep documentation")
	}
	if exists(tree, "/usr/bin/dash") {
		t.Fatal("disabling strip-docs also disabled strip-shells")
	}
}

func TestApply_PrivilegedBits(t *testing.T) {
	tree := mergedTree(t)
	addFile(t, tree, "/usr/bin/sudo", fs.ModeSetuid|0o755, packageOrigin)
	addFile(t, tree, "/usr/bin/wall", fs.ModeSetgid|0o755, packageOrigin)
	addFile(t, tree, "/usr/bin/plain", 0o755, packageOrigin)
	if err := tree.Hardlink("/usr/sbin/sudo", "/usr/bin/sudo", packageOrigin); err != nil {
		t.Fatalf("Hardlink: %v", err)
	}
	if err := tree.Declare("/app/tool", vfs.File, vfs.Attrs{Mode: fs.ModeSetuid | 0o755,
		Origin: vfs.Origin{Path: "filesystem.paths"}}, ""); err != nil {
		t.Fatalf("Declare: %v", err)
	}
	if err := tree.Dir("/app/sticky", vfs.Attrs{Mode: fs.ModeSticky | fs.ModeSetgid | 0o777, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, tc := range []struct {
		path string
		want fs.FileMode
	}{
		{"/usr/bin/sudo", 0o755},
		{"/usr/sbin/sudo", 0o755},
		{"/usr/bin/wall", 0o755},
		{"/usr/bin/plain", 0o755},
		{"/app/tool", 0o755},
		{"/app/sticky", fs.ModeSticky | 0o777},
	} {
		entry, ok := tree.Lookup(tc.path)
		if !ok {
			t.Fatalf("%s is missing", tc.path)
		}
		if entry.Mode != tc.want {
			t.Fatalf("%s mode = %v, want %v", tc.path, entry.Mode, tc.want)
		}
	}
}

func TestApply_DisabledPrivilegedPassKeepsBits(t *testing.T) {
	tree := mergedTree(t)
	addFile(t, tree, "/usr/bin/sudo", fs.ModeSetuid|0o755, packageOrigin)
	flags := enabled()
	no := false
	flags.RemoveSUIDSGID = &no
	if err := hardening.Apply(tree, flags); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if entry, _ := tree.Lookup("/usr/bin/sudo"); entry.Mode != fs.ModeSetuid|0o755 {
		t.Fatalf("mode = %v", entry.Mode)
	}
}

func TestApply_KeepsSynthesizedPackageDatabase(t *testing.T) {
	tree := mergedTree(t)
	addFile(t, tree, "/usr/bin/dpkg", 0o755, packageOrigin)
	if err := tree.File("/var/lib/dpkg/status", []byte("Package: pkg\n"),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Path: "filesystem.packages"}}); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if exists(tree, "/usr/bin/dpkg") {
		t.Fatal("/usr/bin/dpkg was not removed")
	}
	if !exists(tree, "/var/lib/dpkg/status") {
		t.Fatal("synthesized package database was removed")
	}
}

func TestApply_RejectsUndefaultedFlagsAndNilTree(t *testing.T) {
	if err := hardening.Apply(nil, enabled()); err == nil {
		t.Fatal("expected an error for a nil tree")
	}
	if err := hardening.Apply(vfs.New(), policy.Hardening{}); err == nil {
		t.Fatal("expected an error for undefaulted flags")
	}
}

func TestApply_IsDeterministic(t *testing.T) {
	build := func() *vfs.Tree {
		tree := mergedTree(t)
		addFile(t, tree, "/usr/bin/dash", 0o755, packageOrigin)
		addFile(t, tree, "/usr/share/doc/app/README", 0o644, packageOrigin)
		addFile(t, tree, "/usr/share/man/man1/app.1", 0o644, packageOrigin)
		return tree
	}
	first, second := build(), build()
	if err := hardening.Apply(first, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := hardening.Apply(second, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	a, b := first.Entries(), second.Entries()
	if len(a) != len(b) {
		t.Fatalf("entry counts differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Path != b[i].Path || a[i].Mode != b[i].Mode {
			t.Fatalf("entry %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestApply_AllPassesDisabledChangesNothing(t *testing.T) {
	tree := mergedTree(t)
	addFile(t, tree, "/usr/bin/dash", fs.ModeSetuid|0o755, packageOrigin)
	before := tree.Entries()
	if err := hardening.Apply(tree, disabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	after := tree.Entries()
	if len(before) != len(after) {
		t.Fatalf("entry counts differ: %d vs %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Path != after[i].Path || before[i].Mode != after[i].Mode {
			t.Fatalf("entry %d changed: %+v vs %+v", i, before[i], after[i])
		}
	}
}

func TestApply_ReportsAnUnresolvableInventoryAncestor(t *testing.T) {
	tree := vfs.New()
	if err := tree.Symlink("/bin", "bin", vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	err := hardening.Apply(tree, enabled())
	if err == nil || !strings.Contains(err.Error(), "hardening.strip-shells") {
		t.Fatalf("error = %v", err)
	}
	if !exists(tree, "/bin") {
		t.Fatal("a failed apply changed the tree")
	}
}

func TestApply_RemovesADirectoryWhoseChildrenAreAllRemoved(t *testing.T) {
	tests := []struct {
		name  string
		build func(*vfs.Tree)
	}{
		{"file child", func(tree *vfs.Tree) {
			addFile(t, tree, "/usr/share/doc/gone/README", 0o644, packageOrigin)
		}},
		{"symlink child", func(tree *vfs.Tree) {
			if err := tree.Symlink("/usr/share/doc/gone/link", "/opt/app", vfs.Attrs{Origin: packageOrigin}); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
		}},
		{"nested directory child", func(tree *vfs.Tree) {
			if err := tree.Dir("/usr/share/doc/gone/sub", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
				t.Fatalf("Dir: %v", err)
			}
			addFile(t, tree, "/usr/share/doc/gone/sub/README", 0o644, packageOrigin)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := mergedTree(t)
			if err := tree.Dir("/usr/share/doc/gone", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
				t.Fatalf("Dir: %v", err)
			}
			tc.build(tree)
			if err := hardening.Apply(tree, enabled()); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if exists(tree, "/usr/share/doc/gone") {
				t.Fatal("an emptied explicit directory was not removed")
			}
		})
	}
}

// An implicit child survives its own emptied state, so its explicit parent stays
// with it: a pass never removes an entry the image never declared.
func TestApply_KeepsAnExplicitDirectoryHoldingOnlyAnImplicitChild(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/app", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/doc/app/sub/README", 0o644, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if exists(tree, "/usr/share/doc/app/sub/README") {
		t.Fatal("documentation below an implicit directory was kept")
	}
	if !exists(tree, "/usr/share/doc/app/sub") || !exists(tree, "/usr/share/doc/app") {
		t.Fatal("a directory holding an implicit child was removed")
	}
}

// A directory survives exactly when something inside it survives, whatever kind of
// child that is.
func TestApply_KeepsADirectoryWithASurvivingChild(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/kept", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/doc/kept/copyright", 0o644, packageOrigin)
	addFile(t, tree, "/usr/share/doc/kept/README", 0o644, packageOrigin)
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !exists(tree, "/usr/share/doc/kept") || !exists(tree, "/usr/share/doc/kept/copyright") {
		t.Fatal("a directory holding a protected child was removed")
	}
	if exists(tree, "/usr/share/doc/kept/README") {
		t.Fatal("a sibling of a protected child was kept")
	}
}

// A package's documentation directory is often a link to a directory several
// packages share. Removing the link removes the only path to the notice, so the
// directory that holds a notice is kept even though its siblings are stripped.
func TestApply_KeepsADocumentationDirectoryLinkToANotice(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/upstream", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/doc/upstream/copyright", 0o644, packageOrigin)
	addFile(t, tree, "/usr/share/doc/upstream/README", 0o644, packageOrigin)
	if err := tree.Symlink("/usr/share/doc/app", "upstream", vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, p := range []string{"/usr/share/doc/app", "/usr/share/doc/upstream", "/usr/share/doc/upstream/copyright"} {
		if !exists(tree, p) {
			t.Fatalf("%s was removed, so the notice is no longer reachable", p)
		}
	}
	if exists(tree, "/usr/share/doc/upstream/README") {
		t.Fatal("a sibling of the notice was kept")
	}
}

// A documentation link that leads nowhere protected is still removed, so the pass
// keeps notices rather than every directory link in the image.
func TestApply_RemovesADocumentationDirectoryLinkWithoutANotice(t *testing.T) {
	tree := mergedTree(t)
	if err := tree.Dir("/usr/share/doc/upstream", vfs.Attrs{Mode: 0o755, Origin: packageOrigin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	addFile(t, tree, "/usr/share/doc/upstream/README", 0o644, packageOrigin)
	if err := tree.Symlink("/usr/share/doc/app", "upstream", vfs.Attrs{Origin: packageOrigin}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := hardening.Apply(tree, enabled()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if exists(tree, "/usr/share/doc/app") {
		t.Fatal("a documentation link without a notice was kept")
	}
}
