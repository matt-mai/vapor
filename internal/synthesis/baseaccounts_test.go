package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

// basePasswdMaster and baseGroupMaster are the records Debian's base-passwd ships,
// trimmed to the accounts a test reads back.
const (
	basePasswdMaster = "root:*:0:0:root:/root:/bin/bash\n" +
		"daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"_apt:*:42:65534::/nonexistent:/usr/sbin/nologin\n"
	baseGroupMaster = "root:*:0:\n" +
		"daemon:*:1:\n" +
		"nogroup:*:65534:\n"
)

// packageAccounts is a tree as a package left it: the masters, and the sparse account
// databases a maintainer script would have populated.
func packageAccounts(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for path, content := range map[string]string{
		synthesis.BasePasswdMasterPath: basePasswdMaster,
		synthesis.BaseGroupMasterPath:  baseGroupMaster,
		synthesis.PasswdPath:           "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
		synthesis.GroupPath:            "nogroup:x:65534:\n",
	} {
		if err := tree.File(path, []byte(content), vfs.Attrs{Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	return tree
}

// The masters are what a distribution would have copied into the databases, so an
// image gets those records and not a hardcoded guess.
func TestBaseAccounts_CopiesTheMastersIntoTheDatabases(t *testing.T) {
	tree := packageAccounts(t)
	if err := synthesis.BaseAccounts(tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	// The image's own _apt record stays where it was: a base account is appended and
	// never displaces one.
	passwd := readFile(t, tree, synthesis.PasswdPath)
	want := "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n" +
		"root:*:0:0:root:/root:/bin/bash\n" +
		"daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	if passwd != want {
		t.Fatalf("passwd = %q, want %q", passwd, want)
	}
	group := readFile(t, tree, synthesis.GroupPath)
	if group != "nogroup:x:65534:\nroot:*:0:\ndaemon:*:1:\n" {
		t.Fatalf("group = %q", group)
	}
}

// An image that ships no masters still has a superuser, so uid 0 gets a name. This is
// the record apt needs to chown its download directories.
func TestBaseAccounts_NamesRootWithoutAMaster(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "app:x:65532:65532::/app:/sbin/nologin\n")
	if err := synthesis.BaseAccounts(tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if !strings.Contains(passwd, "\nroot:*:0:0:root:/root:/bin/bash\n") {
		t.Fatalf("passwd = %q", passwd)
	}
	group := readFile(t, tree, synthesis.GroupPath)
	if group != "root:*:0:\n" {
		t.Fatalf("group = %q", group)
	}
}

// A name the image already uses keeps its record: the id a base account would take may
// belong to another account, and rewriting it would change who that is.
func TestBaseAccounts_KeepsAnAccountTheImageAlreadyNames(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "root:x:1000:1000::/srv:/bin/sh\n")
	if err := synthesis.BaseAccounts(tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); strings.Count(passwd, "root:") != 1 {
		t.Fatalf("passwd = %q", passwd)
	}
}

// A taken id keeps its record too, even under another name: uid 0 is the case that
// matters, because the image's own record is the one that has to survive.
func TestBaseAccounts_KeepsAnIDThatBelongsToAnotherAccount(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "superuser:x:0:0::/root:/bin/sh\n")
	if err := synthesis.BaseAccounts(tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if passwd != "superuser:x:0:0::/root:/bin/sh\n" {
		t.Fatalf("passwd = %q", passwd)
	}
}

// A tree built from static binaries carries no account, and giving it a database would
// grow the image to name nothing it did not already resolve by number.
func TestBaseAccounts_SkipsAnImageThatCarriesNoAccounts(t *testing.T) {
	tree := treeWithFile(t, "/usr/bin/server", "")
	if err := synthesis.BaseAccounts(tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	for _, location := range []string{synthesis.PasswdPath, synthesis.GroupPath} {
		if _, ok := tree.Lookup(location); ok {
			t.Fatalf("%s was written into an image that carries no accounts", location)
		}
	}
}

// A real image holds one shadow line per account, and a reader that takes a missing
// line to mean "no password" would read the opposite of what the passwd record says. An
// image without a shadow file needs none: its records carry the disabled password.
func TestBaseAccounts_KeepsShadowInStep(t *testing.T) {
	tree := packageAccounts(t)
	if err := tree.File(synthesis.ShadowPath, []byte("_apt:*:::::::\n"), vfs.Attrs{Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if err := synthesis.BaseAccounts(tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	shadow := readFile(t, tree, synthesis.ShadowPath)
	if shadow != "_apt:*:::::::\nroot:*:::::::\ndaemon:*:::::::\n" {
		t.Fatalf("shadow = %q", shadow)
	}
	treeWithoutShadow := packageAccounts(t)
	if err := synthesis.BaseAccounts(treeWithoutShadow); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	if _, ok := treeWithoutShadow.Lookup(synthesis.ShadowPath); ok {
		t.Fatal("an image without a shadow file gained one")
	}
}

// The passwd half is useless without the group it names, so both come from the same
// pass and a group database that cannot be written fails the build instead of leaving
// a half-populated pair.
func TestBaseAccounts_RefusesAMalformedMaster(t *testing.T) {
	tree := packageAccounts(t)
	if err := tree.ReplaceFile(synthesis.BaseGroupMasterPath, []byte("root\n")); err != nil {
		t.Fatal(err)
	}
	if err := synthesis.BaseAccounts(tree); err == nil {
		t.Fatal("a malformed master was accepted")
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); strings.Contains(passwd, "root:") {
		t.Fatalf("a failed pass left passwd written: %q", passwd)
	}
}
