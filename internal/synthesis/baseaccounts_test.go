package synthesis_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
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

// applyAccounts runs the account pass the way a build does, with nothing declared and
// no package able to fetch.
func applyAccounts(t *testing.T, tree *vfs.Tree) error {
	t.Helper()
	return synthesis.ApplyAccounts(tree, nil, nil, debianMasters)
}

// debianMasters is where Debian's base-passwd package keeps the records its maintainer
// script would have copied into the databases.
var debianMasters = synthesis.BaseAccountMasters{
	Passwd: "/usr/share/base-passwd/passwd.master",
	Group:  "/usr/share/base-passwd/group.master",
}

// packageAccounts is a tree as a package left it: the masters, and the sparse account
// databases a maintainer script would have populated.
func packageAccounts(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for path, content := range map[string]string{
		debianMasters.Passwd: basePasswdMaster,
		debianMasters.Group:  baseGroupMaster,
		synthesis.PasswdPath: "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
		synthesis.GroupPath:  "nogroup:x:65534:\n",
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
	if err := applyAccounts(t, tree); err != nil {
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
	if err := applyAccounts(t, tree); err != nil {
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
	if err := applyAccounts(t, tree); err != nil {
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
	if err := applyAccounts(t, tree); err != nil {
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
	if err := applyAccounts(t, tree); err != nil {
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
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	shadow := readFile(t, tree, synthesis.ShadowPath)
	if shadow != "_apt:*:::::::\nroot:*:::::::\ndaemon:*:::::::\n" {
		t.Fatalf("shadow = %q", shadow)
	}
	treeWithoutShadow := packageAccounts(t)
	if err := applyAccounts(t, treeWithoutShadow); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	if _, ok := treeWithoutShadow.Lookup(synthesis.ShadowPath); ok {
		t.Fatal("an image without a shadow file gained one")
	}
}

// A master record that would authenticate is refused, because copying it in would ship
// a login the specification never declared. An image with a shadow file is refused too:
// a disabled shadow record does not override a credential written in passwd.
func TestBaseAccounts_RefusesAnEnabledMasterRecord(t *testing.T) {
	records := map[string]string{
		"no password": "daemon::1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"inline hash": "daemon:$6$salt$hash:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
	}
	for name, record := range records {
		for _, shadow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s shadow=%t", name, shadow), func(t *testing.T) {
				tree := packageAccounts(t)
				if shadow {
					if err := tree.File(synthesis.ShadowPath, []byte("_apt:*:::::::\n"), vfs.Attrs{Mode: 0o600}); err != nil {
						t.Fatal(err)
					}
				}
				master := strings.Replace(basePasswdMaster, "daemon:*:1:1", record, 1)
				if err := tree.ReplaceFile(debianMasters.Passwd, []byte(master)); err != nil {
					t.Fatal(err)
				}
				before := snapshotAccounts(t, tree)
				err := applyAccounts(t, tree)
				if err == nil || !strings.Contains(err.Error(), "not disabled") {
					t.Fatalf("error = %v", err)
				}
				assertUnchanged(t, tree, before)
			})
		}
	}
}

// A leading comment is not an account. Counting one as a taken name or id would take
// the slot the real root record needs, and a master of nothing but comments would
// defeat the fallback that names uid 0.
func TestBaseAccounts_IgnoresCommentsInAMaster(t *testing.T) {
	tree := packageAccounts(t)
	commented := "# standard accounts\n\n" + basePasswdMaster
	if err := tree.ReplaceFile(debianMasters.Passwd, []byte(commented)); err != nil {
		t.Fatal(err)
	}
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if !strings.Contains(passwd, "\nroot:*:0:0:root:/root:/bin/bash\n") {
		t.Fatalf("passwd = %q", passwd)
	}
	if !strings.HasPrefix(passwd, "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n# standard accounts\n\n") {
		t.Fatalf("comment was not carried over: %q", passwd)
	}
}

// A master that carries no account names uid 0 through the fallback rather than
// leaving the image without a superuser record.
func TestBaseAccounts_NamesRootWhenTheMasterHasNoAccounts(t *testing.T) {
	tree := packageAccounts(t)
	if err := tree.ReplaceFile(debianMasters.Passwd, []byte("# no accounts here\n")); err != nil {
		t.Fatal(err)
	}
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); !strings.Contains(passwd, "\nroot:*:0:0:root:/root:/bin/bash\n") {
		t.Fatalf("passwd = %q", passwd)
	}
}

// An account the image already has is skipped before its password field is looked at:
// the record stays as the image had it, and a build does not fail over a record this
// pass is not going to change.
func TestBaseAccounts_LeavesACollidingRecordAloneWhenItIsEnabled(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "root:$6$salt$hash:1000:1000::/srv:/bin/sh\n")
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("BaseAccounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if passwd != "root:$6$salt$hash:1000:1000::/srv:/bin/sh\n" {
		t.Fatalf("passwd = %q", passwd)
	}
}

// snapshotAccounts records the account files as bytes, so a refusal can be shown to
// have left them alone rather than merely rewritten to the same values.
func snapshotAccounts(t *testing.T, tree *vfs.Tree) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, location := range []string{synthesis.PasswdPath, synthesis.GroupPath, synthesis.ShadowPath} {
		if content, err := tree.Read(location); err == nil {
			files[location] = string(content)
		}
	}
	return files
}

func assertUnchanged(t *testing.T, tree *vfs.Tree, before map[string]string) {
	t.Helper()
	for location, want := range before {
		if got := readFile(t, tree, location); got != want {
			t.Fatalf("%s = %q, want %q", location, got, want)
		}
	}
}

// A master that cannot be read fails the build and leaves the image's own files as they
// were. The later master is the one that breaks, so the groups have already been written
// to the staged copy when the error arrives: the guarantee is not that nothing was
// attempted, but that an attempt is discarded.
func TestApplyAccounts_DiscardsAPassThatFailsPartway(t *testing.T) {
	tree := packageAccounts(t)
	if err := tree.ReplaceFile(debianMasters.Passwd, []byte("root\n")); err != nil {
		t.Fatal(err)
	}
	if err := applyAccounts(t, tree); err == nil {
		t.Fatal("a malformed master was accepted")
	}
	if group := readFile(t, tree, synthesis.GroupPath); group != "nogroup:x:65534:\n" {
		t.Fatalf("a failed pass left group written: %q", group)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); passwd != "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n" {
		t.Fatalf("a failed pass left passwd written: %q", passwd)
	}
}

// A declared user may name a group only the distribution's master supplies. The
// masters go in before a declaration is applied, so the group resolves.
func TestApplyAccounts_ResolvesADeclaredUserWithAMasterGroup(t *testing.T) {
	tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
	if err := tree.File(debianMasters.Group, []byte(baseGroupMaster), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	gid := 1
	uid := 65532
	home, shell := "/srv", "/sbin/nologin"
	declared := &filesystem.Accounts{Users: []filesystem.UserAccount{{
		Name: "www-data", UID: &uid, GID: &gid, Home: &home, Shell: &shell,
	}}}
	if err := synthesis.ApplyAccounts(tree, declared, nil, debianMasters); err != nil {
		t.Fatalf("ApplyAccounts: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); !strings.Contains(passwd, "www-data:x:65532:1:") {
		t.Fatalf("passwd = %q", passwd)
	}
}

// The other direction: a master user whose group the image already gives another name
// is not imported, because the record would name a group the image does not define.
func TestApplyAccounts_SkipsAMasterUserWhoseGroupWasNotImported(t *testing.T) {
	tree := vfs.New()
	for path, content := range map[string]string{
		// The image's own group file takes the daemon name at another id, so the
		// master's daemon group is skipped and gid 1 stays undefined: the daemon user
		// would name a group the image does not have.
		synthesis.PasswdPath: "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
		synthesis.GroupPath:  "nogroup:x:65534:\ndaemon:x:100:\n",
		debianMasters.Passwd: basePasswdMaster,
		debianMasters.Group:  baseGroupMaster,
	} {
		if err := tree.File(path, []byte(content), vfs.Attrs{Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("ApplyAccounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if strings.Contains(passwd, "daemon:") {
		t.Fatalf("a user naming a group the image does not define was imported: %q", passwd)
	}
	if !strings.Contains(passwd, "root:*:0:0:root:/root:/bin/bash\n") {
		t.Fatalf("passwd = %q", passwd)
	}
}

// The third case: the image names gid 1 something else, so the master's group is skipped
// on the name but the id is still defined, and the master's user joins it. The record
// has to be admitted, because the group it names exists even though its name is not the
// master's.
func TestApplyAccounts_AdmitsAMasterUserWhoseGroupHasAnotherName(t *testing.T) {
	tree := vfs.New()
	for path, content := range map[string]string{
		synthesis.PasswdPath: "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
		synthesis.GroupPath:  "nogroup:x:65534:\nsystemd:x:1:\n",
		debianMasters.Passwd: basePasswdMaster,
		debianMasters.Group:  baseGroupMaster,
	} {
		if err := tree.File(path, []byte(content), vfs.Attrs{Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("ApplyAccounts: %v", err)
	}
	if group := readFile(t, tree, synthesis.GroupPath); !strings.Contains(group, "systemd:x:1:\n") ||
		strings.Contains(group, "daemon:") {
		t.Fatalf("group = %q", group)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); !strings.Contains(passwd,
		"daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n") {
		t.Fatalf("passwd = %q", passwd)
	}
}

// An account pass that adds nothing leaves the file byte-identical and keeps a hard
// link to it, so a name another path shares is not silently detached.
func TestApplyAccounts_LeavesAnUnchangedFileAlone(t *testing.T) {
	tree := packageAccounts(t)
	// Every account both masters name is already in the image under the same name and
	// id, so neither merge has anything to add.
	for path, content := range map[string]string{
		synthesis.PasswdPath: "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n" +
			"root:*:0:0:root:/root:/bin/bash\n" +
			"daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
		synthesis.GroupPath: "nogroup:x:65534:\nroot:*:0:\ndaemon:*:1:\n",
	} {
		if err := tree.ReplaceFile(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tree.Hardlink("/etc/group.alias", synthesis.GroupPath, vfs.Origin{}); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, tree, synthesis.GroupPath)
	if err := applyAccounts(t, tree); err != nil {
		t.Fatalf("ApplyAccounts: %v", err)
	}
	if after := readFile(t, tree, synthesis.GroupPath); after != before {
		t.Fatalf("group = %q, want %q", after, before)
	}
	if inodes := tree.Inodes(); inodes["/etc/group.alias"] != inodes[synthesis.GroupPath] {
		t.Fatal("a no-op pass detached the group database from its hard link")
	}
}

// The account files are read without a declaration asking for them, so the archive
// member bound does not cover them: a file beyond the parser's own bound is refused
// before it is read whole.
func TestApplyAccounts_RefusesAnOversizedAccountFile(t *testing.T) {
	tree := packageAccounts(t)
	oversized := make([]byte, 1<<20+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	if err := tree.ReplaceFile(synthesis.PasswdPath, oversized); err != nil {
		t.Fatal(err)
	}
	err := applyAccounts(t, tree)
	if err == nil || !strings.Contains(err.Error(), "account database bound") {
		t.Fatalf("error = %v", err)
	}
}

// A record count beyond the bound is refused as well, so a small file cannot cost
// unbounded allocation.
func TestApplyAccounts_RefusesAnAccountFileWithTooManyRecords(t *testing.T) {
	tree := packageAccounts(t)
	var builder strings.Builder
	for range 1<<16 + 1 {
		builder.WriteString("u:x:1:1:\n")
	}
	if err := tree.ReplaceFile(synthesis.PasswdPath, []byte(builder.String())); err != nil {
		t.Fatal(err)
	}
	err := applyAccounts(t, tree)
	if err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("error = %v", err)
	}
}

// The image that caught this in an end-to-end build: no account files at all, but apt
// fetches, so the sandbox account will create them. The base accounts have to be
// admitted on what the image is about to hold, not on what it holds when the group pass
// starts.
func TestApplyAccounts_ItselfAnImageThatOnlyGainsTheSandboxAccount(t *testing.T) {
	tree, packages := aptImage(t)
	if err := synthesis.ApplyAccounts(tree, nil, packages, debianMasters); err != nil {
		t.Fatalf("ApplyAccounts: %v", err)
	}
	group := readFile(t, tree, synthesis.GroupPath)
	if !strings.Contains(group, "root:*:0:\n") {
		t.Fatalf("group = %q", group)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); !strings.Contains(passwd, "root:*:0:0:") {
		t.Fatalf("passwd = %q", passwd)
	}
}
