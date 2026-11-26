package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

// aptImage is a tree holding apt's fetcher plus the package record that names it,
// which is what tells synthesis the image can fetch.
func aptImage(t *testing.T) (*vfs.Tree, []synthesis.PackageState) {
	t.Helper()
	tree := treeWithFile(t, "/usr/bin/apt-get", "")
	if err := tree.File("/usr/bin/apt", []byte("binary"), vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	return tree, []synthesis.PackageState{
		packageState("base-files", "26.04", synthesis.StatusSliced, baseFilesControl),
		packageState("apt", "2.8.3", synthesis.StatusInstalled, aptControl),
	}
}

const aptControl = `Package: apt
Version: 2.8.3
Architecture: amd64
Description: commandline package manager
`

func TestSandboxAccount_GivesAPTFetcherAnAPTSandboxUser(t *testing.T) {
	tree, packages := aptImage(t)
	if err := synthesis.SandboxAccount(tree, packages); err != nil {
		t.Fatalf("SandboxAccount: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if passwd != "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n" {
		t.Fatalf("passwd = %q", passwd)
	}
	group := readFile(t, tree, synthesis.GroupPath)
	if group != "nogroup:x:65534:\n" {
		t.Fatalf("group = %q", group)
	}
	if shadow := readFile(t, tree, synthesis.ShadowPath); !strings.HasPrefix(shadow, "_apt:*:") {
		t.Fatalf("shadow = %q", shadow)
	}
	entry, ok := tree.Lookup(synthesis.PasswdPath)
	if !ok || len(entry.Origins) != 1 || entry.Origins[0] != synthesis.AccountOrigin {
		t.Fatalf("passwd origins = %+v, ok=%v", entry.Origins, ok)
	}
}

// The account silences a warning. An image without a fetcher gains nothing from it,
// so it stays out of images that do not need one.
func TestSandboxAccount_SkipsAnImageThatCannotFetch(t *testing.T) {
	for name, setup := range map[string]func(*testing.T) (*vfs.Tree, []synthesis.PackageState){
		"no apt package": func(t *testing.T) (*vfs.Tree, []synthesis.PackageState) {
			tree, _ := aptImage(t)
			return tree, []synthesis.PackageState{packageState("openssl", "3.0", synthesis.StatusInstalled, baseFilesControl)}
		},
		"package without fetchers": func(t *testing.T) (*vfs.Tree, []synthesis.PackageState) {
			tree, packages := aptImage(t)
			for _, binary := range []string{"/usr/bin/apt", "/usr/bin/apt-get"} {
				if err := tree.Remove(binary); err != nil {
					t.Fatal(err)
				}
			}
			return tree, packages
		},
		"fetcher of a package the lock dropped": func(t *testing.T) (*vfs.Tree, []synthesis.PackageState) {
			tree, packages := aptImage(t)
			return tree, packages[:1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			tree, packages := setup(t)
			if err := synthesis.SandboxAccount(tree, packages); err != nil {
				t.Fatalf("SandboxAccount: %v", err)
			}
			if _, ok := tree.Lookup(synthesis.PasswdPath); ok {
				t.Fatalf("an account was synthesized without a fetcher:\n%s", readFile(t, tree, synthesis.PasswdPath))
			}
		})
	}
}

// base-passwd records the account and apt's postinst only creates it when it is
// missing, so an image that has one must not gain a second.
func TestSandboxAccount_KeepsAnAccountTheImageShips(t *testing.T) {
	tree, packages := aptImage(t)
	if err := tree.File(synthesis.PasswdPath,
		[]byte("root:x:0:0:root:/root:/bin/bash\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := synthesis.SandboxAccount(tree, packages); err != nil {
		t.Fatalf("SandboxAccount: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); strings.Count(passwd, "_apt:") != 1 {
		t.Fatalf("passwd = %q", passwd)
	}
}

// The uid is a number the image may already have given someone else. Taking it over
// would change who another account is, so the warning stays and the image is left
// alone.
func TestSandboxAccount_KeepsAUIDThatBelongsToAnotherAccount(t *testing.T) {
	tree, packages := aptImage(t)
	if err := tree.File(synthesis.PasswdPath,
		[]byte("app:x:42:42::/app:/sbin/nologin\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := synthesis.SandboxAccount(tree, packages); err != nil {
		t.Fatalf("SandboxAccount: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); strings.Contains(passwd, "_apt") {
		t.Fatalf("passwd = %q", passwd)
	}
}

// A distribution that gives the numeric group another name is followed rather than
// contradicted: joining a second group with the same gid would make the account's
// primary group ambiguous.
func TestSandboxAccount_JoinsTheGroupThatOwnsTheGID(t *testing.T) {
	tree, packages := aptImage(t)
	if err := tree.File(synthesis.GroupPath, []byte("root:x:0:\nstaff:x:65534:\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := synthesis.SandboxAccount(tree, packages); err != nil {
		t.Fatalf("SandboxAccount: %v", err)
	}
	if group := readFile(t, tree, synthesis.GroupPath); group != "root:x:0:\nstaff:x:65534:\n" {
		t.Fatalf("group = %q", group)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); !strings.Contains(passwd, "_apt:x:42:65534:") {
		t.Fatalf("passwd = %q", passwd)
	}
}

// A declared account may claim the uid first. The specification asked for that
// account, so the declaration keeps it and the warning stays.
func TestSandboxAccount_DefersToDeclaredAccounts(t *testing.T) {
	tree, packages := aptImage(t)
	uid, gid, home, shell := 42, 42, "/app", "/sbin/nologin"
	if err := synthesis.Accounts(tree, &filesystem.Accounts{
		Groups: []filesystem.GroupAccount{{Name: "app", GID: &gid}},
		Users: []filesystem.UserAccount{{Name: "app", UID: &uid, GID: &gid,
			Home: &home, Shell: &shell}},
	}); err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if err := synthesis.SandboxAccount(tree, packages); err != nil {
		t.Fatalf("SandboxAccount: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); passwd != "app:x:42:42::/app:/sbin/nologin\n" {
		t.Fatalf("passwd = %q", passwd)
	}
}

// A group called `nogroup` with another id leaves no group for the account to join.
// The image keeps what it has: this account removes a warning, so it is not worth
// failing a build over.
func TestSandboxAccount_SkipsAGroupNameWithAnotherID(t *testing.T) {
	tree, packages := aptImage(t)
	if err := tree.File(synthesis.GroupPath, []byte("nogroup:x:1000:\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := synthesis.SandboxAccount(tree, packages); err != nil {
		t.Fatalf("SandboxAccount: %v", err)
	}
	if _, ok := tree.Lookup(synthesis.PasswdPath); ok {
		t.Fatalf("passwd = %q", readFile(t, tree, synthesis.PasswdPath))
	}
	if group := readFile(t, tree, synthesis.GroupPath); group != "nogroup:x:1000:\n" {
		t.Fatalf("group = %q", group)
	}
}

func TestSandboxAccount_RejectsNilTree(t *testing.T) {
	if err := synthesis.SandboxAccount(nil, nil); err == nil {
		t.Fatal("expected an error for a nil tree")
	}
}
