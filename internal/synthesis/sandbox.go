package synthesis

import (
	"errors"
	"slices"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/vfs"
)

// The account apt drops to before writing a download. Ubuntu ships no such record
// in base-passwd; apt's own postinst creates it while configuring, and a build that
// never runs maintainer scripts has to supply it itself.
const (
	sandboxUserName  = "_apt"
	sandboxUID       = 42
	sandboxGID       = 65534
	sandboxHome      = "/nonexistent"
	sandboxShell     = "/usr/sbin/nologin"
	sandboxGroupName = "nogroup"
)

// aptPackage is the package that fetches, and the binaries whose presence means the
// image really carries a fetcher rather than the package's record alone.
const aptPackage = "apt"

var aptFetchBinaries = []string{"/usr/bin/apt", "/usr/bin/apt-get"}

// SandboxAccount gives an image that ships apt the unprivileged user apt drops to
// while fetching. Without it apt warns on every download and fetches as root.
//
// The function writes nothing when the image cannot fetch, when the user is already
// there, or when apt's uid belongs to someone else: the account removes a warning,
// so it never displaces an account the image already had.
func SandboxAccount(tree *vfs.Tree, packages []PackageState) error {
	if tree == nil {
		return errors.New("apt sandbox account synthesis requires an image tree")
	}
	if !aptFetches(tree, packages) {
		return nil
	}
	passwd, err := newAccountDatabaseFrom(tree, passwdFile)
	if err != nil {
		return err
	}
	if _, taken := passwd.byName[sandboxUserName]; taken {
		return nil
	}
	if _, taken := passwd.byID[sandboxUID]; taken {
		return nil
	}
	group, ok, err := sandboxGroupFor(tree)
	if err != nil || !ok {
		return err
	}
	uid, gid, home, shell := sandboxUID, sandboxGID, sandboxHome, sandboxShell
	return Accounts(tree, &filesystem.Accounts{
		Groups: []filesystem.GroupAccount{{Name: group, GID: &gid}},
		Users: []filesystem.UserAccount{{Name: sandboxUserName, UID: &uid, GID: &gid,
			Home: &home, Shell: &shell}},
	})
}

// aptFetches reports whether the image can fetch: the package is recorded and one
// of its fetchers is in the tree. A whole package always ships both, so the second
// half only decides for a slice that dropped them.
func aptFetches(tree *vfs.Tree, packages []PackageState) bool {
	if !slices.ContainsFunc(packages, func(pkg PackageState) bool { return pkg.Name == aptPackage }) {
		return false
	}
	return slices.ContainsFunc(aptFetchBinaries, func(binary string) bool {
		entry, ok := tree.Lookup(binary)
		return ok && entry.Kind == vfs.File
	})
}

// sandboxGroupFor is the group the account joins. The id is fixed by the
// distribution, so an image that already gives that id another name keeps it and a
// new group is written only when the id is unused.
//
// The name being taken by a different id gives no group to join: writing the id
// under that name would contradict the image, and nothing is worth failing a build
// over an account that only removes a warning.
func sandboxGroupFor(tree *vfs.Tree) (string, bool, error) {
	groups, err := newAccountDatabaseFrom(tree, groupFile)
	if err != nil {
		return "", false, err
	}
	if found, ok := groups.byID[sandboxGID]; ok {
		return found.name, true, nil
	}
	if _, taken := groups.byName[sandboxGroupName]; taken {
		return "", false, nil
	}
	return sandboxGroupName, true, nil
}
