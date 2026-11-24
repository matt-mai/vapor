package synthesis

import (
	"errors"

	"github.com/matt-mai/vapor/internal/vfs"
)

// The master files base-passwd ships in place of a populated account database.
const (
	BasePasswdMasterPath = "/usr/share/base-passwd/passwd.master" //nolint:gosec // a file path, not a credential
	BaseGroupMasterPath  = "/usr/share/base-passwd/group.master"
)

// rootName is the account uid 0 and gid 0 are spelled as. Both databases use it, so it
// is a constant rather than five literals.
const rootName = "root"

// BaseAccounts gives an image the standard accounts its packages expect.
//
// Debian and Ubuntu generate /etc/passwd and /etc/group from these masters in a
// maintainer script, which a build never runs, so an image names only what it
// declares. Package tooling then fails on the names it expects to resolve: apt cannot
// chown its download directories to root and falls back to fetching as root, and a
// script calling `chown root:root` reports an unknown group.
//
// The records come from the masters the image's own package ships, so a release that
// changes them changes the image. An image without base-passwd gains uid 0's two
// records, because a container has a superuser whether its account database names one
// or not.
//
// A base account is a convenience, so it never displaces one the image already has: a
// taken name or id keeps its record, even when the other half of the pair is free.
// An image that carries no account data at all gains none, so an image built to hold a
// static binary keeps its empty root filesystem.
func BaseAccounts(tree *vfs.Tree) error {
	if tree == nil {
		return errors.New("base account synthesis requires an image tree")
	}
	if !carriesAccounts(tree) {
		return nil
	}
	// Accounts are staged on a copy so a failure on one database cannot leave the
	// other half of the pair written.
	staged := tree.Clone()
	// Groups first: a passwd record's primary group has to resolve.
	if _, err := addBaseAccounts(staged, BaseGroupMasterPath, groupFile, rootGroup()); err != nil {
		return err
	}
	added, err := addBaseAccounts(staged, BasePasswdMasterPath, passwdFile, rootUser())
	if err != nil {
		return err
	}
	if err := keepShadowInStep(staged, added); err != nil {
		return err
	}
	return tree.Replace(staged)
}

// addBaseAccounts merges one master file into the database it belongs to, falling back
// to a single record when the image ships no master. It returns the names it added.
func addBaseAccounts(tree *vfs.Tree, master string, kind accountDatabaseFile, fallback databaseRecord) ([]string, error) {
	records, err := readDatabase(tree, kind.withLocation(master))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		records = database{fallback}
	}
	merged, err := newAccountDatabaseFrom(tree, kind)
	if err != nil {
		return nil, err
	}
	var added []string
	for _, record := range records {
		if merged.addIfFree(record) {
			added = append(added, record.name)
		}
	}
	return added, writeDatabase(tree, kind, merged.records)
}

// keepShadowInStep gives an added account a disabled shadow record when the image
// ships a shadow file. A real Debian image holds one line per account, and a reader
// that takes a missing line to mean "no password" would read the opposite of what the
// passwd record says. An image without a shadow file needs no line: its records carry
// the disabled password themselves.
func keepShadowInStep(tree *vfs.Tree, names []string) error {
	if len(names) == 0 {
		return nil
	}
	if _, ok := tree.Lookup(ShadowPath); !ok {
		return nil
	}
	shadowed, err := newAccountDatabaseFrom(tree, shadowFile)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := ensureShadow(shadowed, name); err != nil {
			return err
		}
	}
	return writeDatabase(tree, shadowFile, shadowed.records)
}

// withLocation returns a copy of the file description pointing elsewhere, so one
// database's location names the file to read and another its file to write.
func (f accountDatabaseFile) withLocation(location string) accountDatabaseFile {
	f.location = location
	return f
}

// carriesAccounts reports whether the image has account data at all. An image with
// neither a database nor a master file was built to hold no accounts, and giving one a
// database would add state nothing asked for.
func carriesAccounts(tree *vfs.Tree) bool {
	for _, location := range []string{PasswdPath, GroupPath, BasePasswdMasterPath, BaseGroupMasterPath} {
		if _, ok := tree.Lookup(location); ok {
			return true
		}
	}
	return false
}

// addIfFree appends a record when neither its name nor its id is taken, and reports
// whether it did.
func (d *accountDatabase) addIfFree(record databaseRecord) bool {
	if _, taken := d.byName[record.name]; taken {
		return false
	}
	if _, taken := d.byID[record.id]; taken {
		return false
	}
	d.records = append(d.records, record)
	d.byName[record.name], d.byID[record.id] = record, record
	return true
}

// rootUser and rootGroup are what an image without base-passwd gains for uid 0, spelled
// as the masters carry them so the result does not depend on which came first.
func rootUser() databaseRecord {
	return databaseRecord{name: rootName, id: 0,
		fields: []string{rootName, DisabledPassword, "0", "0", rootName, "/root", "/bin/bash"}}
}

func rootGroup() databaseRecord {
	return databaseRecord{name: rootName, id: 0,
		fields: []string{rootName, DisabledPassword, "0", ""}}
}
