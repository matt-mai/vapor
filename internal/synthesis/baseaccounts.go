package synthesis

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/vfs"
)

// rootName is the account uid 0 and gid 0 are spelled as. Both databases use it, so it
// is a constant rather than five literals.
const rootName = "root"

// BaseAccountMasters are the files a distribution's packages ship in place of a
// populated account database. An empty field means the distribution ships none, and
// the image gains uid 0's two records alone.
type BaseAccountMasters struct {
	Passwd string
	Group  string
}

// ApplyAccounts writes every account an image needs, in the order that lets each one
// resolve, and stages the result so a failure leaves the tree untouched.
//
// Debian and Ubuntu generate /etc/passwd and /etc/group from the master files their
// base-passwd package ships, in a maintainer script a build never runs, so an image
// would otherwise name only what it declares. Package tooling then fails on the names
// it expects to resolve: apt cannot chown its download directories to root and falls
// back to fetching as root, and a script calling `chown root:root` reports an unknown
// group.
//
// A distribution account is a convenience, so it never displaces one the image already
// has: a taken name or id keeps its record, even when the other half of the pair is
// free. An image that carries no account data at all gains none, so an image built to
// hold a static binary keeps its empty root filesystem.
//
// The order is what makes each record resolve. Declared groups go in first so a
// declaration keeps the name and id it asked for; the distribution's groups follow,
// yielding to any declaration that took a name or id; declared users come next, because a
// declaration may name a group either source supplied; the apt sandbox account follows,
// since it joins whatever group owns its gid; and the distribution's users come last,
// admitted only against the group set the earlier passes produced.
func ApplyAccounts(tree *vfs.Tree, declared *filesystem.Accounts, packages []PackageState,
	masters BaseAccountMasters,
) error {
	if tree == nil {
		return errors.New("account synthesis requires an image tree")
	}
	staged := tree.Clone()
	// Decided once, before any pass writes a file: a later pass must not see the
	// databases an earlier one created and mistake them for the image's own account
	// data. An image apt fetches in counts, because the sandbox account is about to give
	// it a database either way, and so does a declared account, which needs a database
	// to be written into.
	carries := carriesAccounts(staged, masters) || aptFetches(staged, packages) || declaresAccounts(declared)
	accounts := filesystem.Accounts{}
	if declared != nil {
		accounts = *declared
	}
	// Declared groups go in before the masters so a declaration keeps the name and id it
	// asked for, and a master group that would take either is the one that yields.
	if err := applyGroups(staged, accounts.Groups); err != nil {
		return err
	}
	if err := addMasters(staged, masters.Group, groupFile, rootGroup(), nil, carries); err != nil {
		return err
	}
	if err := applyUsers(staged, accounts.Users); err != nil {
		return err
	}
	if err := SandboxAccount(staged, packages); err != nil {
		return err
	}
	groups, err := newAccountDatabaseFrom(staged, groupFile)
	if err != nil {
		return err
	}
	if err := addMasters(staged, masters.Passwd, passwdFile, rootUser(), groups, carries); err != nil {
		return err
	}
	return tree.Replace(staged)
}

// addMasters merges one master file into the database it belongs to, falling back to a
// single record when the image ships no master. A user is the only record with a shadow
// counterpart, so a passwd merge keeps `/etc/shadow` in step as it goes.
func addMasters(tree *vfs.Tree, master string, kind accountDatabaseFile, fallback databaseRecord,
	groups *accountDatabase, carries bool,
) error {
	if !carries {
		return nil
	}
	records, err := readDatabase(tree, kind.withLocation(master))
	if err != nil {
		return err
	}
	if !hasAccountRecords(records) {
		records = append(records, fallback)
	}
	merged, err := newAccountDatabaseFrom(tree, kind)
	if err != nil {
		return err
	}
	added, err := mergeMaster(merged, records, kind, master, groups)
	if err != nil {
		return err
	}
	if len(added) == 0 {
		// Every record already had a name or an id, so the file is as it was.
		// Rewriting it would detach a hard link and reflow a shape nothing asked to
		// change.
		return nil
	}
	if kind.location == PasswdPath {
		if err := keepShadowInStep(tree, added); err != nil {
			return err
		}
	}
	return writeDatabase(tree, kind, merged.records)
}

// mergeMaster adds the records whose names and ids are free and reports their names,
// which are how a caller tells an unchanged file from a rewritten one. Only a passwd
// record's password field is a credential, so only that master is held to it.
func mergeMaster(merged *accountDatabase, records database, kind accountDatabaseFile, master string,
	groups *accountDatabase,
) ([]string, error) {
	var added []string
	for _, record := range records {
		if record.fields == nil {
			// A comment or blank line is not an account, so it neither needs a free
			// name nor may hold one. It is also not copied: a reader that treats it as a
			// record would be reading a comment the master never meant to publish, and the
			// image's own file keeps the comments it already had.
			continue
		}
		if !merged.free(record) {
			// The image's own record wins, and an account that is already there is
			// not this pass's to inspect.
			continue
		}
		if kind.location == PasswdPath && !passwdDelegates(record) {
			return nil, fmt.Errorf("base account %q in %s is not disabled; its password field must be %q",
				record.name, master, DisabledPassword)
		}
		admitted, err := primaryGroupResolves(master, record, groups)
		if err != nil {
			return nil, err
		}
		if !admitted {
			continue
		}
		merged.add(record)
		added = append(added, record.name)
	}
	return added, nil
}

// primaryGroupResolves reports whether a passwd record may join the database: with no
// group database it always may, and with one its primary group must be defined there.
// The id may have gone to another account, and a passwd record naming a group the image
// does not define is worse than no record at all.
func primaryGroupResolves(master string, record databaseRecord, groups *accountDatabase) (bool, error) {
	if groups == nil {
		return true, nil
	}
	gid, err := primaryGID(master, record)
	if err != nil {
		return false, err
	}
	_, defined := groups.byID[gid]
	return defined, nil
}

// primaryGID reads the group a passwd record names as its primary group.
func primaryGID(master string, record databaseRecord) (uint32, error) {
	const gidField = 3
	if len(record.fields) <= gidField {
		return 0, fmt.Errorf("%s record %q is missing its primary group", master, record.name)
	}
	gid, err := strconv.ParseUint(record.fields[gidField], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s record %q has a non-numeric primary group", master, record.name)
	}
	return uint32(gid), nil
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
		if _, err := ensureShadow(shadowed, name); err != nil {
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
func carriesAccounts(tree *vfs.Tree, masters BaseAccountMasters) bool {
	for _, location := range []string{PasswdPath, GroupPath, masters.Passwd, masters.Group} {
		if location == "" {
			continue
		}
		if _, ok := tree.Lookup(location); ok {
			return true
		}
	}
	return false
}

// declaresAccounts reports whether the specification declares an account at all.
//
// A declaration is written into a database, so an image that would otherwise carry none
// still needs one: the accounts a specification names are not the convenience the
// masters are, and skipping them would build an image that ignores what it declares.
func declaresAccounts(declared *filesystem.Accounts) bool {
	return declared != nil && (len(declared.Users) > 0 || len(declared.Groups) > 0)
}

// hasAccountRecords reports whether a database holds a real account, as opposed to the
// comments and blank lines a master may consist of.
func hasAccountRecords(records database) bool {
	return slices.ContainsFunc(records, func(record databaseRecord) bool { return record.fields != nil })
}

// free reports whether neither the record's name nor its id is taken.
func (d *accountDatabase) free(record databaseRecord) bool {
	if _, taken := d.byName[record.name]; taken {
		return false
	}
	_, taken := d.byID[record.id]
	return !taken
}

// add appends a record whose name and id are free.
func (d *accountDatabase) add(record databaseRecord) {
	d.records = append(d.records, record)
	d.byName[record.name], d.byID[record.id] = record, record
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
