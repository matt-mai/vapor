// Package synthesis writes the image state that no package supplies: accounts,
// timezone, release identity, trust roots and package database records. It never
// executes a maintainer script and never reads the host.
package synthesis

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"strconv"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Account database locations. The provider decides which of these an image
// uses, so the paths are declared here rather than assumed at a call site.
const (
	PasswdPath = "/etc/passwd"
	GroupPath  = "/etc/group"
	ShadowPath = "/etc/shadow"
)

// accountDatabaseFile describes one colon-separated account database: where it
// lives, which field holds a numeric id, and the mode it is written with. A
// password database is readable but never world-writable, and the shadow file is
// readable by its owner only.
type accountDatabaseFile struct {
	location string
	mode     fs.FileMode
	idField  int
}

// noIDField marks a database that has no numeric id to collide on.
const noIDField = -1

var (
	passwdFile = accountDatabaseFile{location: PasswdPath, mode: 0o644, idField: 2}
	groupFile  = accountDatabaseFile{location: GroupPath, mode: 0o644, idField: 2}
	shadowFile = accountDatabaseFile{location: ShadowPath, mode: 0o600, idField: noIDField}
)

// DisabledPassword is the shadow password field for an account that cannot log
// in with a password. An empty field would mean "no password required", which is
// the opposite of what a declared account should get. The asterisk is what
// Debian's own account master files use, so a synthesized record is
// indistinguishable from a shipped one.
const DisabledPassword = "*"

// AccountOrigin attributes synthesized account records to the specification
// rather than to a package.
var AccountOrigin = vfs.Origin{Path: "filesystem.accounts"}

// Accounts applies the declared accounts to an image. Existing records are
// preserved and a declaration that contradicts one fails, so a selected
// package's account is never silently rewritten.
//
// A declared user's primary group may come from a selected package; only a
// missing group is an error, not an undeclared one.
func Accounts(tree *vfs.Tree, accounts *filesystem.Accounts) error {
	if tree == nil {
		return errors.New("account synthesis requires an image tree")
	}
	if accounts == nil || (len(accounts.Users) == 0 && len(accounts.Groups) == 0) {
		return nil
	}
	// Accounts are staged on a copy: a user can fail after its group was written,
	// and a caller that gets an error must not be left holding half an account
	// database.
	staged := tree.Clone()
	if err := applyGroups(staged, accounts.Groups); err != nil {
		return err
	}
	if err := applyUsers(staged, accounts.Users); err != nil {
		return err
	}
	return tree.Replace(staged)
}

// applyGroups merges declared groups into the existing group database.
func applyGroups(tree *vfs.Tree, groups []filesystem.GroupAccount) error {
	if len(groups) == 0 {
		return nil
	}
	database, err := newAccountDatabaseFrom(tree, groupFile)
	if err != nil {
		return err
	}
	changed := false
	for _, group := range groups {
		added, err := database.addGroup(group)
		if err != nil {
			return err
		}
		changed = changed || added
	}
	if !changed {
		// Every declared group was already there, so the file is as it was. Rewriting it
		// would detach a hard link and reflow a shape nothing asked to change.
		return nil
	}
	return writeDatabase(tree, groupFile, database.records)
}

// applyUsers merges declared users into the passwd and shadow databases. The
// group database is read again because a declared group may have just been
// added.
func applyUsers(tree *vfs.Tree, users []filesystem.UserAccount) error {
	if len(users) == 0 {
		return nil
	}
	// The group database is read again because a declared group may have just been
	// added.
	groups, err := newAccountDatabaseFrom(tree, groupFile)
	if err != nil {
		return err
	}
	passwd, err := newAccountDatabaseFrom(tree, passwdFile)
	if err != nil {
		return err
	}
	shadowed, err := newAccountDatabaseFrom(tree, shadowFile)
	if err != nil {
		return err
	}
	changed := false
	for _, user := range users {
		added, err := passwd.applyUser(user, groups.byID, shadowed)
		if err != nil {
			return err
		}
		changed = changed || added
	}
	if !changed {
		// Every declared user was already there, so neither file is rewritten: a rewrite
		// would detach a hard link and reflow a shape nothing asked to change.
		return nil
	}
	if err := writeDatabase(tree, passwdFile, passwd.records); err != nil {
		return err
	}
	return writeDatabase(tree, shadowFile, shadowed.records)
}

// groupID converts a declared group identifier, which the schema has already
// bounded, into the unsigned form the database stores.
func groupID(group filesystem.GroupAccount) (uint32, error) {
	if group.GID == nil {
		return 0, fmt.Errorf("group %q has no resolved gid", group.Name)
	}
	if *group.GID < 0 || *group.GID > math.MaxUint32 {
		return 0, fmt.Errorf("group %q has a gid outside the 32-bit range", group.Name)
	}
	return uint32(*group.GID), nil
}

// accountDatabase is a passwd or group database plus its lookup indexes, which
// are kept in step as declarations are applied.
type accountDatabase struct {
	records database
	byName  map[string]databaseRecord
	byID    map[uint32]databaseRecord
}

// newAccountDatabaseFrom reads one database and indexes it, refusing a file that
// names the same account or id twice.
func newAccountDatabaseFrom(tree *vfs.Tree, file accountDatabaseFile) (*accountDatabase, error) {
	records, err := readDatabase(tree, file)
	if err != nil {
		return nil, err
	}
	byName, err := records.byName(file.location)
	if err != nil {
		return nil, err
	}
	byID := make(map[uint32]databaseRecord)
	// Shadow records carry no numeric id, so indexing them by one would give every
	// account the same id 0 and refuse an ordinary multi-user file.
	if file.idField != noIDField {
		if byID, err = records.byID(file.location); err != nil {
			return nil, err
		}
	}
	return &accountDatabase{records: records, byName: byName, byID: byID}, nil
}

// applyUser merges one declared user, recording the matching shadow entry so a
// user can never exist without a disabled password. It reports whether the passwd
// or shadow database changed, so a declaration that added nothing leaves both files
// alone.
func (d *accountDatabase) applyUser(user filesystem.UserAccount, groupIDs map[uint32]databaseRecord,
	shadowed *accountDatabase,
) (bool, error) {
	if user.UID == nil || user.GID == nil || user.Home == nil || user.Shell == nil {
		return false, fmt.Errorf("user %q has unresolved account fields", user.Name)
	}
	uid, gid, err := accountIDs(user)
	if err != nil {
		return false, err
	}
	if _, ok := groupIDs[gid]; !ok {
		return false, fmt.Errorf("user %q requires primary gid %d, which the image does not define",
			user.Name, gid)
	}
	if found, ok := d.byName[user.Name]; ok {
		if err := checkDeclaredIdentity(user, found, uid, gid); err != nil {
			return false, err
		}
		return ensureShadow(shadowed, user.Name)
	}
	if other, ok := d.byID[uid]; ok {
		return false, fmt.Errorf("user %q is declared with uid %d, already used by user %q",
			user.Name, uid, other.name)
	}
	d.add(databaseRecord{name: user.Name, id: uid, fields: []string{user.Name, "x",
		strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10),
		"", *user.Home, *user.Shell}})
	// A new account always needs its shadow line, so the file changed even when the
	// line was already there: the passwd record is the change.
	if _, err := ensureShadow(shadowed, user.Name); err != nil {
		return false, err
	}
	return true, nil
}

// addGroup merges one declared group, refusing a declaration that contradicts the
// image's own record, and reports whether it added one.
func (d *accountDatabase) addGroup(group filesystem.GroupAccount) (bool, error) {
	gid, err := groupID(group)
	if err != nil {
		return false, err
	}
	if found, ok := d.byName[group.Name]; ok {
		if found.id != gid {
			return false, fmt.Errorf("group %q is declared with gid %d but the image has %d",
				group.Name, gid, found.id)
		}
		return false, nil
	}
	if other, ok := d.byID[gid]; ok {
		return false, fmt.Errorf("group %q is declared with gid %d, already used by group %q",
			group.Name, gid, other.name)
	}
	d.add(databaseRecord{name: group.Name, id: gid,
		fields: []string{group.Name, "x", strconv.FormatUint(uint64(gid), 10), ""}})
	return true, nil
}

// ensureShadow makes a declared user's shadow record unable to authenticate, and reports
// whether it changed the file. A package that ships the passwd record but not the shadow
// one would otherwise leave the account without the disabled-password guarantee.
//
// An existing record with a usable password fails: a declared account must not stay
// loggable with a password the specification never mentioned.
func ensureShadow(shadowed *accountDatabase, name string) (bool, error) {
	if found, ok := shadowed.byName[name]; ok {
		if passwordUsable(found) {
			return false, fmt.Errorf("user %q has a password in the image's shadow file; "+
				"declare no password and remove the record to disable it", name)
		}
		return false, nil
	}
	shadowed.add(disabledShadow(name))
	return true, nil
}

// passwdDelegates reports whether a passwd record's password field leaves
// authentication to the shadow file or disables the account outright. `x` is the
// delegation marker; `*`, `!` and `!!` are the conventional locked values. An
// empty field means no password is required and an inline hash is verified from
// passwd itself, so both are refused.
func passwdDelegates(record databaseRecord) bool {
	const passwordField = 1
	if len(record.fields) <= passwordField {
		return false
	}
	switch record.fields[passwordField] {
	case "x", DisabledPassword, "!", "!!":
		return true
	default:
		return false
	}
}

// passwordUsable reports whether a shadow record's password field would let the
// account authenticate. An empty field means no password is required, which is
// the opposite of disabled, so it counts as usable.
func passwordUsable(record databaseRecord) bool {
	const passwordField = 1
	if len(record.fields) <= passwordField {
		return true
	}
	password := record.fields[passwordField]
	return password != DisabledPassword && password != "!" && password != "!!"
}

// checkDeclaredIdentity compares a declaration against an existing record on the
// fields a declaration actually controls. Password and gecos are not declarable,
// so a package's own values are preserved: comparing the whole record would
// reject a declaration that agrees with the package on everything it can state.
//
// The passwd password field is still checked, because it is not merely preserved:
// an account that authenticates from passwd does not read shadow at all, so a
// disabled shadow record would not disable it.
func checkDeclaredIdentity(user filesystem.UserAccount, found databaseRecord, uid, gid uint32) error {
	if found.id != uid {
		return fmt.Errorf("user %q is declared with uid %d but the image has %d", user.Name, uid, found.id)
	}
	if !passwdDelegates(found) {
		return fmt.Errorf("user %q has a password in the image's passwd file; "+
			"declare no password and remove the record to disable it", user.Name)
	}
	const (
		gidField   = 3
		homeField  = 5
		shellField = 6
	)
	if len(found.fields) <= shellField {
		return fmt.Errorf("user %q has a malformed record in the image", user.Name)
	}
	if found.fields[gidField] != strconv.FormatUint(uint64(gid), 10) {
		return fmt.Errorf("user %q is declared with gid %d but the image has %q", user.Name, gid, found.fields[gidField])
	}
	if found.fields[homeField] != *user.Home {
		return fmt.Errorf("user %q is declared with home %q but the image has %q", user.Name, *user.Home, found.fields[homeField])
	}
	if found.fields[shellField] != *user.Shell {
		return fmt.Errorf("user %q is declared with shell %q but the image has %q",
			user.Name, *user.Shell, found.fields[shellField])
	}
	return nil
}

// accountIDs converts the declared identifiers, which the schema has already
// bounded, into the unsigned form the databases store.
func accountIDs(user filesystem.UserAccount) (uint32, uint32, error) {
	if *user.UID < 0 || *user.GID < 0 || *user.UID > math.MaxUint32 || *user.GID > math.MaxUint32 {
		return 0, 0, fmt.Errorf("user %q has an identifier outside the 32-bit range", user.Name)
	}
	return uint32(*user.UID), uint32(*user.GID), nil
}

// disabledShadow returns a shadow record that cannot authenticate. The password
// field is the only one that matters; the remaining fields keep the record
// well-formed without inventing an expiry policy.
func disabledShadow(name string) databaseRecord {
	return databaseRecord{name: name,
		fields: []string{name, DisabledPassword, "", "", "", "", "", "", ""}}
}
