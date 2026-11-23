package synthesis_test

import (
	"math"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

func accountsFixture() *filesystem.Accounts {
	group := &filesystem.Accounts{
		Groups: []filesystem.GroupAccount{{Name: "app", GID: new(65532)}},
		Users: []filesystem.UserAccount{{
			Name: "app", UID: new(65532), GID: new(65532),
			Home: new("/app"), Shell: new("/sbin/nologin"),
		}},
	}
	return group
}

func treeWithFile(t *testing.T, path, content string) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	if err := tree.File(path, []byte(content), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	return tree
}

func readFile(t *testing.T, tree *vfs.Tree, path string) string {
	t.Helper()
	content, err := tree.Read(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func TestAccounts_CreatesDatabases(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if passwd != "app:x:65532:65532::/app:/sbin/nologin\n" {
		t.Fatalf("passwd = %q", passwd)
	}
	group := readFile(t, tree, synthesis.GroupPath)
	if group != "app:x:65532:\n" {
		t.Fatalf("group = %q", group)
	}
	shadow := readFile(t, tree, synthesis.ShadowPath)
	if !strings.HasPrefix(shadow, "app:*:") {
		t.Fatalf("shadow = %q", shadow)
	}
	entry, ok := tree.Lookup(synthesis.ShadowPath)
	if !ok || entry.Mode != 0o600 {
		t.Fatalf("shadow mode = %v", entry.Mode)
	}
}

func TestAccounts_PreservesExistingRecords(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "root:x:0:0:root:/root:/bin/sh\n")
	if err := tree.File(synthesis.GroupPath, []byte("root:x:0:\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	passwd := readFile(t, tree, synthesis.PasswdPath)
	if !strings.HasPrefix(passwd, "root:x:0:0:root:/root:/bin/sh\n") {
		t.Fatalf("existing record was rewritten: %q", passwd)
	}
	if !strings.Contains(passwd, "app:x:65532:65532::/app:/sbin/nologin\n") {
		t.Fatalf("declared record missing: %q", passwd)
	}
}

func TestAccounts_AcceptsGroupFromSelectedPackages(t *testing.T) {
	tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if !strings.Contains(readFile(t, tree, synthesis.PasswdPath), "app:x:65532:65532::") {
		t.Fatal("user was not written")
	}
}

func TestAccounts_RejectsMissingGroup(t *testing.T) {
	declared := &filesystem.Accounts{Users: accountsFixture().Users}
	err := synthesis.Accounts(vfs.New(), declared)
	if err == nil || !strings.Contains(err.Error(), "does not define") {
		t.Fatalf("error = %v", err)
	}
}

// A user can fail after its group was written, so the whole application is staged:
// a caller that gets an error must not be left holding half an account database.
func TestAccounts_LeavesTheTreeUntouchedOnFailure(t *testing.T) {
	tree := vfs.New()
	declared := &filesystem.Accounts{
		Groups: []filesystem.GroupAccount{{Name: "newgroup", GID: new(4000)}},
		Users:  []filesystem.UserAccount{{Name: "newuser", UID: new(4000), GID: new(9999)}},
	}
	if err := synthesis.Accounts(tree, declared); err == nil {
		t.Fatal("expected an error")
	}
	for _, location := range []string{"/etc/group", "/etc/passwd", "/etc/shadow"} {
		if _, ok := tree.Lookup(location); ok {
			t.Fatalf("%s was written despite the failure", location)
		}
	}
}

func TestAccounts_RejectsCollisions(t *testing.T) {
	tests := []struct {
		name     string
		passwd   string
		group    string
		declared *filesystem.Accounts
		want     string
	}{
		{
			name:     "gid used by another group",
			group:    "other:x:65532:\n",
			declared: accountsFixture(),
			want:     "already used by group",
		},
		{
			name:     "uid used by another user",
			passwd:   "other:x:65532:0::/:/bin/sh\n",
			group:    "app:x:65532:\n",
			declared: accountsFixture(),
			want:     "already used by user",
		},
		{
			name:     "name declared with a different gid",
			group:    "app:x:1000:\n",
			declared: accountsFixture(),
			want:     "but the image has",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := vfs.New()
			if test.passwd != "" {
				if err := tree.File(synthesis.PasswdPath, []byte(test.passwd), vfs.Attrs{Mode: 0o644}); err != nil {
					t.Fatalf("passwd: %v", err)
				}
			}
			if test.group != "" {
				if err := tree.File(synthesis.GroupPath, []byte(test.group), vfs.Attrs{Mode: 0o644}); err != nil {
					t.Fatalf("group: %v", err)
				}
			}
			err := synthesis.Accounts(tree, test.declared)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAccounts_RejectsConflictingUserFields(t *testing.T) {
	tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
	if err := tree.File(synthesis.PasswdPath, []byte("app:x:65532:65532::/srv:/bin/sh\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	err := synthesis.Accounts(tree, accountsFixture())
	if err == nil || !strings.Contains(err.Error(), `declared with home "/app" but the image has "/srv"`) {
		t.Fatalf("error = %v", err)
	}
}

// TestAccounts_AcceptsDeclaredUserFromPackage covers a package shipping the
// account already: password and gecos are not declarable, so a declaration that
// agrees on everything it can state must not be rejected.
func TestAccounts_AcceptsDeclaredUserFromPackage(t *testing.T) {
	tree := treeWithFile(t, synthesis.GroupPath, "www-data:*:33:\n")
	if err := tree.File(synthesis.PasswdPath,
		[]byte("www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	uid, gid := 33, 33
	home, shell := "/var/www", "/usr/sbin/nologin"
	accounts := &filesystem.Accounts{Users: []filesystem.UserAccount{{
		Name: "www-data", UID: &uid, GID: &gid, Home: &home, Shell: &shell,
	}}}
	if err := synthesis.Accounts(tree, accounts); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if content := readFile(t, tree, synthesis.PasswdPath); content != "www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin\n" {
		t.Fatalf("passwd was rewritten: %q", content)
	}
	if _, err := tree.Read(synthesis.ShadowPath); err != nil {
		t.Fatalf("shadow record was not added: %v", err)
	}
}

// TestAccounts_RejectsConflictingUserIdentity covers each declarable field
// separately, so a mismatch names the field that disagrees.
func TestAccounts_RejectsConflictingUserIdentity(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		field string
	}{
		{name: "gid", line: "app:x:65532:65533::/app:/sbin/nologin", field: "gid 65532"},
		{name: "home", line: "app:x:65532:65532::/srv:/sbin/nologin", field: `home "/app"`},
		{name: "shell", line: "app:x:65532:65532::/app:/bin/sh", field: `shell "/sbin/nologin"`},
		{name: "malformed", line: "app:x:65532:65532:/app", field: "malformed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
			if err := tree.File(synthesis.PasswdPath, []byte(test.line+"\n"),
				vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("passwd: %v", err)
			}
			err := synthesis.Accounts(tree, accountsFixture())
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error = %v, want %q", err, test.field)
			}
		})
	}
}

// TestAccounts_RejectsUsablePackagePassword refuses to assemble an image whose
// declared account would stay loggable with a password the specification never
// mentioned.
func TestAccounts_RejectsUsablePackagePassword(t *testing.T) {
	tests := []struct {
		name   string
		shadow string
		usable bool
	}{
		{name: "crypt hash", shadow: "app:$6$salt$hash:19000:0:99999:7:::", usable: true},
		{name: "empty field", shadow: "app::19000:0:99999:7:::", usable: true},
		{name: "locked", shadow: "app:!:19000:0:99999:7:::", usable: false},
		{name: "locked twice", shadow: "app:!!:19000:0:99999:7:::", usable: false},
		{name: "disabled", shadow: "app:*:19000:0:99999:7:::", usable: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
			if err := tree.File(synthesis.PasswdPath, []byte("app:x:65532:65532::/app:/sbin/nologin\n"),
				vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("passwd: %v", err)
			}
			if err := tree.File(synthesis.ShadowPath, []byte(test.shadow+"\n"),
				vfs.Attrs{Mode: 0o600}); err != nil {
				t.Fatalf("shadow: %v", err)
			}
			err := synthesis.Accounts(tree, accountsFixture())
			if test.usable {
				if err == nil || !strings.Contains(err.Error(), "has a password in the image's shadow file") {
					t.Fatalf("error = %v, want a password refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("accounts: %v", err)
			}
			if content := readFile(t, tree, synthesis.ShadowPath); content != test.shadow+"\n" {
				t.Fatalf("shadow was rewritten: %q", content)
			}
		})
	}
}

// TestAccounts_RejectsUsablePasswdPassword covers the second way a declared
// account can stay loggable: an account whose passwd password field does not
// delegate to shadow authenticates from passwd, so a disabled shadow record
// beside it disables nothing.
func TestAccounts_RejectsUsablePasswdPassword(t *testing.T) {
	tests := []struct {
		name   string
		passwd string
		usable bool
	}{
		{name: "empty field", passwd: "app::65532:65532::/app:/sbin/nologin", usable: true},
		{name: "crypt hash", passwd: "app:$6$salt$hash:65532:65532::/app:/sbin/nologin", usable: true},
		{name: "delegated", passwd: "app:x:65532:65532::/app:/sbin/nologin", usable: false},
		{name: "disabled", passwd: "app:*:65532:65532::/app:/sbin/nologin", usable: false},
		{name: "locked", passwd: "app:!:65532:65532::/app:/sbin/nologin", usable: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
			if err := tree.File(synthesis.PasswdPath, []byte(test.passwd+"\n"),
				vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("passwd: %v", err)
			}
			err := synthesis.Accounts(tree, accountsFixture())
			if test.usable {
				if err == nil || !strings.Contains(err.Error(), "has a password in the image's passwd file") {
					t.Fatalf("error = %v, want a passwd password refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("accounts: %v", err)
			}
			if content := readFile(t, tree, synthesis.PasswdPath); content != test.passwd+"\n" {
				t.Fatalf("passwd was rewritten: %q", content)
			}
		})
	}
}

// TestAccounts_RejectsDuplicateRecords refuses a database that names one account
// twice. A last-wins index and a first-match reader disagree about which record
// is authoritative, so a usable record could survive behind a disabled one.
func TestAccounts_RejectsDuplicateRecords(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		lines string
		want  string
	}{
		{
			name:  "shadow name",
			file:  synthesis.ShadowPath,
			lines: "app:$6$salt$hash:19000:0:99999:7:::\napp:*:19000:0:99999:7:::\n",
			want:  `more than one record for "app"`,
		},
		{
			name:  "passwd name",
			file:  synthesis.PasswdPath,
			lines: "app:x:65532:65532::/app:/sbin/nologin\napp:x:65532:65532::/app:/sbin/nologin\n",
			want:  `more than one record for "app"`,
		},
		{
			name:  "passwd id",
			file:  synthesis.PasswdPath,
			lines: "app:x:65532:65532::/app:/sbin/nologin\nother:x:65532:65532::/app:/sbin/nologin\n",
			want:  `the same id 65532`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\n")
			if err := tree.File(test.file, []byte(test.lines), vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("create %s: %v", test.file, err)
			}
			err := synthesis.Accounts(tree, accountsFixture())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// TestAccounts_RejectsDuplicateGroupRecords covers the group database, which is
// indexed the same way and would otherwise let one gid name two groups.
func TestAccounts_RejectsDuplicateGroupRecords(t *testing.T) {
	tree := treeWithFile(t, synthesis.GroupPath, "app:x:65532:\nother:x:65532:\n")
	err := synthesis.Accounts(tree, accountsFixture())
	if err == nil || !strings.Contains(err.Error(), "the same id 65532") {
		t.Fatalf("error = %v", err)
	}
}

func TestAccounts_IsIdempotent(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := readFile(t, tree, synthesis.PasswdPath)
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if second := readFile(t, tree, synthesis.PasswdPath); second != first {
		t.Fatalf("second run changed passwd: %q", second)
	}
}

func TestAccounts_EmptyDeclarationIsNoop(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.Accounts(tree, nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := synthesis.Accounts(tree, &filesystem.Accounts{}); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if entries := tree.Entries(); len(entries) != 0 {
		t.Fatalf("entries = %v", entries)
	}
}

func TestAccounts_RejectsMalformedDatabase(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "broken\n")
	err := synthesis.Accounts(tree, accountsFixture())
	if err == nil || !strings.Contains(err.Error(), "malformed record") {
		t.Fatalf("error = %v", err)
	}
}

// A malformed shadow line can carry a password hash, so the error must name the
// record without echoing it: errors reach logs.
func TestAccounts_DoesNotEchoMalformedRecords(t *testing.T) {
	const hash = "$6$secretsalt$secretverifier"
	tree := treeWithFile(t, synthesis.ShadowPath, "root:"+hash+"\n")
	err := synthesis.Accounts(tree, accountsFixture())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "secretverifier") || strings.Contains(err.Error(), "secretsalt") {
		t.Fatalf("error echoes the record: %v", err)
	}
}

func TestAccounts_RequiresTree(t *testing.T) {
	if err := synthesis.Accounts(nil, accountsFixture()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestAccounts_PreservesComments(t *testing.T) {
	tree := treeWithFile(t, synthesis.GroupPath, "# managed\napp:x:65532:\n")
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if group := readFile(t, tree, synthesis.GroupPath); !strings.HasPrefix(group, "# managed\n") {
		t.Fatalf("comment was dropped: %q", group)
	}
}

func TestAccounts_RejectsOutOfRangeIDs(t *testing.T) {
	tooBig := math.MaxUint32 + 1
	tests := []struct {
		name     string
		declared *filesystem.Accounts
		want     string
	}{
		{
			name:     "group gid",
			declared: &filesystem.Accounts{Groups: []filesystem.GroupAccount{{Name: "app", GID: &tooBig}}},
			want:     "outside the 32-bit range",
		},
		{
			name: "user uid",
			declared: &filesystem.Accounts{Users: []filesystem.UserAccount{{
				Name: "app", UID: &tooBig, GID: new(0), Home: new("/"), Shell: new("/bin/sh"),
			}}},
			want: "outside the 32-bit range",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := vfs.New()
			if err := tree.File(synthesis.GroupPath, []byte("root:x:0:\n"), vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("group: %v", err)
			}
			err := synthesis.Accounts(tree, test.declared)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAccounts_PreservesShadowRecords(t *testing.T) {
	tree := vfs.New()
	if err := tree.File(synthesis.GroupPath, []byte("app:x:65532:\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := tree.File(synthesis.ShadowPath, []byte("root:$6$hash:19000:0:99999:7:::\n"),
		vfs.Attrs{Mode: 0o600}); err != nil {
		t.Fatalf("shadow: %v", err)
	}
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	shadow := readFile(t, tree, synthesis.ShadowPath)
	if !strings.HasPrefix(shadow, "root:$6$hash:19000:0:99999:7:::\n") {
		t.Fatalf("existing shadow record was rewritten: %q", shadow)
	}
	if strings.Count(shadow, "app:") != 1 {
		t.Fatalf("shadow = %q", shadow)
	}
}

func TestAccounts_DoesNotDuplicateExistingShadowEntry(t *testing.T) {
	tree := vfs.New()
	if err := tree.File(synthesis.GroupPath, []byte("app:x:65532:\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := tree.File(synthesis.ShadowPath, []byte("app:*:19900:0:99999:7:::\n"),
		vfs.Attrs{Mode: 0o600}); err != nil {
		t.Fatalf("shadow: %v", err)
	}
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if shadow := readFile(t, tree, synthesis.ShadowPath); strings.Count(shadow, "app:") != 1 {
		t.Fatalf("shadow = %q", shadow)
	}
}

// Shadow records have no numeric id, so indexing them by one would give every
// account the same id 0 and refuse an ordinary multi-user image.
func TestAccounts_AcceptsMultipleShadowRecords(t *testing.T) {
	tree := vfs.New()
	if err := tree.File(synthesis.GroupPath, []byte("root:x:0:\napp:x:65532:\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := tree.File(synthesis.ShadowPath,
		[]byte("root:*:19000:0:99999:7:::\napp:!:19000:0:99999:7:::\n"),
		vfs.Attrs{Mode: 0o600}); err != nil {
		t.Fatalf("shadow: %v", err)
	}
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if shadow := readFile(t, tree, synthesis.ShadowPath); strings.Count(shadow, "app:") != 1 {
		t.Fatalf("shadow = %q", shadow)
	}
}

// A blank line is not an account: it has an empty name, and two of them would
// otherwise be reported as one id used twice.
func TestAccounts_AcceptsBlankLines(t *testing.T) {
	tree := treeWithFile(t, synthesis.PasswdPath, "root:x:0:0:root:/root:/bin/sh\n\n\n")
	if err := tree.File(synthesis.GroupPath, []byte("root:x:0:\n\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := synthesis.Accounts(tree, accountsFixture()); err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if passwd := readFile(t, tree, synthesis.PasswdPath); !strings.Contains(passwd, "/bin/sh\n\n\napp:") {
		t.Fatalf("blank lines were not preserved: %q", passwd)
	}
}

// Applying the same multi-user declaration twice must not fail on the records the
// first application wrote.
func TestAccounts_IsIdempotentForMultipleUsers(t *testing.T) {
	declared := &filesystem.Accounts{
		Groups: []filesystem.GroupAccount{{Name: "app", GID: new(65532)}, {Name: "data", GID: new(65533)}},
		Users: []filesystem.UserAccount{
			{Name: "app", UID: new(65532), GID: new(65532), Home: new("/app"), Shell: new("/sbin/nologin")},
			{Name: "data", UID: new(65533), GID: new(65533), Home: new("/data"), Shell: new("/sbin/nologin")},
		},
	}
	tree := vfs.New()
	if err := synthesis.Accounts(tree, declared); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := readFile(t, tree, synthesis.ShadowPath)
	if err := synthesis.Accounts(tree, declared); err != nil {
		t.Fatalf("second: %v", err)
	}
	if second := readFile(t, tree, synthesis.ShadowPath); second != first {
		t.Fatalf("second run changed shadow: %q", second)
	}
}
