package filesystem_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

const filesystemFixture = minimalSpec + `filesystem:
  paths:
    - path: /app/data
      type: directory
      uid: 65532
      gid: 65532
      mode: "0750"
    - path: /app/current
      type: symlink
      target: data
    - path: /app/ready
      type: file
  accounts:
    groups:
      - name: app
        gid: 65532
    users:
      - name: app
        uid: 65532
        gid: 65532
  timezone: Europe/Berlin
  ca:
    mode: append
    sources: [certificates/company.pem]
  os-release:
    PRETTY_NAME: Example application image
`

func TestLoadSpec_Filesystem(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, filesystemFixture)
	if err != nil {
		t.Fatal(err)
	}
	fs := &spec.Filesystem
	if len(fs.Paths) != 3 || fs.Paths[0].UID != 65532 || *fs.Paths[0].Mode != "0750" ||
		*fs.Paths[1].Target != "data" || *fs.Paths[1].Mode != "0777" || *fs.Paths[2].Mode != "0644" ||
		fs.Paths[2].UID != 0 || fs.Paths[2].GID != 0 {
		t.Fatalf("unexpected path defaults: %#v", fs.Paths)
	}
	user := fs.Accounts.Users[0]
	if *user.UID != 65532 || *user.GID != 65532 || *user.Home != "/" || *user.Shell != "/sbin/nologin" || spec.Container.User != "" {
		t.Fatalf("unexpected account defaults: %#v", user)
	}
	if *fs.Timezone != "Europe/Berlin" || fs.CA.Mode != "append" || fs.CA.Sources[0] != "certificates/company.pem" ||
		fs.OSRelease["PRETTY_NAME"] != "Example application image" {
		t.Fatalf("OS-state declarations changed: %#v", fs)
	}
}

func TestLoadSpec_FilesystemOmission(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"", "filesystem: {}", "filesystem: {paths: [], accounts: {users: [], groups: []}, os-release: {}}"} {
		spec, err := loadText(t, minimalSpec+suffix)
		if err != nil {
			t.Fatal(err)
		}
		fs := spec.Filesystem
		if len(fs.Paths) != 0 || len(fs.Accounts.Users) != 0 || len(fs.Accounts.Groups) != 0 || fs.Timezone != nil || fs.CA != nil || len(fs.OSRelease) != 0 {
			t.Fatalf("unexpected implicit modifications: %#v", fs)
		}
	}
}

func TestFilesystemDefaults_SeparateAndIdempotent(t *testing.T) {
	t.Parallel()
	spec, err := schemaSpec.DecodeSpec([]byte(filesystemFixture))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Filesystem.Paths[1].Mode != nil || spec.Filesystem.Accounts.Users[0].Home != nil || spec.Filesystem.Accounts.Users[0].Shell != nil {
		t.Fatal("decoder applied defaults")
	}
	schemaSpec.ApplyDefaults(spec)
	before, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	schemaSpec.ApplyDefaults(spec)
	after, err := json.Marshal(spec)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("defaults not idempotent: %v", err)
	}
	other, err := loadText(t, filesystemFixture)
	if err != nil {
		t.Fatal(err)
	}
	*spec.Filesystem.Paths[1].Mode = "0000"
	*spec.Filesystem.Accounts.Users[0].Home = "/changed"
	if *other.Filesystem.Paths[1].Mode != "0777" || *other.Filesystem.Accounts.Users[0].Home != "/" {
		t.Fatal("mutable defaults shared across loads")
	}
}

func TestLoadSpec_FilesystemValidVariants(t *testing.T) {
	t.Parallel()
	for i, suffix := range []string{
		`paths: [{path: /, type: directory}]`,
		`paths: [{path: /a, type: file, uid: 4294967295, gid: 0, mode: "04755"}]`,
		`paths: [{path: /link, type: symlink, target: /usr/bin/tool}]`,
		`paths: [{path: /a/link, type: symlink, target: ../lib}]`,
		`paths: [{path: /a/link, type: symlink, target: .}]`,
		`paths: [{path: /a/link, type: symlink, target: ..}]`,
		`accounts: {users: [{name: _User.1, uid: 0, gid: 4294967295, home: /app, shell: /bin/sh}]}`,
		`accounts: {groups: [{name: app, gid: 4294967295}], users: [{name: app, uid: 4294967295, gid: 0}]}`,
		`timezone: Etc/UTC`, `timezone: UTC`, `timezone: Etc/GMT+12`,
		`ca: {mode: replace, sources: [definitely-not-present/company.pem]}`,
		`os-release: {NAME: Custom, PRETTY_NAME: '', VERSION: Custom, HOME_URL: text, DOCUMENTATION_URL: text, SUPPORT_URL: text, BUG_REPORT_URL: text, LOGO: custom}`,
		"os-release: {PRETTY_NAME: " + strconv.Quote("literal \\\"'$`") + "}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+"filesystem: {"+suffix+"}")
			if err != nil || spec == nil {
				t.Fatalf("want valid declaration: %v", err)
			}
		})
	}
}

func TestLoadSpec_CAPathIsNotRead(t *testing.T) {
	t.Parallel()
	missing := "absent.pem"
	if _, err := loadText(t, minimalSpec+"filesystem: {ca: {mode: append, sources: ["+strconv.Quote(missing)+"]}}"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSpec_FilesystemInvalidEntries(t *testing.T) {
	t.Parallel()
	for i, entry := range []string{
		`{path: /a}`, `{type: file}`, `{path: /a, type: socket}`,
		`{path: relative, type: directory}`, `{path: /a/../b, type: file}`,
		`{path: /a/, type: directory}`, `{path: /, type: file}`, `{path: /, type: symlink, target: /a}`,
		`{path: "/a\\b", type: file}`, `{path: "/a\nb", type: file}`,
		`{path: /a, type: file, uid: -1}`, `{path: /a, type: file, gid: 4294967296}`,
		`{path: /a, type: file, mode: "755"}`, `{path: /a, type: file, mode: "00755"}`,
		`{path: /a, type: file, mode: "0888"}`, `{path: /a, type: file, mode: ''}`,
		`{path: /a, type: directory, target: ''}`, `{path: /a, type: file, target: /b}`,
		`{path: /a, type: symlink}`, `{path: /a, type: symlink, target: ''}`,
		`{path: /a, type: symlink, target: /b, mode: "0755"}`,
		`{path: /a, type: symlink, target: ../b}`, `{path: /a/link, type: symlink, target: ../../b}`,
		`{path: /a/link, type: symlink, target: ../b/../..}`,
		`{path: /a, type: symlink, target: ./b}`, `{path: /a, type: symlink, target: a}`,
		`{path: /a, type: symlink, target: /a}`, `{path: /a, type: symlink, target: /b/../a}`,
		`{path: /a, type: symlink, target: "b\\c"}`, `{path: /a, type: symlink, target: "b\nc"}`,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if spec, err := loadText(t, minimalSpec+"filesystem: {paths: ["+entry+"]}"); err == nil || spec != nil {
				t.Fatalf("want rejected entry: spec=%#v err=%v", spec, err)
			}
		})
	}
	for _, entries := range []string{
		`{path: /a, type: file}, {path: /a, type: directory}`,
		`{path: /a/b, type: directory}, {path: /a, type: file}`,
		`{path: /a, type: symlink, target: /b}, {path: /a/c, type: file}`,
	} {
		if spec, err := loadText(t, minimalSpec+"filesystem: {paths: ["+entries+"]}"); err == nil || spec != nil {
			t.Fatalf("want conflict rejection: spec=%#v err=%v", spec, err)
		}
	}
}

func TestLoadSpec_FilesystemErrorsRedactInputs(t *testing.T) {
	t.Parallel()
	const secret = "sensitive-marker"
	for i, suffix := range []string{
		`paths: [{path: ` + secret + `, type: file}]`,
		`paths: [{path: /a, type: symlink, target: "` + secret + `\nb"}]`,
		`accounts: {users: [{name: "` + secret + `:bad", uid: 0, gid: 0}]}`,
		`ca: {mode: append, sources: ["` + secret + `/../bad"]}`,
		`os-release: {` + secret + `: value}`, `os-release: {NAME: "` + secret + `\nother"}`,
		`os-release: {NAME: ` + secret + `, NAME: other}`, `ca: ` + secret,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+"filesystem: {"+suffix+"}")
			if err == nil || spec != nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("want redacted failure: spec=%#v err=%v", spec, err)
			}
		})
	}
}
