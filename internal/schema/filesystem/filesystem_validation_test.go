package filesystem_test

import (
	"strconv"
	"strings"
	"testing"
)

func TestLoadSpec_InvalidAccounts(t *testing.T) {
	t.Parallel()
	for i, accounts := range []string{
		`users: [{name: app, gid: 0}]`, `users: [{name: app, uid: 0}]`,
		`groups: [{name: app}]`, `groups: [{gid: 0}]`,
		`users: [{uid: 0, gid: 0}]`, `users: [{name: '1user', uid: 0, gid: 0}]`,
		`users: [{name: '` + strings.Repeat("a", 33) + `', uid: 0, gid: 0}]`,
		`users: [{name: 'a:b', uid: 0, gid: 0}]`, `groups: [{name: "a\nb", gid: 0}]`,
		`users: [{name: app, uid: -1, gid: 0}]`, `users: [{name: app, uid: 0, gid: 4294967296}]`,
		`groups: [{name: app, gid: -1}]`, `groups: [{name: app, gid: 4294967296}]`,
		`users: [{name: app, uid: 0, gid: 0, home: ''}]`,
		`users: [{name: app, uid: 0, gid: 0, shell: ''}]`,
		`users: [{name: app, uid: 0, gid: 0, shell: /}]`,
		`users: [{name: app, uid: 0, gid: 0, home: /a/../b}]`,
		`users: [{name: app, uid: 0, gid: 0, shell: relative}]`,
		`users: [{name: app, uid: 0, gid: 0, home: '/app:x'}]`,
		`users: [{name: app, uid: 0, gid: 0, shell: '/app:x'}]`,
		`users: [{name: app, uid: 0, gid: 0, shell: "/app\nx"}]`,
		`users: [{name: app, uid: 0, gid: 0}, {name: app, uid: 1, gid: 0}]`,
		`users: [{name: app, uid: 0, gid: 0}, {name: other, uid: 0, gid: 0}]`,
		`groups: [{name: app, gid: 0}, {name: app, gid: 1}]`,
		`groups: [{name: app, gid: 0}, {name: other, gid: 0}]`,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if spec, err := loadText(t, minimalSpec+"filesystem: {accounts: {"+accounts+"}}"); err == nil || spec != nil {
				t.Fatalf("want rejected account: spec=%#v err=%v", spec, err)
			}
		})
	}
}

func TestLoadSpec_InvalidOSState(t *testing.T) {
	t.Parallel()
	for i, suffix := range []string{
		`timezone: ''`, `timezone: /UTC`, `timezone: ../UTC`, `timezone: Europe//Berlin`,
		`timezone: Europe/Berlin/`, `timezone: "Europe\nBerlin"`, `timezone: 'Europe.Berlin'`,
		`ca: {}`, `ca: {sources: [cert.pem]}`, `ca: {mode: add, sources: [cert.pem]}`,
		`ca: {mode: append}`, `ca: {mode: replace, sources: []}`,
		`ca: {mode: append, sources: [cert.pem, cert.pem]}`,
		`ca: {mode: append, sources: ['']}`, `ca: {mode: append, sources: [a/../cert.pem]}`,
		`os-release: {ID: other}`, `os-release: {ID_LIKE: other}`,
		`os-release: {VERSION_ID: '1'}`, `os-release: {VERSION_CODENAME: other}`,
		`os-release: {NEW_KEY: text}`, `os-release: {NAME: "a\nb"}`,
		`os-release: {NAME: "a\rb"}`, `os-release: {NAME: "a\tb"}`,
		`os-release: {NAME: "a\u2028b"}`, `os-release: {NAME: "a\u2029b"}`,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if spec, err := loadText(t, minimalSpec+"filesystem: {"+suffix+"}"); err == nil || spec != nil {
				t.Fatalf("want rejected OS-state declaration: spec=%#v err=%v", spec, err)
			}
		})
	}
}

func TestLoadSpec_FilesystemStrictYAML(t *testing.T) {
	t.Parallel()
	for i, suffix := range []string{
		`filesystem: []`, `filesystem: null`, `filesystem: text`,
		`filesystem: {paths: null}`, `filesystem: {paths: {path: /a}}`,
		`filesystem: {paths: [null]}`, `filesystem: {paths: [{path: /a, type: file, uid: '0'}]}`,
		`filesystem: {paths: [{path: /a, type: file, mode: 0755}]}`,
		`filesystem: {paths: [{path: /a, type: file, mode: null}]}`,
		`filesystem: {paths: [{path: /a, type: symlink, target: null}]}`,
		`filesystem: {paths: [{path: /a, type: file, future: value}]}`,
		`filesystem: {paths: [{path: /a, path: /b, type: file}]}`,
		`filesystem: {paths: [{path: /a, type: file, content: text}]}`,
		`filesystem: {accounts: null}`, `filesystem: {accounts: {users: null}}`,
		`filesystem: {accounts: {groups: null}}`, `filesystem: {accounts: {users: [false]}}`,
		`filesystem: {accounts: {users: [{name: app, uid: null, gid: 0}]}}`,
		`filesystem: {accounts: {users: [{name: app, uid: 0, gid: true}]}}`,
		`filesystem: {accounts: {users: [{name: app, uid: 0, gid: 0, home: null}]}}`,
		`filesystem: {accounts: {users: [{name: app, uid: 0, gid: 0, shell: null}]}}`,
		`filesystem: {accounts: {users: [{name: app, uid: 0, gid: 0, password: secret}]}}`,
		`filesystem: {accounts: {groups: [{name: app, gid: 0, members: [app]}]}}`,
		`filesystem: {timezone: null}`, `filesystem: {timezone: true}`,
		`filesystem: {ca: null}`, `filesystem: {ca: []}`,
		`filesystem: {ca: {mode: append, sources: [null]}}`,
		`filesystem: {ca: {mode: append, sources: ['${HOST_CERT}']}}`,
		`filesystem: {os-release: null}`, `filesystem: {os-release: []}`,
		`filesystem: {os-release: {NAME: 42}}`, `filesystem: {os-release: {NAME: null}}`,
		`filesystem: {os-release: {NAME: one, NAME: two}}`,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if spec, err := loadText(t, minimalSpec+suffix); err == nil || spec != nil {
				t.Fatalf("want strict YAML rejection: spec=%#v err=%v", spec, err)
			}
		})
	}
}
