package vfs

import (
	"io/fs"
	"strings"
	"testing"
)

func mustTree(t *testing.T, build func(*Tree) error) *Tree {
	t.Helper()
	tree := New()
	if err := build(tree); err != nil {
		t.Fatalf("build: %v", err)
	}
	return tree
}

func TestResolve_FollowsLinks(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.Dir("/usr/bin", attrs(0o755)); err != nil {
			return err
		}
		if err := tree.File("/usr/bin/tool", nil, attrs(0o755)); err != nil {
			return err
		}
		if err := tree.Symlink("/bin", "/usr/bin", attrs(0o777)); err != nil {
			return err
		}
		return tree.Symlink("/usr/bin/alias", "tool", attrs(0o777))
	})
	tests := []struct {
		path string
		want string
	}{
		{"/bin", "/usr/bin"},
		{"/bin/tool", "/usr/bin/tool"},
		{"/usr/bin/alias", "/usr/bin/tool"},
		{"/usr", "/usr"},
		{"/", "/"},
		{"/missing", "/missing"},
		{"/bin/missing", "/usr/bin/missing"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			got, err := tree.Resolve(test.path)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != test.want {
				t.Fatalf("Resolve = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolve_RelativeDotDotTargetIsAppliedToTheLinksParent(t *testing.T) {
	// /a/link -> ../real resolves against /a, not against the tree root.
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.Dir("/real", attrs(0o755)); err != nil {
			return err
		}
		return tree.Symlink("/a/link", "../real", attrs(0o777))
	})
	got, err := tree.Resolve("/a/link")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "/real" {
		t.Fatalf("Resolve = %q, want /real", got)
	}
}

func TestResolve_EscapesAndCycles(t *testing.T) {
	tests := []struct {
		name    string
		build   func(*Tree) error
		path    string
		want    string
		wantErr string
	}{
		{
			name: "relative escape beyond root",
			build: func(tree *Tree) error {
				return tree.Symlink("/a", "../b", attrs(0o777))
			},
			path:    "/a",
			wantErr: "escapes the image root",
		},
		{
			name: "self cycle",
			build: func(tree *Tree) error {
				return tree.Symlink("/a", "/a", attrs(0o777))
			},
			path:    "/a",
			wantErr: "symlink cycle",
		},
		{
			name: "mutual cycle",
			build: func(tree *Tree) error {
				if err := tree.Symlink("/a", "/b", attrs(0o777)); err != nil {
					return err
				}
				return tree.Symlink("/b", "/a", attrs(0o777))
			},
			path:    "/a",
			wantErr: "symlink cycle",
		},
		{
			name: "chained link",
			build: func(tree *Tree) error {
				if err := tree.Dir("/real", attrs(0o755)); err != nil {
					return err
				}
				if err := tree.Symlink("/b", "/real", attrs(0o777)); err != nil {
					return err
				}
				return tree.Symlink("/a", "/b", attrs(0o777))
			},
			path: "/a",
			want: "/real",
		},
		{
			name: "dangling link resolves literally",
			build: func(tree *Tree) error {
				return tree.Symlink("/a", "/nowhere", attrs(0o777))
			},
			path: "/a",
			want: "/nowhere",
		},
		{
			name: "passes through regular file",
			build: func(tree *Tree) error {
				if err := tree.File("/f", nil, attrs(0o644)); err != nil {
					return err
				}
				return tree.Symlink("/a", "/f/x", attrs(0o777))
			},
			path:    "/a",
			wantErr: "passes through non-directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := mustTree(t, test.build)
			got, err := tree.Resolve(test.path)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != test.want {
				t.Fatalf("Resolve = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolve_ExpansionIsBounded(t *testing.T) {
	tree := New()
	deep := "/" + strings.TrimSuffix(strings.Repeat("deep/", 200), "/")
	if err := tree.Symlink("/a", deep, attrs(0o777)); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	_, err := tree.Resolve("/a")
	if err == nil || !strings.Contains(err.Error(), "symlink expansion limit") {
		t.Fatalf("error = %v", err)
	}
}

func TestHardlink_RejectsInvalidPaths(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error { return tree.File("/f", nil, attrs(0o644)) })
	if err := tree.Hardlink("relative", "/f", Origin{Package: "pkg"}); err == nil {
		t.Fatal("relative hardlink path accepted")
	}
	if err := tree.Hardlink("/g", "relative", Origin{Package: "pkg"}); err == nil {
		t.Fatal("relative hardlink target accepted")
	}
}

func TestResolve_RejectsInvalidPaths(t *testing.T) {
	tree := New()
	for _, p := range []string{"", "relative", "/a/../b", "/a//b", "/a\\b"} {
		if _, err := tree.Resolve(p); err == nil {
			t.Fatalf("path %q accepted", p)
		}
	}
}

func TestDeclare_CreatesAndPreserves(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		return tree.File("/etc/config", []byte("keep"), attrs(0o600))
	})
	if err := tree.Declare("/etc/config", File, Attrs{Mode: 0o640, UID: 7, GID: 8,
		Origin: Origin{Package: "declared"}}, ""); err != nil {
		t.Fatalf("Declare file: %v", err)
	}
	entry, _ := tree.Lookup("/etc/config")
	if entry.Mode != 0o640 || entry.UID != 7 || entry.GID != 8 {
		t.Fatalf("metadata not applied: %+v", entry)
	}
	data, err := tree.Read("/etc/config")
	if err != nil || string(data) != "keep" {
		t.Fatalf("content changed: %q %v", data, err)
	}
	if len(entry.Origins) != 2 {
		t.Fatalf("origins = %+v", entry.Origins)
	}

	if err := tree.Declare("/var/empty", File, attrs(0o644), ""); err != nil {
		t.Fatalf("Declare new file: %v", err)
	}
	if data, err := tree.Read("/var/empty"); err != nil || len(data) != 0 {
		t.Fatalf("new file = %q %v", data, err)
	}
	if err := tree.Declare("/var/data", Dir, attrs(0o750), ""); err != nil {
		t.Fatalf("Declare directory: %v", err)
	}
	if entry, ok := tree.Lookup("/var/data"); !ok || entry.Kind != Dir || entry.Mode != 0o750 {
		t.Fatalf("directory = %+v", entry)
	}
	if err := tree.Declare("/var/link", Symlink, attrs(0o777), "/etc/config"); err != nil {
		t.Fatalf("Declare symlink: %v", err)
	}
	if entry, ok := tree.Lookup("/var/link"); !ok || entry.Kind != Symlink || entry.Target != "/etc/config" {
		t.Fatalf("symlink = %+v", entry)
	}
	second := attrs(0o777)
	second.Origin.Package = "other"
	if err := tree.Declare("/var/link", Symlink, second, "/etc/config"); err != nil {
		t.Fatalf("repeat identical symlink: %v", err)
	}
	if entry, _ := tree.Lookup("/var/link"); len(entry.Origins) != 2 {
		t.Fatalf("origins = %+v", entry.Origins)
	}
}

func TestDeclare_SymlinkMetadataDoesNotFollowTarget(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.File("/target", []byte("x"), attrs(0o644)); err != nil {
			return err
		}
		return tree.Symlink("/link", "/target", attrs(0o777))
	})
	if err := tree.Declare("/link", Symlink, Attrs{Mode: 0o644, UID: 42, GID: 43,
		Origin: Origin{Package: "declared"}}, "/target"); err != nil {
		t.Fatalf("Declare symlink: %v", err)
	}
	link, _ := tree.Lookup("/link")
	if link.UID != 42 || link.GID != 43 || link.Mode != SymlinkMode {
		t.Fatalf("link = %+v", link)
	}
	target, _ := tree.Lookup("/target")
	if target.UID != 0 || target.Mode != 0o644 {
		t.Fatalf("target was modified: %+v", target)
	}
}

func TestDeclare_Conflicts(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Tree) error
		kind    Kind
		target  string
		path    string
		mode    fs.FileMode
		want    string
	}{
		{
			name:    "kind mismatch",
			prepare: func(t *Tree) error { return t.File("/a", []byte("x"), attrs(0o644)) },
			kind:    Dir,
			want:    "conflicts with existing file",
		},
		{
			name:    "symlink target mismatch",
			prepare: func(t *Tree) error { return t.Symlink("/a", "/one", attrs(0o777)) },
			kind:    Symlink,
			target:  "/two",
			want:    "conflicts with existing target",
		},
		{
			name:    "target on non-symlink",
			prepare: func(*Tree) error { return nil },
			kind:    File,
			target:  "/x",
			want:    "must not declare a target",
		},
		{
			name:    "unknown kind",
			prepare: func(*Tree) error { return nil },
			kind:    Kind("socket"),
			want:    "unsupported kind",
		},
		{
			name:    "non-directory ancestor",
			prepare: func(t *Tree) error { return t.File("/a", nil, attrs(0o644)) },
			kind:    File,
			want:    "non-directory ancestor",
		},
		{
			name:    "invalid path",
			prepare: func(*Tree) error { return nil },
			kind:    File,
			path:    "/a/../b",
			want:    "is not a clean absolute POSIX path",
		},
		{
			name:    "root declaration",
			prepare: func(*Tree) error { return nil },
			kind:    Dir,
			path:    "/",
			want:    "root directory is implicit",
		},
		{
			name:    "invalid symlink target",
			prepare: func(*Tree) error { return nil },
			kind:    Symlink,
			target:  "/a/../b",
			want:    "target must be a clean POSIX path",
		},
		{
			name:    "non-permission mode bits",
			prepare: func(t *Tree) error { return t.File("/a", nil, attrs(0o644)) },
			kind:    File,
			mode:    fs.ModeDir | 0o755,
			want:    "mode has non-permission bits",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := mustTree(t, test.prepare)
			path := test.path
			if path == "" {
				path = "/a/b"
				if test.kind == Dir || test.name == "kind mismatch" || test.name == "symlink target mismatch" {
					path = "/a"
				}
			}
			mode := fs.FileMode(0o755)
			if test.mode != 0 {
				mode = test.mode
			}
			err := tree.Declare(path, test.kind, attrs(mode), test.target)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDeclare_FailuresAreNonDestructive(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.File("/a", []byte("original"), attrs(0o600)); err != nil {
			return err
		}
		return tree.Symlink("/link", "/a", attrs(0o777))
	})
	before := tree.Entries()
	if err := tree.Declare("/a", Dir, attrs(0o755), ""); err == nil {
		t.Fatal("conflicting declaration succeeded")
	}
	if err := tree.Declare("/link/x", File, attrs(0o644), ""); err == nil {
		t.Fatal("declaration under symlink ancestor succeeded")
	}
	after := tree.Entries()
	if len(before) != len(after) {
		t.Fatalf("entry count changed: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Path != after[i].Path || before[i].Kind != after[i].Kind ||
			before[i].Mode != after[i].Mode || before[i].UID != after[i].UID {
			t.Fatalf("entry %d changed: %+v -> %+v", i, before[i], after[i])
		}
	}
	if data, err := tree.Read("/a"); err != nil || string(data) != "original" {
		t.Fatalf("content changed: %q %v", data, err)
	}
}

func TestHardlink_RejectsSymlinkAncestor(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.File("/real/file", nil, attrs(0o644)); err != nil {
			return err
		}
		return tree.Symlink("/alias", "/real", attrs(0o777))
	})
	err := tree.Hardlink("/alias/file", "/real/file", Origin{Package: "pkg"})
	if err == nil || !strings.Contains(err.Error(), "symlink ancestor") {
		t.Fatalf("error = %v", err)
	}
}

func TestDeclare_RejectsRootAndLeavesItImplicit(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error { return tree.File("/f", nil, attrs(0o644)) })
	if err := tree.Declare("/", Dir, Attrs{Mode: 0o700, UID: 1, GID: 1}, ""); err == nil {
		t.Fatal("root declaration succeeded")
	}
	if entry, ok := tree.Lookup("/"); !ok || entry.Mode != ImplicitDirMode || entry.UID != 0 || !entry.Implicit {
		t.Fatalf("root was mutated: %+v", entry)
	}
}

func TestDeclare_RejectsSymlinkAncestor(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.Dir("/real", attrs(0o755)); err != nil {
			return err
		}
		return tree.Symlink("/alias", "/real", attrs(0o777))
	})
	err := tree.Declare("/alias/file", File, attrs(0o644), "")
	if err == nil || !strings.Contains(err.Error(), "symlink ancestor") {
		t.Fatalf("error = %v", err)
	}
	if _, ok := tree.Lookup("/real/file"); ok {
		t.Fatal("declaration followed the alias")
	}
}

func TestDeclare_DoesNotMutateACloneSource(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		if err := tree.File("/etc/config", []byte("keep"), attrs(0o600)); err != nil {
			return err
		}
		return tree.Hardlink("/etc/alias", "/etc/config", Origin{Package: "pkg"})
	})
	staged := tree.Clone()
	if err := staged.Declare("/etc/config", File, Attrs{Mode: 0o640, UID: 7, GID: 8,
		Origin: Origin{Package: "declared"}}, ""); err != nil {
		t.Fatalf("Declare: %v", err)
	}
	original, _ := tree.Lookup("/etc/config")
	if original.Mode != 0o600 || original.UID != 0 || original.GID != 0 {
		t.Fatalf("declaring on a clone changed the source tree: %+v", original)
	}
	if len(original.Origins) != 1 {
		t.Fatalf("source origins = %+v", original.Origins)
	}
	declared, _ := staged.Lookup("/etc/config")
	linked, _ := staged.Lookup("/etc/alias")
	if declared.Mode != 0o640 || linked.Mode != 0o600 {
		t.Fatalf("declaring one hard-link name changed another: %+v %+v", declared, linked)
	}
}
