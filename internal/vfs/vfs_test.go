package vfs

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
)

func attrs(mode fs.FileMode) Attrs {
	return Attrs{Mode: mode, Origin: Origin{Package: "pkg", Slice: "pkg_slice", Path: "slices/pkg.yaml"}}
}

func TestTree_EntriesAreSortedAndParentsImplicit(t *testing.T) {
	tree := New()
	if err := tree.File("/usr/bin/tool", []byte("x"), attrs(0o755)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Dir("/etc", attrs(0o750)); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	want := []string{"/etc", "/usr", "/usr/bin", "/usr/bin/tool"}
	entries := tree.Entries()
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for i, entry := range entries {
		if entry.Path != want[i] {
			t.Fatalf("entry %d is %q, want %q", i, entry.Path, want[i])
		}
	}
	if !entries[1].Implicit || entries[1].Mode != ImplicitDirMode {
		t.Fatalf("implicit parent = %+v", entries[1])
	}
	if entries[0].Implicit || entries[0].Mode != 0o750 {
		t.Fatalf("explicit directory = %+v", entries[0])
	}
}

func TestTree_ExplicitDirReplacesImplicitParent(t *testing.T) {
	tree := New()
	if err := tree.File("/a/b", nil, attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Dir("/a", Attrs{Mode: 0o700, UID: 5, GID: 6, Origin: Origin{Package: "other"}}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	entry, ok := tree.Lookup("/a")
	if !ok {
		t.Fatal("missing /a")
	}
	if entry.Implicit || entry.Mode != 0o700 || entry.UID != 5 || entry.GID != 6 {
		t.Fatalf("entry = %+v", entry)
	}
}

func TestTree_Conflicts(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Tree) error
		apply   func(*Tree) error
		want    string
	}{
		{
			name:    "different kind",
			prepare: func(t *Tree) error { return t.Dir("/a", attrs(0o755)) },
			apply:   func(t *Tree) error { return t.File("/a", nil, attrs(0o644)) },
			want:    "conflicts with existing directory",
		},
		{
			name:    "different mode",
			prepare: func(t *Tree) error { return t.File("/a", nil, attrs(0o644)) },
			apply:   func(t *Tree) error { return t.File("/a", nil, attrs(0o600)) },
			want:    "conflicts with existing file",
		},
		{
			name:    "different content",
			prepare: func(t *Tree) error { return t.File("/a", []byte("one"), attrs(0o644)) },
			apply:   func(t *Tree) error { return t.File("/a", []byte("two"), attrs(0o644)) },
			want:    "conflicts with existing file",
		},
		{
			name:    "different symlink target",
			prepare: func(t *Tree) error { return t.Symlink("/a", "one", attrs(0o777)) },
			apply:   func(t *Tree) error { return t.Symlink("/a", "two", attrs(0o777)) },
			want:    "conflicts with existing symlink",
		},
		{
			name:    "non-directory ancestor",
			prepare: func(t *Tree) error { return t.File("/a", nil, attrs(0o644)) },
			apply:   func(t *Tree) error { return t.File("/a/b", nil, attrs(0o644)) },
			want:    "non-directory ancestor",
		},
		{
			name:    "symlink ancestor",
			prepare: func(t *Tree) error { return t.Symlink("/a", "/b", attrs(0o777)) },
			apply:   func(t *Tree) error { return t.Dir("/a/b", attrs(0o755)) },
			want:    "has a symlink ancestor",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := New()
			if err := test.prepare(tree); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			err := test.apply(tree)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTree_IdenticalEntriesShareOrigins(t *testing.T) {
	tree := New()
	first := Attrs{Mode: 0o644, Origin: Origin{Package: "one"}}
	second := Attrs{Mode: 0o644, Origin: Origin{Package: "two"}}
	if err := tree.File("/a", []byte("x"), first); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.File("/a", []byte("x"), second); err != nil {
		t.Fatalf("File again: %v", err)
	}
	if err := tree.File("/a", []byte("x"), second); err != nil {
		t.Fatalf("File third time: %v", err)
	}
	entry, ok := tree.Lookup("/a")
	if !ok {
		t.Fatal("missing /a")
	}
	if len(entry.Origins) != 2 || entry.Origins[0].Package != "one" || entry.Origins[1].Package != "two" {
		t.Fatalf("origins = %+v", entry.Origins)
	}
}

func TestTree_HardlinkSharesInode(t *testing.T) {
	tree := New()
	if err := tree.File("/a", []byte("x"), attrs(0o640)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Hardlink("/dir/b", "/a", Origin{Package: "link"}); err != nil {
		t.Fatalf("Hardlink: %v", err)
	}
	first, _ := tree.Lookup("/a")
	second, ok := tree.Lookup("/dir/b")
	if !ok {
		t.Fatal("missing /dir/b")
	}
	if first.Mode != second.Mode || first.Size != second.Size || second.Kind != File {
		t.Fatalf("linked entries differ: %+v %+v", first, second)
	}
	if len(second.Origins) != 1 || second.Origins[0].Package != "link" {
		t.Fatalf("origins = %+v", second.Origins)
	}
	if err := tree.Hardlink("/a", "/dir/b", Origin{Package: "again"}); err != nil {
		t.Fatalf("Hardlink back: %v", err)
	}
	first, _ = tree.Lookup("/a")
	if len(first.Origins) != 2 {
		t.Fatalf("origins = %+v", first.Origins)
	}
}

func TestTree_HardlinkRejects(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Tree) error
		link    string
		target  string
		want    string
	}{
		{
			name:    "missing target",
			prepare: func(*Tree) error { return nil },
			link:    "/b",
			target:  "/a",
			want:    "does not exist",
		},
		{
			name:    "directory target",
			prepare: func(t *Tree) error { return t.Dir("/a", attrs(0o755)) },
			link:    "/b",
			target:  "/a",
			want:    "is a directory",
		},
		{
			name:    "symlink target",
			prepare: func(t *Tree) error { return t.Symlink("/a", "/c", attrs(0o777)) },
			link:    "/b",
			target:  "/a",
			want:    "is a symlink",
		},
		{
			name: "occupied by a file with different content",
			prepare: func(t *Tree) error {
				if err := t.File("/a", []byte("theirs"), attrs(0o644)); err != nil {
					return err
				}
				return t.File("/b", []byte("ours"), attrs(0o644))
			},
			link:   "/b",
			target: "/a",
			want:   "conflicts with existing file",
		},
		{
			name: "occupied by a file with a different mode",
			prepare: func(t *Tree) error {
				if err := t.File("/a", []byte("same"), attrs(0o644)); err != nil {
					return err
				}
				return t.File("/b", []byte("same"), attrs(0o600))
			},
			link:   "/b",
			target: "/a",
			want:   "conflicts with existing file",
		},
		{
			name: "occupied by directory",
			prepare: func(t *Tree) error {
				if err := t.File("/a", nil, attrs(0o644)); err != nil {
					return err
				}
				return t.Dir("/b", attrs(0o755))
			},
			link:   "/b",
			target: "/a",
			want:   "conflicts with existing directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := New()
			if err := test.prepare(tree); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			err := tree.Hardlink(test.link, test.target, Origin{Package: "link"})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTree_RejectsInvalidPaths(t *testing.T) {
	invalid := []string{"", "relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\\b", "/a\x00b", "/a\nb"}
	for _, p := range invalid {
		t.Run(p, func(t *testing.T) {
			if err := New().File(p, nil, attrs(0o644)); err == nil {
				t.Fatalf("path %q accepted", p)
			}
		})
	}
	if err := New().File("/", nil, attrs(0o644)); err == nil {
		t.Fatal("root file accepted")
	}
	if err := New().Dir("/", attrs(0o755)); err == nil {
		t.Fatal("root directory declaration accepted")
	}
}

func TestTree_RejectsNonPermissionModeBits(t *testing.T) {
	if err := New().File("/a", nil, attrs(fs.ModeDir|0o755)); err == nil {
		t.Fatal("type bit accepted in mode")
	}
	if err := New().File("/a", nil, attrs(fs.ModeSetuid|0o755)); err != nil {
		t.Fatalf("setuid rejected: %v", err)
	}
}

func TestTree_SymlinkModesAndTargets(t *testing.T) {
	tree := New()
	if err := tree.Symlink("/a", "b", Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	entry, _ := tree.Lookup("/a")
	if entry.Mode != SymlinkMode {
		t.Fatalf("mode = %v, want %v", entry.Mode, SymlinkMode)
	}
	if err := tree.Symlink("/c", "", attrs(0o777)); err == nil {
		t.Fatal("empty target accepted")
	}
	if err := tree.Symlink("/d", "a\x00b", attrs(0o777)); err == nil {
		t.Fatal("NUL target accepted")
	}
}

func TestTree_Remove(t *testing.T) {
	tree := New()
	if err := tree.File("/a/file", []byte("x"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Remove("/a/file"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := tree.Lookup("/a/file"); ok {
		t.Fatal("path survived removal")
	}
	if _, ok := tree.Lookup("/a"); !ok {
		t.Fatal("implicit parent was removed")
	}
}

func TestTree_RemoveRejectsImplicitAndMissingPaths(t *testing.T) {
	tree := New()
	if err := tree.File("/a/file", []byte("x"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	cases := map[string]string{
		"/":        "implicit",
		"/a":       "implicit",
		"/missing": "does not exist",
	}
	for name, want := range cases {
		err := tree.Remove(name)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Remove(%q) = %v, want %q", name, err, want)
		}
	}
}

func TestTree_RemoveKeepsHardlinkedContent(t *testing.T) {
	tree := New()
	if err := tree.File("/a/file", []byte("x"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Hardlink("/a/other", "/a/file", Origin{Package: "pkg"}); err != nil {
		t.Fatalf("Hardlink: %v", err)
	}
	if err := tree.Remove("/a/file"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	data, err := tree.Read("/a/other")
	if err != nil || string(data) != "x" {
		t.Fatalf("hardline content lost: %q, %v", data, err)
	}
}

func TestTree_Children(t *testing.T) {
	tree := New()
	for _, p := range []string{"/b", "/a", "/dir/x"} {
		if err := tree.File(p, nil, attrs(0o644)); err != nil {
			t.Fatalf("File %s: %v", p, err)
		}
	}
	names, err := tree.Children("/")
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	want := []string{"/a", "/b", "/dir/"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if _, err := tree.Children("/a"); err == nil {
		t.Fatal("non-directory accepted")
	}
	if _, err := tree.Children("/missing"); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestTree_Read(t *testing.T) {
	tree := New()
	if err := tree.File("/a", []byte("content"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	data, err := tree.Read("/a")
	if err != nil || string(data) != "content" {
		t.Fatalf("Read = %q, %v", data, err)
	}
	data[0] = 'X'
	again, _ := tree.Read("/a")
	if string(again) != "content" {
		t.Fatal("Read returned mutable storage")
	}
	if _, err := tree.Read("/missing"); err == nil {
		t.Fatal("missing path read")
	}
	if _, err := tree.Read("/"); err == nil {
		t.Fatal("directory read")
	}
}

func TestTree_OpenFileKeepsOriginalBytesAfterReplacement(t *testing.T) {
	tree := New()
	if err := tree.File("/file", []byte("old"), attrs(0o644)); err != nil {
		t.Fatal(err)
	}
	body, err := tree.OpenFile("/file")
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.ReplaceFile("/file", []byte("new")); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body)
	if err != nil || body.Size() != 3 || string(data) != "old" {
		t.Fatalf("original reader = %q, size %d, error %v", data, body.Size(), err)
	}
	if _, err := tree.OpenFile("/missing"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := tree.OpenFile("/"); err == nil {
		t.Fatal("opened directory")
	}
}

func TestTree_FileCopiesData(t *testing.T) {
	data := []byte("abc")
	tree := New()
	if err := tree.File("/a", data, attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	data[0] = 'X'
	got, _ := tree.Read("/a")
	if string(got) != "abc" {
		t.Fatalf("stored %q", got)
	}
}

func TestTree_OrderingPermutations(t *testing.T) {
	paths := []string{"/z", "/a/b", "/y", "/m/n/o"}
	insertions := [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {2, 0, 3, 1}, {1, 3, 0, 2}}
	var want []Entry
	for _, order := range insertions {
		tree := New()
		for _, index := range order {
			if err := tree.File(paths[index], nil, attrs(0o644)); err != nil {
				t.Fatalf("File %s: %v", paths[index], err)
			}
		}
		entries := tree.Entries()
		if want == nil {
			want = entries
			continue
		}
		if len(entries) != len(want) {
			t.Fatalf("entry count %d, want %d", len(entries), len(want))
		}
		for i, entry := range entries {
			if entry.Path != want[i].Path || entry.Kind != want[i].Kind || entry.Mode != want[i].Mode {
				t.Fatalf("order %v: entry %d = %+v, want %+v", order, i, entry, want[i])
			}
		}
	}
}

func TestTree_InodesAreStableAndShared(t *testing.T) {
	tree := New()
	if err := tree.File("/usr/bin/tool", []byte("x"), attrs(0o755)); err != nil {
		t.Fatal(err)
	}
	if err := tree.Hardlink("/usr/bin/tool-alias", "/usr/bin/tool", Origin{Package: "pkg"}); err != nil {
		t.Fatal(err)
	}
	if err := tree.File("/usr/bin/other", []byte("y"), attrs(0o755)); err != nil {
		t.Fatal(err)
	}
	first := tree.Inodes()
	if first["/usr/bin/tool"] != first["/usr/bin/tool-alias"] {
		t.Fatalf("hard link identity lost: %v", first)
	}
	if first["/usr/bin/tool"] == first["/usr/bin/other"] {
		t.Fatalf("distinct inodes share an identifier: %v", first)
	}
	if first["/usr/bin/other"] >= first["/usr/bin/tool"] {
		t.Fatalf("identifiers are not assigned in sorted order: %v", first)
	}
	second := tree.Inodes()
	for path, id := range first {
		if second[path] != id {
			t.Fatalf("identifier for %q changed: %d -> %d", path, id, second[path])
		}
	}
}

func TestReplaceFileSwapsContentWithoutSharing(t *testing.T) {
	tree := New()
	if err := tree.File("/etc/app.conf", []byte("original"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	staged := tree.Clone()
	if err := staged.ReplaceFile("/etc/app.conf", []byte("changed")); err != nil {
		t.Fatalf("ReplaceFile: %v", err)
	}
	committed, err := tree.Read("/etc/app.conf")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(committed) != "original" {
		t.Fatalf("clone changed the source tree: %q", committed)
	}
	entry, ok := staged.Lookup("/etc/app.conf")
	if !ok || entry.Size != int64(len("changed")) || entry.Mode != 0o644 {
		t.Fatalf("staged entry = %+v", entry)
	}
}

func TestReplaceFileRejectsUnsupportedPaths(t *testing.T) {
	tree := New()
	if err := tree.Dir("/etc", attrs(0o755)); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if err := tree.ReplaceFile("/etc/missing", nil); err == nil {
		t.Fatal("expected an error for a missing path")
	}
	if err := tree.ReplaceFile("/etc", nil); err == nil {
		t.Fatal("expected an error for a directory")
	}
}

func TestReplaceCommitsAStagedTree(t *testing.T) {
	tree := New()
	if err := tree.File("/etc/app.conf", []byte("original"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	staged := tree.Clone()
	if err := staged.File("/etc/new.conf", []byte("new"), attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Replace(staged); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, ok := tree.Lookup("/etc/new.conf"); !ok {
		t.Fatal("staged entry was not committed")
	}
	if err := tree.Replace(nil); err == nil {
		t.Fatal("expected an error for a nil tree")
	}
}

func TestTree_ReportsMissingPathsWithASentinel(t *testing.T) {
	tree := New()
	if err := tree.File("/a", nil, attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Symlink("/link", "/a", Attrs{}); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := tree.Read("/missing"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Read error %v is not ErrNotExist", err)
	}
	if _, err := tree.Read("/link"); errors.Is(err, ErrNotExist) {
		t.Fatalf("Read of a symlink reported ErrNotExist: %v", err)
	}
	if _, err := tree.Children("/missing"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Children error %v is not ErrNotExist", err)
	}
	if err := tree.ReplaceFile("/missing", nil); !errors.Is(err, ErrNotExist) {
		t.Fatalf("ReplaceFile error %v is not ErrNotExist", err)
	}
	if err := tree.Remove("/missing"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Remove error %v is not ErrNotExist", err)
	}
}

// Clearing bits is per inode, so every name of a hard link changes together and
// the names keep sharing one inode.
func TestClearModeBits_ClearsEveryHardLinkNameOnce(t *testing.T) {
	tree := New()
	if err := tree.File("/bin/tool", []byte("x"), attrs(fs.ModeSetuid|fs.ModeSetgid|0o755)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := tree.Hardlink("/usr/bin/tool", "/bin/tool", Origin{Package: "link"}); err != nil {
		t.Fatalf("Hardlink: %v", err)
	}
	if err := tree.File("/bin/plain", nil, attrs(fs.ModeSticky|0o777)); err != nil {
		t.Fatalf("File: %v", err)
	}
	staged := tree.Clone()
	if err := staged.ClearModeBits(fs.ModeSetuid | fs.ModeSetgid); err != nil {
		t.Fatalf("ClearModeBits: %v", err)
	}
	for _, p := range []string{"/bin/tool", "/usr/bin/tool"} {
		if entry, _ := staged.Lookup(p); entry.Mode != 0o755 {
			t.Fatalf("%s mode = %04o", p, entry.Mode)
		}
		if entry, _ := tree.Lookup(p); entry.Mode != fs.ModeSetuid|fs.ModeSetgid|0o755 {
			t.Fatalf("%s changed in the clone source: %v", p, entry.Mode)
		}
	}
	if ids := staged.Inodes(); ids["/bin/tool"] != ids["/usr/bin/tool"] {
		t.Fatalf("hard link names no longer share an inode: %v", ids)
	}
	if entry, _ := staged.Lookup("/bin/plain"); entry.Mode != fs.ModeSticky|0o777 {
		t.Fatalf("unrelated bits were cleared: %v", entry.Mode)
	}
	if err := staged.ClearModeBits(fs.ModeDir); err == nil {
		t.Fatal("type bits were accepted")
	}
}
