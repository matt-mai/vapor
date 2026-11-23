package vfs

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"strings"
	"testing"
)

// tarEntry describes one synthetic archive member.
type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	uid, gid int
	content  string
	linkname string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Mode:     entry.mode,
			Uid:      entry.uid,
			Gid:      entry.gid,
			Size:     int64(len(entry.content)),
			Linkname: entry.linkname,
		}
		if header.Typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header %q: %v", entry.name, err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(entry.content)); err != nil {
				t.Fatalf("write content %q: %v", entry.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func importTar(t *testing.T, entries []tarEntry) (*Tree, error) {
	t.Helper()
	return ImportTar(bytes.NewReader(buildTar(t, entries)), Origin{Package: "demo"}, DefaultLimits())
}

func TestImportTar_EntriesOwnershipAndLinks(t *testing.T) {
	tree, err := importTar(t, []tarEntry{
		{name: "./", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./usr/", typeflag: tar.TypeDir, mode: 0o755, uid: 0, gid: 0},
		{name: "./usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o4755, uid: 12, gid: 34, content: "binary"},
		{name: "./usr/bin/alias", typeflag: tar.TypeLink, linkname: "./usr/bin/tool"},
		{name: "./usr/bin/rel", typeflag: tar.TypeSymlink, linkname: "tool"},
		{name: "./usr/bin/abs", typeflag: tar.TypeSymlink, linkname: "/usr/bin/tool"},
	})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	tool, ok := tree.Lookup("/usr/bin/tool")
	if !ok || tool.Kind != File || tool.Mode != fs.ModeSetuid|0o755 || tool.UID != 12 || tool.GID != 34 {
		t.Fatalf("tool = %+v", tool)
	}
	if tool.Origins[0].Package != "demo" {
		t.Fatalf("origins = %+v", tool.Origins)
	}
	if data, err := tree.Read("/usr/bin/alias"); err != nil || string(data) != "binary" {
		t.Fatalf("hardlink content = %q %v", data, err)
	}
	alias, _ := tree.Lookup("/usr/bin/alias")
	if alias.Mode != tool.Mode || alias.UID != tool.UID {
		t.Fatalf("hardlink metadata = %+v, want %+v", alias, tool)
	}
	if resolved, err := tree.Resolve("/usr/bin/rel"); err != nil || resolved != "/usr/bin/tool" {
		t.Fatalf("relative link = %q %v", resolved, err)
	}
	if resolved, err := tree.Resolve("/usr/bin/abs"); err != nil || resolved != "/usr/bin/tool" {
		t.Fatalf("absolute link = %q %v", resolved, err)
	}
}

func TestImportTar_RejectsUnsafeArchives(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{
			name:    "absolute path",
			entries: []tarEntry{{name: "/etc/passwd", typeflag: tar.TypeReg, mode: 0o644}},
			want:    "not a clean relative path",
		},
		{
			name:    "parent traversal",
			entries: []tarEntry{{name: "../escape", typeflag: tar.TypeReg, mode: 0o644}},
			want:    "not a clean relative path",
		},
		{
			name:    "dot inside path",
			entries: []tarEntry{{name: "./a/../b", typeflag: tar.TypeReg, mode: 0o644}},
			want:    "not a clean relative path",
		},
		{
			name:    "escaping symlink",
			entries: []tarEntry{{name: "./link", typeflag: tar.TypeSymlink, linkname: "../../etc"}},
			want:    "escapes the image root",
		},
		{
			name: "symlink cycle",
			entries: []tarEntry{
				{name: "./a", typeflag: tar.TypeSymlink, linkname: "b"},
				{name: "./b", typeflag: tar.TypeSymlink, linkname: "a"},
			},
			want: "symlink cycle",
		},
		{
			name:    "special file",
			entries: []tarEntry{{name: "./dev/null", typeflag: tar.TypeChar, mode: 0o666}},
			want:    "unsupported type",
		},
		{
			name:    "hardlink to missing target",
			entries: []tarEntry{{name: "./alias", typeflag: tar.TypeLink, linkname: "./missing"}},
			want:    "does not exist",
		},
		{
			name:    "hardlink to directory",
			entries: []tarEntry{{name: "./d/", typeflag: tar.TypeDir, mode: 0o755}, {name: "./alias", typeflag: tar.TypeLink, linkname: "./d"}},
			want:    "is a directory",
		},
		{
			name: "conflicting duplicate",
			entries: []tarEntry{
				{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "one"},
				{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "two"},
			},
			want: "conflicts with existing",
		},
		{
			name: "identical duplicate",
			entries: []tarEntry{
				{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "one"},
				{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "one"},
			},
		},
		{
			name: "file under a symlink",
			entries: []tarEntry{
				{name: "./alias", typeflag: tar.TypeSymlink, linkname: "/etc"},
				{name: "./alias/passwd", typeflag: tar.TypeReg, mode: 0o644},
			},
			want: "symlink ancestor",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree, err := importTar(t, test.entries)
			if test.want == "" {
				if err != nil {
					t.Fatalf("ImportTar: %v", err)
				}
				if len(tree.Entries()) == 0 {
					t.Fatal("tree is empty")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// TestImportTar_BoundsSymlinkTargets covers the path bound applying to a link
// target as well as a member name. A target is stored and resolved like a path, so
// leaving it unbounded lets an archive hold an arbitrarily long one under a bound
// that otherwise rejects a long name.
func TestImportTar_BoundsSymlinkTargets(t *testing.T) {
	build := func(target string) []byte {
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		header := &tar.Header{Name: "./link", Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close tar: %v", err)
		}
		return buffer.Bytes()
	}
	limits := Limits{MaxEntries: 10, MaxFileSize: 100, MaxTotalSize: 100, MaxPathSize: 32,
		MaxStreamSize: 1 << 20}
	if _, err := ImportTar(bytes.NewReader(build("/"+strings.Repeat("a", 20000))), Origin{}, limits); err == nil ||
		!strings.Contains(err.Error(), "link target longer than 32 bytes") {
		t.Fatalf("error = %v, want a target-length refusal", err)
	}
	// A target within the bound is accepted only when the archive also contains it,
	// so the accepted case imports the target alongside the link.
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	target := "/" + strings.Repeat("a", 20)
	for _, header := range []*tar.Header{
		{Name: "./" + strings.Repeat("a", 20), Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "./link", Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777},
	} {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	tree, err := ImportTar(bytes.NewReader(buffer.Bytes()), Origin{}, limits)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if entry, ok := tree.Lookup("/link"); !ok || len(entry.Target) != 21 {
		t.Fatalf("link = %+v", entry)
	}
}

// A link to nothing is a normal filesystem state: Ubuntu packages ship man-page
// links for programs in packages that are not installed. Only confinement is
// enforced, so the import keeps the link.
func TestImportTar_KeepsDanglingSymlinks(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{name: "./link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/missing"},
	})
	tree, err := ImportTar(bytes.NewReader(data), Origin{},
		Limits{MaxEntries: 10, MaxFileSize: 100, MaxTotalSize: 100, MaxPathSize: 100, MaxStreamSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := tree.Lookup("/link")
	if !ok || entry.Kind != Symlink || entry.Target != "/missing" {
		t.Fatalf("link = %+v", entry)
	}
}

func TestImportTar_EnforcesLimits(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{name: "./aa", typeflag: tar.TypeReg, mode: 0o644, content: "0123456789"},
		{name: "./bb", typeflag: tar.TypeReg, mode: 0o644, content: "0123456789"},
	})
	tests := []struct {
		name   string
		limits Limits
		want   string
	}{
		{
			name:   "entry count",
			limits: Limits{MaxEntries: 1, MaxFileSize: 100, MaxTotalSize: 100, MaxPathSize: 100, MaxStreamSize: 1 << 20},
			want:   "exceeds 1 entries",
		},
		{
			name:   "file size",
			limits: Limits{MaxEntries: 10, MaxFileSize: 5, MaxTotalSize: 100, MaxPathSize: 100, MaxStreamSize: 1 << 20},
			want:   "exceeds the import size bound",
		},
		{
			name:   "total size",
			limits: Limits{MaxEntries: 10, MaxFileSize: 100, MaxTotalSize: 15, MaxPathSize: 100, MaxStreamSize: 1 << 20},
			want:   "exceeds the import size bound",
		},
		{
			name:   "path size",
			limits: Limits{MaxEntries: 10, MaxFileSize: 100, MaxTotalSize: 100, MaxPathSize: 1, MaxStreamSize: 1 << 20},
			want:   "not a clean relative path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ImportTar(bytes.NewReader(data), Origin{Package: "demo"}, test.limits)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// TestImportTar_RejectsNegativeIdentities covers the ownership domain. A negative
// uid or gid is outside the 32-bit range and must fail rather than read as zero,
// which would hand an unprivileged member root ownership.
func TestImportTar_RejectsNegativeIdentities(t *testing.T) {
	tests := []struct {
		name string
		uid  int
		gid  int
	}{
		{name: "negative uid", uid: -5, gid: 0},
		{name: "negative gid", uid: 0, gid: -7},
		{name: "both negative", uid: -1, gid: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			header := &tar.Header{Name: "./f", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1,
				Uid: test.uid, Gid: test.gid}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatalf("write header: %v", err)
			}
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatalf("write content: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close tar: %v", err)
			}
			_, err := ImportTar(bytes.NewReader(buffer.Bytes()), Origin{Package: "demo"}, DefaultLimits())
			if err == nil || !strings.Contains(err.Error(), "identity is negative") {
				t.Fatalf("error = %v, want a negative-identity refusal", err)
			}
		})
	}
}

func TestImportTar_RejectsInvalidInput(t *testing.T) {
	if _, err := ImportTar(nil, Origin{}, DefaultLimits()); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := ImportTar(bytes.NewReader(nil), Origin{}, Limits{}); err == nil ||
		!strings.Contains(err.Error(), "must all be positive") {
		t.Fatalf("zero limits error = %v", err)
	}
	if _, err := ImportTar(bytes.NewReader([]byte("not a tar archive")), Origin{}, DefaultLimits()); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestImportTar_TruncatedMemberFails(t *testing.T) {
	data := buildTar(t, []tarEntry{{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "0123456789"}})
	_, err := ImportTar(bytes.NewReader(data[:520]), Origin{Package: "demo"}, DefaultLimits())
	if err == nil {
		t.Fatal("truncated archive accepted")
	}
}

func TestImportTar_IsStandalone(t *testing.T) {
	tree, err := importTar(t, []tarEntry{{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "x"}})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	if err := tree.File("/b", nil, attrs(0o644)); err != nil {
		t.Fatalf("File: %v", err)
	}
	if _, ok := tree.Lookup("/b"); !ok {
		t.Fatal("import tree is not mutable")
	}
}

func TestMerge_AppliesCompatibleEntries(t *testing.T) {
	base := mustTree(t, func(tree *Tree) error {
		return tree.File("/etc/keep", []byte("keep"), attrs(0o600))
	})
	other, err := importTar(t, []tarEntry{
		{name: "./etc/keep", typeflag: tar.TypeReg, mode: 0o600, content: "keep"},
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "bin"},
		{name: "./usr/bin/alias", typeflag: tar.TypeLink, linkname: "./usr/bin/tool"},
		{name: "./usr/lib/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./usr/lib/link", typeflag: tar.TypeSymlink, linkname: "/usr/bin/tool"},
	})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	if err := base.Merge(other); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	keep, _ := base.Lookup("/etc/keep")
	if len(keep.Origins) != 2 {
		t.Fatalf("keep origins = %+v", keep.Origins)
	}
	if data, err := base.Read("/usr/bin/alias"); err != nil || string(data) != "bin" {
		t.Fatalf("hardlink content = %q %v", data, err)
	}
	if resolved, err := base.Resolve("/usr/lib/link"); err != nil || resolved != "/usr/bin/tool" {
		t.Fatalf("symlink = %q %v", resolved, err)
	}
}

func TestMerge_RejectsConflicts(t *testing.T) {
	tests := []struct {
		name  string
		build func(*Tree) error
		want  string
	}{
		{
			name:  "different content",
			build: func(tree *Tree) error { return tree.File("/a", []byte("mine"), attrs(0o644)) },
			want:  "conflicts with existing",
		},
		{
			name:  "different mode",
			build: func(tree *Tree) error { return tree.File("/a", []byte("theirs"), attrs(0o600)) },
			want:  "conflicts with existing",
		},
		{
			name:  "different kind",
			build: func(tree *Tree) error { return tree.Dir("/a", attrs(0o755)) },
			want:  "conflicts with existing",
		},
	}
	other, err := importTar(t, []tarEntry{
		{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "theirs"},
	})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := mustTree(t, test.build)
			err := tree.Merge(other)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMerge_FailureLeavesTreeUnchanged(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		return tree.File("/z", []byte("theirs"), attrs(0o644))
	})
	other, err := importTar(t, []tarEntry{
		{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "new"},
		{name: "./z", typeflag: tar.TypeReg, mode: 0o644, content: "other"},
	})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	if err := tree.Merge(other); err == nil {
		t.Fatal("conflicting merge succeeded")
	}
	if _, ok := tree.Lookup("/a"); ok {
		t.Fatal("merge applied entries before failing")
	}
}

func TestMerge_NilIsNoop(t *testing.T) {
	tree := New()
	if err := tree.Merge(nil); err != nil {
		t.Fatalf("Merge(nil): %v", err)
	}
	if len(tree.Entries()) != 0 {
		t.Fatalf("entries = %+v", tree.Entries())
	}
}

func TestMerge_SeedsOnlySyntheticParents(t *testing.T) {
	parent := "/private"
	seed := Attrs{Mode: 0o700, UID: 7, GID: 8, Origin: Origin{Package: "source"}, Implicit: true}
	source := New()
	if err := source.Dir(parent, seed); err != nil {
		t.Fatal(err)
	}
	if err := source.File(parent+"/token", nil, attrs(0o644)); err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		target := New()
		want := seed
		if explicit {
			want = attrs(0o750)
			if err := target.Dir(parent, want); err != nil {
				t.Fatal(err)
			}
		}
		if err := target.File(parent+"/existing", nil, attrs(0o644)); err != nil {
			t.Fatal(err)
		}
		if err := target.Merge(source); err != nil {
			t.Fatal(err)
		}
		got, ok := target.Lookup(parent)
		if !ok || got.Mode != want.Mode || got.UID != want.UID || got.GID != want.GID || got.Implicit != want.Implicit {
			t.Fatalf("explicit=%t: parent = %+v, want %+v", explicit, got, want)
		}
	}
}

func TestMerge_PreservesHardlinkIdentity(t *testing.T) {
	other, err := importTar(t, []tarEntry{
		{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "same"},
		{name: "./b", typeflag: tar.TypeLink, linkname: "./a"},
	})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	tree := New()
	if err := tree.Merge(other); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if tree.entries["/a"].node != tree.entries["/b"].node {
		t.Fatal("hardlink identity was lost")
	}
}

// TestMerge_ReconcilesCompatibleHardlinkGroups covers the same content arriving in
// either order. A tree that declares two separate files and a tree that declares
// them as one hard-link group describe the same image, so merging must agree
// whichever side is the destination.
func TestMerge_ReconcilesCompatibleHardlinkGroups(t *testing.T) {
	separate := func() *Tree {
		tree := New()
		for _, p := range []string{"/a", "/b"} {
			if err := tree.File(p, []byte("same"), attrs(0o644)); err != nil {
				t.Fatalf("file: %v", err)
			}
		}
		return tree
	}
	linked := func() *Tree {
		tree := New()
		if err := tree.File("/a", []byte("same"), attrs(0o644)); err != nil {
			t.Fatalf("file: %v", err)
		}
		if err := tree.Hardlink("/b", "/a", Origin{Package: "demo"}); err != nil {
			t.Fatalf("hardlink: %v", err)
		}
		return tree
	}
	for _, test := range []struct {
		name   string
		target *Tree
		source *Tree
	}{
		{name: "separate then linked", target: separate(), source: linked()},
		{name: "linked then separate", target: linked(), source: separate()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.target.Merge(test.source); err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if test.target.entries["/a"].node != test.target.entries["/b"].node {
				t.Fatal("hardlink identity was not reconciled")
			}
			if content, err := test.target.Read("/b"); err != nil || string(content) != "same" {
				t.Fatalf("content = %q, %v", content, err)
			}
		})
	}
}

// TestMerge_ReconcilesAWholeHardlinkGroup checks that every name on the replaced
// inode moves with it. Repointing only the merged path would split a group the
// destination already declared.
func TestMerge_ReconcilesAWholeHardlinkGroup(t *testing.T) {
	tree := New()
	if err := tree.File("/a", []byte("same"), attrs(0o644)); err != nil {
		t.Fatalf("file: %v", err)
	}
	for _, p := range []string{"/b", "/c"} {
		if err := tree.Hardlink(p, "/a", Origin{Package: "demo"}); err != nil {
			t.Fatalf("hardlink: %v", err)
		}
	}
	// The source declares /b as its own inode, so reconciling it must carry /a and
	// /c along rather than leaving them on the abandoned node.
	other := New()
	if err := other.File("/b", []byte("same"), attrs(0o644)); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := tree.Merge(other); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	inodes := tree.Inodes()
	for _, p := range []string{"/a", "/b", "/c"} {
		if inodes[p] != inodes["/a"] {
			t.Fatalf("%s has inode %d, want %d", p, inodes[p], inodes["/a"])
		}
	}
}

// TestMerge_KeepsSeparateInodesSeparate checks that reconciling does not merge
// link groups the two trees never related: identical content is not a declaration
// that two paths share an inode.
func TestMerge_KeepsSeparateInodesSeparate(t *testing.T) {
	tree := New()
	for _, p := range []string{"/a", "/d"} {
		if err := tree.File(p, []byte("same"), attrs(0o644)); err != nil {
			t.Fatalf("file: %v", err)
		}
	}
	other := New()
	if err := other.File("/d", []byte("same"), attrs(0o644)); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := other.Hardlink("/e", "/d", Origin{Package: "other"}); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	if err := tree.Merge(other); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	inodes := tree.Inodes()
	if inodes["/d"] != inodes["/e"] {
		t.Fatalf("d=%d e=%d, want one group", inodes["/d"], inodes["/e"])
	}
	if inodes["/a"] == inodes["/d"] {
		t.Fatal("unrelated inodes were merged")
	}
}

// TestMerge_KeepsOriginsWhenReconcilingHardlinks checks that reconciling a group
// does not lose the attribution the merge exists to preserve.
func TestMerge_KeepsOriginsWhenReconcilingHardlinks(t *testing.T) {
	tree := New()
	for _, p := range []string{"/a", "/b"} {
		if err := tree.File(p, []byte("same"), Attrs{Mode: 0o644, Origin: Origin{Package: "first"}}); err != nil {
			t.Fatalf("file: %v", err)
		}
	}
	other := New()
	if err := other.File("/a", []byte("same"), Attrs{Mode: 0o644, Origin: Origin{Package: "second"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := other.Hardlink("/b", "/a", Origin{Package: "second"}); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	if err := tree.Merge(other); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	for _, p := range []string{"/a", "/b"} {
		if len(tree.entries[p].origins) != 2 {
			t.Fatalf("%s origins = %+v", p, tree.entries[p].origins)
		}
	}
}

func TestMerge_DoesNotShareNodesWithSource(t *testing.T) {
	other, err := importTar(t, []tarEntry{{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "x"}})
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	tree := New()
	if err := tree.Merge(other); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if tree.entries["/a"].node == other.entries["/a"].node {
		t.Fatal("merged tree shares a node with the source")
	}
	if mode := tree.entries["/a"].node.mode; mode != fs.FileMode(0o644) {
		t.Fatalf("mode = %v", mode)
	}
}
