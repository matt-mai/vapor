package slices_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/vfs"
)

func TestApplyContent_SeedsAnUnselectedParentFromTheSource(t *testing.T) {
	// Selecting only the file must not widen the 0700 parent to the implicit 0755,
	// which would make the copied file readable to every user in the image.
	slice := slices.Slice{
		Package:  "private",
		Name:     "private_runtime",
		Contents: map[string]slices.PathInfo{"/private/token": {Kind: slices.PathCopy}},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"private": privateSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	parent, ok := selected.Tree.Lookup("/private")
	if !ok || parent.Kind != vfs.Dir || parent.Mode != 0o700 || parent.UID != 7 || parent.GID != 8 {
		t.Fatalf("parent = %+v", parent)
	}
	if !parent.Implicit {
		t.Fatal("a seeded parent must stay implicit: the image did not declare it")
	}
}

func TestApplyContent_GlobSeedsAnUnselectedParentFromTheSource(t *testing.T) {
	slice := slices.Slice{
		Package:  "private",
		Name:     "private_runtime",
		Contents: map[string]slices.PathInfo{"/private/*": {Kind: slices.PathGlob}},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"private": privateSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if parent, ok := selected.Tree.Lookup("/private"); !ok || parent.Mode != 0o700 {
		t.Fatalf("parent = %+v", parent)
	}
}

func TestApplyContent_DeclaredParentWinsOverTheSource(t *testing.T) {
	// An explicit declaration of the parent is the image's own statement about it,
	// so seeding never overrides one, and the declaration is not implicit.
	slice := slices.Slice{
		Package: "private",
		Name:    "private_runtime",
		Contents: map[string]slices.PathInfo{
			"/private":       {Kind: slices.PathDir, Mode: 0o750},
			"/private/token": {Kind: slices.PathCopy},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"private": privateSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	parent, ok := selected.Tree.Lookup("/private")
	if !ok || parent.Mode != 0o750 {
		t.Fatalf("parent = %+v", parent)
	}
	if parent.Implicit {
		t.Fatal("a declared parent must not be implicit")
	}
}

func TestApplyContent_SeedsAParentAnEarlierDeclarationCreatedImplicitly(t *testing.T) {
	// A synthetic file creates /private as an implicit 0755 parent first. That
	// parent is not a declaration, so the later copy still seeds it from the
	// archive's 0700 directory instead of leaving the wider mode in place.
	slice := slices.Slice{
		Package: "private",
		Name:    "private_runtime",
		Contents: map[string]slices.PathInfo{
			"/private/aaa":   {Kind: slices.PathText, Info: "public\n"},
			"/private/token": {Kind: slices.PathCopy},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"private": privateSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	parent, ok := selected.Tree.Lookup("/private")
	if !ok || parent.Mode != 0o700 || parent.UID != 7 || parent.GID != 8 {
		t.Fatalf("parent = %+v", parent)
	}
	if !parent.Implicit {
		t.Fatal("a seeded parent must stay implicit: the image did not declare it")
	}
}

func TestApplyContent_SeedsEveryUnselectedAncestor(t *testing.T) {
	// Each ancestor is seeded from its own source directory, not from the file's
	// parent, so a chain of narrowing modes survives the selection.
	tree := vfs.New()
	origin := vfs.Origin{Package: "chain"}
	for _, dir := range []struct {
		path string
		mode fs.FileMode
	}{{"/a", 0o755}, {"/a/b", 0o750}, {"/a/b/c", 0o700}} {
		if err := tree.Dir(dir.path, vfs.Attrs{Mode: dir.mode, Origin: origin}); err != nil {
			t.Fatalf("build source: %v", err)
		}
	}
	if err := tree.File("/a/b/c/file", []byte("x"), vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	slice := slices.Slice{
		Package:  "chain",
		Name:     "chain_runtime",
		Contents: map[string]slices.PathInfo{"/a/b/c/file": {Kind: slices.PathCopy}},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"chain": {Package: "chain", Tree: tree}}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	for path, want := range map[string]fs.FileMode{"/a": 0o755, "/a/b": 0o750, "/a/b/c": 0o700} {
		if entry, ok := selected.Tree.Lookup(path); !ok || entry.Mode != want {
			t.Fatalf("%s = %+v, want mode %v", path, entry, want)
		}
	}
}

func TestApplyContent_ExplicitModeOverridesCopy(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "modes",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/copied": {Kind: slices.PathCopy, Info: "/usr/share/fixture/source", Mode: 0o600},
		},
	}
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	copied, _ := selected.Tree.Lookup("/usr/share/fixture/copied")
	if copied.Mode != 0o600 {
		t.Fatalf("mode = %v", copied.Mode)
	}
	if copied.UID != 5 || copied.GID != 6 {
		t.Fatalf("ownership = %d/%d", copied.UID, copied.GID)
	}
}

func TestApplyContent_CopiesSymlinkWithoutFollowingIt(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "links",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/copied-link": {Kind: slices.PathCopy, Info: "/usr/share/fixture/alias"},
		},
	}
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	link, ok := selected.Tree.Lookup("/usr/share/fixture/copied-link")
	if !ok || link.Kind != vfs.Symlink || link.Target != "source" {
		t.Fatalf("link = %+v", link)
	}
}

// A directory source is normally spelled with a trailing slash, but the tree
// stores clean paths. The slash must not become part of the lookup key.
func TestApplyContent_CopyRenameAcceptsATrailingSlash(t *testing.T) {
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture"}
	if err := tree.Dir("/old", vfs.Attrs{Mode: 0o750, UID: 3, GID: 4, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	if err := tree.File("/old/data", []byte("x"), vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	sources := map[string]*slices.Source{"fixture": {Package: "fixture", Tree: tree}}
	for _, source := range []string{"/old/", "/old"} {
		slice := slices.Slice{Package: "fixture", Name: "rename", Contents: map[string]slices.PathInfo{
			"/new/": {Kind: slices.PathCopy, Info: source},
		}}
		selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
		if err != nil {
			t.Fatalf("copy %q: %v", source, err)
		}
		dir, ok := selected.Tree.Lookup("/new")
		if !ok || dir.Kind != vfs.Dir || dir.Mode != 0o750 || dir.UID != 3 {
			t.Fatalf("copy %q produced %+v, ok = %v", source, dir, ok)
		}
	}
}

// A trailing slash declares that the source is a directory, so it must be checked
// against the entry rather than silently ignored.
func TestApplyContent_CopyRenameRejectsASlashOnAFile(t *testing.T) {
	slice := slices.Slice{Package: "fixture", Name: "rename", Contents: map[string]slices.PathInfo{
		"/new/": {Kind: slices.PathCopy, Info: "/usr/share/fixture/source/"},
	}}
	_, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": sourceTree(t)}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_PreservesSourceHardLinks(t *testing.T) {
	// Two selected paths copied from one source inode stay one inode: the source
	// declared them as hard links, and mutation refuses to write a path that shares
	// an inode with another. Recreating them as independent files would lose that
	// relationship and let a script write one name without touching the other.
	slice := slices.Slice{
		Package: "fixture",
		Name:    "twice",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/one": {Kind: slices.PathCopy, Info: "/usr/share/fixture/source"},
			"/usr/share/fixture/two": {Kind: slices.PathCopy, Info: "/usr/share/fixture/hard"},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": sourceTree(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	inodes := selected.Tree.Inodes()
	if inodes["/usr/share/fixture/one"] != inodes["/usr/share/fixture/two"] {
		t.Fatalf("copies of one source inode were separated: %v", inodes)
	}
}

// A hard link shares one mode and one owner, so a second declaration that
// disagrees about either cannot be satisfied by linking.
func TestApplyContent_RejectsConflictingHardLinkCopies(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "twice",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/one": {Kind: slices.PathCopy, Info: "/usr/share/fixture/source"},
			"/usr/share/fixture/two": {Kind: slices.PathCopy, Info: "/usr/share/fixture/hard", Mode: 0o600},
		},
	}
	_, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": sourceTree(t)}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "conflicts with existing copy") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_ExplicitParentOverridesImplicit(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "parents",
		Contents: map[string]slices.PathInfo{
			"/var/lib/fixture/":        {Kind: slices.PathDir, Mode: 0o700},
			"/var/lib/fixture/state/":  {Kind: slices.PathDir},
			"/var/lib/fixture/state/x": {Kind: slices.PathText, Info: "x\n"},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	parent, _ := selected.Tree.Lookup("/var/lib/fixture")
	if parent.Mode != 0o700 || parent.Implicit {
		t.Fatalf("explicit parent = %+v", parent)
	}
	implicit, _ := selected.Tree.Lookup("/var/lib")
	if !implicit.Implicit || implicit.Mode != slices.DefaultSynthesizedDirMode {
		t.Fatalf("implicit parent = %+v", implicit)
	}
	state, _ := selected.Tree.Lookup("/var/lib/fixture/state")
	if state.Implicit || state.Mode != slices.DefaultSynthesizedDirMode {
		t.Fatalf("state = %+v", state)
	}
}
