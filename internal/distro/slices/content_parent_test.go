package slices_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/vfs"
)

// parentSource is an archive holding one private parent directory and one file.
func parentSource(t *testing.T, pkg string, mode fs.FileMode, uid, gid uint32) *slices.Source {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: pkg}
	if err := tree.Dir("/private", vfs.Attrs{Mode: mode, UID: uid, GID: gid, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	if err := tree.File("/private/token", []byte(pkg+"\n"),
		vfs.Attrs{Mode: 0o640, UID: uid, GID: gid, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	return &slices.Source{Package: pkg, Tree: tree}
}

// Two slices copy into the same undeclared parent from archives that disagree about
// it. The parent must keep the first source's restrictive metadata and the second
// source must not widen it, whichever slice is applied first.
func TestApplyContent_RejectsConflictingSeededParentMetadata(t *testing.T) {
	narrow := slices.Slice{
		Package: "narrow", Name: "narrow_p",
		Contents: map[string]slices.PathInfo{"/private/token": {Kind: slices.PathCopy}},
	}
	wide := slices.Slice{
		Package: "wide", Name: "wide_p",
		Contents: map[string]slices.PathInfo{"/private/other": {Kind: slices.PathCopy, Info: "/private/token"}},
	}
	sources := map[string]*slices.Source{
		"narrow": parentSource(t, "narrow", 0o700, 7, 8),
		"wide":   parentSource(t, "wide", 0o755, 0, 0),
	}
	for name, order := range map[string][]slices.Slice{
		"narrow first": {narrow, wide},
		"wide first":   {wide, narrow},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := slices.ApplyContent(order, sources, "", nil)
			if err == nil || !strings.Contains(err.Error(), "conflicts with seeded") {
				t.Fatalf("error = %v, want the conflicting parent refused", err)
			}
		})
	}
}

// The same metadata from both archives is agreement, so the copies still land and
// the parent stays implicit with both contributors recorded.
func TestApplyContent_AcceptsAgreeingSeededParentMetadata(t *testing.T) {
	first := slices.Slice{
		Package: "one", Name: "one_p",
		Contents: map[string]slices.PathInfo{"/private/token": {Kind: slices.PathCopy}},
	}
	second := slices.Slice{
		Package: "two", Name: "two_p",
		Contents: map[string]slices.PathInfo{"/private/other": {Kind: slices.PathCopy, Info: "/private/token"}},
	}
	sources := map[string]*slices.Source{
		"one": parentSource(t, "one", 0o700, 7, 8),
		"two": parentSource(t, "two", 0o700, 7, 8),
	}
	selected, err := slices.ApplyContent([]slices.Slice{first, second}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	parent, ok := selected.Tree.Lookup("/private")
	if !ok || parent.Mode != 0o700 || parent.UID != 7 || !parent.Implicit {
		t.Fatalf("parent = %+v", parent)
	}
	if len(parent.Origins) != 2 {
		t.Fatalf("origins = %+v", parent.Origins)
	}
}

// A narrower mode from the source is still narrowed: the point of the check is
// that nobody rewrites a parent another source already owns, not that the first
// source always wins with a wider mode.
func TestApplyContent_SeedsFromTheSourceOnlyOnce(t *testing.T) {
	slice := slices.Slice{
		Package: "private", Name: "private_p",
		Contents: map[string]slices.PathInfo{
			"/private/token": {Kind: slices.PathCopy},
			"/private/okay":  {Kind: slices.PathText, Info: "x\n"},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"private": privateSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	parent, _ := selected.Tree.Lookup("/private")
	if parent.Mode != 0o700 || parent.UID != 7 || parent.GID != 8 {
		t.Fatalf("parent = %+v", parent)
	}
}
