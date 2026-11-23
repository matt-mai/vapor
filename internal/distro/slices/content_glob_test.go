package slices_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/vfs"
)

// globSource builds a verified payload tree with the shapes glob patterns have to
// distinguish: several directories, a nested directory and files whose names
// differ only by a suffix or a single character.
func globSource(t *testing.T) *slices.Source {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture"}
	paths := []struct {
		path string
		kind vfs.Kind
	}{
		{"/usr/lib/fixture/liba.so", vfs.File},
		{"/usr/lib/fixture/liba.so.1", vfs.File},
		{"/usr/lib/fixture/libb.so", vfs.File},
		{"/usr/lib/fixture/private/libc.so", vfs.File},
		{"/usr/lib/fixture/private/deep/libd.so", vfs.File},
		{"/usr/lib/fixture/README", vfs.File},
		{"/usr/lib/fixture/empty", vfs.Dir},
	}
	for _, entry := range paths {
		var err error
		if entry.kind == vfs.Dir {
			err = tree.Dir(entry.path, vfs.Attrs{Mode: 0o755, Origin: origin})
		} else {
			err = tree.File(entry.path, []byte(entry.path), vfs.Attrs{Mode: 0o644, Origin: origin})
		}
		if err != nil {
			t.Fatalf("build source: %v", err)
		}
	}
	return &slices.Source{Package: "fixture", Tree: tree}
}

func globSlice(pattern string, info slices.PathInfo) slices.Slice {
	info.Kind = slices.PathGlob
	return slices.Slice{
		Package:  "fixture",
		Name:     "globs",
		Contents: map[string]slices.PathInfo{pattern: info},
	}
}

func selectedPaths(t *testing.T, slice slices.Slice) []string {
	t.Helper()
	selected, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	var paths []string
	for _, entry := range selected.Tree.Entries() {
		if entry.Implicit {
			continue
		}
		paths = append(paths, entry.Path)
	}
	return paths
}

func TestApplyContent_GlobExpansion(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{
			name:    "star stays inside one component",
			pattern: "/usr/lib/fixture/*.so",
			want:    []string{"/usr/lib/fixture/liba.so", "/usr/lib/fixture/libb.so"},
		},
		{
			name:    "star matches empty remainder",
			pattern: "/usr/lib/fixture/liba.so*",
			want:    []string{"/usr/lib/fixture/liba.so", "/usr/lib/fixture/liba.so.1"},
		},
		{
			name:    "double star crosses slashes",
			pattern: "/usr/lib/fixture/**.so",
			want: []string{"/usr/lib/fixture/liba.so", "/usr/lib/fixture/libb.so",
				"/usr/lib/fixture/private/deep/libd.so", "/usr/lib/fixture/private/libc.so"},
		},
		{
			name:    "question mark is one character",
			pattern: "/usr/lib/fixture/lib?.so",
			want:    []string{"/usr/lib/fixture/liba.so", "/usr/lib/fixture/libb.so"},
		},
		{
			name:    "directory matches through its trailing slash",
			pattern: "/usr/lib/fixture/empty/",
			want:    []string{"/usr/lib/fixture/empty"},
		},
		{
			name:    "star matches zero characters",
			pattern: "/usr/lib/fixture/*",
			want: []string{"/usr/lib/fixture", "/usr/lib/fixture/README", "/usr/lib/fixture/liba.so",
				"/usr/lib/fixture/liba.so.1", "/usr/lib/fixture/libb.so"},
		},
		{
			name:    "double star alone selects the subtree",
			pattern: "/usr/lib/fixture/**",
			want: []string{"/usr/lib/fixture", "/usr/lib/fixture/README", "/usr/lib/fixture/empty",
				"/usr/lib/fixture/liba.so", "/usr/lib/fixture/liba.so.1", "/usr/lib/fixture/libb.so",
				"/usr/lib/fixture/private", "/usr/lib/fixture/private/deep",
				"/usr/lib/fixture/private/deep/libd.so", "/usr/lib/fixture/private/libc.so"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := selectedPaths(t, globSlice(test.pattern, slices.PathInfo{}))
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("paths = %v, want %v", got, test.want)
			}
		})
	}
}

func TestApplyContent_GlobIsNotShellGlob(t *testing.T) {
	// Bracket classes are not part of the upstream pattern language, so they are
	// literal characters rather than a character class, and a pattern that only
	// matches through a character class matches nothing.
	for _, pattern := range []string{"/usr/lib/fixture/lib[a].so", "/usr/lib/fixture/?"} {
		slice := globSlice(pattern, slices.PathInfo{})
		if _, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil); err == nil {
			t.Fatalf("pattern %q matched content", pattern)
		}
	}
}

func TestApplyContent_GlobUnmatchedPatternFails(t *testing.T) {
	slice := globSlice("/usr/lib/fixture/*.dll", slices.PathInfo{})
	_, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "matches no content") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_GlobCopiesModesAndOwnership(t *testing.T) {
	slice := globSlice("/usr/lib/fixture/*.so", slices.PathInfo{})
	selected, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	entry, ok := selected.Tree.Lookup("/usr/lib/fixture/liba.so")
	if !ok || entry.Mode != 0o644 || entry.Origins[0].Path != "/usr/lib/fixture/liba.so" {
		t.Fatalf("entry = %+v", entry)
	}
}

func TestApplyContent_GlobAppliesUntilToEveryMatch(t *testing.T) {
	slice := globSlice("/usr/lib/fixture/*.so", slices.PathInfo{Until: slices.UntilMutate})
	selected, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	want := "/usr/lib/fixture/liba.so,/usr/lib/fixture/libb.so"
	if strings.Join(selected.Temporary, ",") != want {
		t.Fatalf("temporary = %v", selected.Temporary)
	}
}

func TestApplyContent_GlobRespectsArchitecture(t *testing.T) {
	slice := globSlice("/usr/lib/fixture/*.so", slices.PathInfo{Arch: []string{"amd64"}})
	arm, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "arm64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if len(arm.Tree.Entries()) != 0 {
		t.Fatalf("filtered glob selected %v", arm.Tree.Entries())
	}
	amd, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "amd64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if len(selectedPaths(t, slice)) != 2 {
		t.Fatalf("selected %v", amd.Tree.Entries())
	}
}

func TestApplyContent_GlobExpansionIsDeterministic(t *testing.T) {
	slice := globSlice("/usr/lib/fixture/**", slices.PathInfo{})
	first := selectedPaths(t, slice)
	second := selectedPaths(t, slice)
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("expansion differs: %v / %v", first, second)
	}
}

func TestApplyContent_GlobAndExactDeclarationConflict(t *testing.T) {
	// A glob and an exact declaration that resolve to the same path must not be
	// silently merged: the tree's collision rules decide, and identical content
	// is shared rather than duplicated.
	slice := slices.Slice{
		Package: "fixture",
		Name:    "overlap",
		Contents: map[string]slices.PathInfo{
			"/usr/lib/fixture/*.so": {Kind: slices.PathGlob},
			"/usr/lib/fixture/liba.so": {Kind: slices.PathCopy,
				Info: "/usr/lib/fixture/liba.so"},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	entry, ok := selected.Tree.Lookup("/usr/lib/fixture/liba.so")
	if !ok {
		t.Fatal("overlapping declaration dropped the path")
	}
	// Both declarations name the same slice and source path, so the entry keeps
	// one origin rather than duplicating it.
	if len(entry.Origins) != 1 || entry.Origins[0].Path != "/usr/lib/fixture/liba.so" {
		t.Fatalf("origins = %+v", entry.Origins)
	}
}

func TestApplyContent_GlobAndExactDeclarationConflictOnMode(t *testing.T) {
	// Overlap is decided by declaration content, not by the resulting bytes: the
	// glob forwards the archive mode and the exact declaration overrides it, so
	// the two declarations disagree about the same path.
	slice := slices.Slice{
		Package: "fixture",
		Name:    "overlap",
		Contents: map[string]slices.PathInfo{
			"/usr/lib/fixture/*.so":    {Kind: slices.PathGlob},
			"/usr/lib/fixture/liba.so": {Kind: slices.PathCopy, Mode: 0o600},
		},
	}
	_, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": globSource(t)}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "conflicts with existing") {
		t.Fatalf("error = %v", err)
	}
}
