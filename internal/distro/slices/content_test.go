package slices_test

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/vfs"
)

// sourceTree builds a verified-payload tree with a directory, a regular file, an
// executable, a symlink and a hard link.
func sourceTree(t *testing.T) *slices.Source {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture"}
	build := []struct {
		apply func() error
	}{
		{func() error {
			return tree.Dir("/usr/share/fixture", vfs.Attrs{Mode: 0o750, UID: 3, GID: 4, Origin: origin})
		}},
		{func() error {
			return tree.File("/usr/share/fixture/source", []byte("payload\n"),
				vfs.Attrs{Mode: 0o640, UID: 5, GID: 6, Origin: origin})
		}},
		{func() error {
			return tree.File("/usr/share/fixture/tool", []byte("#!/bin/sh\n"),
				vfs.Attrs{Mode: fs.ModeSetuid | 0o755, UID: 0, GID: 0, Origin: origin})
		}},
		{func() error {
			return tree.File("/usr/share/fixture/input", []byte("input\n"),
				vfs.Attrs{Mode: 0o644, Origin: origin})
		}},
		{func() error { return tree.Symlink("/usr/share/fixture/alias", "source", vfs.Attrs{Origin: origin}) }},
		{func() error { return tree.Hardlink("/usr/share/fixture/hard", "/usr/share/fixture/source", origin) }},
	}
	for _, step := range build {
		if err := step.apply(); err != nil {
			t.Fatalf("build source: %v", err)
		}
	}
	return &slices.Source{Package: "fixture", Tree: tree}
}

func fixtureSlice(t *testing.T, pkg, name string) slices.Slice {
	t.Helper()
	packages := fixturePackages(t)
	decoded, ok := packages[pkg]
	if !ok {
		t.Fatalf("package %q not found", pkg)
	}
	slice, ok := decoded.Slices[name]
	if !ok {
		t.Fatalf("slice %s_%s not found", pkg, name)
	}
	return slice
}

// exactSlice mirrors the fixture runtime slice without its glob and preference
// declarations, which belong to later selection stages.
func exactSlice() slices.Slice {
	return slices.Slice{
		Package: "fixture",
		Name:    "runtime",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/input":  {Kind: slices.PathCopy, Until: slices.UntilMutate},
			"/usr/share/fixture/output": {Kind: slices.PathText, Info: "before\n", Mutable: true, Mode: 0o644},
			"/usr/share/fixture/copied": {Kind: slices.PathCopy, Info: "/usr/share/fixture/source"},
			"/usr/share/fixture/link":   {Kind: slices.PathSymlink, Info: "output"},
			"/usr/share/fixture/empty/": {Kind: slices.PathDir, Mode: 0o750},
		},
	}
}

func TestApplyContent_CopiesFiles(t *testing.T) {
	slice := exactSlice()
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	copied, ok := selected.Tree.Lookup("/usr/share/fixture/copied")
	if !ok || copied.Kind != vfs.File || copied.Mode != 0o640 || copied.UID != 5 || copied.GID != 6 {
		t.Fatalf("copied = %+v", copied)
	}
	if content, err := selected.Tree.Read("/usr/share/fixture/copied"); err != nil || string(content) != "payload\n" {
		t.Fatalf("content = %q %v", content, err)
	}
	if copied.Origins[0].Path != "/usr/share/fixture/source" {
		t.Fatalf("origins = %+v", copied.Origins)
	}
}

func TestApplyContent_SynthesizesContent(t *testing.T) {
	slice := exactSlice()
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	output, ok := selected.Tree.Lookup("/usr/share/fixture/output")
	if !ok || output.Mode != 0o644 || output.Size != int64(len("before\n")) {
		t.Fatalf("output = %+v", output)
	}
	link, ok := selected.Tree.Lookup("/usr/share/fixture/link")
	if !ok || link.Kind != vfs.Symlink || link.Target != "output" || link.Mode != vfs.SymlinkMode {
		t.Fatalf("link = %+v", link)
	}
	if resolved, err := selected.Tree.Resolve("/usr/share/fixture/link"); err != nil ||
		resolved != "/usr/share/fixture/output" {
		t.Fatalf("resolved = %q %v", resolved, err)
	}
}

func TestApplyContent_TracksTemporaryAndMutable(t *testing.T) {
	slice := exactSlice()
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if strings.Join(selected.Temporary, ",") != "/usr/share/fixture/input" {
		t.Fatalf("temporary = %v", selected.Temporary)
	}
	if strings.Join(selected.Mutable, ",") != "/usr/share/fixture/output" {
		t.Fatalf("mutable = %v", selected.Mutable)
	}
}

func TestApplyContent_SharedTemporaryPathSurvivesWhenRetained(t *testing.T) {
	// One slice keeps the path permanently, so removal must not delete it even
	// though another slice asked for `until: mutate`.
	retained := slices.Slice{
		Package: "fixture",
		Name:    "kept",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/input": {Kind: slices.PathCopy},
		},
	}
	temporary := slices.Slice{
		Package: "fixture",
		Name:    "scratch",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/input": {Kind: slices.PathCopy, Until: slices.UntilMutate},
		},
	}
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	for name, order := range map[string][]slices.Slice{
		"retained first":  {retained, temporary},
		"temporary first": {temporary, retained},
	} {
		t.Run(name, func(t *testing.T) {
			selected, err := slices.ApplyContent(order, sources, "", nil)
			if err != nil {
				t.Fatalf("ApplyContent: %v", err)
			}
			if len(selected.Temporary) != 0 {
				t.Fatalf("temporary = %v", selected.Temporary)
			}
			if _, err := selected.Tree.Read("/usr/share/fixture/input"); err != nil {
				t.Fatalf("shared path missing: %v", err)
			}
		})
	}
}

func TestApplyContent_SharedTemporaryPathIsRemovedOnce(t *testing.T) {
	first := slices.Slice{
		Package: "fixture",
		Name:    "scratch",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/input": {Kind: slices.PathCopy, Until: slices.UntilMutate},
		},
	}
	second := slices.Slice{
		Package: "fixture",
		Name:    "scratch-too",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/input": {Kind: slices.PathCopy, Until: slices.UntilMutate},
		},
	}
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{first, second}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if strings.Join(selected.Temporary, ",") != "/usr/share/fixture/input" {
		t.Fatalf("temporary = %v", selected.Temporary)
	}
}

func TestApplyContent_SelectsOnlyDeclaredPaths(t *testing.T) {
	slice := exactSlice()
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	for _, path := range []string{"/usr/share/fixture/tool", "/usr/share/fixture/hard",
		"/usr/share/fixture/alias", "/usr/share/fixture/source"} {
		if _, ok := selected.Tree.Lookup(path); ok {
			t.Fatalf("undeclared path %q was selected", path)
		}
	}
}

func TestApplyContent_DirectorySelectionIsNotRecursive(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "dirs",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/": {Kind: slices.PathCopy},
		},
	}
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	dir, ok := selected.Tree.Lookup("/usr/share/fixture")
	if !ok || dir.Kind != vfs.Dir || dir.Mode != 0o750 || dir.UID != 3 {
		t.Fatalf("dir = %+v", dir)
	}
	if _, ok := selected.Tree.Lookup("/usr/share/fixture/source"); ok {
		t.Fatal("directory selection was recursive")
	}
}

// privateSource is an archive whose parent directory is narrower than the file it
// holds, so a selection that omits the parent exposes the difference.
func privateSource(t *testing.T) *slices.Source {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: "private"}
	if err := tree.Dir("/private", vfs.Attrs{Mode: 0o700, UID: 7, GID: 8, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	if err := tree.File("/private/token", []byte("secret\n"),
		vfs.Attrs{Mode: 0o644, UID: 7, GID: 8, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	return &slices.Source{Package: "private", Tree: tree}
}

func TestApplyContent_CopiesSpecialBits(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "suid",
		Contents: map[string]slices.PathInfo{
			"/usr/bin/tool": {Kind: slices.PathCopy, Info: "/usr/share/fixture/tool"},
		},
	}
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	tool, _ := selected.Tree.Lookup("/usr/bin/tool")
	if tool.Mode != fs.ModeSetuid|0o755 {
		t.Fatalf("mode = %v", tool.Mode)
	}
}

func TestApplyContent_EmptyTextIsMeaningful(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "empty",
		Contents: map[string]slices.PathInfo{
			"/etc/empty": {Kind: slices.PathText, Info: ""},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	empty, ok := selected.Tree.Lookup("/etc/empty")
	if !ok || empty.Kind != vfs.File || empty.Size != 0 || empty.Mode != 0o644 {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestApplyContent_MakeDirectoryDefaults(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "dirs",
		Contents: map[string]slices.PathInfo{
			"/var/lib/fixture/": {Kind: slices.PathDir},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	dir, ok := selected.Tree.Lookup("/var/lib/fixture")
	if !ok || dir.Mode != slices.DefaultSynthesizedDirMode || dir.Implicit {
		t.Fatalf("dir = %+v", dir)
	}
}

func TestApplyContent_RejectsInvalidDeclarations(t *testing.T) {
	sources := map[string]*slices.Source{"fixture": sourceTree(t)}
	tests := []struct {
		name     string
		contents map[string]slices.PathInfo
		want     string
	}{
		{
			name:     "missing source",
			contents: map[string]slices.PathInfo{"/usr/share/fixture/missing": {Kind: slices.PathCopy}},
			want:     "is missing from package",
		},
		{
			name:     "missing package source",
			contents: map[string]slices.PathInfo{"/usr/share/fixture/source": {Kind: slices.PathCopy}},
			want:     "no verified content",
		},
		{
			name:     "generate is unsupported",
			contents: map[string]slices.PathInfo{"/var/lib/fixture/**": {Kind: slices.PathGenerate, Generate: slices.GenerateManifest}},
			want:     "does not support",
		},
		{
			name:     "mode on symlink",
			contents: map[string]slices.PathInfo{"/etc/link": {Kind: slices.PathSymlink, Info: "target", Mode: 0o777}},
			want:     "sets a mode on a symlink",
		},
		{
			name:     "mode on copied directory",
			contents: map[string]slices.PathInfo{"/usr/share/fixture/": {Kind: slices.PathCopy, Mode: 0o700}},
			want:     "sets a mode on a copied directory",
		},
		{
			name:     "escaping symlink target",
			contents: map[string]slices.PathInfo{"/etc/link": {Kind: slices.PathSymlink, Info: "../../etc/shadow"}},
			want:     "escapes the image root",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slice := slices.Slice{Package: "fixture", Name: "invalid", Contents: test.contents}
			used := sources
			if test.name == "missing package source" {
				used = map[string]*slices.Source{}
			}
			_, err := slices.ApplyContent([]slices.Slice{slice}, used, "", nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestApplyContent_DoesNotMutateSource(t *testing.T) {
	source := sourceTree(t)
	before := source.Tree.Inodes()
	slice := exactSlice()
	if _, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": source}, "", nil); err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	after := source.Tree.Inodes()
	if len(before) != len(after) {
		t.Fatalf("source changed: %d -> %d entries", len(before), len(after))
	}
	for path, id := range before {
		if after[path] != id {
			t.Fatalf("source inode for %q changed", path)
		}
	}
}

func TestApplyContent_IsDeterministic(t *testing.T) {
	slice := exactSlice()
	first, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": sourceTree(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	second, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": sourceTree(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	firstEntries, secondEntries := first.Tree.Entries(), second.Tree.Entries()
	if len(firstEntries) != len(secondEntries) {
		t.Fatalf("entry counts differ: %d / %d", len(firstEntries), len(secondEntries))
	}
	for i := range firstEntries {
		if firstEntries[i].Path != secondEntries[i].Path || firstEntries[i].Mode != secondEntries[i].Mode {
			t.Fatalf("entries differ at %d: %+v / %+v", i, firstEntries[i], secondEntries[i])
		}
	}
}

func TestApplyContent_PreferenceWithoutSelectedProviderKeepsDeclaration(t *testing.T) {
	// A preference does not select its provider: when the preferred package is
	// not part of the selection, the declaring package still provides the path.
	slice := slices.Slice{
		Package: "fixture",
		Name:    "preferred",
		Contents: map[string]slices.PathInfo{
			"/usr/share/fixture/preferred": {Kind: slices.PathText, Info: "fixture\n", Prefer: "provider"},
		},
	}
	selected, err := slices.ApplyContent([]slices.Slice{slice}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if _, ok := selected.Tree.Lookup("/usr/share/fixture/preferred"); !ok {
		t.Fatal("declaration was dropped although its provider is not selected")
	}
}

func TestApplyContent_RejectsGenerate(t *testing.T) {
	// Upstream ships exactly one generate declaration (base-files_chisel). Vapor
	// rejects it by name rather than silently producing an image without the
	// manifest the declaration asked for.
	slice := fixtureSlice(t, "fixture", "manifest")
	_, err := slices.ApplyContent([]slices.Slice{slice}, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("error does not name the unsupported feature: %v", err)
	}
}

func TestApplyContent_RejectsUnselectedSlice(t *testing.T) {
	if _, err := slices.ApplyContent([]slices.Slice{{}}, nil, "", nil); err == nil ||
		!strings.Contains(err.Error(), "requires a selected slice") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_ArchFilterSkipsDeclarations(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "arch",
		Contents: map[string]slices.PathInfo{
			"/usr/lib/amd64-only": {Kind: slices.PathText, Info: "amd64\n", Arch: []string{"amd64"}},
			"/usr/lib/any":        {Kind: slices.PathText, Info: "any\n"},
		},
	}
	arm, err := slices.ApplyContent([]slices.Slice{slice}, nil, "arm64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if _, ok := arm.Tree.Lookup("/usr/lib/amd64-only"); ok {
		t.Fatal("architecture filter was ignored")
	}
	if _, ok := arm.Tree.Lookup("/usr/lib/any"); !ok {
		t.Fatal("unfiltered declaration was dropped")
	}
	amd, err := slices.ApplyContent([]slices.Slice{slice}, nil, "amd64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if _, ok := amd.Tree.Lookup("/usr/lib/amd64-only"); !ok {
		t.Fatal("matching architecture was dropped")
	}
}

func TestApplyContent_RecordsOriginalMutableBytes(t *testing.T) {
	slice := exactSlice()
	selected, err := slices.ApplyContent([]slices.Slice{slice}, map[string]*slices.Source{"fixture": sourceTree(t)}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	original, ok := selected.Original["/usr/share/fixture/output"]
	if !ok || len(original) != 64 {
		t.Fatalf("original = %q", original)
	}
	if _, ok := selected.Original["/usr/share/fixture/copied"]; ok {
		t.Fatal("non-mutable path recorded as mutable original")
	}
}

func TestApplyContent_RejectsFileAncestorOfDeclaration(t *testing.T) {
	slice := slices.Slice{
		Package: "fixture",
		Name:    "ancestor",
		Contents: map[string]slices.PathInfo{
			"/etc/fixture":       {Kind: slices.PathText, Info: "file\n"},
			"/etc/fixture/state": {Kind: slices.PathText, Info: "nested\n"},
		},
	}
	_, err := slices.ApplyContent([]slices.Slice{slice}, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "non-directory ancestor") {
		t.Fatalf("error = %v", err)
	}
}

// A broad slice copies many files from one package, so the source is numbered once.
// Numbering twice would see a source that is still the same and could not tell a hard
// link from a copy, so a source read through the cached numbering keeps its links.
func TestApplyContent_NumbersEachSourceOnce(t *testing.T) {
	source := sourceTree(t)
	slice := slices.Slice{Package: "fixture", Name: "copy", Contents: map[string]slices.PathInfo{
		"/usr/share/copied/source": {Kind: slices.PathCopy, Info: "/usr/share/fixture/source"},
		"/usr/share/copied/hard":   {Kind: slices.PathCopy, Info: "/usr/share/fixture/hard"},
	}}
	selected, err := slices.ApplyContent([]slices.Slice{slice},
		map[string]*slices.Source{"fixture": source}, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	inodes := selected.Tree.Inodes()
	if inodes["/usr/share/copied/source"] != inodes["/usr/share/copied/hard"] {
		t.Fatal("the hard link was copied as an independent file")
	}
}

// BenchmarkApplyContent_CopyManyFiles measures the per-file cost of a broad copy from
// one unchanged source, which is the shape a real runtime slice has.
func BenchmarkApplyContent_CopyManyFiles(b *testing.B) {
	const files = 500
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture"}
	contents := make(map[string]slices.PathInfo, files)
	for i := range files {
		source := "/usr/share/fixture/file" + strconv.Itoa(i)
		contents[source] = slices.PathInfo{Kind: slices.PathCopy}
		if err := tree.File(source, []byte("payload\n"), vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
			b.Fatal(err)
		}
	}
	slice := slices.Slice{Package: "fixture", Name: "runtime", Contents: contents}
	sources := map[string]*slices.Source{"fixture": {Package: "fixture", Tree: tree}}
	b.ResetTimer()
	for range b.N {
		if _, err := slices.ApplyContent([]slices.Slice{slice}, sources, "", nil); err != nil {
			b.Fatal(err)
		}
	}
}
