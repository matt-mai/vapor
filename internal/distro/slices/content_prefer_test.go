package slices_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/vfs"
)

func preferSlice(pkg, name string, contents map[string]slices.PathInfo) slices.Slice {
	return slices.Slice{Package: pkg, Name: name, Contents: contents}
}

func textInfo(text string) slices.PathInfo {
	return slices.PathInfo{Kind: slices.PathText, Info: text}
}

func preferredInfo(text, provider string) slices.PathInfo {
	return slices.PathInfo{Kind: slices.PathText, Info: text, Prefer: provider}
}

// selectedText returns the bytes of one path in a selected tree.
func selectedText(t *testing.T, selected *slices.SelectedContent, path string) string {
	t.Helper()
	content, err := selected.Tree.Read(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

// A preference chain is traversed through the catalogue, not through the
// selection: aaa prefers bbb and bbb prefers ccc, so selecting aaa and ccc still
// resolves to ccc although bbb is absent from the image.
func TestApplyContent_PreferenceChainSkipsAnUnselectedProvider(t *testing.T) {
	aaa := preferSlice("aaa", "one", map[string]slices.PathInfo{"/x": preferredInfo("aaa\n", "bbb")})
	ccc := preferSlice("ccc", "three", map[string]slices.PathInfo{"/x": textInfo("ccc\n")})
	catalogue := map[string]*slices.Package{
		"aaa": {Name: "aaa", Slices: map[string]slices.Slice{"one": aaa}},
		"bbb": {Name: "bbb", Slices: map[string]slices.Slice{"two": preferSlice("bbb", "two",
			map[string]slices.PathInfo{"/x": preferredInfo("bbb\n", "ccc")})}},
		"ccc": {Name: "ccc", Slices: map[string]slices.Slice{"three": ccc}},
	}
	selected, err := slices.ApplyContent([]slices.Slice{aaa, ccc}, nil, "", catalogue)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if text := selectedText(t, selected, "/x"); text != "ccc\n" {
		t.Fatalf("content = %q, want the end of the chain", text)
	}
}

// Without a catalogue only the selected links are known, so a chain through an
// absent provider cannot be resolved and the conflicting declarations are refused
// rather than silently decided by application order.
func TestApplyContent_PreferenceChainNeedsTheCatalogue(t *testing.T) {
	_, err := slices.ApplyContent([]slices.Slice{
		preferSlice("aaa", "one", map[string]slices.PathInfo{"/x": preferredInfo("aaa\n", "bbb")}),
		preferSlice("ccc", "three", map[string]slices.PathInfo{"/x": textInfo("ccc\n")}),
	}, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_PreferenceChainWinsAcrossSelection(t *testing.T) {
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": preferredInfo("a\n", "b")}),
		preferSlice("b", "two", map[string]slices.PathInfo{"/x": preferredInfo("b\n", "c")}),
		preferSlice("c", "three", map[string]slices.PathInfo{"/x": textInfo("c\n")}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, selected, "/x"); got != "c\n" {
		t.Fatalf("content = %q", got)
	}
	entry, _ := selected.Tree.Lookup("/x")
	if len(entry.Origins) != 1 || entry.Origins[0].Package != "c" {
		t.Fatalf("origins = %+v", entry.Origins)
	}
}

func TestApplyContent_PreferenceIgnoresUnselectedProvider(t *testing.T) {
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": preferredInfo("a\n", "b")}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, selected, "/x"); got != "a\n" {
		t.Fatalf("content = %q", got)
	}
}

func TestApplyContent_PreferenceToPackageWithoutPathKeepsDeclaration(t *testing.T) {
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": preferredInfo("a\n", "b")}),
		preferSlice("b", "two", map[string]slices.PathInfo{"/y": textInfo("b\n")}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, selected, "/x"); got != "a\n" {
		t.Fatalf("content = %q", got)
	}
}

func TestApplyContent_PreferenceDecidesBetweenSelectedProviders(t *testing.T) {
	// The preferred package declares the path too, so it wins even when the
	// declaring slices are applied in the opposite order.
	forward, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": preferredInfo("a\n", "b")}),
		preferSlice("b", "two", map[string]slices.PathInfo{"/x": textInfo("b\n")}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	reverse, err := slices.ApplyContent([]slices.Slice{
		preferSlice("b", "two", map[string]slices.PathInfo{"/x": textInfo("b\n")}),
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": preferredInfo("a\n", "b")}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, forward, "/x"); got != "b\n" {
		t.Fatalf("forward content = %q", got)
	}
	if got := selectedText(t, reverse, "/x"); got != "b\n" {
		t.Fatalf("reverse content = %q", got)
	}
}

func TestApplyContent_ConflictingProvidersWithoutPreferenceFail(t *testing.T) {
	_, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": textInfo("a\n")}),
		preferSlice("b", "two", map[string]slices.PathInfo{"/x": textInfo("b\n")}),
	}, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "conflicts with existing") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_PreferenceDoesNotOverrideMetadataDisagreement(t *testing.T) {
	// Equal eventual bytes are not enough: the preferred provider supplies the
	// path, so the losing package's ownership is not silently applied instead.
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{
			"/x": {Kind: slices.PathText, Info: "same\n", Mode: 0o600, Prefer: "b"},
		}),
		preferSlice("b", "two", map[string]slices.PathInfo{
			"/x": {Kind: slices.PathText, Info: "same\n", Mode: 0o644},
		}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	entry, _ := selected.Tree.Lookup("/x")
	if entry.Mode != 0o644 {
		t.Fatalf("mode = %v", entry.Mode)
	}
	if len(entry.Origins) != 1 || entry.Origins[0].Package != "b" {
		t.Fatalf("origins = %+v", entry.Origins)
	}
}

func TestApplyContent_SamePackageSlicesStillConflict(t *testing.T) {
	// A preference is a cross-package relationship; two slices of one package
	// must agree on a path rather than being resolved by ordering.
	_, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": textInfo("one\n")}),
		preferSlice("a", "two", map[string]slices.PathInfo{"/x": textInfo("two\n")}),
	}, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "conflicts with existing") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_SamePackageSharedDeclarationKeepsBothOrigins(t *testing.T) {
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": textInfo("same\n")}),
		preferSlice("a", "two", map[string]slices.PathInfo{"/x": textInfo("same\n")}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	entry, _ := selected.Tree.Lookup("/x")
	if len(entry.Origins) != 2 {
		t.Fatalf("origins = %+v", entry.Origins)
	}
}

func TestApplyContent_PreferenceDoesNotCoverGlobOverlap(t *testing.T) {
	// A glob has no preference, and a preference on an exact path does not make
	// a glob from another package overlap it safely.
	source := &slices.Source{Package: "b", Tree: vfs.New()}
	if err := source.Tree.File("/usr/lib/libx.so", []byte("x"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	_, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{
			"/usr/lib/libx.so": {Kind: slices.PathText, Info: "a\n", Prefer: "b"},
		}),
		preferSlice("b", "two", map[string]slices.PathInfo{
			"/usr/lib/*.so": {Kind: slices.PathGlob},
		}),
	}, map[string]*slices.Source{"b": source}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "conflicts with existing") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_PreferenceCycleFails(t *testing.T) {
	_, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{"/x": preferredInfo("a\n", "b")}),
		preferSlice("b", "two", map[string]slices.PathInfo{"/x": preferredInfo("b\n", "a")}),
	}, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "prefer loop") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyContent_PreferenceTracksTemporaryAndMutable(t *testing.T) {
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{
			"/x": {Kind: slices.PathText, Info: "a\n", Until: slices.UntilMutate, Prefer: "b"},
		}),
		preferSlice("b", "two", map[string]slices.PathInfo{
			"/x": {Kind: slices.PathText, Info: "b\n", Mutable: true},
		}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if len(selected.Temporary) != 0 {
		t.Fatalf("temporary = %v", selected.Temporary)
	}
	if strings.Join(selected.Mutable, ",") != "/x" {
		t.Fatalf("mutable = %v", selected.Mutable)
	}
	if _, ok := selected.Original["/x"]; !ok {
		t.Fatal("mutable original was not recorded")
	}
}

func TestApplyContent_PreferenceIgnoresFilteredArchitecture(t *testing.T) {
	// A declaration filtered out by architecture does not compete for its path,
	// so it cannot pull a preference into the selection.
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{
			"/x": {Kind: slices.PathText, Info: "a\n", Arch: []string{"amd64"}, Prefer: "b"},
		}),
		preferSlice("b", "two", map[string]slices.PathInfo{"/x": textInfo("b\n")}),
	}, nil, "arm64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, selected, "/x"); got != "b\n" {
		t.Fatalf("content = %q", got)
	}
}

func TestApplyContent_PreferenceNeverAddsAPackage(t *testing.T) {
	// Preferring a package that provides nothing else must not create content
	// for it: only its own declarations can put paths in the image.
	selected, err := slices.ApplyContent([]slices.Slice{
		preferSlice("a", "one", map[string]slices.PathInfo{
			"/x": {Kind: slices.PathText, Info: "a\n", Prefer: "b"},
			"/y": textInfo("only a\n"),
		}),
	}, nil, "", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if _, ok := selected.Tree.Lookup("/x"); !ok {
		t.Fatal("path was dropped for an unselected provider")
	}
	if got := selectedText(t, selected, "/y"); got != "only a\n" {
		t.Fatalf("content = %q", got)
	}
}

// fixtureSourceTree adds the preferred path to the shared fixture payload so the
// decoded fixture catalogue can be applied end to end.
func fixtureSourceTree(t *testing.T) *slices.Source {
	t.Helper()
	source := sourceTree(t)
	origin := vfs.Origin{Package: "fixture"}
	if err := source.Tree.File("/usr/share/fixture/preferred", []byte("fixture payload\n"),
		vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("build source: %v", err)
	}
	return source
}

func TestApplyContent_DecodedFixturePreference(t *testing.T) {
	runtime := fixtureSlice(t, "fixture", "runtime")
	data := fixtureSlice(t, "provider", "data")
	sources := map[string]*slices.Source{"fixture": fixtureSourceTree(t)}

	both, err := slices.ApplyContent([]slices.Slice{runtime, data}, sources, "arm64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, both, "/usr/share/fixture/preferred"); got != "preferred provider\n" {
		t.Fatalf("preferred content = %q", got)
	}

	reversed, err := slices.ApplyContent([]slices.Slice{data, runtime}, sources, "arm64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, reversed, "/usr/share/fixture/preferred"); got != "preferred provider\n" {
		t.Fatalf("reversed content = %q", got)
	}

	alone, err := slices.ApplyContent([]slices.Slice{runtime}, sources, "arm64", nil)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, alone, "/usr/share/fixture/preferred"); got != "fixture payload\n" {
		t.Fatalf("unselected provider content = %q", got)
	}
}

// The preference may be declared only in a slice the image does not select. The
// catalogue graph still decides between the selected providers, so the chain runs
// aaa -> bbb -> ccc even though aaa and bbb are not selected.
func TestApplyContent_PreferenceDeclaredOnlyInUnselectedSlices(t *testing.T) {
	aaa := preferSlice("aaa", "run", map[string]slices.PathInfo{"/x": textInfo("aaa\n")})
	ccc := preferSlice("ccc", "run", map[string]slices.PathInfo{"/x": textInfo("ccc\n")})
	catalogue := map[string]*slices.Package{
		"aaa": {Name: "aaa", Slices: map[string]slices.Slice{
			"run":    aaa,
			"policy": preferSlice("aaa", "policy", map[string]slices.PathInfo{"/x": preferredInfo("aaa\n", "bbb")}),
		}},
		"bbb": {Name: "bbb", Slices: map[string]slices.Slice{
			"run": preferSlice("bbb", "run", map[string]slices.PathInfo{"/x": preferredInfo("bbb\n", "ccc")}),
		}},
		"ccc": {Name: "ccc", Slices: map[string]slices.Slice{"run": ccc}},
	}
	selected, err := slices.ApplyContent([]slices.Slice{aaa, ccc}, nil, "", catalogue)
	if err != nil {
		t.Fatalf("ApplyContent: %v", err)
	}
	if got := selectedText(t, selected, "/x"); got != "ccc\n" {
		t.Fatalf("content = %q, want the end of the catalogue's chain", got)
	}
}

// A catalogue preference with no relation to the selected providers keeps the
// ordinary collision rules instead of inventing a winner.
func TestApplyContent_CataloguePreferenceWithoutRelationStillConflicts(t *testing.T) {
	_, err := slices.ApplyContent([]slices.Slice{
		preferSlice("aaa", "run", map[string]slices.PathInfo{"/x": textInfo("aaa\n")}),
		preferSlice("ccc", "run", map[string]slices.PathInfo{"/x": textInfo("ccc\n")}),
	}, nil, "", map[string]*slices.Package{
		"aaa": {Name: "aaa", Slices: map[string]slices.Slice{
			"policy": preferSlice("aaa", "policy", map[string]slices.PathInfo{"/x": preferredInfo("aaa\n", "bbb")}),
		}},
		"bbb": {Name: "bbb", Slices: map[string]slices.Slice{
			"run": preferSlice("bbb", "run", map[string]slices.PathInfo{"/x": textInfo("bbb\n")}),
		}},
		"ccc": {Name: "ccc", Slices: map[string]slices.Slice{
			"run": preferSlice("ccc", "run", map[string]slices.PathInfo{"/x": textInfo("ccc\n")}),
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("error = %v", err)
	}
}
