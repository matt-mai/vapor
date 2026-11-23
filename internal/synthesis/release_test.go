package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

func ubuntuIdentity() map[string]string {
	return map[string]string{
		"ID": "ubuntu", "ID_LIKE": "debian", "VERSION_ID": "24.04",
		"VERSION_CODENAME": "noble", "NAME": "Ubuntu 24.04 LTS", "VERSION": "Ubuntu 24.04 LTS",
	}
}

func releaseTree(t *testing.T, content string) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	if err := tree.File(synthesis.OSReleasePath, []byte(content), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("os-release: %v", err)
	}
	return tree
}

func TestRelease_FillsMissingStateFromProvider(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	for _, want := range []string{`ID="ubuntu"`, `ID_LIKE="debian"`, `VERSION_ID="24.04"`, `NAME="Ubuntu 24.04 LTS"`} {
		if !strings.Contains(content, want) {
			t.Fatalf("missing %s in %q", want, content)
		}
	}
}

func TestRelease_PreservesSelectedState(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nLOGO=ubuntu-logo\n")
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	if !strings.Contains(content, `PRETTY_NAME="Ubuntu 24.04.5 LTS"`) {
		t.Fatalf("selected state lost: %q", content)
	}
	if !strings.Contains(content, `LOGO="ubuntu-logo"`) {
		t.Fatalf("selected state lost: %q", content)
	}
}

func TestRelease_AppliesDescriptiveOverrides(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	overrides := map[string]string{"PRETTY_NAME": "Example application image", "HOME_URL": "https://example.test"}
	if err := synthesis.Release(tree, ubuntuIdentity(), overrides); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	if !strings.Contains(content, `PRETTY_NAME="Example application image"`) {
		t.Fatalf("override missing: %q", content)
	}
	if !strings.Contains(content, `HOME_URL="https://example.test"`) {
		t.Fatalf("override missing: %q", content)
	}
}

func TestRelease_RejectsIdentityOverrides(t *testing.T) {
	for _, field := range []string{"ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME"} {
		t.Run(field, func(t *testing.T) {
			err := synthesis.Release(vfs.New(), ubuntuIdentity(), map[string]string{field: "other"})
			if err == nil || !strings.Contains(err.Error(), "not a descriptive field") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRelease_RejectsConflictingSelectedIdentity(t *testing.T) {
	tree := releaseTree(t, "ID=debian\nVERSION_ID=\"24.04\"\n")
	err := synthesis.Release(tree, ubuntuIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), "but the image is") {
		t.Fatalf("error = %v", err)
	}
}

func TestRelease_UpdatesBothLocations(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	if err := tree.File(synthesis.OSReleaseLegacyPath, []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	overrides := map[string]string{"PRETTY_NAME": "Example"}
	if err := synthesis.Release(tree, ubuntuIdentity(), overrides); err != nil {
		t.Fatalf("release: %v", err)
	}
	legacy := readFile(t, tree, synthesis.OSReleaseLegacyPath)
	if !strings.Contains(legacy, `PRETTY_NAME="Example"`) {
		t.Fatalf("/etc/os-release drifted: %q", legacy)
	}
}

// Both release files are written, so a failure at the second location must not
// leave the first one updated.
func TestRelease_LeavesTheTreeUntouchedOnFailure(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	before := readFile(t, tree, synthesis.OSReleasePath)
	// A directory at the legacy path cannot be replaced, so the write fails there
	// after the library file would have been updated.
	if err := tree.Dir(synthesis.OSReleaseLegacyPath, vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("dir: %v", err)
	}
	if err := tree.File(synthesis.OSReleaseLegacyPath+"/child", nil, vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("child: %v", err)
	}
	err := synthesis.Release(tree, ubuntuIdentity(), map[string]string{"PRETTY_NAME": "Example"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if after := readFile(t, tree, synthesis.OSReleasePath); after != before {
		t.Fatalf("library file changed despite the failure: %q -> %q", before, after)
	}
}

// TestRelease_RejectsConflictingLegacyIdentity covers the second file: it is
// overwritten on write, so its identity must be checked rather than skipped.
func TestRelease_RejectsConflictingLegacyIdentity(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	if err := tree.File(synthesis.OSReleaseLegacyPath, []byte("ID=debian\nVERSION_ID=\"12\"\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	err := synthesis.Release(tree, ubuntuIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), `has ID "debian"`) {
		t.Fatalf("error = %v", err)
	}
}

// TestRelease_PrefersLibraryLocation covers the merge order: when both files hold
// state, the value a reader of the image would see wins.
func TestRelease_PrefersLibraryLocation(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Library\"\n")
	if err := tree.File(synthesis.OSReleaseLegacyPath,
		[]byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Legacy\"\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	for _, location := range []string{synthesis.OSReleasePath, synthesis.OSReleaseLegacyPath} {
		if content := readFile(t, tree, location); !strings.Contains(content, `PRETTY_NAME="Library"`) {
			t.Fatalf("%s = %q, want the library value", location, content)
		}
	}
}

// The standard layout links /etc/os-release at the /usr/lib file. The link must
// survive and the file it names must carry the merged state.
func TestRelease_KeepsSymlinkedLegacyAndUpdatesItsTarget(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	if err := tree.Symlink(synthesis.OSReleaseLegacyPath, "../usr/lib/os-release", vfs.Attrs{}); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := synthesis.Release(tree, ubuntuIdentity(), map[string]string{"PRETTY_NAME": "Example"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	entry, ok := tree.Lookup(synthesis.OSReleaseLegacyPath)
	if !ok || entry.Kind != vfs.Symlink {
		t.Fatalf("legacy = %+v", entry)
	}
	if content := readFile(t, tree, synthesis.OSReleasePath); !strings.Contains(content, "Example") {
		t.Fatalf("merged state missing from the link target: %q", content)
	}
}

// A link to a file outside the standard locations is read, so contradictory
// identity is reported instead of silently left in place.
func TestRelease_RejectsContradictorySymlinkedState(t *testing.T) {
	tree := vfs.New()
	if err := tree.File("/opt/release", []byte("ID=other\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := tree.Symlink(synthesis.OSReleaseLegacyPath, "/opt/release", vfs.Attrs{}); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := synthesis.Release(tree, ubuntuIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), "selected os-release") {
		t.Fatalf("error = %v", err)
	}
}

// A dangling standard link is refused rather than left pointing at nothing while
// the image claims an identity.
func TestRelease_RejectsDanglingSymlink(t *testing.T) {
	tree := vfs.New()
	if err := tree.Symlink(synthesis.OSReleaseLegacyPath, "/opt/missing", vfs.Attrs{}); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := synthesis.Release(tree, ubuntuIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), "not a release file") {
		t.Fatalf("error = %v", err)
	}
}

// Parsing and serialization are inverse, so a value holding escapes is stable
// across repeated passes instead of doubling on every one.
func TestRelease_RoundTripsEscapedValues(t *testing.T) {
	for _, value := range []string{`a"b`, `a\b`, `a$b`, "a`b", `a\"b`} {
		tree := vfs.New()
		identity := map[string]string{"ID": "vapor", "NAME": value, "VERSION_ID": "1"}
		if err := synthesis.Release(tree, identity, nil); err != nil {
			t.Fatalf("%q: first write: %v", value, err)
		}
		first := readFile(t, tree, synthesis.OSReleasePath)
		if err := synthesis.Release(tree, identity, nil); err != nil {
			t.Fatalf("%q: second write: %v", value, err)
		}
		if again := readFile(t, tree, synthesis.OSReleasePath); again != first {
			t.Fatalf("%q is not stable: %q -> %q", value, first, again)
		}
	}
}

func TestRelease_EscapesQuotes(t *testing.T) {
	tree := vfs.New()
	overrides := map[string]string{"PRETTY_NAME": `Example "quoted" $HOME \ path`}
	if err := synthesis.Release(tree, ubuntuIdentity(), overrides); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	if !strings.Contains(content, `PRETTY_NAME="Example \"quoted\" \$HOME \\ path"`) {
		t.Fatalf("escaping = %q", content)
	}
}

func TestRelease_IsDeterministic(t *testing.T) {
	first, second := vfs.New(), vfs.New()
	for _, tree := range []*vfs.Tree{first, second} {
		if err := synthesis.Release(tree, ubuntuIdentity(), map[string]string{"PRETTY_NAME": "Example"}); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
	if readFile(t, first, synthesis.OSReleasePath) != readFile(t, second, synthesis.OSReleasePath) {
		t.Fatal("output is not deterministic")
	}
}

func TestRelease_RejectsMalformedSelectedState(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nno-equals-sign\n")
	err := synthesis.Release(tree, ubuntuIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), "malformed line") {
		t.Fatalf("error = %v", err)
	}
}

// TestRelease_RejectsUnsafeFieldNames covers keys that are data to the parser but
// shell syntax in the output. The serializer writes a key unquoted, so a key must
// be a plain assignment name before it is retained.
func TestRelease_RejectsUnsafeFieldNames(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "command separator", line: ":; echo INJECTED; #=x", want: "not a plain identifier"},
		{name: "substitution", line: "$(id)=x", want: "not a plain identifier"},
		{name: "backtick", line: "`id`=x", want: "not a plain identifier"},
		{name: "space", line: "A B=x", want: "not a plain identifier"},
		{name: "dot", line: "A.B=x", want: "not a plain identifier"},
		{name: "digit first", line: "1A=x", want: "starts with a digit"},
		{name: "empty", line: "=x", want: "field name is empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := releaseTree(t, "ID=ubuntu\n"+test.line+"\n")
			err := synthesis.Release(tree, ubuntuIdentity(), nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRelease_AcceptsUnderscoreFieldNames(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVENDOR_BUILD_ID=7\n")
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if content := readFile(t, tree, synthesis.OSReleasePath); !strings.Contains(content, `VENDOR_BUILD_ID="7"`) {
		t.Fatalf("content = %q", content)
	}
}

func TestRelease_RejectsMultilineOverride(t *testing.T) {
	err := synthesis.Release(vfs.New(), ubuntuIdentity(), map[string]string{"NAME": "a\nb"})
	if err == nil || !strings.Contains(err.Error(), "single line") {
		t.Fatalf("error = %v", err)
	}
}

func TestRelease_RequiresTree(t *testing.T) {
	if err := synthesis.Release(nil, ubuntuIdentity(), nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRelease_UnquotesSelectedValues(t *testing.T) {
	tree := releaseTree(t, "ID=\"ubuntu\"\nVERSION_ID='24.04'\n")
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	if !strings.Contains(content, `ID="ubuntu"`) {
		t.Fatalf("content = %q", content)
	}
}

// An apostrophe inside a double-quoted value is ordinary data, and the serializer
// writes such a value double-quoted, so the next pass must accept it.
func TestRelease_AcceptsApostropheInDoubleQuotes(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\n")
	if err := synthesis.Release(tree, ubuntuIdentity(), map[string]string{"NAME": "Vendor's Linux"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	if !strings.Contains(content, `NAME="Vendor's Linux"`) {
		t.Fatalf("content = %q", content)
	}
	if err := synthesis.Release(tree, ubuntuIdentity(), map[string]string{"NAME": "Vendor's Linux"}); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again := readFile(t, tree, synthesis.OSReleasePath); again != content {
		t.Fatalf("second pass changed the file:\n%q\n%q", content, again)
	}
}

// A single-quoted value is literal: its backslashes are data, not escapes.
func TestRelease_KeepsBackslashesInSingleQuotes(t *testing.T) {
	tree := releaseTree(t, "ID=ubuntu\nVENDOR='a\\$b'\n")
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	if !strings.Contains(content, `VENDOR="a\\\$b"`) {
		t.Fatalf("content = %q", content)
	}
	if err := synthesis.Release(tree, ubuntuIdentity(), nil); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again := readFile(t, tree, synthesis.OSReleasePath); again != content {
		t.Fatalf("second pass changed the file:\n%q\n%q", content, again)
	}
}

// debianIdentity is Debian's provider identity: it pins no descriptive defaults
// and publishes no ID_LIKE or UBUNTU_CODENAME.
func debianIdentity() map[string]string {
	return map[string]string{
		"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie",
		"ID_LIKE": "", "UBUNTU_CODENAME": "",
	}
}

// A provider's descriptive default only fills a gap: the released file is more
// specific than a distribution default.
func TestRelease_ProviderDescriptiveDefaultFillsAGap(t *testing.T) {
	defaults := map[string]string{"ID": "ubuntu", "VERSION_ID": "26.04", "NAME": "Ubuntu 26.04 LTS"}
	tree := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"26.04\"\nNAME=\"Ubuntu Base 26.04\"\n")
	if err := synthesis.Release(tree, defaults, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if content := readFile(t, tree, synthesis.OSReleasePath); !strings.Contains(content, `NAME="Ubuntu Base 26.04"`) {
		t.Fatalf("provider default overwrote released state: %q", content)
	}

	gap := releaseTree(t, "ID=ubuntu\nVERSION_ID=\"26.04\"\n")
	if err := synthesis.Release(gap, defaults, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if content := readFile(t, gap, synthesis.OSReleasePath); !strings.Contains(content, `NAME="Ubuntu 26.04 LTS"`) {
		t.Fatalf("provider default did not fill the gap: %q", content)
	}
}

func TestRelease_DebianPinsIdentity(t *testing.T) {
	tree := releaseTree(t, "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n")
	if err := synthesis.Release(tree, debianIdentity(), map[string]string{"PRETTY_NAME": "Example application image"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	content := readFile(t, tree, synthesis.OSReleasePath)
	for _, want := range []string{
		`ID="debian"`, `VERSION_ID="13"`, `VERSION_CODENAME="trixie"`,
		`PRETTY_NAME="Example application image"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("missing %s in %q", want, content)
		}
	}
	for _, absent := range []string{"ID_LIKE", "UBUNTU_CODENAME", "\nNAME="} {
		if strings.Contains(content, absent) {
			t.Fatalf("Debian identity wrote %s: %q", absent, content)
		}
	}
}

// Debian publishes no UBUNTU_CODENAME. Rewriting the field would invent a value the
// distribution does not have, so a selected package claiming one is refused.
func TestRelease_RejectsUbuntuCodenameOnDebian(t *testing.T) {
	tree := releaseTree(t, "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nUBUNTU_CODENAME=resolute\n")
	err := synthesis.Release(tree, debianIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), `declares UBUNTU_CODENAME "resolute"`) {
		t.Fatalf("error = %v", err)
	}
	// The tree is untouched, so the image is not left half-changed.
	if content := readFile(t, tree, synthesis.OSReleasePath); !strings.Contains(content, "UBUNTU_CODENAME=resolute") {
		t.Fatalf("tree changed despite the failure: %q", content)
	}
}

func TestRelease_RejectsConflictingDebianCodename(t *testing.T) {
	for _, content := range []string{
		"ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=bookworm\n",
		"ID=ubuntu\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n",
		"ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=trixie\n",
	} {
		if err := synthesis.Release(releaseTree(t, content), debianIdentity(), nil); err == nil ||
			!strings.Contains(err.Error(), "but the image is") {
			t.Fatalf("error = %v for %q", err, content)
		}
	}
}

// A conflicting second release file is refused before either file is written.
func TestRelease_RejectsConflictingDebianLegacyFile(t *testing.T) {
	tree := releaseTree(t, "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n")
	if err := tree.File(synthesis.OSReleaseLegacyPath, []byte("ID=debian\nVERSION_CODENAME=bookworm\n"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	err := synthesis.Release(tree, debianIdentity(), nil)
	if err == nil || !strings.Contains(err.Error(), "VERSION_CODENAME") {
		t.Fatalf("error = %v", err)
	}
}

// An unknown codename has no version number, so the provider pins none and the
// released value is kept rather than blanked.
func TestRelease_UnknownCodenameKeepsReleasedVersion(t *testing.T) {
	tree := releaseTree(t, "ID=debian\nVERSION_ID=\"14\"\nVERSION_CODENAME=forky\n")
	identity := map[string]string{"ID": "debian", "VERSION_CODENAME": "forky",
		"ID_LIKE": "", "UBUNTU_CODENAME": ""}
	if err := synthesis.Release(tree, identity, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if content := readFile(t, tree, synthesis.OSReleasePath); !strings.Contains(content, `VERSION_ID="14"`) {
		t.Fatalf("released version was dropped: %q", content)
	}
}
