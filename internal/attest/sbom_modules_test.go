package attest_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// A vendored module is a package a payload carries rather than the payload itself. The
// lock names the payload and nothing inside it, so these tests pin the claims a document
// makes about what a payload happens to contain.

// newVendoredFixture builds a tree holding one deb's payload with an npm tree inside it,
// which is the shape both real images have.

func newVendoredFixture(t *testing.T) *attest.SBOMInput {
	t.Helper()
	tree := vfs.New()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	const deb = "pool/main/n/nodejs/nodejs.deb"
	must(tree.Dir("/usr/lib/node_modules", vfs.Attrs{Mode: 0o755,
		Origin: vfs.Origin{Package: "nodejs", Path: deb}}))
	// glob 10.5.0, a module the deb carries.
	must(tree.Dir("/usr/lib/node_modules/npm/node_modules/glob", vfs.Attrs{Mode: 0o755}))
	must(tree.File("/usr/lib/node_modules/npm/node_modules/glob/package.json",
		[]byte(`{"name":"glob","version":"10.5.0"}`), vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Package: "nodejs", Path: deb}}))
	must(tree.File("/usr/lib/node_modules/npm/node_modules/glob/index.js", []byte("glob"),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: "nodejs", Path: deb}}))
	// The same module at a second path in a different version: one package each, not one
	// package with the second version winning.
	must(tree.Dir("/usr/lib/node_modules/npm/node_modules/pacote", vfs.Attrs{Mode: 0o755}))
	must(tree.File("/usr/lib/node_modules/npm/node_modules/pacote/package.json",
		[]byte(`{"name":"pacote","version":"20.0.1"}`), vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Package: "nodejs", Path: deb}}))
	must(tree.Dir("/usr/lib/node_modules/x/node_modules/pacote", vfs.Attrs{Mode: 0o755}))
	must(tree.File("/usr/lib/node_modules/x/node_modules/pacote/package.json",
		[]byte(`{"name":"pacote","version":"19.0.2"}`), vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Package: "nodejs", Path: deb}}))
	// A project manifest with no version is a build input, not an installed module.
	must(tree.Dir("/app", vfs.Attrs{Mode: 0o755}))
	must(tree.File("/app/package.json", []byte(`{"name":"my-app","private":true}`),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Path: "filesystem.paths"}}))

	input := &attest.SBOMInput{
		Name: "vendored-image", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ab", 32),
		Distro:  "ubuntu", Release: "26.04",
		Packages: []lock.Package{{Platform: "linux/amd64", Name: "nodejs",
			Version: "22.23.5-1nodesource1", Architecture: "amd64",
			Content: lock.Content{Path: "pool/main/n/nodejs/nodejs.deb",
				SHA256: strings.Repeat("cd", 32), Size: 4096}}},
		Tree: tree,
	}
	return input
}

// documents renders the platform's SPDX document as a decoded object.
func documents(t *testing.T, input *attest.SBOMInput) map[string]any {
	t.Helper()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

// packagesNamed lists the packages a document states, by name.
func packagesNamed(t *testing.T, document map[string]any, name string) []map[string]any {
	t.Helper()
	found := make([]map[string]any, 0)
	for _, entry := range document["packages"].([]any) {
		current := entry.(map[string]any)
		if current["name"] == name {
			found = append(found, current)
		}
	}
	return found
}

// locatorOf returns the package URL a document states for a package.
func locatorOf(t *testing.T, found map[string]any) string {
	t.Helper()
	for _, entry := range found["externalRefs"].([]any) {
		current := entry.(map[string]any)
		if current["referenceType"] == "purl" {
			return current["referenceLocator"].(string)
		}
	}
	return ""
}

// TestSBOMStatesVendoredModules is the fix under test: a payload that carries packages of
// its own is described as carrying them, with the package URL a scanner follows.
func TestSBOMStatesVendoredModules(t *testing.T) {
	input := newVendoredFixture(t)
	document := documents(t, input)

	glob := packagesNamed(t, document, "glob")
	if len(glob) != 1 {
		t.Fatalf("document states %d glob packages, want 1", len(glob))
	}
	if got, want := glob[0]["versionInfo"], "10.5.0"; got != want {
		t.Errorf("glob version = %v, want %v", got, want)
	}
	if got, want := locatorOf(t, glob[0]), "pkg:npm/glob@10.5.0"; got != want {
		t.Errorf("glob purl = %q, want %q", got, want)
	}
	if checksums, present := glob[0]["checksums"]; present && checksums != nil {
		t.Errorf("a vendored module has no payload of its own, but it states %v", checksums)
	}
}

// TestSBOMKeepsBothClaimants records the decision that a vendored module and the payload
// carrying it both state the file: the deb really does contain those bytes and the module
// really is a package a scanner must see.
func TestSBOMKeepsBothClaimants(t *testing.T) {
	input := newVendoredFixture(t)
	document := documents(t, input)

	moduleFiles := filesOf(t, document, "glob")
	debFiles := filesOf(t, document, "nodejs")
	const manifest = "SPDXRef-File--usr-lib-node-modules-npm-node-modules-glob-package.json"
	if !moduleFiles[manifest] {
		t.Errorf("glob does not state %s; it states %v", manifest, keysOf(moduleFiles))
	}
	if !debFiles[manifest] {
		t.Errorf("nodejs gave up %s, but the deb still contains it", manifest)
	}
}

// TestSBOMStatesTheSameModuleTwiceWhenItsVersionsDiffer is the case a name-keyed scan gets
// wrong: two versions installed at two paths are two packages, not one.
func TestSBOMStatesTheSameModuleTwiceWhenItsVersionsDiffer(t *testing.T) {
	input := newVendoredFixture(t)
	document := documents(t, input)

	pacote := packagesNamed(t, document, "pacote")
	if len(pacote) != 2 {
		t.Fatalf("document states %d pacote packages, want 2", len(pacote))
	}
	versions := []string{pacote[0]["versionInfo"].(string), pacote[1]["versionInfo"].(string)}
	if versions[0] == versions[1] {
		t.Errorf("both pacote packages state version %q", versions[0])
	}
	for _, found := range pacote {
		locator := locatorOf(t, found)
		if !strings.HasSuffix(locator, "@"+found["versionInfo"].(string)) {
			t.Errorf("purl %q does not name version %v", locator, found["versionInfo"])
		}
	}
}

// TestSBOMIgnoresAProjectManifest refuses to invent a package for a manifest that states
// no version, which is an application's own build input.
func TestSBOMIgnoresAProjectManifest(t *testing.T) {
	input := newVendoredFixture(t)
	document := documents(t, input)

	if found := packagesNamed(t, document, "my-app"); len(found) != 0 {
		t.Errorf("document claims the project manifest as a package: %v", found)
	}
}

// TestSBOMVendoredModulesAreDeterministic pins that the same tree describes the same
// modules in the same order, which is what makes the document reproducible.
func TestSBOMVendoredModulesAreDeterministic(t *testing.T) {
	first := newVendoredFixture(t)
	second := newVendoredFixture(t)
	left, err := attest.SPDX(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := attest.SPDX(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Error("two builds of the same tree produced different documents")
	}
}

// filesOf lists the files a package states it contains.
func filesOf(t *testing.T, document map[string]any, name string) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, found := range packagesNamed(t, document, name) {
		ids[found["SPDXID"].(string)] = true
	}
	owned := map[string]bool{}
	for _, entry := range document["relationships"].([]any) {
		current := entry.(map[string]any)
		if !ids[current["spdxElementId"].(string)] {
			continue
		}
		if current["relationshipType"] != "CONTAINS" {
			continue
		}
		owned[current["relatedSpdxElement"].(string)] = true
	}
	return owned
}

func keysOf(found map[string]bool) []string {
	keys := make([]string, 0, len(found))
	for key := range found {
		keys = append(keys, key)
	}
	return keys
}

// TestSBOMReadsTheTopLevelNameOnly refuses a nested object's name. A package.json states
// the module's author as {"name": ...}, and reading that as the module's own name turns
// "glob" into a person's name.
func TestSBOMReadsTheTopLevelNameOnly(t *testing.T) {
	document := ecosystemFixture(t, "/usr/lib/node_modules/glob/package.json",
		[]byte(`{"name":"glob","version":"10.5.0","author":{"name":"isaacs","version":"x"}}`),
		"/usr/lib/node_modules/glob/index.js", []byte("glob"))
	stated := packagesNamed(t, document, "glob")
	if len(stated) != 1 {
		t.Fatalf("document states %d glob packages, want 1", len(stated))
	}
	if got, want := locatorOf(t, stated[0]), "pkg:npm/glob@10.5.0"; got != want {
		t.Errorf("purl = %q, want %q", got, want)
	}
}
