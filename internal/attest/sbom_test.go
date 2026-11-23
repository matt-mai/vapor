package attest_test

import (
	"crypto/sha1" // #nosec G505 -- the fixture mirrors the format's mandatory SHA-1.
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// sbomFixture is one platform's locked records and the tree built from them: a whole
// package, a slice of another package, an artifact, a declared path, a file that a
// slice script rewrote and a synthesized file nothing locked contributed.
type sbomFixture struct {
	packageFile, modifiedFile, sliceFile, artifactFile, declaredFile, synthesized string
	license, noLicense                                                            string
	// The element identifiers are the documented domain-separated identities, so they
	// are computed here rather than spelled out.
	packageElement, sliceElement, artifactElement string
}

func newSBOMFixture() (*attest.SBOMInput, sbomFixture) {
	tree := vfs.New()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(tree.Dir("/usr", vfs.Attrs{Mode: 0o755, Origin: vfs.Origin{Package: "coreutils",
		Path: "pool/coreutils.deb"}}))
	must(tree.Dir("/usr/bin", vfs.Attrs{Mode: 0o755, Origin: vfs.Origin{Package: "coreutils",
		Path: "pool/coreutils.deb"}}))
	must(tree.File("/usr/bin/coreutils", []byte("coreutils"), vfs.Attrs{Mode: 0o755,
		Origin: vfs.Origin{Package: "coreutils", Path: "pool/coreutils.deb"}}))
	must(tree.File("/etc/motd", []byte("rewritten"), vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Package: "libc6", Slice: "libc6_libs", Path: "pool/libc6.deb"}}))
	must(tree.File("/usr/bin/tool", []byte("tool"), vfs.Attrs{Mode: 0o755,
		Origin: vfs.Origin{Package: "libc6", Slice: "libc6_libs", Path: "pool/libc6.deb"}}))
	must(tree.File("/usr/bin/server", []byte("server"), vfs.Attrs{Mode: 0o755,
		Origin: vfs.Origin{Package: "server-cert", Path: "https://example.invalid/server"}}))
	must(tree.File("/etc/vapor/config", []byte("config"), vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Path: "filesystem.paths"}}))
	must(tree.File("/etc/os-release", []byte("PRETTY_NAME=\"Vapor\"\n"), vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Path: "filesystem.os-release"}}))
	must(tree.File("/usr/share/doc/coreutils/copyright", []byte("Copyright coreutils"),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: "coreutils",
			Path: "pool/coreutils.deb"}}))

	input := &attest.SBOMInput{
		Name: "fixture-image", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ee", 32),
		Distro:  "ubuntu",
		Release: "26.04",
		Packages: []lock.Package{{Platform: "linux/amd64", Name: "coreutils", Version: "9.4-3ubuntu1",
			Architecture: "amd64", Content: lock.Content{Path: "pool/coreutils.deb",
				SHA256: strings.Repeat("a", 64), Size: 1234}}},
		Slices: []lock.Slice{{Platform: "linux/amd64", Package: "libc6", Version: "2.41-1",
			Architecture: "all", Content: lock.Content{Path: "pool/libc6.deb",
				SHA256: strings.Repeat("b", 64), Size: 5678},
			// Selected and Closure differ on purpose: the element identity covers the
			// dependency-first closure the contract names, not the requested slices.
			Selected: []string{"libs"}, Closure: []string{"core", "libs"},
			DefinitionDigest: "sha256:" + strings.Repeat("d", 64)}},
		Artifacts: []lock.Artifact{{Name: "server-cert", Platform: "linux/amd64",
			URL:    "https://example.invalid/server",
			SHA256: strings.Repeat("c", 64), Size: 9012, Dest: "/usr/bin/server",
			SBOM: contents.ArtifactIdentity{Name: "server", Version: "1.0"}}},
		Tree: tree,
		Original: map[string]string{
			"/etc/motd": digestOf([]byte("original")),
		},
	}
	return input, sbomFixture{
		packageElement: mustIdentity(attest.PackageIdentity("linux/amd64", "coreutils",
			"9.4-3ubuntu1", "amd64", strings.Repeat("a", 64), 1234)),
		sliceElement: mustIdentity(attest.SlicesIdentity("linux/amd64", "libc6",
			"2.41-1", "all", strings.Repeat("d", 64), strings.Repeat("b", 64), 5678,
			[]string{"core", "libs"})),
		artifactElement: mustIdentity(attest.ArtifactIdentity("linux/amd64", "server-cert",
			attest.ArtifactVersion{Name: "server", Version: "1.0"}, strings.Repeat("c", 64), 9012)),
		packageFile:  "SPDXRef-File--usr-bin-coreutils",
		modifiedFile: "SPDXRef-File--etc-motd",
		sliceFile:    "SPDXRef-File--usr-bin-tool",
		artifactFile: "SPDXRef-File--usr-bin-server",
		declaredFile: "SPDXRef-File--etc-vapor-config",
		synthesized:  "SPDXRef-File--etc-os-release",
		license:      "SPDXRef-File--usr-share-doc-coreutils-copyright",
		noLicense:    "SPDXRef-File--usr-bin-tool",
	}
}

// mustIdentity is the identifier grammar test fixtures use, where a failed identity is
// a broken fixture rather than a result to report.
func mustIdentity(identity string, err error) string {
	if err != nil {
		panic(err)
	}
	return identity
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func digestOfSHA1(content []byte) string {
	sum := sha1.Sum(content)
	return hex.EncodeToString(sum[:])
}

// TestSBOMs_DisabledSkipsGeneration checks that a disabled SBOM produces no payload
// and no error, which is what keeps provenance and VEX independent of it.
func TestSBOMs_DisabledSkipsGeneration(t *testing.T) {
	input, _ := newSBOMFixture()
	payloads, err := attest.SBOMs(false, []attest.SBOMInput{*input})
	if err != nil || payloads != nil {
		t.Fatalf("disabled sbom = %v %v", payloads, err)
	}
	payloads, err = attest.SBOMs(true, []attest.SBOMInput{*input})
	if err != nil || len(payloads) != 1 {
		t.Fatalf("enabled sbom = %d %v", len(payloads), err)
	}
}

// TestSPDX_SliceElementDescribesThePackage checks that a sliced package is one element
// named after its package. An advisory is filed under the package, so an element per
// slice would report the same finding once per slice. The name, the purl and the version
// therefore describe the package, and the comment is the only place the slices appear.
func TestSPDX_SliceElementDescribesThePackage(t *testing.T) {
	input, wanted := newSBOMFixture()
	selectedOnly := mustIdentity(attest.SlicesIdentity("linux/amd64", "libc6",
		"2.41-1", "all", strings.Repeat("d", 64), strings.Repeat("b", 64), 5678,
		[]string{"libs"}))
	document := decodeSBOM(t, mustSPDX(t, input))
	found := packageNamed(t, document, spdxID(wanted.sliceElement))
	if found.Name != "libc6" {
		t.Fatalf("slice element name = %q, want the package it was cut from", found.Name)
	}
	if !strings.Contains(found.Comment, "slices core, libs") {
		t.Fatalf("slice element comment = %q, want it to name the locked slices", found.Comment)
	}
	// The closure is an input, the requested slices are not: nothing else would notice a
	// writer that folded every slice of a package together whatever the lock selected.
	if found.SPDXID == spdxID(selectedOnly) {
		t.Fatal("the identifier repeats the requested slices instead of the locked closure")
	}
}

// TestSPDX_RefusesASliceOutsideTheLockedClosure checks that a tree entry cannot name a
// slice the lock does not hold: the identity is built from the lock, so an unknown slice
// name would be published as if the closure had included it.
func TestSPDX_RefusesASliceOutsideTheLockedClosure(t *testing.T) {
	tree := vfs.New()
	if err := tree.File("/usr/lib/libc.so", []byte("libc"), vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Package: "libc6", Slice: "libc6_missing",
			Path: "pool/libc6.deb"}}); err != nil {
		t.Fatal(err)
	}
	input := &attest.SBOMInput{Name: "slices", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ee", 32), Distro: "ubuntu", Release: "26.04",
		Slices: []lock.Slice{{Platform: "linux/amd64", Package: "libc6", Version: "2.41-1",
			Architecture: "all", Content: lock.Content{Path: "pool/libc6.deb",
				SHA256: strings.Repeat("b", 64), Size: 5678},
			Selected: []string{"libs"}, Closure: []string{"core", "libs"},
			DefinitionDigest: "sha256:" + strings.Repeat("d", 64)}},
		Tree: tree}
	if _, err := attest.SPDX(input); err == nil {
		t.Fatal("a slice outside the locked closure was published")
	} else if !strings.Contains(err.Error(), "not in the locked closure") {
		t.Fatalf("error = %v", err)
	}
}

// TestSPDX_KeepsSlicesOfDifferentPackagesApart checks the grouping the document uses to
// join contributors. Two packages can both have a "libs" slice, and the tree names them
// "libc6_libs" and "libssl3_libs"; grouping by the short slice name alone would put both
// sets of files under one element and report the other package as absent.
func TestSPDX_KeepsSlicesOfDifferentPackagesApart(t *testing.T) {
	// The two slices have to be the same in every other respect, so the slice name is
	// the only thing that could merge them.
	shared := lock.Slice{Platform: "linux/amd64", Version: "2.41-1", Architecture: "all",
		Content:  lock.Content{Path: "pool/shared.deb", SHA256: strings.Repeat("b", 64), Size: 5678},
		Selected: []string{"libs"}, Closure: []string{"libs"},
		DefinitionDigest: "sha256:" + strings.Repeat("d", 64)}
	libc6, libssl3 := shared, shared
	libc6.Package, libssl3.Package = "libc6", "libssl3"

	tree := vfs.New()
	for _, contributed := range []struct{ path, owner string }{
		{"/usr/lib/libc.so", "libc6"},
		{"/usr/lib/libssl.so", "libssl3"},
	} {
		if err := tree.File(contributed.path, []byte(contributed.owner),
			vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: contributed.owner,
				Slice: contributed.owner + "_libs", Path: "pool/shared.deb"}}); err != nil {
			t.Fatal(err)
		}
	}
	input := &attest.SBOMInput{Name: "slices", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ee", 32), Distro: "ubuntu", Release: "26.04",
		Slices: []lock.Slice{libc6, libssl3}, Tree: tree}

	document := decodeSBOM(t, mustSPDX(t, input))
	sliced := make([]sbomPackage, 0, 2)
	for position := range document.Packages {
		if strings.HasPrefix(document.Packages[position].Comment, "This package is present as slices ") {
			sliced = append(sliced, document.Packages[position])
		}
	}
	if len(sliced) != 2 {
		t.Fatalf("%d slice elements, want one per package: %+v", len(sliced), sliced)
	}
	if sliced[0].SPDXID == sliced[1].SPDXID {
		t.Fatalf("two packages' slices share the identifier %s", sliced[0].SPDXID)
	}
	// Each element must be joined to the files its own package contributed.
	owning := map[string][]string{}
	for _, relationship := range document.Relationships {
		if relationship.RelationshipType == "CONTAINS" {
			owning[relationship.SPDXElementID] = append(owning[relationship.SPDXElementID],
				relationship.RelatedSPDXElement)
		}
	}
	for _, element := range sliced {
		wanted := ""
		switch element.Name {
		case "libc6":
			wanted = "libc.so"
		case "libssl3":
			wanted = "libssl.so"
		default:
			t.Fatalf("unexpected slice element %q", element.Name)
		}
		joined := owning[element.SPDXID]
		if len(joined) != 1 || !strings.HasSuffix(joined[0], wanted) {
			t.Fatalf("%s contains %v, want only the %s file", element.SPDXID, joined, wanted)
		}
	}
}
