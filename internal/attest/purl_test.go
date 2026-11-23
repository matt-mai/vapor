package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/attestation"
)

// TestPackageURL_IsTheSameEverywhere checks the one identity both payloads use, including
// the escaping a name with characters outside the URL-safe set needs.
func TestPackageURL_IsTheSameEverywhere(t *testing.T) {
	input, _ := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	vex := newVEXInput()
	vex.Claims = []attestation.VEXAssertion{
		assertion("CVE-2026-0030", "coreutils", "fixed"),
	}
	claims, err := attest.CompileClaims(vex)
	if err != nil {
		t.Fatalf("CompileClaims: %v", err)
	}
	if want := packageNamed(t, document, "coreutils"); len(want.ExternalRefs) != 1 ||
		want.ExternalRefs[0].ReferenceLocator != claims[0].Products[0] {
		t.Fatalf("SPDX says %v, VEX says %v", want.ExternalRefs, claims[0].Products)
	}
}

// TestPackageURL_NamesTheSourcePackage checks the upstream qualifier: advisories are
// published per source package, so a binary whose source is named differently has to
// say so, and a binary that is its own source says nothing extra.
func TestPackageURL_NamesTheSourcePackage(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Packages[0].Source = "coreutils-src"
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	locator := packageNamed(t, decodeSBOM(t, payload), "coreutils").ExternalRefs[0].ReferenceLocator
	if !strings.Contains(locator, "upstream=coreutils-src") {
		t.Fatalf("locator = %q, want the source package", locator)
	}

	input, _ = newSBOMFixture()
	input.Packages[0].Source = "coreutils"
	payload, err = attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	locator = packageNamed(t, decodeSBOM(t, payload), "coreutils").ExternalRefs[0].ReferenceLocator
	if strings.Contains(locator, "upstream=") {
		t.Fatalf("locator = %q, want no upstream qualifier", locator)
	}
}

// TestImportClaims_ReadsEncodedProducts checks that an imported product with escaped
// characters and qualifiers is decoded before it is matched, and that an unreadable one
// is refused rather than skipped.
func TestImportClaims_ReadsEncodedProducts(t *testing.T) {
	cases := map[string]struct{ purl, want string }{
		"escaped version": {
			"pkg:deb/ubuntu/coreutils@9.4%2B3ubuntu1", "is not in the lock"},
		"subpath": {
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1#/usr/bin/ls", "carries a subpath"},
		"no type":   {"pkg:coreutils@9.4", "has no type and name"},
		"not a url": {"coreutils", "is not a package URL"},
		"bad escape": {
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=%zz", "unreadable qualifier"},
	}
	for name, testCase := range cases {
		document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
			openVEXStatement("CVE-2026-0031", testCase.purl, "fixed", ""),
		)))
		if err != nil {
			t.Fatalf("%s: DecodeVEXDocument: %v", name, err)
		}
		_, err = attest.ImportClaims(newVEXInput(), document)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if !strings.Contains(err.Error(), testCase.want) {
			t.Fatalf("%s: %v, want %s", name, err, testCase.want)
		}
	}
}

// TestImportClaims_MatchesQualifiers checks the matching rule from both sides: a stated
// qualifier has to agree, and an omitted one constrains nothing.
func TestImportClaims_MatchesQualifiers(t *testing.T) {
	cases := map[string]struct {
		purl    string
		matched bool
	}{
		"omitted qualifiers": {"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1", true},
		"matching arch": {
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64", true},
		"architecture independent": {
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=all", false},
		"matching distro": {
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?distro=ubuntu-26.04", true},
		"stale version":   {"pkg:deb/ubuntu/coreutils@9.3-1", false},
		"wrong namespace": {"pkg:deb/debian/coreutils@9.4-3ubuntu1", false},
	}
	for name, testCase := range cases {
		document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
			openVEXStatement("CVE-2026-0032", testCase.purl, "fixed", ""),
		)))
		if err != nil {
			t.Fatalf("%s: DecodeVEXDocument: %v", name, err)
		}
		_, err = attest.ImportClaims(newVEXInput(), document)
		if testCase.matched && err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
		if !testCase.matched && err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
