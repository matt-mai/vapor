package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// TestSPDX_RefusesATamperedLockDigest checks that an element whose archive digest is
// not a SHA256 is reported instead of published. The lock is the only source of the
// claim a document makes about a package, so a digest it cannot parse is an error,
// exactly as Provenance treats the same input.
func TestSPDX_RefusesATamperedLockDigest(t *testing.T) {
	cases := map[string]func(*attest.SBOMInput){
		"package": func(input *attest.SBOMInput) {
			input.Packages[0].Content.SHA256 = "not-a-digest"
		},
		"package missing": func(input *attest.SBOMInput) {
			input.Packages[0].Content.SHA256 = ""
		},
		"slice": func(input *attest.SBOMInput) {
			input.Slices[0].Content.SHA256 = strings.Repeat("A", 64)
		},
		"slice missing": func(input *attest.SBOMInput) {
			input.Slices[0].Content.SHA256 = ""
		},
		"artifact": func(input *attest.SBOMInput) {
			input.Artifacts[0].SHA256 = strings.Repeat("c", 63)
		},
		"artifact missing": func(input *attest.SBOMInput) {
			input.Artifacts[0].SHA256 = ""
		},
	}
	for name, change := range cases {
		input, _ := newSBOMFixture()
		change(input)
		payload, err := attest.SPDX(input)
		if err == nil {
			t.Fatalf("tampered %s digest accepted into %d bytes", name, len(payload))
		}
		if !strings.Contains(err.Error(), "SHA256 digest") {
			t.Fatalf("tampered %s digest reported %q", name, err)
		}
	}
}

// TestSPDX_RefusesATamperedLockVersion checks that a record with no version cannot be
// described, because the version is what a reader matches a package by.
func TestSPDX_RefusesATamperedLockVersion(t *testing.T) {
	cases := map[string]func(*attest.SBOMInput){
		"package": func(input *attest.SBOMInput) { input.Packages[0].Version = "" },
		"slice":   func(input *attest.SBOMInput) { input.Slices[0].Version = "" },
		"artifact": func(input *attest.SBOMInput) {
			input.Artifacts[0].SBOM.Version = ""
		},
	}
	for name, change := range cases {
		input, _ := newSBOMFixture()
		change(input)
		if _, err := attest.SPDX(input); err == nil {
			t.Fatalf("tampered %s version accepted", name)
		} else if !strings.Contains(err.Error(), "no version") {
			t.Fatalf("tampered %s version reported %q", name, err)
		}
	}
}

// TestSPDX_RefusesATamperedLockName checks that an unnamed contributor is reported
// rather than published under an empty identifier.
func TestSPDX_RefusesATamperedLockName(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Artifacts[0].SBOM.Name = ""
	if _, err := attest.SPDX(input); err == nil {
		t.Fatal("tampered name accepted")
	}
}

// TestSPDX_NormalizesAPrefixedDigest checks that a lock digest carrying its algorithm
// prefix is published as the bare hex SPDX requires, not with the prefix left on.
func TestSPDX_NormalizesAPrefixedDigest(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Packages[0].Content.SHA256 = "sha256:" + strings.Repeat("a", 64)
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	if strings.Contains(string(payload), "sha256:") {
		t.Fatal("algorithm prefix reached the document")
	}
	if !strings.Contains(string(payload), strings.Repeat("a", 64)) {
		t.Fatal("package digest is missing from the document")
	}
}
