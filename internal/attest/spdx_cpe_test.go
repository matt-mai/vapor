package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

const nodeCPE = "cpe:2.3:a:nodejs:node.js:26.13.1:*:*:*:*:*:*:*"

// TestSPDX_DeclaresCPEForPackagesAndSlices checks that a declared CPE reaches the
// document beside the purl. A vendor package's advisories are filed under a name the
// package URL cannot reach, so the CPE is the only handle a scanner has on it.
func TestSPDX_DeclaresCPEForPackagesAndSlices(t *testing.T) {
	cases := map[string]struct {
		apply  func(*attest.SBOMInput)
		name   string
		absent bool
	}{
		"whole package carries its cpe": {
			apply: func(input *attest.SBOMInput) { input.Packages[0].CPE = nodeCPE },
			name:  "coreutils",
		},
		"sliced package carries its cpe": {
			apply: func(input *attest.SBOMInput) { input.Slices[0].CPE = nodeCPE },
			name:  "libc6",
		},
		"undeclared cpe is written by nobody": {
			apply:  func(*attest.SBOMInput) {},
			name:   "coreutils",
			absent: true,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			input, _ := newSBOMFixture()
			testCase.apply(input)
			payload, err := attest.SPDX(input)
			if err != nil {
				t.Fatalf("SPDX: %v", err)
			}
			refs := packageNamed(t, decodeSBOM(t, payload), testCase.name).ExternalRefs
			var found string
			for _, ref := range refs {
				if ref.ReferenceType == "cpe23Type" {
					found = ref.ReferenceLocator
				}
			}
			if testCase.absent && found != "" {
				t.Fatalf("cpe = %q, want none", found)
			}
			if !testCase.absent && found != nodeCPE {
				t.Fatalf("cpe = %q, want %q", found, nodeCPE)
			}
		})
	}
}

// TestSPDX_CPESitsBesideThePurl checks the reference a package keeps: the purl names the
// package and the CPE names the advisory database's entry for it, and a scanner reads
// both from one element.
func TestSPDX_CPESitsBesideThePurl(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Packages[0].CPE = nodeCPE
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	refs := packageNamed(t, decodeSBOM(t, payload), "coreutils").ExternalRefs
	if len(refs) != 2 {
		t.Fatalf("refs = %v, want a purl and a cpe", refs)
	}
	if refs[0].ReferenceType != "purl" || refs[1].ReferenceType != "cpe23Type" {
		t.Fatalf("refs = %v, want the purl first and the cpe second", refs)
	}
	if !strings.Contains(refs[0].ReferenceLocator, "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1") {
		t.Fatalf("purl = %q, want the package URL", refs[0].ReferenceLocator)
	}
}

// TestSPDX_WildcardCPETakesTheLockedVersion checks the promise the reference makes: a
// declared `*` in the version field names the version the lock recorded. Passing the
// declaration through verbatim would hand a scanner an all-versions identifier, and the
// document is the only place the resolved name can appear.
func TestSPDX_WildcardCPETakesTheLockedVersion(t *testing.T) {
	cases := map[string]struct {
		apply func(*attest.SBOMInput)
		name  string
		want  string
	}{
		"whole package": {
			apply: func(input *attest.SBOMInput) {
				input.Packages[0].CPE = "cpe:2.3:a:gnu:coreutils:*:*:*:*:*:*:*:*"
			},
			name: "coreutils",
			want: "cpe:2.3:a:gnu:coreutils:9.4-3ubuntu1:*:*:*:*:*:*:*",
		},
		"sliced package": {
			apply: func(input *attest.SBOMInput) { input.Slices[0].CPE = "cpe:2.3:a:gnu:libc6:*:*:*:*:*:*:*:*" },
			name:  "libc6",
			want:  "cpe:2.3:a:gnu:libc6:2.41-1:*:*:*:*:*:*:*",
		},
		"fixed version is left alone": {
			apply: func(input *attest.SBOMInput) { input.Packages[0].CPE = nodeCPE },
			name:  "coreutils",
			want:  nodeCPE,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			input, _ := newSBOMFixture()
			testCase.apply(input)
			payload, err := attest.SPDX(input)
			if err != nil {
				t.Fatalf("SPDX: %v", err)
			}
			refs := packageNamed(t, decodeSBOM(t, payload), testCase.name).ExternalRefs
			var found string
			for _, ref := range refs {
				if ref.ReferenceType == "cpe23Type" {
					found = ref.ReferenceLocator
				}
			}
			if found != testCase.want {
				t.Fatalf("cpe = %q, want %q", found, testCase.want)
			}
		})
	}
}

// TestSPDX_EscapesAnEpochVersion keeps a Debian version's epoch inside one CPE field. A
// colon is the field separator, so substituting the version verbatim would hand a scanner
// a fourteen-field name, which Vapor's own importer refuses.
func TestSPDX_EscapesAnEpochVersion(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Packages[0].Version = "1:9.4-3ubuntu1"
	input.Packages[0].CPE = "cpe:2.3:a:gnu:coreutils:*:*:*:*:*:*:*:*"
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	refs := packageNamed(t, decodeSBOM(t, payload), "coreutils").ExternalRefs
	var found string
	for _, ref := range refs {
		if ref.ReferenceType == "cpe23Type" {
			found = ref.ReferenceLocator
		}
	}
	if !strings.Contains(found, `1\:9.4-3ubuntu1`) {
		t.Fatalf("cpe = %q, want the epoch escaped", found)
	}
	if err := contents.ValidateCPE(found); err != nil {
		t.Fatalf("ValidateCPE(%q) = %v", found, err)
	}
}
