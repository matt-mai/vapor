package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
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
