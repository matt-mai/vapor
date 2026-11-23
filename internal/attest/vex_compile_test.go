package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/attestation"
)

// TestCompileClaims_ResolvesPackageSelectors checks the package URL an inline claim
// resolves to: it is the same one the SPDX document writes, so a consumer can match the
// two payloads without translating names.
func TestCompileClaims_ResolvesPackageSelectors(t *testing.T) {
	input := newVEXInput()
	input.Claims = []attestation.VEXAssertion{
		assertion("CVE-2026-0001", "coreutils", attestation.StatusFixed),
		assertion("CVE-2026-0002", "libc6", attestation.StatusUnderInvestigation),
	}
	claims, err := attest.CompileClaims(input)
	if err != nil {
		t.Fatalf("CompileClaims: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("claims = %d, want 2", len(claims))
	}
	want := []string{
		"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64&distro=ubuntu-26.04",
		"pkg:deb/ubuntu/libc6@2.41-1?arch=amd64&distro=ubuntu-26.04",
	}
	for position, claim := range claims {
		if len(claim.Products) != 1 || claim.Products[0] != want[position] {
			t.Fatalf("products of %s = %v, want %s", claim.Vulnerability, claim.Products,
				want[position])
		}
	}
}

// TestCompileClaims_ResolvesArtifactSelectors checks that an artifact claim uses the
// upstream identity the specification declares, not the local name it is locked under.
func TestCompileClaims_ResolvesArtifactSelectors(t *testing.T) {
	input := newVEXInput()
	input.Claims = []attestation.VEXAssertion{{
		Vulnerability: "CVE-2026-0003", Artifact: new("server-cert"),
		Status: attestation.StatusFixed, Statement: "Reviewed by the maintainers",
	}}
	claims, err := attest.CompileClaims(input)
	if err != nil {
		t.Fatalf("CompileClaims: %v", err)
	}
	if len(claims) != 1 || len(claims[0].Products) != 1 ||
		claims[0].Products[0] != "pkg:generic/server@1.0" {
		t.Fatalf("claims = %+v", claims)
	}
}

// TestCompileClaims_AllStatusesAndJustifications covers every status and every
// justification the specification accepts, so a label that stops resolving is noticed
// before generation.
func TestCompileClaims_AllStatusesAndJustifications(t *testing.T) {
	for _, status := range []string{attestation.StatusFixed, attestation.StatusAffected,
		attestation.StatusUnderInvestigation} {
		input := newVEXInput()
		input.Claims = []attestation.VEXAssertion{assertion("CVE-2026-0004", "coreutils", status)}
		if claims, err := attest.CompileClaims(input); err != nil || len(claims) != 1 {
			t.Fatalf("%s: %v %v", status, claims, err)
		}
	}
	justifications := []string{"component_not_present", "vulnerable_code_not_present",
		"vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist"}
	for _, justification := range justifications {
		input := newVEXInput()
		claim := assertion("CVE-2026-0005", "coreutils", attestation.StatusNotAffected)
		claim.Justification = new(justification)
		claim.AbsentPaths = []string{"/usr/bin/vulnerable"}
		input.Claims = []attestation.VEXAssertion{claim}
		claims, err := attest.CompileClaims(input)
		if err != nil {
			t.Fatalf("%s: %v", justification, err)
		}
		if claims[0].Justification != justification ||
			len(claims[0].Absent) != 1 || claims[0].Absent[0] != "/usr/bin/vulnerable" {
			t.Fatalf("%s resolved to %+v", justification, claims[0])
		}
	}
}

// TestCompileClaims_RefusesSelectorsThePlatformDoesNotLock checks the ambiguous and
// missing cases: a name locked only on another platform is refused, not silently dropped.
func TestCompileClaims_RefusesSelectorsThePlatformDoesNotLock(t *testing.T) {
	cases := map[string]attestation.VEXAssertion{
		"unknown package": assertion("CVE-2026-0006", "curl", attestation.StatusFixed),
		"unknown artifact": {Vulnerability: "CVE-2026-0007", Artifact: new("nobody"),
			Status: attestation.StatusFixed, Statement: "Reviewed by the maintainers"},
	}
	for name, claim := range cases {
		input := newVEXInput()
		input.Claims = []attestation.VEXAssertion{claim}
		_, err := attest.CompileClaims(input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if !strings.Contains(err.Error(), "is not locked on linux/amd64") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	arm := newVEXInput()
	arm.Platform = "linux/arm64"
	arm.Claims = []attestation.VEXAssertion{
		assertion("CVE-2026-0008", "libc6", attestation.StatusFixed),
	}
	if _, err := attest.CompileClaims(arm); err == nil {
		t.Fatal("a slice locked only on amd64 was claimed on arm64")
	}
}

// TestCompileClaims_RefusesAnUnusablePlatform checks the input contract before any claim
// is looked at, because an empty platform would mean every claim matches nothing.
func TestCompileClaims_RefusesAnUnusablePlatform(t *testing.T) {
	for _, platform := range []string{"", "linux/amd64\x01"} {
		input := newVEXInput()
		input.Platform = platform
		if _, err := attest.CompileClaims(input); err == nil {
			t.Fatalf("platform %q was accepted", platform)
		}
	}
}

// TestImportClaims_ResolvesProductsAgainstTheLock checks that an imported statement
// keeps only the products this platform actually holds.
func TestImportClaims_ResolvesProductsAgainstTheLock(t *testing.T) {
	document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
		openVEXStatement("CVE-2026-0009",
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1", attestation.StatusFixed, ""),
	)))
	if err != nil {
		t.Fatalf("DecodeVEXDocument: %v", err)
	}
	claims, err := attest.ImportClaims(newVEXInput(), document)
	if err != nil {
		t.Fatalf("ImportClaims: %v", err)
	}
	if len(claims) != 1 || claims[0].Vulnerability != "CVE-2026-0009" ||
		len(claims[0].Products) != 1 ||
		claims[0].Products[0] != "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64&distro=ubuntu-26.04" {
		t.Fatalf("claims = %+v", claims)
	}
}

// TestImportClaims_RefusesProductsOutsideTheLock covers the subject mismatches: a product
// the lock does not hold, another architecture, another distribution and another type.
func TestImportClaims_RefusesProductsOutsideTheLock(t *testing.T) {
	cases := map[string]struct{ purl, want string }{
		"unknown package": {"pkg:deb/ubuntu/curl@8.0", "is not in the lock"},
		"other architecture": {
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=arm64", "names architecture \"arm64\""},
		"other distribution": {
			"pkg:deb/debian/coreutils@9.4-3ubuntu1?distro=debian-13", "names distribution \"debian-13\""},
		"other type": {"pkg:rpm/ubuntu/coreutils@9.4", "unsupported product type"},
	}
	for name, testCase := range cases {
		document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
			openVEXStatement("CVE-2026-0010", testCase.purl, attestation.StatusFixed, ""),
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

// TestImportClaims_UsesTheUpstreamIdentity checks that an imported statement about an
// artifact matches through the identity the specification declares.
func TestImportClaims_UsesTheUpstreamIdentity(t *testing.T) {
	document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
		openVEXStatement("CVE-2026-0011", "pkg:generic/server@1.0", attestation.StatusFixed, ""),
	)))
	if err != nil {
		t.Fatalf("DecodeVEXDocument: %v", err)
	}
	claims, err := attest.ImportClaims(newVEXInput(), document)
	if err != nil || len(claims) != 1 || claims[0].Products[0] != "pkg:generic/server@1.0" {
		t.Fatalf("claims = %+v %v", claims, err)
	}
}

// TestCoalesce_MergesIdenticalClaims checks that repeating a claim about another product
// of the same platform produces one claim with both products instead of two statements.
func TestCoalesce_MergesIdenticalClaims(t *testing.T) {
	claims, err := attest.Coalesce([]attest.Claim{
		{Vulnerability: "CVE-2026-0012", Status: attestation.StatusFixed,
			Justification: "", Products: []string{"pkg:generic/b@1"}},
		{Vulnerability: "CVE-2026-0012", Status: attestation.StatusFixed,
			Justification: "", Products: []string{"pkg:generic/a@1"}},
	}, unchecked())
	if err != nil {
		t.Fatalf("Coalesce: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(claims))
	}
	if got := claims[0].Products; len(got) != 2 || got[0] != "pkg:generic/a@1" ||
		got[1] != "pkg:generic/b@1" {
		t.Fatalf("products = %v", got)
	}
}

// TestCoalesce_RefusesConflictingClaims checks the conflict rule: two claims asserting
// different things about one product stop the build instead of one of them winning.
func TestCoalesce_RefusesConflictingClaims(t *testing.T) {
	cases := map[string][]attest.Claim{
		"different status": {
			{Vulnerability: "CVE-2026-0013", Status: attestation.StatusFixed,
				Products: []string{"pkg:generic/a@1"}},
			{Vulnerability: "CVE-2026-0013", Status: attestation.StatusAffected,
				Products: []string{"pkg:generic/a@1"}},
		},
		"different justification": {
			{Vulnerability: "CVE-2026-0014", Status: attestation.StatusNotAffected,
				Justification: "component_not_present", Products: []string{"pkg:generic/a@1"}},
			{Vulnerability: "CVE-2026-0014", Status: attestation.StatusNotAffected,
				Justification: "inline_mitigations_already_exist",
				Products:      []string{"pkg:generic/a@1"}},
		},
	}
	for name, claims := range cases {
		if _, err := attest.Coalesce(claims, unchecked()); err == nil {
			t.Fatalf("%s was accepted", name)
		} else if !strings.Contains(err.Error(), "is claimed for") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestCoalesce_ChecksTheEvidenceOfMatchingClaims checks the case a claim merged from two
// sources is about: the import names no paths, the inline claim about the same product
// names the path that proves it, and the two are one claim rather than a conflict. The
// inline evidence decides it, because the imported claim asserts the same thing and
// carries nothing to check.
func TestCoalesce_ChecksTheEvidenceOfMatchingClaims(t *testing.T) {
	evidence := evidenceFor(t)
	imported := attest.Claim{Vulnerability: "CVE-2026-0031",
		Status: attestation.StatusNotAffected, Justification: "vulnerable_code_not_present",
		Products: []string{"pkg:generic/a@1"}}
	inline := imported
	inline.Absent = []string{"/usr/bin/gone"}
	for name, claims := range map[string][]attest.Claim{
		"import first": {imported, inline},
		"import last":  {inline, imported},
	} {
		merged, err := attest.Coalesce(claims, evidence)
		if err != nil {
			t.Fatalf("%s: Coalesce: %v", name, err)
		}
		if len(merged) != 1 {
			t.Fatalf("%s: claims = %+v, want one", name, merged)
		}
		if absent := merged[0].Absent; len(absent) != 1 || absent[0] != "/usr/bin/gone" {
			t.Fatalf("%s: absent = %v, want the inline path", name, absent)
		}
	}
}

// TestCoalesce_ChecksEachProductAlone checks that merging does not lend one product the
// evidence named for another: an imported statement names no paths, so a product only it
// covers has nothing to check and is refused, even though a claim about another product
// merged into the same statement does name a path.
func TestCoalesce_ChecksEachProductAlone(t *testing.T) {
	inline := attest.Claim{Vulnerability: "CVE-2026-0032",
		Status: attestation.StatusNotAffected, Justification: "vulnerable_code_not_present",
		Products: []string{"pkg:generic/a@1"}, Absent: []string{"/usr/bin/gone"}}
	imported := inline
	imported.Absent = nil
	imported.Products = []string{"pkg:generic/a@1", "pkg:generic/b@1"}
	for name, claims := range map[string][]attest.Claim{
		"import first": {imported, inline},
		"import last":  {inline, imported},
	} {
		_, err := attest.Coalesce(claims, evidenceFor(t))
		if err == nil {
			t.Fatalf("%s: a claim about b was published without evidence", name)
		}
		if !strings.Contains(err.Error(), "no absent path shows why") {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// With the check switched off the claim is published, and the note says the evidence
	// was not checked, so a reader can tell it apart from a checked claim.
	merged, err := attest.Coalesce([]attest.Claim{inline, imported},
		attest.Evidence{Tree: evidenceFor(t).Tree})
	if err != nil {
		t.Fatalf("Coalesce unchecked: %v", err)
	}
	if len(merged) != 1 || len(merged[0].Products) != 2 ||
		!strings.Contains(merged[0].Notes, attest.VEXWaiver) {
		t.Fatalf("merged = %+v", merged)
	}
}

// TestCoalesce_KeepsDistinctClaim checks that two statements about two vulnerabilities
// stay separate, and that the same claim for a different vulnerability is not merged.
func TestCoalesce_KeepsDistinctClaim(t *testing.T) {
	claims, err := attest.Coalesce([]attest.Claim{
		{Vulnerability: "CVE-2026-0016", Status: attestation.StatusFixed,
			Products: []string{"pkg:generic/a@1"}},
		{Vulnerability: "CVE-2026-0017", Status: attestation.StatusFixed,
			Products: []string{"pkg:generic/a@1"}},
	}, unchecked())
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims = %+v %v", claims, err)
	}
}

// TestCoalesce_IsOrderIndependent checks that the order claims arrive in does not change
// the result, so the same inputs always produce the same payload.
func TestCoalesce_IsOrderIndependent(t *testing.T) {
	first := []attest.Claim{
		{Vulnerability: "CVE-2026-0018", Status: attestation.StatusFixed,
			Products: []string{"pkg:generic/a@1"}},
		{Vulnerability: "CVE-2026-0018", Status: attestation.StatusFixed,
			Products: []string{"pkg:generic/b@1"}},
	}
	second := []attest.Claim{first[1], first[0]}
	forward, err := attest.Coalesce(first, unchecked())
	if err != nil {
		t.Fatal(err)
	}
	backward, err := attest.Coalesce(second, unchecked())
	if err != nil {
		t.Fatal(err)
	}
	if len(forward) != 1 || len(backward) != 1 ||
		forward[0].Products[0] != backward[0].Products[0] ||
		forward[0].Products[1] != backward[0].Products[1] {
		t.Fatalf("forward = %+v, backward = %+v", forward, backward)
	}
}

// TestImportClaims_NeedsADocument checks that a missing document is an error rather than
// an empty claim set, so a caller cannot mistake "nothing imported" for "nothing claimed".
func TestImportClaims_NeedsADocument(t *testing.T) {
	_, err := attest.ImportClaims(newVEXInput(), nil)
	if err == nil || !strings.Contains(err.Error(), "no document to import") {
		t.Fatalf("error = %v", err)
	}
}

// TestCoalesce_KeepsTheNotesOfEverySource checks that a note an imported statement carries
// survives the merge even when the matching inline claim, which carries none, was seen
// first. Keeping the first claim's notes would drop the one note a reader can act on.
func TestCoalesce_KeepsTheNotesOfEverySource(t *testing.T) {
	inline := attest.Claim{Vulnerability: "CVE-2026-0033",
		Status:    attestation.StatusNotAffected,
		Products:  []string{"pkg:generic/a@1"},
		Statement: "The vulnerable code is not present."}
	imported := inline
	imported.Notes = "Vendor advisory 42 says the shipped build has the patch."
	for name, claims := range map[string][]attest.Claim{
		"inline first": {inline, imported},
		"import first": {imported, inline},
	} {
		merged, err := attest.Coalesce(claims, unchecked())
		if err != nil {
			t.Fatalf("%s: Coalesce: %v", name, err)
		}
		if len(merged) != 1 {
			t.Fatalf("%s: claims = %+v, want one", name, merged)
		}
		if !strings.Contains(merged[0].Notes, imported.Notes) {
			t.Fatalf("%s: notes = %q, want the imported note", name, merged[0].Notes)
		}
	}
}

// TestCoalesce_DoesNotPadNotes checks that a claim whose evidence adds nothing keeps the
// notes it had byte for byte: trailing whitespace would reach the published payload.
func TestCoalesce_DoesNotPadNotes(t *testing.T) {
	claim := attest.Claim{Vulnerability: "CVE-2026-0034", Status: attestation.StatusFixed,
		Products: []string{"pkg:generic/a@1"},
		Notes:    "Imported from the vendor advisory."}
	merged, err := attest.Coalesce([]attest.Claim{claim}, unchecked())
	if err != nil {
		t.Fatalf("Coalesce: %v", err)
	}
	if len(merged) != 1 || merged[0].Notes != claim.Notes {
		t.Fatalf("notes = %q, want %q", merged[0].Notes, claim.Notes)
	}
}
