package attest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// vexTree holds the files the claims below talk about plus a symlink that reaches one of
// them, because a claim must not be satisfied by the link rather than the file.
func newVEXInputWithTree(t *testing.T) *attest.VEXInput {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: "coreutils", Path: "pool/coreutils.deb"}
	for _, entry := range []struct{ path, data, target string }{
		{path: "/usr"}, {path: "/usr/bin"}, {path: "/etc"}, {path: "/opt"},
		{path: "/usr/bin/coreutils", data: "coreutils"},
		{path: "/usr/bin/vulnerable", data: "vulnerable"},
		{path: "/etc/alias", target: "/usr/bin/vulnerable"},
		{path: "/dangling", target: "/nowhere"},
	} {
		var err error
		switch {
		case entry.target != "":
			err = tree.Symlink(entry.path, entry.target, vfs.Attrs{Mode: 0o777, Origin: origin})
		case entry.data != "":
			err = tree.File(entry.path, []byte(entry.data), vfs.Attrs{Mode: 0o755, Origin: origin})
		default:
			err = tree.Dir(entry.path, vfs.Attrs{Mode: 0o755, Origin: origin})
		}
		if err != nil {
			t.Fatalf("build tree: %v", err)
		}
	}
	input := newVEXInput()
	input.Name = "fixture-image"
	input.Subject = "sha256:" + strings.Repeat("ee", 32)
	input.Tree = tree
	input.AbsentChecks = true
	return input
}

func vexAssertion(vulnerability, packageName, status string) attestation.VEXAssertion {
	return assertion(vulnerability, packageName, status)
}

func decodeVEX(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode VEX payload: %v", err)
	}
	return document
}

// TestVEX_IsAnOpenVEXDocument checks the document header a reader needs: the context that
// makes it v0.2.0, a required author and timestamp, and an identifier that changes with
// the image it describes.
func TestVEX_IsAnOpenVEXDocument(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0040", "coreutils",
		attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	document := decodeVEX(t, payload)
	if document["@context"] != "https://openvex.dev/ns/v0.2.0" ||
		document["author"] != "vaporize" || document["timestamp"] != "1970-01-01T00:00:00Z" {
		t.Fatalf("document = %v", document)
	}
	want := "https://mattnet.de/vapor/vex/fixture-image/linux/amd64/" + strings.Repeat("ee", 32)
	if document["@id"] != want {
		t.Fatalf("@id = %v, want %s", document["@id"], want)
	}
}

// TestVEX_PublishesOnlyCheckedClaims checks the default: a not_affected claim without any
// path that would hold the vulnerable code is refused instead of published.
func TestVEX_PublishesOnlyCheckedClaims(t *testing.T) {
	input := newVEXInputWithTree(t)
	claim := vexAssertion("CVE-2026-0041", "coreutils", attestation.StatusNotAffected)
	claim.Justification = new("vulnerable_code_not_present")
	input.Claims = []attestation.VEXAssertion{claim}
	_, err := attest.VEX(input)
	if err == nil {
		t.Fatal("a not_affected claim without evidence was published")
	}
	if !strings.Contains(err.Error(), "no absent path shows why") {
		t.Fatalf("error = %v", err)
	}
}

// TestVEX_RefusesAPathTheImageHolds checks the evidence itself: a claim is only published
// when every path it names is missing.
func TestVEX_RefusesAPathTheImageHolds(t *testing.T) {
	input := newVEXInputWithTree(t)
	claim := vexAssertion("CVE-2026-0042", "coreutils", attestation.StatusNotAffected)
	claim.Justification = new("vulnerable_code_not_present")
	claim.AbsentPaths = []string{"/usr/bin/missing", "/usr/bin/vulnerable"}
	input.Claims = []attestation.VEXAssertion{claim}
	_, err := attest.VEX(input)
	if err == nil {
		t.Fatal("a claim was published while the image held the path")
	}
	if !strings.Contains(err.Error(), "/usr/bin/vulnerable is in the image") {
		t.Fatalf("error = %v", err)
	}
}

// TestVEX_ChecksTheResolvedPath checks that a claim cannot pass by naming a link whose
// target is in the image, and that a link to nothing counts as absent.
func TestVEX_ChecksTheResolvedPath(t *testing.T) {
	input := newVEXInputWithTree(t)
	throughLink := vexAssertion("CVE-2026-0043", "coreutils", attestation.StatusNotAffected)
	throughLink.Justification = new("vulnerable_code_not_present")
	throughLink.AbsentPaths = []string{"/etc/alias"}
	input.Claims = []attestation.VEXAssertion{throughLink}
	if _, err := attest.VEX(input); err == nil {
		t.Fatal("a claim passed by naming a link to a file in the image")
	}

	dangling := vexAssertion("CVE-2026-0044", "coreutils", attestation.StatusNotAffected)
	dangling.Justification = new("vulnerable_code_not_present")
	dangling.AbsentPaths = []string{"/dangling", "/usr/bin/vulnerable-x"}
	input.Claims = []attestation.VEXAssertion{dangling}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("a dangling link made the claim fail: %v", err)
	}
	if statements := decodeVEX(t, payload)["statements"].([]any); len(statements) != 1 {
		t.Fatalf("statements = %v", statements)
	}
}

// TestVEX_RefusesAnUnresolvablePath checks that a path Vapor cannot resolve refuses the
// claim: "could not check" must never be published as "not there".
func TestVEX_RefusesAnUnresolvablePath(t *testing.T) {
	input := newVEXInputWithTree(t)
	claim := vexAssertion("CVE-2026-0045", "coreutils", attestation.StatusNotAffected)
	claim.Justification = new("vulnerable_code_not_present")
	claim.AbsentPaths = []string{"/usr/bin/coreutils/inside"}
	input.Claims = []attestation.VEXAssertion{claim}
	_, err := attest.VEX(input)
	if err == nil || !strings.Contains(err.Error(), "cannot be checked") {
		t.Fatalf("error = %v", err)
	}
}

// TestVEX_DisabledCheckIsAVisibleWaiver checks the remaining rule: with the switch off, the
// claim is published but says that nothing verified it.
func TestVEX_DisabledCheckIsAVisibleWaiver(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.AbsentChecks = false
	claim := vexAssertion("CVE-2026-0046", "coreutils", attestation.StatusNotAffected)
	claim.Justification = new("component_not_present")
	input.Claims = []attestation.VEXAssertion{claim}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	statement := decodeVEX(t, payload)["statements"].([]any)[0].(map[string]any)
	if statement["status_notes"] != attest.VEXWaiver {
		t.Fatalf("status_notes = %v", statement["status_notes"])
	}
}

// TestVEX_RefusesAbsentPathsOnAnotherStatus checks that a path on a status that cannot
// mean absence is refused rather than silently dropped: it would look checked.
func TestVEX_RefusesAbsentPathsOnAnotherStatus(t *testing.T) {
	input := newVEXInputWithTree(t)
	claim := vexAssertion("CVE-2026-0047", "coreutils", attestation.StatusFixed)
	claim.AbsentPaths = []string{"/usr/bin/missing"}
	input.Claims = []attestation.VEXAssertion{claim}
	if _, err := attest.VEX(input); err == nil {
		t.Fatal("absent paths on a fixed claim were accepted")
	}
}

// TestVEX_MergesInlineAndImportedClaims checks that both sources reach one payload and
// that a claim about every platform appears once per platform.
func TestVEX_MergesInlineAndImportedClaims(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0048", "coreutils",
		attestation.StatusFixed)}
	document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
		openVEXStatement("CVE-2026-0049", "pkg:deb/ubuntu/libc6@2.41-1", "under_investigation", ""),
	)))
	if err != nil {
		t.Fatalf("DecodeVEXDocument: %v", err)
	}
	imported, err := attest.ImportClaims(input, document)
	if err != nil {
		t.Fatalf("ImportClaims: %v", err)
	}
	input.Imported = imported
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	statements := decodeVEX(t, payload)["statements"].([]any)
	if len(statements) != 2 {
		t.Fatalf("statements = %v", statements)
	}
	named := statements[0].(map[string]any)["vulnerability"].(map[string]any)["name"]
	if named != "CVE-2026-0048" {
		t.Fatalf("first statement = %v", statements[0])
	}
}

// TestVEX_RefusesAClaimSetThatStatesNothing checks a claim that names no product here: it
// claims nothing about this image, and a document has to state something, so no document
// is produced instead of an empty one.
func TestVEX_RefusesAClaimSetThatStatesNothing(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{{
		Vulnerability: "CVE-2026-0050", Status: attestation.StatusFixed,
		Statement: "Reviewed by the maintainers",
	}}
	if _, err := attest.VEX(input); !errors.Is(err, attest.ErrNoClaims) {
		t.Fatalf("VEX: %v, want ErrNoClaims", err)
	}
}

// TestVEX_RefusesAClaimThePlatformCannotSupply checks the case the plan calls a
// platform-only artifact: a claim about an artifact locked on amd64 only is refused for
// arm64 instead of being published without a product, and instead of being dropped.
func TestVEX_RefusesAClaimThePlatformCannotSupply(t *testing.T) {
	arm := newVEXInputWithTree(t)
	arm.Platform = "linux/arm64"
	arm.Claims = []attestation.VEXAssertion{{
		Vulnerability: "CVE-2026-0050", Artifact: new("server-cert"),
		Status: attestation.StatusFixed, Statement: "Reviewed by the maintainers",
	}}
	_, err := attest.VEX(arm)
	if err == nil || !strings.Contains(err.Error(), "is not locked on linux/arm64") {
		t.Fatalf("error = %v", err)
	}
}

// TestVEX_KeepsEachPlatformApart checks that a claim resolved for amd64 names the amd64
// product only when the arm64 payload is rendered.
func TestVEX_KeepsEachPlatformApart(t *testing.T) {
	amd64 := newVEXInputWithTree(t)
	amd64.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0051", "coreutils",
		attestation.StatusFixed)}
	arm64 := newVEXInputWithTree(t)
	arm64.Platform = "linux/arm64"
	arm64.Claims = amd64.Claims

	first, err := attest.VEX(amd64)
	if err != nil {
		t.Fatalf("VEX amd64: %v", err)
	}
	second, err := attest.VEX(arm64)
	if err != nil {
		t.Fatalf("VEX arm64: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("both platforms produced the same document")
	}
	if !strings.Contains(string(second), "arch=arm64") ||
		strings.Contains(string(second), "arch=amd64") {
		t.Fatalf("arm64 payload names the wrong product: %s", second)
	}
}

// TestVEX_IsByteStable checks that two renderings of the same input are identical, which
// is what makes an attached payload reproducible.
func TestVEX_IsByteStable(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{
		vexAssertion("CVE-2026-0052", "coreutils", attestation.StatusFixed),
		vexAssertion("CVE-2026-0053", "libc6", attestation.StatusUnderInvestigation),
	}
	first, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	second, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("two renderings differ")
	}
}

// TestVEX_IsOrderIndependent checks that listing the same claims in another order produces
// the same bytes, so a specification edit that only reorders changes nothing.
func TestVEX_IsOrderIndependent(t *testing.T) {
	first := newVEXInputWithTree(t)
	first.Claims = []attestation.VEXAssertion{
		vexAssertion("CVE-2026-0054", "coreutils", attestation.StatusFixed),
		vexAssertion("CVE-2026-0055", "libc6", attestation.StatusFixed),
	}
	second := newVEXInputWithTree(t)
	second.Claims = []attestation.VEXAssertion{first.Claims[1], first.Claims[0]}
	one, err := attest.VEX(first)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	two, err := attest.VEX(second)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	if !bytes.Equal(one, two) {
		t.Fatalf("order changed the payload:\n%s\n%s", one, two)
	}
}

// TestVEX_NoHostPathOrClock checks the payload for everything it may not carry.
func TestVEX_NoHostPathOrClock(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0056", "coreutils",
		attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	for _, forbidden := range []string{"/home/", "/tmp/", "example.invalid", "pool/",
		"last_updated", "action_statement", "supplier", "tooling", "aliases"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("payload contains %q: %s", forbidden, payload)
		}
	}
}

// TestVEX_HasOnlyPublishedFields checks the payload against the field set the OpenVEX
// v0.2.0 specification defines for the objects Vapor writes.
func TestVEX_HasOnlyPublishedFields(t *testing.T) {
	input := newVEXInputWithTree(t)
	claim := vexAssertion("CVE-2026-0057", "coreutils", attestation.StatusNotAffected)
	claim.Justification = new("vulnerable_code_not_present")
	claim.AbsentPaths = []string{"/usr/bin/vulnerable"}
	claim.AbsentPaths = []string{"/usr/bin/elsewhere"}
	input.Claims = []attestation.VEXAssertion{
		claim, vexAssertion("CVE-2026-0058", "libc6", attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	checkFields(t, decodeVEX(t, payload), "", map[string]map[string]bool{
		"": {
			"@context": true, "@id": true, "author": true, "timestamp": true,
			"version": true, "statements": true,
		},
		"statements": {
			"vulnerability": true, "products": true, "status": true,
			"justification": true, "status_notes": true,
			"action_statement": true, "impact_statement": true,
		},
		"statements.vulnerability": {"name": true},
		"statements.products":      {"@id": true},
	})
}

// TestVEX_RefusesIncompleteInput checks the header inputs, since a payload without them
// would identify nothing.
func TestVEX_RefusesIncompleteInput(t *testing.T) {
	cases := map[string]func(*attest.VEXInput){
		"no name":     func(input *attest.VEXInput) { input.Name = "" },
		"unsafe name": func(input *attest.VEXInput) { input.Name = "a b" },
		"no subject":  func(input *attest.VEXInput) { input.Subject = "" },
		"digestless":  func(input *attest.VEXInput) { input.Subject = strings.Repeat("ee", 32) },
		"no tree":     func(input *attest.VEXInput) { input.Tree = nil },
		"no platform": func(input *attest.VEXInput) { input.Platform = "" },
		"unknown package": func(input *attest.VEXInput) {
			input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0059", "curl", attestation.StatusFixed)}
		},
	}
	for name, breakInput := range cases {
		input := newVEXInputWithTree(t)
		if name != "unknown package" {
			input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0060", "coreutils",
				attestation.StatusFixed)}
		}
		breakInput(input)
		if _, err := attest.VEX(input); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestVEX_ChecksAnImportedAbsenceAgainstTheInlineEvidence is the case where both sources
// state the same not_affected claim: the document names no path, the specification's own
// claim names one, and the image decides. The imported claim is published because the
// evidence that proves it was already given.
func TestVEX_ChecksAnImportedAbsenceAgainstTheInlineEvidence(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{{
		Vulnerability: "CVE-2026-0051", Package: new("coreutils"),
		Status:        attestation.StatusNotAffected,
		Justification: new("vulnerable_code_not_present"),
		AbsentPaths:   []string{"/usr/bin/gone"},
	}}
	document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
		openVEXStatement("CVE-2026-0051",
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64&distro=ubuntu-26.04",
			"not_affected", `"justification": "vulnerable_code_not_present"`),
	)))
	if err != nil {
		t.Fatalf("DecodeVEXDocument: %v", err)
	}
	imported, err := attest.ImportClaims(input, document)
	if err != nil {
		t.Fatalf("ImportClaims: %v", err)
	}
	input.Imported = imported
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	statements := decodeVEX(t, payload)["statements"].([]any)
	if len(statements) != 1 {
		t.Fatalf("statements = %v, want the claim stated once", statements)
	}
	status := statements[0].(map[string]any)["status"]
	if status != "not_affected" {
		t.Fatalf("status = %v", status)
	}

	// The same evidence still decides the claim: a path the image holds refuses it.
	held := newVEXInputWithTree(t)
	held.Claims = []attestation.VEXAssertion{{
		Vulnerability: "CVE-2026-0051", Package: new("coreutils"),
		Status:        attestation.StatusNotAffected,
		Justification: new("vulnerable_code_not_present"),
		AbsentPaths:   []string{"/usr/bin/vulnerable"},
	}}
	held.Imported = imported
	if _, err := attest.VEX(held); err == nil ||
		!strings.Contains(err.Error(), "is in the image") {
		t.Fatalf("VEX with a present path: %v", err)
	}
}

// TestVEX_ProductsJoinTheSBOMPurls checks the promise both payloads make: a claim names a
// product the SPDX document also writes for the same element, so a reader can join them
// without translating names. A sliced package and an artifact are the elements SPDX used
// to leave without a purl at all, so they are the cases that matter.
func TestVEX_ProductsJoinTheSBOMPurls(t *testing.T) {
	sbom, _ := newSBOMFixture()
	payload, err := attest.SPDX(sbom)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	locators := map[string]bool{}
	for _, element := range decodeSBOM(t, payload).Packages {
		for _, reference := range element.ExternalRefs {
			locators[reference.ReferenceLocator] = true
		}
	}
	vexInput := &attest.VEXInput{Platform: sbom.Platform, Distro: sbom.Distro,
		Release: sbom.Release, Packages: sbom.Packages, Slices: sbom.Slices,
		Artifacts: sbom.Artifacts,
		Claims: []attestation.VEXAssertion{
			vexAssertion("CVE-2026-0050", "coreutils", attestation.StatusFixed),
			vexAssertion("CVE-2026-0051", "libc6", attestation.StatusFixed),
		}}
	claims, err := attest.CompileClaims(vexInput)
	if err != nil {
		t.Fatalf("CompileClaims: %v", err)
	}
	document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
		openVEXStatement("CVE-2026-0052", "pkg:generic/server@1.0", "fixed", ""))))
	if err != nil {
		t.Fatalf("DecodeVEXDocument: %v", err)
	}
	artifact, err := attest.ImportClaims(vexInput, document)
	if err != nil {
		t.Fatalf("ImportClaims: %v", err)
	}
	for _, claim := range append(claims, artifact...) {
		if len(claim.Products) == 0 {
			t.Fatalf("%s resolves to no product", claim.Vulnerability)
		}
		for _, product := range claim.Products {
			if !locators[product] {
				t.Fatalf("%s resolves to %q, which no SPDX element carries",
					claim.Vulnerability, product)
			}
		}
	}
	if len(locators) != 3 {
		t.Fatalf("SPDX purls = %v, want one per element", locators)
	}
}

// TestVEX_StatesTheDeclaredCPE checks the finding that started this: the CPE the lock
// records reaches the OpenVEX product beside the purl. A scanner matches a package by URL
// and finds nothing in a database that files the vendor's advisories under a CPE name.
func TestVEX_StatesTheDeclaredCPE(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Packages[0].CPE = nodeCPE
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0080", "coreutils",
		attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	document := decodeVEX(t, payload)
	statements, ok := document["statements"].([]any)
	if !ok || len(statements) != 1 {
		t.Fatalf("statements = %v", document["statements"])
	}
	product := statements[0].(map[string]any)["products"].([]any)[0].(map[string]any)
	identifiers, ok := product["identifiers"].(map[string]any)
	if !ok {
		t.Fatalf("identifiers = %v, want a cpe beside the purl", product)
	}
	if identifiers["cpe"] != nodeCPE {
		t.Fatalf("cpe = %v, want %s", identifiers["cpe"], nodeCPE)
	}
	if !strings.HasPrefix(identifiers["purl"].(string), "pkg:deb/ubuntu/coreutils@") {
		t.Fatalf("purl = %v", identifiers["purl"])
	}
}

// TestVEX_OmitsIdentifiersWhenNoCPEIsDeclared keeps a document for a package without a
// declared CPE as it was: the URL alone identifies it, and an empty identifier map would
// claim an identity nobody stated.
func TestVEX_OmitsIdentifiersWhenNoCPEIsDeclared(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0081", "coreutils",
		attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	document := decodeVEX(t, payload)
	statements := document["statements"].([]any)
	product := statements[0].(map[string]any)["products"].([]any)[0].(map[string]any)
	if _, present := product["identifiers"]; present {
		t.Fatalf("product = %v, want no identifiers", product)
	}
}

// TestVEX_WildcardCPETakesTheLockedVersion holds the VEX document to the same rule as the
// SPDX document: a `*` version names the version the lock recorded.
func TestVEX_WildcardCPETakesTheLockedVersion(t *testing.T) {
	input := newVEXInputWithTree(t)
	input.Packages[0].CPE = "cpe:2.3:a:gnu:coreutils:*:*:*:*:*:*:*:*"
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0082", "coreutils",
		attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	document := decodeVEX(t, payload)
	statements := document["statements"].([]any)
	product := statements[0].(map[string]any)["products"].([]any)[0].(map[string]any)
	identifiers := product["identifiers"].(map[string]any)
	if identifiers["cpe"] != "cpe:2.3:a:gnu:coreutils:9.4-3ubuntu1:*:*:*:*:*:*:*" {
		t.Fatalf("cpe = %v", identifiers["cpe"])
	}
}

// TestVEX_NamesTheVendorForItsOwnRepository checks that VEX and SPDX answer the vendor
// question the same way. Both documents name a product by its package URL, so a package
// one names as the vendor's and the other as the distribution's would be two products to
// a reader matching them against each other.
func TestVEX_NamesTheVendorForItsOwnRepository(t *testing.T) {
	repository := lock.Repository{ID: "sha256:" + strings.Repeat("2", 64), Name: "nodesource",
		Platform: "linux/amd64", Suite: "nodistro", Identity: contents.RepositoryIdentityOwn}
	input := newVEXInputWithTree(t)
	input.Repositories = []lock.Repository{repository}
	input.Packages[0].Repository = repository.ID
	input.Claims = []attestation.VEXAssertion{vexAssertion("CVE-2026-0060", "coreutils",
		attestation.StatusFixed)}
	payload, err := attest.VEX(input)
	if err != nil {
		t.Fatalf("VEX: %v", err)
	}
	document := decodeVEX(t, payload)
	statements := document["statements"].([]any)
	product := statements[0].(map[string]any)["products"].([]any)[0].(map[string]any)
	for _, want := range []string{"pkg:deb/nodesource/coreutils@", "distro=nodesource-nodistro"} {
		if identifier, _ := product["@id"].(string); !strings.Contains(identifier, want) {
			t.Fatalf("@id = %v, want %s", product["@id"], want)
		}
	}
}
