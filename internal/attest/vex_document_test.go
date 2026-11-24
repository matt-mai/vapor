package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// TestDecodeVEXDocument_ReadsAPublishedShape checks the document a security team
// publishes in the shape the OpenVEX v0.2.0 specification defines.
func TestDecodeVEXDocument_ReadsAPublishedShape(t *testing.T) {
	document, err := attest.DecodeVEXDocument([]byte(openVEXDocument(
		openVEXStatement("CVE-2026-0020", "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1",
			"not_affected",
			`"justification": "vulnerable_code_not_present",
			"impact_statement": "the package does not ship the affected code"`),
	)))
	if err != nil {
		t.Fatalf("DecodeVEXDocument: %v", err)
	}
	if document.Context != "https://openvex.dev/ns/v0.2.0" || len(document.Statements) != 1 {
		t.Fatalf("document = %+v", document)
	}
	statement := document.Statements[0]
	if statement.Status != "not_affected" ||
		statement.Justification != "vulnerable_code_not_present" {
		t.Fatalf("statement = %+v", statement)
	}
}

// TestDecodeVEXDocument_RefusesForeignInput covers everything an imported document may
// not be: another format, another version, two documents, an unknown field, a statement
// about nothing and a claim nobody can act on.
func TestDecodeVEXDocument_RefusesForeignInput(t *testing.T) {
	statement := openVEXStatement("CVE-2026-0021", "pkg:deb/ubuntu/coreutils@9.4", "fixed", "")
	cases := map[string]string{
		"other context": strings.Replace(openVEXDocument(statement),
			"https://openvex.dev/ns/v0.2.0", "https://openvex.dev/ns/v0.1.0", 1),
		"missing author": strings.Replace(openVEXDocument(statement), `"author": "Example Security Team",`, "", 1),
		"bad timestamp":  strings.Replace(openVEXDocument(statement), "2026-11-20T09:00:00Z", "yesterday", 1),
		"zero version":   strings.Replace(openVEXDocument(statement), `"version": 1`, `"version": 0`, 1),
		"no statements":  strings.Replace(openVEXDocument(statement), statement, "", 1),
		"unknown field":  strings.Replace(openVEXDocument(statement), `"status"`, `"confidence": "high", "status"`, 1),
		"unknown status": strings.Replace(openVEXDocument(statement), `"fixed"`, `"probably_fine"`, 1),
		"no products":    strings.Replace(openVEXDocument(statement), `"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/coreutils@9.4"}}],`, "", 1),
		"product hashes": strings.Replace(openVEXDocument(statement), `"purl": "pkg:deb/ubuntu/coreutils@9.4"`, `"purl": "pkg:deb/ubuntu/coreutils@9.4"}}, {"hashes": {"sha256": "aa"`, 1),
		"two documents":  openVEXDocument(statement) + openVEXDocument(statement),
		"blank vulnerability": strings.Replace(openVEXDocument(statement), `"name": "CVE-2026-0021"`,
			`"name": " "`, 1),
		"affected without action": strings.Replace(openVEXDocument(statement), `"status": "fixed"`,
			`"status": "affected"`, 1),
		"not_affected without justification": strings.Replace(openVEXDocument(statement),
			`"status": "fixed"`, `"status": "not_affected"`, 1),
		"vulnerability alias": strings.Replace(openVEXDocument(statement),
			`"name": "CVE-2026-0021"`, `"name": "CVE-2026-0021", "aliases": ["GHSA-aaaa-bbbb-cccc"]`, 1),
	}
	for name, input := range cases {
		if _, err := attest.DecodeVEXDocument([]byte(input)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeVEXDocument_RefusesAnAlias checks that a statement naming the same issue by a
// second identifier is refused: Vapor publishes one name per claim, so an accepted alias
// would let two claims about one vulnerability look like two different ones.
func TestDecodeVEXDocument_RefusesAnAlias(t *testing.T) {
	statement := strings.Replace(openVEXDocument(openVEXStatement("CVE-2026-0021",
		"pkg:deb/ubuntu/coreutils@9.4", "fixed", "")),
		`"name": "CVE-2026-0021"`,
		`"name": "CVE-2026-0021", "aliases": ["GHSA-aaaa-bbbb-cccc"]`, 1)
	_, err := attest.DecodeVEXDocument([]byte(statement))
	if err == nil || !strings.Contains(err.Error(), "aliases are not supported") {
		t.Fatalf("error = %v", err)
	}
}

// TestDecodeVEXDocument_RefusesProductsWithoutAPurl covers the component identities Vapor
// cannot check: a bare identifier that is not a package URL, and a purl that disagrees
// with the component identifier.
func TestDecodeVEXDocument_RefusesProductsWithoutAPurl(t *testing.T) {
	cases := map[string]string{
		"not a package url": openVEXStatement("CVE-2026-0022", "coreutils", "fixed", ""),
		"disagreeing id": `{"@id": "pkg:generic/other@1", "identifiers": {"purl":
			"pkg:deb/ubuntu/coreutils@9.4"}, "status": "fixed"}`,
	}
	for name, product := range cases {
		input := `{"@context": "https://openvex.dev/ns/v0.2.0",
			"@id": "https://example.invalid/vex/2026-11-20.json", "author": "Example",
			"timestamp": "2026-11-20T09:00:00Z", "version": 1,
			"statements": [{"vulnerability": {"name": "CVE-2026-0022"},
			"products": [` + product + `]}]}`
		if _, err := attest.DecodeVEXDocument([]byte(input)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeVEXDocument_RefusesOversizedInput checks the size bound before decoding, so a
// hostile input cannot exhaust memory.
func TestDecodeVEXDocument_RefusesOversizedInput(t *testing.T) {
	huge := make([]byte, (4<<20)+1)
	for position := range huge {
		huge[position] = ' '
	}
	_, err := attest.DecodeVEXDocument(huge)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

// TestDecodeVEXDocument_RefusesTooManyStatements checks the statement bound, so a
// document cannot make generation do unbounded work.
func TestDecodeVEXDocument_RefusesTooManyStatements(t *testing.T) {
	statement := openVEXStatement("CVE-2026-0023", "pkg:deb/ubuntu/coreutils@9.4", "fixed", "")
	statements := make([]string, 1001)
	for position := range statements {
		statements[position] = statement
	}
	_, err := attest.DecodeVEXDocument([]byte(openVEXDocument(statements...)))
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("error = %v", err)
	}
}

// TestOpenVEX_AcceptsTheCPEItWrites checks that a document Vapor renders reads back. A
// product states its purl and the declared CPE beside it, so the importer has to accept
// both or Vapor refuses its own output.
func TestOpenVEX_AcceptsTheCPEItWrites(t *testing.T) {
	document := `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex/x.json", "author": "Example", "timestamp": "2026-11-20T09:00:00Z", "version": 1,
"statements": [{"vulnerability": {"name": "CVE-2026-0070"},
"products": [{"@id": "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64",
"identifiers": {"purl": "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64",
"cpe": "cpe:2.3:a:gnu:coreutils:9.4-3ubuntu1:*:*:*:*:*:*:*"}}],
"status": "fixed"}]}`
	parsed, err := attest.DecodeVEXDocument([]byte(document))
	if err != nil {
		t.Fatalf("ImportOpenVEX: %v", err)
	}
	if len(parsed.Statements) != 1 || len(parsed.Statements[0].Products) != 1 {
		t.Fatalf("statements = %v", parsed.Statements)
	}
}

// TestOpenVEX_RefusesAnUnknownIdentifier keeps the importer to the identities it can
// check: a swid or an unsupported key would be dropped silently, and a dropped identity is
// a claim Vapor appears to have read but did not.
func TestOpenVEX_RefusesAnUnknownIdentifier(t *testing.T) {
	document := `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex/x.json", "author": "Example", "timestamp": "2026-11-20T09:00:00Z", "version": 1,
"statements": [{"vulnerability": {"name": "CVE-2026-0071"},
"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64",
"swid": "something"}}],
"status": "fixed"}]}`
	if _, err := attest.DecodeVEXDocument([]byte(document)); err == nil {
		t.Fatal("an unsupported identifier was accepted")
	}
}

// TestOpenVEX_RefusesAMalformedCPE checks the declared-CPE grammar on import, so a
// document cannot introduce a name the specification could never have declared.
func TestOpenVEX_RefusesAMalformedCPE(t *testing.T) {
	document := `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex/x.json", "author": "Example", "timestamp": "2026-11-20T09:00:00Z", "version": 1,
"statements": [{"vulnerability": {"name": "CVE-2026-0072"},
"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64",
"cpe": "not-a-cpe"}}],
"status": "fixed"}]}`
	if _, err := attest.DecodeVEXDocument([]byte(document)); err == nil {
		t.Fatal("a malformed cpe was accepted")
	}
}
