package attest_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// TestDocumentStatement_WrapsADocument checks the wrapper a document needs before it
// can be attached: the statement type, its one subject, the predicate type that names
// the document and the document itself unchanged.
func TestDocumentStatement_WrapsADocument(t *testing.T) {
	document := []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",` +
		`"packages":[{"name":"coreutils"}]}`)
	subject := "sha256:" + strings.Repeat("ab", 32)
	encoded, err := attest.DocumentStatement(attest.PredicateTypeSPDX, subject, "app amd64", document)
	if err != nil {
		t.Fatalf("DocumentStatement: %v", err)
	}
	var statement map[string]any
	if err := json.Unmarshal(encoded, &statement); err != nil {
		t.Fatalf("decode statement: %v", err)
	}
	if statement["_type"] != "https://in-toto.io/Statement/v1" {
		t.Fatalf("_type = %v", statement["_type"])
	}
	if statement["predicateType"] != "https://spdx.dev/Document" {
		t.Fatalf("predicateType = %v", statement["predicateType"])
	}
	subjects := statement["subject"].([]any)
	if len(subjects) != 1 {
		t.Fatalf("subject = %v", subjects)
	}
	descriptor := subjects[0].(map[string]any)
	if descriptor["name"] != "app amd64" {
		t.Fatalf("subject name = %v", descriptor["name"])
	}
	if descriptor["digest"].(map[string]any)["sha256"] != strings.Repeat("ab", 32) {
		t.Fatalf("subject digest = %v", descriptor["digest"])
	}
	predicate := statement["predicate"].(map[string]any)
	if predicate["spdxVersion"] != "SPDX-2.3" || predicate["SPDXID"] != "SPDXRef-DOCUMENT" {
		t.Fatalf("predicate = %v", predicate)
	}
	if !bytes.Contains(encoded, []byte(`"name":"coreutils"`)) {
		t.Fatalf("the document's own encoding did not survive: %s", encoded)
	}
}

// TestDocumentStatement_KeepsNumbers checks that a document's numbers are embedded as
// written. Decoding into float64 would turn a size into 1e+06 and change bytes nobody
// asked to change.
func TestDocumentStatement_KeepsNumbers(t *testing.T) {
	document := []byte(`{"size":1234567,"ratio":0.5,"count":0}`)
	encoded, err := attest.DocumentStatement(attest.PredicateTypeOpenVEX,
		"sha256:"+strings.Repeat("cd", 32), "app", document)
	if err != nil {
		t.Fatalf("DocumentStatement: %v", err)
	}
	for _, literal := range []string{`"size":1234567`, `"ratio":0.5`, `"count":0`} {
		if !bytes.Contains(encoded, []byte(literal)) {
			t.Fatalf("number written as something else: %s", encoded)
		}
	}
	if bytes.Contains(encoded, []byte("e+06")) || bytes.Contains(encoded, []byte("1.234567e")) {
		t.Fatalf("a number was reformatted: %s", encoded)
	}
}

// TestStatement_RefusesBrokenWrappers checks each way a wrapper can be wrong. A
// statement that names nothing, or names a claim type that is not a URI, is not
// evidence and is refused rather than written.
func TestStatement_RefusesBrokenWrappers(t *testing.T) {
	subject := attest.ResourceDescriptor{
		Name: "app", Digest: map[string]string{"sha256": strings.Repeat("ef", 32)},
	}
	cases := map[string]struct {
		predicateType string
		subject       attest.ResourceDescriptor
		predicate     any
		want          string
	}{
		"no predicate type": {"", subject, map[string]any{}, "predicate type"},
		"relative URI":      {"spdx.dev/Document", subject, map[string]any{}, "not a URI"},
		"no subject digest": {
			attest.PredicateTypeSPDX, attest.ResourceDescriptor{}, map[string]any{},
			"subject digest",
		},
		"short digest": {
			attest.PredicateTypeSPDX,
			attest.ResourceDescriptor{Digest: map[string]string{"sha256": "abcd"}},
			map[string]any{}, "subject digest",
		},
		"no predicate": {attest.PredicateTypeSPDX, subject, nil, "predicate"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := attest.Statement(test.predicateType, test.subject, test.predicate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Statement = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := attest.DocumentStatement(attest.PredicateTypeSPDX, "sha256:"+
		strings.Repeat("ef", 32), "app", []byte(`[1,2]`)); err == nil ||
		!strings.Contains(err.Error(), "must be a JSON object") {
		t.Fatalf("DocumentStatement on an array = %v", err)
	}
	if _, err := attest.DocumentStatement(attest.PredicateTypeSPDX, "sha256:"+
		strings.Repeat("ef", 32), "app", []byte(`{`)); err == nil ||
		!strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("DocumentStatement on broken JSON = %v", err)
	}
}

// TestStatement_IsCanonical checks that a wrapped payload is stable and that its keys
// are sorted at every level, so two runs of the same evidence agree byte for byte.
func TestStatement_IsCanonical(t *testing.T) {
	document := []byte(`{"zeta":1,"alpha":{"b":2,"a":[3,{"y":4,"x":5}]}}`)
	subject := "sha256:" + strings.Repeat("01", 32)
	first, err := attest.DocumentStatement(attest.PredicateTypeSPDX, subject, "app", document)
	if err != nil {
		t.Fatal(err)
	}
	second, err := attest.DocumentStatement(attest.PredicateTypeSPDX, subject, "app", document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("two wrappers of one document differ:\n%s\n%s", first, second)
	}
	if !bytes.HasPrefix(first, []byte(`{"_type":`)) {
		t.Fatalf("the statement's fields are not sorted: %s", first)
	}
	found := bytes.Contains(first, []byte(`"alpha":{"a":[3,{"x":5,"y":4}],"b":2}`))
	if !found {
		t.Fatalf("the predicate's keys are not sorted: %s", first)
	}
}

// TestPayloadTypes matches the values published by the specifications, because these
// strings are what a verifier dispatches on.
func TestPayloadTypes(t *testing.T) {
	expected := map[string]string{
		attest.PayloadTypeInToto:    "application/vnd.in-toto+json",
		attest.PayloadTypeVEX:       "application/vnd.openvex+json",
		attest.PredicateTypeSPDX:    "https://spdx.dev/Document",
		attest.PredicateTypeSLSA:    "https://slsa.dev/provenance/v1",
		attest.PredicateTypeOpenVEX: "https://openvex.dev/ns/v0.2.0",
	}
	for actual, want := range expected {
		if actual != want {
			t.Fatalf("payload or predicate type = %q, want %q", actual, want)
		}
	}
}
