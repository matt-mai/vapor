package attest_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// documentedVectors reads the element identity vectors from the reference page, so an
// edit to the encoding or to the page breaks a test instead of drifting.
var documentedVectors = regexp.MustCompile("(?s)```json\n(.*?)\n```\n\nDigest:\n\n```text\n(sha256:[a-f0-9]{64})\n```")

func TestElementIdentities_DocumentedVectors(t *testing.T) {
	data, err := os.ReadFile("../../docs/developer/attest.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "## Element identities\n")
	if !ok {
		t.Fatal("element identity section missing")
	}
	section, _, _ = strings.Cut(section, "## Platform to subject\n")
	vectors := documentedVectors.FindAllStringSubmatch(section, -1)
	if len(vectors) != 3 {
		t.Fatalf("got %d element vectors, want 3", len(vectors))
	}
	for _, vector := range vectors {
		digest := recomputeVector(t, vector[1])
		if digest != vector[2] {
			t.Fatalf("payload %s digest = %s, want %s", vector[1], digest, vector[2])
		}
	}
}

// recomputeVector hashes one documented payload through the domain its keys name, so
// the vector proves the code, not a second implementation of the same formula.
func recomputeVector(t *testing.T, payload string) string {
	t.Helper()
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	canonical, err := attest.Encode(document)
	if err != nil {
		t.Fatalf("encode vector: %v", err)
	}
	if string(canonical) != payload {
		t.Fatalf("vector %s is not canonical JSON", payload)
	}
	domain := vectorDomain(t, document)
	digest, err := attest.Identity(domain, document)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return digest
}

func vectorDomain(t *testing.T, document map[string]any) string {
	t.Helper()
	_, hasPackage := document["package"]
	_, hasIdentity := document["identity"]
	switch {
	case hasPackage:
		return attest.DomainSlices
	case hasIdentity:
		return attest.DomainArtifact
	default:
		return attest.DomainPackage
	}
}
