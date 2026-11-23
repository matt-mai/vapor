package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// in-toto statement v1 wraps a predicate in the shape every attestation shares: what
// the statement is about, what kind of claim it carries, and the claim itself.
const statementTypeV1 = "https://in-toto.io/Statement/v1"

// Payload types and predicate types of the statements Vapor writes. A payload type
// names the wrapper, a predicate type names the claim inside it; both are signed, so
// neither can be relabelled after the fact.
const (
	// PayloadTypeInToto names an in-toto statement inside a DSSE envelope.
	PayloadTypeInToto = "application/vnd.in-toto+json"
	// PayloadTypeVEX names a bare OpenVEX document inside a DSSE envelope.
	PayloadTypeVEX = "application/vnd.openvex+json"

	// PredicateTypeSPDX names an SPDX document used as the predicate of a statement.
	PredicateTypeSPDX = "https://spdx.dev/Document"
	// PredicateTypeSLSA names a SLSA v1 provenance predicate.
	PredicateTypeSLSA = "https://slsa.dev/provenance/v1"
	// PredicateTypeOpenVEX names an OpenVEX document used as a predicate.
	PredicateTypeOpenVEX = "https://openvex.dev/ns/v0.2.0"
)

// ResourceDescriptor describes one thing a statement is about: its name and the
// digest that identifies the bytes (an algorithm-to-hex map; Vapor writes sha256
// only). The specification allows more fields; Vapor writes only what the build can
// support, so nothing in a descriptor is a guess.
type ResourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest"`
}

// Statement wraps a predicate so a document can be attached and verified as an
// in-toto statement rather than as a bare file. The result is canonical JSON, so the
// predicate's keys are ordered once by the same pass that orders the wrapper.
func Statement(predicateType string, subject ResourceDescriptor, predicate any) ([]byte, error) {
	if predicateType == "" {
		return nil, errors.New("attest: statement requires a predicate type")
	}
	if !strings.HasPrefix(predicateType, "https://") {
		return nil, fmt.Errorf("attest: predicate type %q is not a URI", predicateType)
	}
	if len(subject.Digest["sha256"]) != 64 {
		return nil, errors.New("attest: statement requires the subject digest")
	}
	if predicate == nil {
		return nil, errors.New("attest: statement requires a predicate")
	}
	wrapped := statementWrapper{
		Type:          statementTypeV1,
		Subject:       []ResourceDescriptor{subject},
		PredicateType: predicateType,
		Predicate:     predicate,
	}
	return Encode(wrapped)
}

// DocumentStatement wraps a payload that is already a complete document (SPDX,
// OpenVEX) in a statement. The document is decoded first, so a payload that is not a
// JSON object is refused instead of being embedded as raw bytes.
func DocumentStatement(predicateType, subjectDigest, name string, document []byte) ([]byte, error) {
	predicate, err := decodeObject(document)
	if err != nil {
		return nil, err
	}
	return Statement(predicateType, ResourceDescriptor{
		Name:   name,
		Digest: map[string]string{"sha256": strings.TrimPrefix(subjectDigest, "sha256:")},
	}, predicate)
}

// decodeObject reads a payload into a generic JSON object, numbers intact, so it can
// be embedded as a predicate without re-encoding the document by hand.
func decodeObject(document []byte) (any, error) {
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("attest: predicate is not JSON: %w", err)
	}
	if _, ok := decoded.(map[string]any); !ok {
		return nil, errors.New("attest: predicate must be a JSON object")
	}
	return decoded, nil
}

// statementWrapper is the in-toto statement with a decoded predicate. The predicate
// is held as a decoded object so the encoder sorts its keys once, in the same pass
// that orders the wrapper.
type statementWrapper struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     any                  `json:"predicate"`
}
