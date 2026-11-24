package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

// OpenVEX v0.2.0 is the only imported format. Its documents are JSON-LD objects whose
// statements claim a status for a product; Vapor reads them and never looks anything up.
const (
	openVEXContext = "https://openvex.dev/ns/v0.2.0"
	// MaxVEXDocumentSize bounds an imported document before it is read or decoded, so a
	// caller can refuse an oversized input without allocating for it.
	MaxVEXDocumentSize = 4 << 20
	maxVEXStatements   = 1000
)

// VEXDocument is one imported OpenVEX v0.2.0 document. It keeps the fields Vapor reads
// and discards the rest, so nothing a document says about its author or its age reaches
// an image.
type VEXDocument struct {
	Context     string         `json:"@context"`
	ID          string         `json:"@id"`
	Author      string         `json:"author"`
	Role        string         `json:"role,omitempty"`
	Timestamp   string         `json:"timestamp"`
	LastUpdated string         `json:"last_updated,omitempty"`
	Version     int            `json:"version"`
	Tooling     string         `json:"tooling,omitempty"`
	Statements  []VEXStatement `json:"statements"`
}

// VEXStatement is one claim in an imported document.
type VEXStatement struct {
	ID                       string           `json:"@id,omitempty"`
	Version                  int              `json:"version,omitempty"`
	Vulnerability            VEXVulnerability `json:"vulnerability"`
	Timestamp                string           `json:"timestamp,omitempty"`
	LastUpdated              string           `json:"last_updated,omitempty"`
	Products                 []VEXComponent   `json:"products,omitempty"`
	Status                   string           `json:"status"`
	Supplier                 string           `json:"supplier,omitempty"`
	StatusNotes              string           `json:"status_notes,omitempty"`
	Justification            string           `json:"justification,omitempty"`
	ImpactStatement          string           `json:"impact_statement,omitempty"`
	ActionStatement          string           `json:"action_statement,omitempty"`
	ActionStatementTimestamp string           `json:"action_statement_timestamp,omitempty"`
}

// VEXVulnerability identifies the vulnerability a statement is about.
type VEXVulnerability struct {
	ID          string   `json:"@id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

// VEXComponent is a product or a subcomponent in an imported document.
type VEXComponent struct {
	ID            string            `json:"@id,omitempty"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Hashes        map[string]string `json:"hashes,omitempty"`
	Subcomponents []VEXComponent    `json:"subcomponents,omitempty"`
}

// DecodeVEXDocument reads one imported document. Unknown fields, a foreign context and
// any statement Vapor could not check against the lock are refused rather than ignored,
// because an assertion that cannot be checked must not reach an image.
func DecodeVEXDocument(data []byte) (*VEXDocument, error) {
	if len(data) > MaxVEXDocumentSize {
		return nil, fmt.Errorf("attest: OpenVEX document exceeds %d bytes", MaxVEXDocumentSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document VEXDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("attest: decode OpenVEX document: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, errors.New("attest: OpenVEX input must be exactly one JSON document")
	}
	if err := document.validate(); err != nil {
		return nil, err
	}
	return &document, nil
}

func (document *VEXDocument) validate() error {
	switch {
	case document.Context != openVEXContext:
		return fmt.Errorf("attest: unsupported OpenVEX context %q, want %q",
			document.Context, openVEXContext)
	case document.ID == "" || !absoluteIRI(document.ID):
		return errors.New("attest: OpenVEX @id must be an absolute IRI")
	case strings.TrimSpace(document.Author) == "":
		return errors.New("attest: an OpenVEX document requires an author")
	case document.Version < 1:
		return errors.New("attest: OpenVEX document version must be at least 1")
	case len(document.Statements) == 0:
		return errors.New("attest: an OpenVEX document must contain a statement")
	case len(document.Statements) > maxVEXStatements:
		return fmt.Errorf("attest: OpenVEX document has more than %d statements", maxVEXStatements)
	}
	if err := requireTimestamps(document); err != nil {
		return err
	}
	for position := range document.Statements {
		if err := document.Statements[position].validate(); err != nil {
			return fmt.Errorf("attest: OpenVEX statements[%d]: %w", position, err)
		}
	}
	return nil
}

func requireTimestamps(document *VEXDocument) error {
	if err := requireTimestamp("timestamp", document.Timestamp); err != nil {
		return err
	}
	if document.LastUpdated == "" {
		return nil
	}
	return requireTimestamp("last_updated", document.LastUpdated)
}

func requireTimestamp(field, value string) error {
	if value == "" {
		return fmt.Errorf("attest: OpenVEX %s is required", field)
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("attest: OpenVEX %s %q is not a timestamp", field, value)
	}
	return nil
}

func (statement *VEXStatement) validate() error {
	if err := statement.Vulnerability.validate(); err != nil {
		return err
	}
	if !attestation.IsVEXStatus(statement.Status) {
		return fmt.Errorf("unsupported status %q", statement.Status)
	}
	if len(statement.Products) == 0 {
		return errors.New("every imported statement must name the products it is about")
	}
	for position := range statement.Products {
		if err := statement.Products[position].validate(); err != nil {
			return fmt.Errorf("products[%d]: %w", position, err)
		}
	}
	if err := validateStatementTimestamps(statement); err != nil {
		return err
	}
	return statement.validateClaim()
}

func validateStatementTimestamps(statement *VEXStatement) error {
	for _, entry := range []struct{ field, value string }{
		{"timestamp", statement.Timestamp},
		{"last_updated", statement.LastUpdated},
		{"action_statement_timestamp", statement.ActionStatementTimestamp},
	} {
		if entry.value == "" {
			continue
		}
		if err := requireTimestamp(entry.field, entry.value); err != nil {
			return err
		}
	}
	return nil
}

// explanation is what an imported statement says in its own words, in the field its
// status publishes it under. A statement without one states a status and nothing a
// reader could act on.
func (statement *VEXStatement) explanation() string {
	if statement.ActionStatement != "" {
		return statement.ActionStatement
	}
	if statement.ImpactStatement != "" {
		return statement.ImpactStatement
	}
	return ""
}

// validateClaim applies the requirements the published schema expresses as conditions:
// a reader that skipped them would accept a statement nobody can act on.
func (statement *VEXStatement) validateClaim() error {
	switch statement.Status {
	case attestation.StatusNotAffected:
		if !attestation.IsVEXJustification(statement.Justification) {
			return fmt.Errorf("not_affected requires a justification, not %q", statement.Justification)
		}
	case attestation.StatusAffected:
		if strings.TrimSpace(statement.ActionStatement) == "" {
			return errors.New("affected requires an action_statement")
		}
	}
	return nil
}

func (vulnerability *VEXVulnerability) validate() error {
	// An alias names the same issue under another identifier, so accepting one and
	// publishing only the name would hide that two claims are about one vulnerability.
	if len(vulnerability.Aliases) != 0 {
		return errors.New("vulnerability aliases are not supported")
	}
	name := vulnerability.Name
	if name == "" || strings.TrimSpace(name) != name || strings.ContainsFunc(name,
		func(ch rune) bool { return ch < ' ' || ch == '\u2028' || ch == '\u2029' }) {
		return errors.New("vulnerability name must be a nonblank single-line identifier")
	}
	return nil
}

// validate keeps a product to the identities Vapor can check: the purl it matches the
// lock by and the declared CPE it publishes beside it. A CPE names an advisory
// database's entry for a package whose purl reaches none, so a document Vapor wrote has
// to be readable again with one.
func (component *VEXComponent) validate() error {
	switch {
	case len(component.Hashes) != 0:
		return errors.New("product hashes are not supported")
	case len(component.Subcomponents) != 0:
		return errors.New("product subcomponents are not supported")
	}
	if err := component.validateIdentifiers(); err != nil {
		return err
	}
	if identified, changed := component.Identifiers["purl"]; changed {
		if component.ID != "" && component.ID != identified {
			return errors.New("product @id and purl disagree")
		}
		return nil
	}
	if !strings.HasPrefix(component.ID, "pkg:") {
		return errors.New("product must be identified by a purl")
	}
	return nil
}

// validateIdentifiers keeps a product to the two names Vapor can check, each stated
// once and each usable as an identity.
func (component *VEXComponent) validateIdentifiers() error {
	if len(component.Identifiers) > 2 {
		return errors.New("only purl and cpe identifiers are supported")
	}
	for name, value := range component.Identifiers {
		if name != "purl" && name != "cpe" {
			return fmt.Errorf("identifier %q is not supported", name)
		}
		if value == "" {
			return fmt.Errorf("identifier %q is empty", name)
		}
	}
	if cpe, named := component.Identifiers["cpe"]; named {
		if err := contents.ValidateDeclaredCPE(cpe); err != nil {
			return err
		}
	}
	return nil
}

// purl returns the identity validate settled on.
func (component *VEXComponent) purl() string {
	if identified, ok := component.Identifiers["purl"]; ok {
		return identified
	}
	return component.ID
}

func absoluteIRI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs()
}
