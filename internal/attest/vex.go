package attest

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/vfs"
)

// A VEX document requires a timestamp and an author, and a rebuild of the same inputs
// has to produce the same bytes. The epoch and a fixed author therefore stand in for
// the build instead of the clock that ran it.
const (
	vexAuthor    = "vaporize"
	vexNamespace = "https://mattnet.de/vapor/vex/"
	// VEXWaiver is written into a claim whose absent paths were not checked, so a reader
	// sees that the claim rests on nothing this build verified.
	VEXWaiver = "The absent paths of this claim were not checked against the image."
)

// ErrNoClaims reports that nothing a document could state applies to this platform. An
// OpenVEX document has to carry at least one statement, so this platform has none.
var ErrNoClaims = errors.New("attest: no VEX claim applies to this platform")

// VEX returns the canonical bytes of one platform's OpenVEX v0.2.0 document.
//
// Claims are merged first, so a caller can hand over the specification's assertions and
// the statements of an imported document together. Every claim is then checked against
// the finished tree before any of it is rendered: a payload only describes what the
// image holds, and only claims whose evidence holds are published.
func VEX(input *VEXInput) ([]byte, error) {
	document, err := input.document()
	if err != nil {
		return nil, err
	}
	return Encode(document)
}

type vexPayloadDocument struct {
	Context    string                `json:"@context"`
	ID         string                `json:"@id"`
	Author     string                `json:"author"`
	Timestamp  string                `json:"timestamp"`
	Version    int                   `json:"version"`
	Statements []vexPayloadStatement `json:"statements"`
}

type vexPayloadStatement struct {
	Vulnerability   vexPayloadVulnerability `json:"vulnerability"`
	Products        []vexPayloadProduct     `json:"products"`
	Status          string                  `json:"status"`
	Justification   string                  `json:"justification,omitempty"`
	StatusNotes     string                  `json:"status_notes,omitempty"`
	ActionStatement string                  `json:"action_statement,omitempty"`
	ImpactStatement string                  `json:"impact_statement,omitempty"`
}

type vexPayloadVulnerability struct {
	Name string `json:"name"`
}

// vexPayloadProduct identifies a product by its package URL, the identity Vapor checks
// the lock against and the same one the SPDX document writes. Identifiers carries the
// declared CPE beside it, because a vendor package's advisories are filed under a name
// its purl cannot reach.
type vexPayloadProduct struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
}

func (input *VEXInput) document() (vexPayloadDocument, error) {
	if err := input.payloadValidate(); err != nil {
		return vexPayloadDocument{}, err
	}
	claims, err := input.claims()
	if err != nil {
		return vexPayloadDocument{}, err
	}
	document := vexPayloadDocument{
		Context:    openVEXContext,
		ID:         vexNamespace + input.Name + "/" + input.Platform + "/" + subjectHex(input.Subject),
		Author:     vexAuthor,
		Timestamp:  spdxEpoch,
		Version:    1,
		Statements: make([]vexPayloadStatement, 0, len(claims)),
	}
	if len(claims) == 0 {
		return vexPayloadDocument{}, ErrNoClaims
	}
	for position := range claims {
		document.Statements = append(document.Statements, input.statementOf(&claims[position]))
	}
	return document, nil
}

func (input *VEXInput) payloadValidate() error {
	switch {
	case input.Name == "":
		return fmt.Errorf("attest: vex requires an image name")
	case !safeSegment(input.Name):
		return fmt.Errorf("attest: image name %q is not usable in a document identifier", input.Name)
	case !strings.HasPrefix(input.Subject, "sha256:"):
		return fmt.Errorf("attest: vex requires the subject manifest digest")
	case input.Tree == nil:
		return fmt.Errorf("attest: vex requires the built tree")
	}
	return nil
}

// claims returns this platform's claims in payload order. A claim that names nothing
// here is dropped: it is about content the image does not contain, so it asserts
// nothing about this image. A document has to state something, so a platform left with
// no claim yields no document at all rather than an empty one.
func (input *VEXInput) claims() ([]Claim, error) {
	compiled, err := CompileClaims(input)
	if err != nil {
		return nil, err
	}
	merged, err := Coalesce(append(compiled, input.Imported...), input.evidence())
	if err != nil {
		return nil, err
	}
	rendered := make([]Claim, 0, len(merged))
	for position := range merged {
		if claim := &merged[position]; len(claim.Products) != 0 {
			rendered = append(rendered, *claim)
		}
	}
	sort.Slice(rendered, func(left, right int) bool {
		return claimOrder(&rendered[left]) < claimOrder(&rendered[right])
	})
	return rendered, nil
}

// claimOrder gives every claim one position, so the payload never depends on the order
// the specification or a document happened to list them in.
func claimOrder(claim *Claim) string {
	return claim.Vulnerability + "\x00" + claim.Status + "\x00" + claim.Justification +
		"\x00" + strings.Join(claim.Products, "\x00")
}

// statementOf renders one claim. The claim's own text is published in the field OpenVEX
// defines for its status: an affected claim states the action a reader has to take, which
// the schema requires, and every other status states its impact.
func (input *VEXInput) statementOf(claim *Claim) vexPayloadStatement {
	rendered := vexPayloadStatement{
		Vulnerability: vexPayloadVulnerability{Name: claim.Vulnerability},
		Products:      make([]vexPayloadProduct, 0, len(claim.Products)),
		Status:        claim.Status,
		Justification: claim.Justification,
		StatusNotes:   claim.Notes,
	}
	if claim.Status == attestation.StatusAffected {
		rendered.ActionStatement = claim.Statement
	} else {
		rendered.ImpactStatement = claim.Statement
	}
	for _, product := range claim.Products {
		// A CPE the claim's source stated is the document's own identity for the product,
		// so it wins over the lock's; the lock only fills in what the claim left unsaid.
		cpe := claim.CPEs[product]
		if cpe == "" {
			cpe = input.lockCPE(product)
		}
		rendered.Products = append(rendered.Products, vexPayloadProduct{ID: product,
			Identifiers: productIdentifiers(product, cpe)})
	}
	return rendered
}

// productIdentifiers is the OpenVEX identifier map for one product URL of a resolved
// claim. The URL identifies the product; a CPE names it in an advisory database the URL
// cannot reach, so it is published beside the URL rather than instead.
func productIdentifiers(url, cpe string) map[string]string {
	if cpe == "" {
		return nil
	}
	return map[string]string{"purl": url, "cpe": cpe}
}

// lockCPE returns the CPE this platform's lock declares for a product URL, resolved
// against the version it recorded so a `*` declaration names the locked version here as
// it does in the SPDX document.
func (input *VEXInput) lockCPE(url string) string {
	for _, candidate := range input.lockProductURLs() {
		if candidate.url == url {
			return candidate.cpe
		}
	}
	return ""
}

// evidence is what this input can check a claim against.
func (input *VEXInput) evidence() Evidence {
	return Evidence{Tree: input.Tree, AbsentChecks: input.AbsentChecks}
}

// Evidence holds a not_affected claim to what the finished image can show. Vapor
// publishes "not affected" only when the claim names the paths that would hold the
// vulnerable code and none of them is in the image; anything else would be the claim's
// word alone, which is what a scanner already has.
//
// Evidence is not part of what a claim says. Two claims can therefore state the same
// thing while one of them names the paths that prove it, and an imported statement,
// which names no paths, is not a different claim. Matching claims are merged first and
// checked afterwards, so an imported claim is held to the paths an inline claim about
// the same product names, and two claims for one product cannot disagree about what is
// absent by naming different paths.
type Evidence struct {
	// Tree is the finished filesystem the absent paths are looked up in.
	Tree *vfs.Tree
	// AbsentChecks is the specification's switch for the check. With it off, a
	// not_affected claim without paths is published with a note instead.
	AbsentChecks bool
}

// Check refuses a claim the image cannot support, and notes a claim that was published
// without being checked.
func (evidence Evidence) Check(claim *Claim) error {
	if claim.Status != attestation.StatusNotAffected {
		if len(claim.Absent) != 0 {
			return fmt.Errorf("attest: %s states absent paths for status %s",
				claim.Vulnerability, claim.Status)
		}
		return nil
	}
	if len(claim.Absent) == 0 {
		if evidence.AbsentChecks {
			return fmt.Errorf("attest: %s is claimed not_affected for %s, but no absent path "+
				"shows why", claim.Vulnerability, strings.Join(claim.Products, ", "))
		}
		claim.Notes = joinNotes(claim.Notes, VEXWaiver)
		return nil
	}
	if evidence.Tree == nil {
		return errors.New("attest: checking absent paths requires the built tree")
	}
	for _, path := range claim.Absent {
		present, err := evidence.present(path)
		if err != nil {
			return fmt.Errorf("attest: %s: %w", claim.Vulnerability, err)
		}
		if present {
			return fmt.Errorf("attest: %s is claimed not_affected for %s, but %s is in the image",
				claim.Vulnerability, strings.Join(claim.Products, ", "), path)
		}
	}
	return nil
}

// present reports whether the finished tree holds a path. The path is resolved first, so
// a claim cannot be satisfied by a symlink that points at a file the claim says is
// absent, and a path that cannot be resolved refuses the claim rather than passing it.
func (evidence Evidence) present(path string) (bool, error) {
	resolved, err := evidence.Tree.Resolve(path)
	if err != nil {
		return false, fmt.Errorf("%s cannot be checked: %w", path, err)
	}
	_, exists := evidence.Tree.Lookup(resolved)
	return exists, nil
}

// subjectHex is the digest part of a subject, which names the image a payload describes.
func subjectHex(subject string) string {
	return strings.TrimPrefix(subject, "sha256:")
}

// joinNotes adds a note to a claim that already states one.
func joinNotes(notes, addition string) string {
	if notes == "" {
		return addition
	}
	return notes + " " + addition
}
