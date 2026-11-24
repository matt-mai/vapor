package attest

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Claim is one vulnerability assertion after its selectors are resolved: what it says
// and which products of one platform it says it about. Products are package URLs, the
// same identity the SPDX document uses, so a scanner can match the two.
type Claim struct {
	Vulnerability string
	Status        string
	// Justification is set for a not_affected claim that states one.
	Justification string
	// Statement is what the claim says in its own words: the action a reader has to
	// take for an affected claim, and the explanation for a fixed or investigated one.
	Statement string
	// Absent are the image paths a not_affected claim asserts are missing. They are
	// checked against the finished filesystem, which resolution does not have.
	Absent []string
	// Products are the package URLs this claim is about on its platform.
	Products []string
	// Notes is what the claim has to say about its own evidence. Generation sets it when
	// it publishes a claim whose absent paths were not checked.
	Notes string
}

// VEXInput is the lock content one platform's claims are resolved against. Nothing here
// is read from the network or the host: a claim is accepted only when the lock already
// holds the content it names.
type VEXInput struct {
	// Name is the image, Subject the digest of the platform manifest a payload describes
	// and Tree the finished filesystem its absent paths are checked against. All three
	// are needed to publish a document and ignored while claims are resolved.
	Name    string
	Subject string
	Tree    *vfs.Tree
	// AbsentChecks is the specification's switch for the absent-path check. When it is
	// off, a not_affected claim without paths is published with a note instead of being
	// refused, so a reader can tell an unchecked claim from a checked one.
	AbsentChecks bool

	Platform string
	// Distro and Release are the distribution the image is built for. A record from a
	// repository that authenticates its own release identity is qualified by that
	// vendor instead, so one product string identifies the same package in both payloads.
	Distro  string
	Release string

	// Repositories are the platform's locked repositories, which decide whether a record
	// is published under the distribution's identity or the vendor's.
	Repositories []lock.Repository

	// Claims are the assertions the specification makes. Imported holds the claims
	// already resolved from imported documents, so a payload can merge both sources.
	Claims   []attestation.VEXAssertion
	Imported []Claim

	Packages  []lock.Package
	Slices    []lock.Slice
	Artifacts []lock.Artifact
}

// CompileClaims resolves the specification's assertions for one platform. A claim naming
// a package or artifact the lock does not hold there is refused rather than dropped: a
// silent omission would look like a claim that covers nothing.
func CompileClaims(input *VEXInput) ([]Claim, error) {
	if err := input.validate(); err != nil {
		return nil, err
	}
	claims := make([]Claim, 0, len(input.Claims))
	for position := range input.Claims {
		claim, err := input.compile(&input.Claims[position])
		if err != nil {
			return nil, fmt.Errorf("attest: vex.assertions[%d]: %w", position, err)
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

// ImportClaims resolves the statements of one imported document against the same lock.
// Every product a statement names has to be locked here, so an imported document cannot
// smuggle in a claim about content the image does not contain.
func ImportClaims(input *VEXInput, document *VEXDocument) ([]Claim, error) {
	if err := input.validate(); err != nil {
		return nil, err
	}
	if document == nil {
		return nil, errors.New("attest: no document to import")
	}
	claims := make([]Claim, 0, len(document.Statements))
	for position := range document.Statements {
		statement := &document.Statements[position]
		products, err := input.importProducts(statement)
		if err != nil {
			return nil, fmt.Errorf("attest: statements[%d]: %w", position, err)
		}
		claims = append(claims, Claim{
			Vulnerability: statement.Vulnerability.Name,
			Status:        statement.Status,
			Justification: statement.Justification,
			Statement:     statement.explanation(),
			Notes:         statement.StatusNotes,
			Products:      productURLs(products),
		})
	}
	return claims, nil
}

func (input *VEXInput) validate() error {
	if input.Platform == "" || !safeSegment(input.Platform) {
		return fmt.Errorf("attest: %q is not a usable platform", input.Platform)
	}
	return nil
}

// compile resolves one assertion against the lock.
func (input *VEXInput) compile(claim *attestation.VEXAssertion) (Claim, error) {
	resolved := Claim{
		Vulnerability: claim.Vulnerability,
		Status:        claim.Status,
		Statement:     claim.Statement,
		Absent:        claim.AbsentPaths,
	}
	if claim.Justification != nil {
		resolved.Justification = *claim.Justification
	}
	var (
		products []product
		err      error
	)
	switch {
	case claim.Package != nil:
		products, err = input.packageProducts(*claim.Package)
	case claim.Artifact != nil:
		products, err = input.artifactProducts(*claim.Artifact)
	}
	if err != nil {
		return Claim{}, err
	}
	resolved.Products = productURLs(products)
	return resolved, nil
}

// Coalesce applies the merge rules to claims from any source. Claims saying the same
// thing about different products become one claim listing both, and claims saying
// different things about the same product fail, because preferring one of them would be
// an invented decision.
//
// The evidence a claim rests on is not part of what it says, so a claim is matched to its
// products first and the evidence is checked afterwards. An imported statement carries no
// absent paths, states the same thing as an inline claim about the same product, and is
// therefore held to the paths that claim names instead of being refused as a conflict.
//
// A path is evidence about the product the claim that named it is about, so the check runs
// per product rather than on the merged claim: merging cannot lend one product the
// evidence another product was given.
func Coalesce(claims []Claim, evidence Evidence) ([]Claim, error) {
	byAssertion := make(map[assertion]*Claim, len(claims))
	claimedAs := make(map[identity]assertion)
	absentFor := make(map[identity][]string, len(claims))
	notesFor := make(map[identity][]string, len(claims))
	merged := make([]*Claim, 0, len(claims))
	for position := range claims {
		claim := &claims[position]
		key := assertionOf(claim)
		if err := claimAssertion(claimedAs, claim, key); err != nil {
			return nil, err
		}
		remember(claim, absentFor, notesFor)
		if existing, exists := byAssertion[key]; exists {
			existing.Products = sortedUnique(append(existing.Products, claim.Products...))
			existing.Absent = sortedUnique(append(existing.Absent, claim.Absent...))
			continue
		}
		stored := *claim
		stored.Products = sortedUnique(claim.Products)
		stored.Absent = sortedUnique(claim.Absent)
		// The merged claim collects its notes from every claim about each of its
		// products, so which claim was seen first never decides what is published.
		stored.Notes = ""
		byAssertion[key] = &stored
		merged = append(merged, &stored)
	}
	result := make([]Claim, 0, len(merged))
	for _, current := range merged {
		if err := checkProducts(current, absentFor, notesFor, evidence); err != nil {
			return nil, err
		}
		result = append(result, *current)
	}
	return result, nil
}

// remember records what one claim says about each product it names, so the evidence and
// the notes of every source reach the product they belong to whatever the merge does.
func remember(claim *Claim, absentFor, notesFor map[identity][]string) {
	for _, product := range claim.Products {
		named := identity{vulnerability: claim.Vulnerability, product: product}
		absentFor[named] = append(absentFor[named], claim.Absent...)
		if claim.Notes != "" {
			notesFor[named] = sortedUnique(append(notesFor[named], claim.Notes))
		}
	}
}

// checkProducts holds each product of a merged claim to the evidence named about that
// product alone, and collects the notes every claim about the merged products brought
// with it.
func checkProducts(claim *Claim, absentFor, notesFor map[identity][]string, evidence Evidence) error {
	notes := make([]string, 0, len(claim.Products))
	for _, product := range claim.Products {
		named := identity{vulnerability: claim.Vulnerability, product: product}
		alone := *claim
		alone.Products = []string{product}
		alone.Absent = absentFor[named]
		// The note Check may add is about this product's evidence, so the claim's own
		// notes stay out of the copy and are joined once below.
		alone.Notes = ""
		if err := evidence.Check(&alone); err != nil {
			return err
		}
		notes = append(notes, notesFor[named]...)
		// Every unchecked product yields the same waiver, so it is stated once.
		if alone.Notes != "" {
			notes = append(notes, alone.Notes)
		}
	}
	claim.Notes = strings.Join(sortedUnique(notes), " ")
	return nil
}

// claimAssertion records what one claim says about each of its products, and refuses a
// product that two claims say different things about.
func claimAssertion(claimedAs map[identity]assertion, claim *Claim, key assertion) error {
	for _, product := range claim.Products {
		named := identity{vulnerability: claim.Vulnerability, product: product}
		other, exists := claimedAs[named]
		if !exists {
			claimedAs[named] = key
			continue
		}
		if other != key {
			return fmt.Errorf("attest: %s is claimed for %s as %s and as %s",
				claim.Vulnerability, product, other.status, key.status)
		}
	}
	return nil
}

// identity names one product within one vulnerability.
type identity struct {
	vulnerability string
	product       string
}

// assertion is what a claim says, without the products it says it about and without the
// evidence it rests on. Two claims with the same assertion say the same thing, so the
// payload states it once.
type assertion struct {
	vulnerability string
	status        string
	justification string
	statement     string
}

func assertionOf(claim *Claim) assertion {
	return assertion{
		vulnerability: claim.Vulnerability, status: claim.Status,
		justification: claim.Justification, statement: claim.Statement,
	}
}

func productURLs(products []product) []string {
	urls := make([]string, 0, len(products))
	for _, found := range products {
		urls = append(urls, found.url())
	}
	return sortedUnique(urls)
}

// sortedUnique removes repeats and orders the result, so the same content always
// produces the same claim.
func sortedUnique(values []string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}
