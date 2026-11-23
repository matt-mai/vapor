package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// newVEXInput locks one package, one slice of another package and one artifact on amd64,
// and a package on arm64 to prove that a claim cannot cross platforms.
func newVEXInput() *attest.VEXInput {
	return &attest.VEXInput{
		Platform: "linux/amd64",
		Distro:   "ubuntu",
		Release:  "26.04",
		Packages: []lock.Package{
			{Platform: "linux/amd64", Name: "coreutils", Version: "9.4-3ubuntu1",
				Architecture: "amd64"},
			{Platform: "linux/arm64", Name: "coreutils", Version: "9.4-3ubuntu1",
				Architecture: "arm64"},
		},
		Slices: []lock.Slice{
			{Platform: "linux/amd64", Package: "libc6", Version: "2.41-1",
				Architecture: "amd64"},
		},
		Artifacts: []lock.Artifact{
			{Name: "server-cert", Platform: "linux/amd64",
				SBOM: contents.ArtifactIdentity{Name: "server", Version: "1.0"}},
		},
	}
}

// assertion builds one inline claim. The pointer parameters are spelled out because a
// claim without a justification is a different claim from one with an empty one.
func assertion(vulnerability, packageName, status string) attestation.VEXAssertion {
	return attestation.VEXAssertion{Vulnerability: vulnerability, Package: new(packageName),
		Status: status, Statement: "Reviewed by the maintainers"}
}

// openVEXDocument wraps statements in a valid v0.2.0 document header.
func openVEXDocument(statements ...string) string {
	return `{"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.invalid/vex/2026-11-20.json",
	"author": "Example Security Team",
	"timestamp": "2026-11-20T09:00:00Z",
	"version": 1,
	"statements": [` + strings.Join(statements, ",\n") + `]}`
}

// openVEXStatement builds one imported statement about a package URL.
func openVEXStatement(vulnerability, purl, status, extra string) string {
	statement := `{"vulnerability": {"name": "` + vulnerability + `"},
	"products": [{"identifiers": {"purl": "` + purl + `"}}],
	"status": "` + status + `"`
	if extra != "" {
		statement += ", " + extra
	}
	return statement + "}"
}

// unchecked is the evidence of a caller that only wants the merge rules: with the check
// switched off, a claim without absent paths is published with a note instead of being
// refused, so a merge test does not need a filesystem.
func unchecked() attest.Evidence {
	return attest.Evidence{}
}

// evidenceFor is the evidence of a caller that checks claims against a built tree. The
// tree holds /usr/bin/gone's parent only, so a claim naming /usr/bin/gone can be checked
// and a claim naming /usr/bin/coreutils is refused as present.
func evidenceFor(t *testing.T) attest.Evidence {
	t.Helper()
	input := newVEXInputWithTree(t)
	return attest.Evidence{Tree: input.Tree, AbsentChecks: true}
}
