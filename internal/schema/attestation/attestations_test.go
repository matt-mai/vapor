package attestation_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const attestationFixture = `platforms: [linux/arm64, linux/amd64]
sbom: {enabled: false}
vex:
  inputs: [nonexistent/review.json]
  assertions:
    - vulnerability: CVE-2099-12345
      package: example-library
      status: not_affected
      justification: vulnerable_code_not_present
      statement: Reviewed omitted code; not automatic proof.
      absent-paths: [/usr/bin/example]
    - vulnerability: GHSA-example
      artifact: server
      status: affected
      statement: Needs an update.
`

func TestLoadSpec_Attestations(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, minimalSpec+attestationFixture)
	if err != nil {
		t.Fatal(err)
	}
	if *spec.SBOM.Enabled || !*spec.VEX.CheckAbsentPaths || spec.VEX.Inputs[0] != "nonexistent/review.json" {
		t.Fatal("attestation declarations/defaults changed")
	}
	if *spec.VEX.Assertions[0].Package != "example-library" || *spec.VEX.Assertions[1].Artifact != "server" {
		t.Fatal("claim identity/order changed")
	}
}

func TestAttestationDefaults_PureIsolatedIdempotent(t *testing.T) {
	t.Parallel()
	spec, err := decodeSpec([]byte(minimalSpec))
	if err != nil {
		t.Fatal(err)
	}
	if spec.SBOM.Enabled != nil || spec.VEX.CheckAbsentPaths != nil {
		t.Fatal("decoder applied defaults")
	}
	applyDefaults(spec)
	before, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	applyDefaults(spec)
	after, err := json.Marshal(spec)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("defaults not idempotent: %v", err)
	}
	other, err := loadText(t, minimalSpec)
	if err != nil {
		t.Fatal(err)
	}
	*spec.SBOM.Enabled, *spec.VEX.CheckAbsentPaths = false, false
	if !*other.SBOM.Enabled || !*other.VEX.CheckAbsentPaths {
		t.Fatal("defaults share state")
	}
}

func TestLoadSpec_VEXStatusesAndJustifications(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"affected", "fixed", "under_investigation"} {
		t.Run(status, func(t *testing.T) {
			_, err := loadText(t, minimalSpec+"vex: {assertions: [{vulnerability: OSV-example, package: transitively-selected, status: "+status+", statement: Reviewed}]}\n")
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, justification := range []string{"component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"} {
		t.Run(justification, func(t *testing.T) {
			_, err := loadText(t, minimalSpec+"vex: {assertions: [{vulnerability: CVE-example, artifact: server, status: not_affected, statement: Reviewed, justification: "+justification+", absent-paths: [/missing]}]}\n")
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	waived := strings.Replace(attestationFixture, "  inputs:", "  check-absent-paths: false\n  inputs:", 1)
	waived = strings.Replace(waived, "      absent-paths: [/usr/bin/example]\n", "", 1)
	spec, err := loadText(t, minimalSpec+waived)
	if err != nil || spec == nil || *spec.VEX.CheckAbsentPaths {
		t.Fatalf("explicit check waiver lost: %v", err)
	}
}
