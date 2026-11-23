package policy_test

import (
	"bytes"
	"encoding/json"
	"testing"

	schemaPolicy "github.com/matt-mai/vapor/internal/schema/policy"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

const policiesFixture = minimalSpec + `hardening:
  strip-docs: false
  strip-shells: false
  strip-apt-dpkg: false
  remove-suid-sgid: false
  keep-package-sources: false
contents:
  slices-engine:
    max-steps: 250000
`

func TestLoadSpec_Policies(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, policiesFixture)
	if err != nil {
		t.Fatal(err)
	}
	if *spec.Hardening.StripDocs || *spec.Hardening.StripShells || *spec.Hardening.StripAptDpkg || *spec.Hardening.RemoveSUIDSGID || *spec.Hardening.KeepPackageSources || *spec.Contents.SlicesEngine.MaxSteps != 250_000 {
		t.Fatal("explicit policy overwritten by defaults")
	}
}

func TestLoadSpec_PolicyDefaults(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"", "hardening: {}\ncontents: {slices-engine: {}}"} {
		spec, err := loadText(t, minimalSpec+suffix)
		if err != nil {
			t.Fatal(err)
		}
		if !*spec.Hardening.StripDocs || !*spec.Hardening.StripShells || !*spec.Hardening.StripAptDpkg || !*spec.Hardening.RemoveSUIDSGID || *spec.Hardening.KeepPackageSources || *spec.Contents.SlicesEngine.MaxSteps != 100_000 {
			t.Fatal("incorrect default policy")
		}
	}
}

func TestPolicyDefaults_SeparateAndIsolated(t *testing.T) {
	t.Parallel()
	spec, err := decodeSpec([]byte(minimalSpec))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hardening.StripDocs != nil || spec.Hardening.StripShells != nil || spec.Hardening.StripAptDpkg != nil || spec.Hardening.RemoveSUIDSGID != nil || spec.Hardening.KeepPackageSources != nil || spec.Contents.SlicesEngine.MaxSteps != nil {
		t.Fatal("decoder applied policy defaults")
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
	*spec.Hardening.StripDocs = false
	if !*spec.Hardening.StripShells || !*spec.Hardening.StripAptDpkg || !*spec.Hardening.RemoveSUIDSGID {
		t.Fatal("hardening flags share mutable defaults")
	}
	*spec.Hardening.StripShells = false
	*spec.Hardening.StripAptDpkg = false
	*spec.Hardening.RemoveSUIDSGID = false
	*spec.Contents.SlicesEngine.MaxSteps = 1
	if !*other.Hardening.StripDocs || !*other.Hardening.StripShells || !*other.Hardening.StripAptDpkg || !*other.Hardening.RemoveSUIDSGID || *other.Contents.SlicesEngine.MaxSteps != 100_000 {
		t.Fatal("policy defaults shared between loads")
	}
}

func TestPolicyDefaults_DoNotValidateOrRepair(t *testing.T) {
	t.Parallel()
	spec, err := decodeSpec([]byte(minimalSpec + "contents: {slices-engine: {max-steps: 0}}"))
	if err != nil {
		t.Fatal(err)
	}
	applyDefaults(spec)
	if *spec.Contents.SlicesEngine.MaxSteps != 0 {
		t.Fatal("decoder/defaulter repaired invalid policy")
	}
	if err := schemaSpec.ValidateSpec(spec); err == nil {
		t.Fatal("semantic validation accepted invalid policy")
	}
	if err := schemaPolicy.Validate(schemaSpec.Spec{}.Contents.SlicesEngine); err == nil {
		t.Fatal("missing internal budget accepted without defaulting")
	}
}
