package policy_test

import (
	"strconv"
	"strings"
	"testing"
)

func TestLoadSpec_PolicyRejections(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, suffix, message string }{
		{"empty scripts", "scripts: {}", "unknown field"},
		{"script exception", "scripts: {allow-unhandled: [tzdata]}", "unknown field"},
		{"exact script exception", "scripts: {allow-unhandled: [tzdata/postinst]}", "unknown field"},
		{"zero budget", "contents: {slices-engine: {max-steps: 0}}", "positive integer"},
		{"negative budget", "contents: {slices-engine: {max-steps: -1}}", "positive integer"},
		{"overflow budget", "contents: {slices-engine: {max-steps: 18446744073709551615}}", "invalid YAML"},
		{"null hardening", "hardening: null", "expected a mapping"},
		{"hardening sequence", "hardening: []", "expected a mapping"},
		{"unknown hardening", "hardening: {future: false}", "unknown field"},
		{"duplicate policy", "hardening: {strip-docs: true, strip-docs: false}", "duplicate key"},
		{"null engine", "contents: {slices-engine: null}", "expected a mapping"},
		{"root engine", "slice-engine: {max-steps: 100000}", "unknown field"},
		{"disable engine", "contents: {slices-engine: {enabled: false}}", "unknown field"},
		{"disable mutation", "contents: {slices-engine: {mutation: false}}", "unknown field"},
		{"disable copyright", "contents: {slices-engine: {copyright: false}}", "unknown field"},
		{"collision override", "contents: {slices-engine: {collisions: last-writer-wins}}", "unknown field"},
		{"null budget", "contents: {slices-engine: {max-steps: null}}", "expected an integer"},
		{"string budget", "contents: {slices-engine: {max-steps: '100000'}}", "expected an integer"},
		{"float budget", "contents: {slices-engine: {max-steps: 1.5}}", "expected an integer"},
		{"bool budget", "contents: {slices-engine: {max-steps: true}}", "expected an integer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+tc.suffix)
			if err == nil || spec != nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("want nil spec and %q error; got %#v, %v", tc.message, spec, err)
			}
		})
	}
}

func TestLoadSpec_HardeningStrictBooleans(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"strip-docs", "strip-shells", "strip-apt-dpkg", "remove-suid-sgid"} {
		for _, value := range []string{"null", "'false'", "0", "[]", "{}"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				spec, err := loadText(t, minimalSpec+"hardening: {"+key+": "+value+"}")
				if spec != nil || err == nil || !strings.Contains(err.Error(), "expected a boolean") {
					t.Fatalf("want strict boolean failure, got %#v, %v", spec, err)
				}
			})
		}
	}
}

func TestLoadSpec_MinimumBudget(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, minimalSpec+"contents: {slices-engine: {max-steps: 1}}")
	if err != nil || *spec.Contents.SlicesEngine.MaxSteps != 1 {
		t.Fatalf("valid minimum budget: %#v, %v", spec, err)
	}
}

func TestLoadSpec_PolicyErrorsRedactValues(t *testing.T) {
	t.Parallel()
	const secret = "policy-sensitive-marker"
	for i, suffix := range []string{
		"scripts: {allow-unhandled: ['" + secret + "']}",
		"hardening: {strip-docs: " + secret + "}",
		"contents: {slices-engine: {max-steps: " + secret + "}}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+suffix)
			if spec != nil || err == nil || strings.Contains(err.Error(), secret) {
				t.Fatal("policy error missing or exposed input")
			}
		})
	}
}
