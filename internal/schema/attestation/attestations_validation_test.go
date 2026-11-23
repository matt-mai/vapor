package attestation_test

import (
	"strconv"
	"strings"
	"testing"
)

func TestLoadSpec_AttestationRejections(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, suffix string }{
		{"SBOM bool string", "sbom: {enabled: 'false'}"},
		{"SBOM null", "sbom: {enabled: null}"},
		{"SBOM format", "sbom: {format: spdx}"},
		{"duplicate flag", "sbom: {enabled: true, enabled: false}"},
		{"check string", "vex: {check-absent-paths: 'true'}"},
		{"check null", "vex: {check-absent-paths: null}"},
		{"input scalar", "vex: {inputs: review.json}"},
		{"input unclean", "vex: {inputs: [a/../review.json]}"},
		{"input empty", "vex: {inputs: ['']}"},
		{"duplicate input", "vex: {inputs: [review.json, review.json]}"},
		{"unknown VEX field", "vex: {enable: true}"},
		{"missing vulnerability", "vex: {assertions: [{package: sample, status: fixed, statement: Reviewed}]}"},
		{"empty identifier", "vex: {assertions: [{vulnerability: ' ', package: sample, status: fixed, statement: Reviewed}]}"},
		{"multiline identifier", "vex: {assertions: [{vulnerability: \"ID\\nID\", package: sample, status: fixed, statement: Reviewed}]}"},
		{"both targets", "vex: {assertions: [{vulnerability: ID, package: sample, artifact: sample, status: fixed, statement: Reviewed}]}"},
		{"no target", "vex: {assertions: [{vulnerability: ID, status: fixed, statement: Reviewed}]}"},
		{"bad package", "vex: {assertions: [{vulnerability: ID, package: 'sample:arm64', status: fixed, statement: Reviewed}]}"},
		{"bad artifact", "vex: {assertions: [{vulnerability: ID, artifact: /sample, status: fixed, statement: Reviewed}]}"},
		{"empty statement", "vex: {assertions: [{vulnerability: ID, package: sample, status: fixed, statement: ' '}]}"},
		{"status", "vex: {assertions: [{vulnerability: ID, package: sample, status: safe, statement: Reviewed}]}"},
		{"wrong justification", "vex: {assertions: [{vulnerability: ID, package: sample, status: fixed, justification: component_not_present, statement: Reviewed}]}"},
		{"wrong absence field", "vex: {assertions: [{vulnerability: ID, package: sample, status: affected, absent-paths: [], statement: Reviewed}]}"},
		{"unknown assertion", "vex: {assertions: [{vulnerability: ID, package: sample, status: fixed, statement: Reviewed, automatic: true}]}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+tc.suffix+"\n")
			if err == nil || spec != nil {
				t.Fatalf("accepted invalid declaration: %v", err)
			}
		})
	}
	for _, change := range []struct{ from, to string }{
		{"      absent-paths: [/usr/bin/example]\n", ""},
		{"[/usr/bin/example]", "[]"},
		{"[/usr/bin/example]", "[/]"},
		{"[/usr/bin/example]", "[relative]"},
		{"[/usr/bin/example]", "[/a/../b]"},
		{"[/usr/bin/example]", "[/missing, /missing]"},
		{"      justification: vulnerable_code_not_present\n", ""},
		{"vulnerable_code_not_present", "unknown"},
	} {
		t.Run(change.to, func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+strings.Replace(attestationFixture, change.from, change.to, 1))
			if err == nil || spec != nil {
				t.Fatal("accepted invalid absence claim")
			}
		})
	}
}

func TestLoadSpec_ClaimDuplicatesAndSafeErrors(t *testing.T) {
	t.Parallel()
	const claim = "{vulnerability: ID, package: sample, status: fixed, statement: Reviewed}"
	for _, second := range []string{claim, strings.Replace(claim, "fixed", "affected", 1)} {
		spec, err := loadText(t, minimalSpec+"vex: {assertions: ["+claim+", "+second+"]}\n")
		if err == nil || spec != nil {
			t.Fatal("accepted duplicate/conflicting claim")
		}
	}
	// Package and artifact selectors with the same name remain distinct identities.
	_, err := loadText(t, minimalSpec+"vex: {assertions: ["+claim+", "+strings.Replace(claim, "package:", "artifact:", 1)+"]}\n")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "secret-marker-123"
	for i, suffix := range []string{
		"vex: {assertions: [{vulnerability: ID, package: " + strconv.Quote(secret+"/") + ", status: fixed, statement: " + secret + "}]}",
		"vex: {inputs: [" + strconv.Quote(secret+"/../file") + "]}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, loadErr := loadText(t, minimalSpec+suffix+"\n")
			if loadErr == nil || spec != nil || strings.Contains(loadErr.Error(), secret) {
				t.Fatalf("invalid input accepted or leaked: %v", loadErr)
			}
		})
	}
}
