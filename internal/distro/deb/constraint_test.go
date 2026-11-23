package deb_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func mustConstraint(t *testing.T, value string) deb.Constraint {
	t.Helper()
	constraint, err := deb.ParseConstraint(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return constraint
}

func mustVersion(t *testing.T, value string) deb.Version {
	t.Helper()
	version, err := deb.ParseVersion(value)
	if err != nil {
		t.Fatalf("parse version %q: %v", value, err)
	}
	return version
}

func TestConstraintAllows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		constraint string
		candidate  string
		allowed    bool
	}{
		// "=" is a component prefix for dotted-numeric upstreams.
		{"= 1.4.1", "1.4.1-1ubuntu2", true},
		{"= 1.4.1", "1.4.1+b1", true},
		{"= 1.4.1", "1.4.1", true},
		{"= 1.4.1", "1.4.10", false},
		{"= 1.4.1", "1.4.1~rc1", false},
		{"= 1.4", "1.4.7", true},
		{"= 1.4", "1.5", false},
		{"= 3", "3.11.2", true},
		// A revision in the literal names exactly one build.
		{"= 1.4.1-1ubuntu2", "1.4.1-1ubuntu2", true},
		{"= 1.4.1-1ubuntu2", "1.4.1-1ubuntu3", false},
		{"= 1.4.1-1ubuntu2", "1.4.1", false},
		// A non-numeric upstream falls back to upstream equality.
		{"= 2024a", "2024a-1ubuntu1", true},
		{"= 2024a", "2024b-1", false},
		{"= 13ubuntu10", "13ubuntu10", true},
		{"= 13ubuntu10", "13ubuntu10.1", false},
		{"!= 2024a", "2024b-1", true},
		{"!= 2024a", "2024a-1ubuntu1", false},
		{"!= 1.4.1", "1.4.2-1", true},
		{"!= 1.4.1", "1.4.1-1ubuntu2", false},
		// Ordering compares the upstream unless the literal has a revision.
		{">= 1.4.1", "1.4.1-1ubuntu2", true},
		{">= 1.4.1", "1.4.2-1", true},
		{">= 1.4.1", "1.4.0-9", false},
		{"<= 1.4.1", "1.4.1-1ubuntu2", true},
		{"<= 1.4.1", "1.4.2-1", false},
		{">= 1.4.1, <= 1.4.1", "1.4.1-1ubuntu2", true},
		{">= 1.4.1, <= 1.4.1", "1.4.2-1", false},
		{">= 1.4.1-2", "1.4.1-1ubuntu2", false},
		{">= 1.4.1-2", "1.4.1-3", true},
		{"< 2.0", "1.9.9-1", true},
		{"< 2.0", "2.0", false},
		{"> 1", "1.0.1", true},
		{"> 1", "1", false},
		// A tilde sorts below everything, so a prerelease is outside ">=".
		{">= 1.4.1", "1.4.1~rc1-1", false},
		// Epochs are part of the comparison.
		{">= 1:1.0", "1:1.0", true},
		{">= 1:1.0", "2.0", false},
		{"= 0:1.0", "1.0", true},
		// "~>" accepts the minor line it names.
		{"~> 3.0", "3.0.13-1ubuntu1", true},
		{"~> 3.0", "3.9.1", true},
		{"~> 3.0", "4.0", false},
		{"~> 3.0", "2.9", false},
		{"~> 3.0", "3.0", true},
		{"~> 3", "3.9.1", true},
		{"~> 3", "4.0", false},
		{"~> 3.0.13", "3.0.14", true},
		{"~> 3.0.13", "3.0.13.5", true},
		{"~> 3.0.13", "3.1", false},
		{"~> 3.0.13", "3.0.12", false},
		{"~> 3.0.13.1", "3.0.13.9", true},
		{"~> 3.0.13.1", "3.0.14", false},
		// An epoch survives the derived upper bound.
		{"~> 1:3.0", "1:3.5-1", true},
		{"~> 1:3.0", "1:4.0", false},
		{"~> 1:3.0", "3.5", false},
		// Predicates combine as a conjunction.
		{">= 1.4.1, != 1.4.3, < 1.5", "1.4.2-1", true},
		{">= 1.4.1, != 1.4.3, < 1.5", "1.4.3-1", false},
		{">= 1.4.1 != 1.4.3 < 1.5", "1.4.4-1", true},
		{">= 1.4.1, != 1.4.3, < 1.5", "1.5.0", false},
		// An empty intersection allows nothing.
		{">= 2, < 1", "1.5", false},
	}
	for _, test := range cases {
		constraint := mustConstraint(t, test.constraint)
		if got := constraint.Allows(mustVersion(t, test.candidate)); got != test.allowed {
			t.Errorf("%q allows %q = %v, want %v", test.constraint, test.candidate, got, test.allowed)
		}
	}
}

func TestParseConstraintRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":            "version expression is empty",
		"  ":          "version expression is empty",
		"1.4.1":       "needs an operator",
		">=":          "needs a version",
		">= abc":      "invalid upstream",
		"~> 2024a":    "needs a numeric upstream",
		"~> 13ubuntu": "needs a numeric upstream",
		"~> 1.4.1-2":  "without a Debian revision",
		"== 1.4.1":    "unsupported operator",
		">> 1.4.1":    "unsupported operator",
	}
	for value, wantErr := range cases {
		_, err := deb.ParseConstraint(value)
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("parse %q error = %v, want one containing %q", value, err, wantErr)
		}
	}
}

func TestParseConstraintBareTextSuggestsOperator(t *testing.T) {
	t.Parallel()
	_, err := deb.ParseConstraint("1.4.1")
	if err == nil || !strings.Contains(err.Error(), `write "= 1.4.1"`) {
		t.Fatalf("error = %v, want a suggestion to write \"= 1.4.1\"", err)
	}
}
