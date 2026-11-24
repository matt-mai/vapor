package contents_test

import (
	"reflect"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// Splitting on every colon reads one escaped field as two, so a version that carries a
// colon has to survive the round trip.
func TestSplitCPE(t *testing.T) {
	cases := map[string][]string{
		"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*": {
			"cpe", "2.3", "a", "vendor", "product", "1.0", "*", "*", "*", "*", "*", "*", "*",
		},
		`cpe:2.3:a:vendor:product:1\:2.0:*:*:*:*:*:*:*`: {
			"cpe", "2.3", "a", "vendor", "product", `1\:2.0`, "*", "*", "*", "*", "*", "*", "*",
		},
	}
	for value, want := range cases {
		if got := contents.SplitCPE(value); !reflect.DeepEqual(got, want) {
			t.Fatalf("SplitCPE(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestEscapeCPEField(t *testing.T) {
	cases := map[string]string{
		"1.0":   "1.0",
		"1:2.0": `1\:2.0`,
		"a*b?c": `a\*b\?c`,
		`a\b`:   `a\\b`,
	}
	for value, want := range cases {
		if got := contents.EscapeCPEField(value); got != want {
			t.Fatalf("EscapeCPEField(%q) = %q, want %q", value, got, want)
		}
	}
}

// An escaped colon is one field, not two, so a name that carries one is a whole CPE.
func TestValidateCPEAcceptsAnEscapedColon(t *testing.T) {
	name := `cpe:2.3:a:vendor:product:1\:2.0:*:*:*:*:*:*:*`
	if err := contents.ValidateCPE(name); err != nil {
		t.Fatalf("ValidateCPE(%q) = %v", name, err)
	}
	if fields := contents.SplitCPE(name); len(fields) != 13 {
		t.Fatalf("%q read as %d fields, want 13", name, len(fields))
	}
}
