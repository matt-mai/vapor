package contents_test

import (
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// TestValidateCPE checks that a declared CPE is a whole CPE 2.3 name or absent. A
// truncated name would be written to the document and silently match nothing.
func TestValidateCPE(t *testing.T) {
	for _, bad := range []string{
		"cpe:2.3:a:vendor:product:1.0",
		"cpe:2.2:a:vendor:product:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:*:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:* extra",
	} {
		if err := contents.ValidateCPE(bad); err == nil {
			t.Fatalf("contents.ValidateCPE(%q) accepted an invalid name", bad)
		}
	}
	if err := contents.ValidateCPE(""); err != nil {
		t.Fatalf("contents.ValidateCPE(\"\") = %v, want an absent CPE to be allowed", err)
	}
	if err := contents.ValidateCPE("cpe:2.3:a:python_software_foundation:python:3.15.2:*:*:*:*:*:*:*"); err != nil {
		t.Fatalf("ValidateCPE rejected a valid name: %v", err)
	}
}

// TestValidateDeclaredCPE checks that a CPE a package or slice request declares follows
// the same grammar as an artifact's, because both are written to the same document.
func TestValidateDeclaredCPE(t *testing.T) {
	cases := map[string]struct {
		cpe  string
		want bool
	}{
		"absent":        {"", true},
		"whole name":    {"cpe:2.3:a:nodejs:node.js:26.13.1:*:*:*:*:*:*:*", true},
		"truncated":     {"cpe:2.3:a:nodejs", false},
		"wrong version": {"cpe:2.2:a:nodejs:node.js:1:*:*:*:*:*:*:*", false},
		"wildcard":      {"cpe:2.3:a:*:node.js:1:*:*:*:*:*:*:*", false},
		"whitespace":    {"cpe:2.3:a:nodejs:node.js:1:*:*:*:*:*:*:* x", false},
	}
	for name, testCase := range cases {
		err := contents.ValidateDeclaredCPE(testCase.cpe)
		if (err == nil) != testCase.want {
			t.Fatalf("%s: ValidateDeclaredCPE(%q) = %v, want accepted %v",
				name, testCase.cpe, err, testCase.want)
		}
	}
}
