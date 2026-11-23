package slices_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func TestParseCatalogue_Priorities(t *testing.T) {
	key := testRootKey(t)
	base := catalogueYAML(key.id, key.armor)
	t.Run("single omission", func(t *testing.T) {
		catalogue := parseRoot(t, replace(t, base, "    priority: 10\n", ""))
		if catalogue.Archives["ubuntu"].Priority != 0 {
			t.Fatalf("priority = %d", catalogue.Archives["ubuntu"].Priority)
		}
	})
	t.Run("multiple omission", func(t *testing.T) {
		data := string(fixtureRoot(t))
		for _, line := range []string{"    priority: 10\n", "    priority: 16\n", "    priority: -1\n"} {
			data = replace(t, data, line, "")
		}
		if _, err := slices.ParseCatalogue([]byte(data)); err == nil || !strings.Contains(err.Error(), "missing priority") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("mixed omission", func(t *testing.T) {
		data := replace(t, string(fixtureRoot(t)), "    priority: 16\n", "")
		if _, err := slices.ParseCatalogue([]byte(data)); err == nil || !strings.Contains(err.Error(), "missing priority") {
			t.Fatalf("error = %v", err)
		}
	})
	for name, value := range map[string]string{"zero": "0", "low": "-1001", "high": "1001"} {
		t.Run(name, func(t *testing.T) {
			_, err := slices.ParseCatalogue([]byte(replace(t, base, "priority: 10", "priority: "+value)))
			if err == nil || !strings.Contains(err.Error(), "invalid priority") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		data := replace(t, string(fixtureRoot(t)), "    priority: -1\n", "    priority: 10\n")
		if _, err := slices.ParseCatalogue([]byte(data)); err == nil || !strings.Contains(err.Error(), "same priority") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestParseCatalogue_ArchiveFields(t *testing.T) {
	key := testRootKey(t)
	base := catalogueYAML(key.id, key.armor)
	for name, tc := range map[string]struct {
		old, new string
		want     string
	}{
		"empty suites":         {"suites: [resolute, resolute-updates]", "suites: []", "suites is empty"},
		"duplicate suites":     {"suites: [resolute, resolute-updates]", "suites: [resolute, resolute]", "duplicate"},
		"empty components":     {"components: [main]", "components: []", "components is empty"},
		"duplicate components": {"components: [main]", "components: [main, main]", "duplicate"},
		"unknown pro":          {"    public-keys: [test]", "    pro: esm-other\n    public-keys: [test]", "unsupported pro"},
		"undefined key":        {"public-keys: [test]", "public-keys: [missing]", "undefined public key"},
		"missing version":      {"version: \"26.04\"\n    ", "", "missing version"},
	} {
		t.Run(name, func(t *testing.T) {
			data := replace(t, base, tc.old, tc.new)
			_, err := slices.ParseCatalogue([]byte(data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
