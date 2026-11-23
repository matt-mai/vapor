package slices_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func TestParseCatalogue_Stores(t *testing.T) {
	key := testRootKey(t)
	base := catalogueYAML(key.id, key.armor) +
		"stores:\n  bin:\n    kind: bin\n    version: \"26.04\"\n    default-prefix: bin-\n"
	catalogue := parseRoot(t, base)
	if store := catalogue.Stores["bin"]; store.Kind != "bin" {
		t.Fatalf("store = %+v", store)
	}
	for name, tc := range map[string]struct {
		old, new, want string
	}{
		"kind":    {"kind: bin", "kind: \"\"", "missing kind"},
		"version": {"version: \"26.04\"", "version: \"\"", "missing version"},
		"prefix":  {"default-prefix: bin-", "default-prefix: \"\"", "missing default-prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := slices.ParseCatalogue([]byte(replace(t, base, tc.old, tc.new)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
