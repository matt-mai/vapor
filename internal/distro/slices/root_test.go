package slices_test

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

type rootKey struct {
	id    string
	armor string
	priv  string
	mixed string
	err   error
}

var rootKeys = sync.OnceValue(func() rootKey {
	entity, err := openpgp.NewEntity("Vapor Catalogue Test", "", "catalogue@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEd25519,
	})
	if err != nil {
		return rootKey{err: err}
	}
	entity.Subkeys = nil
	return rootKey{
		id:    entity.PrimaryKey.KeyIdString(),
		armor: armorText(entity, false),
		priv:  armorText(entity, true),
		mixed: mixedArmor(entity),
	}
})

func testRootKey(t *testing.T) rootKey {
	t.Helper()
	key := rootKeys()
	if key.err != nil {
		t.Fatal(key.err)
	}
	return key
}

func armorText(entity *openpgp.Entity, private bool) string {
	var buffer bytes.Buffer
	blockType := openpgp.PublicKeyType
	if private {
		blockType = openpgp.PrivateKeyType
	}
	writer, err := armor.Encode(&buffer, blockType, nil)
	if err != nil {
		panic(err)
	}
	if private {
		err = entity.SerializePrivate(writer, nil)
	} else {
		err = entity.Serialize(writer)
	}
	if err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.String()
}

func mixedArmor(entity *openpgp.Entity) string {
	var buffer bytes.Buffer
	writer, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		panic(err)
	}
	if err := entity.PrimaryKey.Serialize(writer); err != nil {
		panic(err)
	}
	if err := entity.PrivateKey.Serialize(writer); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.String()
}

func catalogueYAML(id, keyArmor string) string {
	return "format: v3\n" +
		"maintenance:\n" +
		"  standard: 2026-04-23\n" +
		"  end-of-life: 2038-04-27\n" +
		"archives:\n" +
		"  ubuntu:\n" +
		"    version: \"26.04\"\n" +
		"    suites: [resolute, resolute-updates]\n" +
		"    components: [main]\n" +
		"    priority: 10\n" +
		"    public-keys: [test]\n" +
		"public-keys:\n" +
		"  test:\n" +
		"    id: " + id + "\n" +
		"    armor: |\n" +
		indent(keyArmor)
}

func indent(text string) string {
	var builder strings.Builder
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		builder.WriteString("      ")
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return builder.String()
}

func fixtureRoot(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/chisel-v3/catalogue/chisel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func parseRoot(t *testing.T, data string) *slices.Catalogue {
	t.Helper()
	catalogue, err := slices.ParseCatalogue([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return catalogue
}

func replace(t *testing.T, data, old, replacement string) string {
	t.Helper()
	if !strings.Contains(data, old) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(data, old, replacement, 1)
}

func TestParseCatalogue_Fixture(t *testing.T) {
	catalogue, err := slices.ParseCatalogue(fixtureRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if catalogue.Format != slices.CatalogueFormat {
		t.Fatalf("format = %q", catalogue.Format)
	}
	if got := catalogue.Maintenance.Standard.Format(time.DateOnly); got != "2026-04-23" {
		t.Fatalf("standard = %q", got)
	}
	if got := catalogue.Maintenance.EndOfLife.Format(time.DateOnly); got != "2038-04-27" {
		t.Fatalf("end of life = %q", got)
	}
	ubuntu := catalogue.Archives["ubuntu"]
	if ubuntu.Priority != 10 || ubuntu.Version != "26.04" {
		t.Fatalf("ubuntu = %+v", ubuntu)
	}
	if got := strings.Join(ubuntu.Suites, ","); got != "resolute,resolute-security,resolute-updates" {
		t.Fatalf("suites = %q", got)
	}
	if got := strings.Join(ubuntu.Components, ","); got != "main,universe" {
		t.Fatalf("components = %q", got)
	}
	if esmApps := catalogue.Archives["ubuntu-esm-apps"]; esmApps.Pro != "esm-apps" {
		t.Fatalf("esm-apps archive pro service = %q", esmApps.Pro)
	}
	if catalogue.Archives["pinned-only"].Priority != -1 {
		t.Fatalf("pinned archive priority = %d", catalogue.Archives["pinned-only"].Priority)
	}
	if key := catalogue.PublicKeys["fixture-only"]; key.ID != "F6DC226F4AAF8F29" || len(key.Fingerprint) != 40 {
		t.Fatalf("public key = %+v", key)
	}
	if store := catalogue.Stores["bin"]; store.Kind != "bin" || store.DefaultPrefix != "bin-" {
		t.Fatalf("store = %+v", store)
	}
}

func TestParseCatalogue_RejectsInterpolation(t *testing.T) {
	key := testRootKey(t)
	data := catalogueYAML(key.id, key.armor)
	_, err := slices.ParseCatalogue([]byte(replace(t, data, `version: "26.04"`, `version: "${RELEASE}"`)))
	if err == nil || !strings.Contains(err.Error(), "interpolation") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseCatalogue_Formats(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v4", "V3", "v3.0"} {
		t.Run(format, func(t *testing.T) {
			_, err := slices.ParseCatalogue([]byte(replace(t, string(fixtureRoot(t)), "format: v3", "format: "+format)))
			if err == nil || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestParseCatalogue_StrictDocuments(t *testing.T) {
	key := testRootKey(t)
	base := catalogueYAML(key.id, key.armor)
	for name, data := range map[string]string{
		"empty":           "",
		"unknown root":    base + "unknown: true\n",
		"unknown archive": replace(t, base, "    priority: 10\n", "    priority: 10\n    unknown: true\n"),
		"unknown key":     replace(t, base, "    id: "+key.id+"\n", "    id: "+key.id+"\n    unknown: true\n"),
		"unknown maintenance": replace(t, base, "  end-of-life: 2038-04-27\n",
			"  end-of-life: 2038-04-27\n  future: 2040-01-01\n"),
		"unknown store": base + "stores:\n  bin:\n    kind: bin\n" +
			"    version: \"26.04\"\n    default-prefix: bin-\n    unknown: true\n",
		"duplicate archive field": replace(t, base, "    version: \"26.04\"\n", "    version: \"26.04\"\n    version: \"26.04\"\n"),
		"duplicate root":          replace(t, base, "format: v3\n", "format: v3\nformat: v3\n"),
		"legacy archives":         replace(t, base, "format: v3\n", "format: v3\nv2-archives: {}\n"),
		"legacy null archives":    replace(t, base, "format: v3\n", "format: v3\nv2-archives: null\n"),
		"default field":           replace(t, base, "    priority: 10\n", "    priority: 10\n    default: false\n"),
		"default null":            replace(t, base, "    priority: 10\n", "    priority: 10\n    default: null\n"),
		"second document":         base + "---\nformat: v3\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := slices.ParseCatalogue([]byte(data)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
