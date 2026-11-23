package slices_test

import (
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func TestParseCatalogue_PublicKeys(t *testing.T) {
	key := testRootKey(t)
	base := catalogueYAML(key.id, key.armor)
	for name, tc := range map[string]struct {
		data string
		want string
	}{
		"invalid id":    {replace(t, base, "id: "+key.id, `id: "1234"`), "invalid id"},
		"lowercase id":  {replace(t, base, "id: "+key.id, "id: "+strings.ToLower(key.id)), "invalid id"},
		"wrong id":      {replace(t, base, "id: "+key.id, `id: "0000000000000000"`), "want"},
		"private key":   {replace(t, base, indent(key.armor), indent(key.priv)), "invalid"},
		"mixed private": {replace(t, base, indent(key.armor), indent(key.mixed)), "invalid"},
		"empty armor":   {replace(t, base, "    armor: |\n"+indent(key.armor), "    armor: \"\""), "invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := slices.ParseCatalogue([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// An archive signs with a subkey, so its published key carries one. A subkey
// packet is not a second key: the catalogue must still accept the key and report
// the primary key's identifier.
func TestParseCatalogue_PublicKeyWithSubkey(t *testing.T) {
	entity, err := openpgp.NewEntity("Vapor Catalogue Subkey Test", "", "subkey@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEd25519,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entity.Subkeys) == 0 {
		t.Fatal("generated key has no subkey to test with")
	}
	key := rootKey{id: entity.PrimaryKey.KeyIdString(), armor: armorText(entity, false)}
	catalogue, err := slices.ParseCatalogue([]byte(catalogueYAML(key.id, key.armor)))
	if err != nil {
		t.Fatal(err)
	}
	if got := catalogue.PublicKeys["test"].ID; got != key.id {
		t.Fatalf("public key id = %q, want %q", got, key.id)
	}
}
