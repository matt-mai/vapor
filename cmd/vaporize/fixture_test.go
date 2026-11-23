package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// testKeyConfig generates an Ed25519 key: key generation is effectively free,
// and the production verifier accepts any algorithm it is not configured to
// reject.
var testKeyConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEd25519}

// testTransport trusts every httptest server in this binary, which share one
// certificate. Installing it once means a test never reassigns http.DefaultTransport
// and tests that talk to a local archive server can run in parallel.
var testTransport = http.DefaultTransport.(*http.Transport).Clone()

func init() {
	testTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpTransport = testTransport
	registryTransport = testTransport
}

// sharedTestEntity builds the signing entity once per test binary. Each fixture
// still gets its own server, cache and key file, so sharing the key costs no
// isolation.
var sharedTestEntity = sync.OnceValues(func() (*openpgp.Entity, error) {
	entity, err := openpgp.NewEntity("Vapor test", "", "test@example.invalid", testKeyConfig)
	if err != nil {
		return nil, err
	}
	entity.Subkeys = nil
	return entity, nil
})

// testEntity returns the shared fixture entity, failing the test on error.
func testEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	entity, err := sharedTestEntity()
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

// writeTestKey writes the shared entity's armored public key to dir/keys/test.asc
// and returns the armored text.
func writeTestKey(t *testing.T, dir string, entity *openpgp.Entity) string {
	t.Helper()
	keyPath := filepath.Join(dir, "keys", "test.asc")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	buffer := &bytes.Buffer{}
	writer, err := armor.Encode(buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

// indentArmor indents armored key text for embedding in chisel.yaml, matching
// the layout the fixtures previously produced with strings.ReplaceAll.
func indentArmor(armorText string) string {
	return "      " + strings.ReplaceAll(
		strings.TrimSuffix(armorText, "\n"), "\n", "\n      ")
}

// keyID formats the entity primary key id the way chisel.yaml references it.
func keyID(entity *openpgp.Entity) string {
	return fmt.Sprintf("%016X", entity.PrimaryKey.KeyId)
}
