package deb_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestPublicKeyringPreservesSelectedKeys(t *testing.T) {
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEd25519}
	signer, err := openpgp.NewEntity("Vapor Key", "", "key@example.com", config)
	if err != nil {
		t.Fatal(err)
	}
	if identityErr := signer.AddUserId("Vapor Second Identity", "", "second@example.com", config); identityErr != nil {
		t.Fatal(identityErr)
	}
	if subkeyErr := signer.AddSigningSubkey(config); subkeyErr != nil {
		t.Fatal(subkeyErr)
	}
	other, unselected := entities(t)
	keys, err := deb.LoadTrustedKeys(binaryRing(t, signer, other, unselected), []string{fingerprint(signer), fingerprint(other)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := deb.PublicKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		slices.Reverse(keys)
		again, encodeErr := deb.PublicKeyring(keys)
		if encodeErr != nil || !bytes.Equal(encoded, again) {
			t.Fatalf("keyring encoding is not stable: %v", encodeErr)
		}
	}
	parsed, err := openpgp.ReadKeyRing(bytes.NewReader(encoded))
	if err != nil || len(parsed) != 2 {
		t.Fatalf("keyring must contain only the two selected public entities: %v", err)
	}
	for _, entity := range parsed {
		if entity.PrivateKey != nil || fingerprint(entity) == fingerprint(unselected) {
			t.Fatal("keyring contains a private or unselected key")
		}
	}
	verifyKeyringSigner(t, parsed, signer)
}

func verifyKeyringSigner(t *testing.T, keys openpgp.EntityList, signer *openpgp.Entity) {
	t.Helper()
	const message = "locked repository release"
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, signer, strings.NewReader(message), nil); err != nil {
		t.Fatal(err)
	}
	packetSignature, err := packet.Read(bytes.NewReader(signature.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	sig, ok := packetSignature.(*packet.Signature)
	signingSubkey := signer.Subkeys[len(signer.Subkeys)-1].PublicKey.KeyId
	if !ok || sig.IssuerKeyId == nil || *sig.IssuerKeyId != signingSubkey {
		t.Fatal("test signature did not use the signing subkey")
	}
	verified, err := openpgp.CheckDetachedSignature(keys, strings.NewReader(message), &signature, nil)
	if err != nil || fingerprint(verified) != fingerprint(signer) || len(verified.Identities) != 2 {
		t.Fatalf("keyring did not retain signing authority and identities: %v", err)
	}
}
