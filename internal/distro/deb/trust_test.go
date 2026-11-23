package deb_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

type generatedKeys struct {
	first, second *openpgp.Entity
	err           error
}

var testEntities = sync.OnceValue(func() generatedKeys {
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEd25519}
	first, err := openpgp.NewEntity("Vapor Test One", "", "one@example.com", config)
	if err != nil {
		return generatedKeys{err: err}
	}
	second, err := openpgp.NewEntity("Vapor Test Two", "", "two@example.com", config)
	if err != nil {
		return generatedKeys{err: err}
	}
	first.Subkeys = nil
	second.Subkeys = nil
	return generatedKeys{first: first, second: second}
})

func entities(t *testing.T) (*openpgp.Entity, *openpgp.Entity) {
	t.Helper()
	keys := testEntities()
	if keys.err != nil {
		t.Fatal(keys.err)
	}
	return keys.first, keys.second
}

func fingerprint(entity *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
}

func armoredRing(t *testing.T, entities ...*openpgp.Entity) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, entity := range entities {
		if err := entity.Serialize(writer); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func binaryRing(t *testing.T, entities ...*openpgp.Entity) []byte {
	t.Helper()
	var buffer bytes.Buffer
	for _, entity := range entities {
		if err := entity.Serialize(&buffer); err != nil {
			t.Fatal(err)
		}
	}
	return buffer.Bytes()
}

func privateRing(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := armor.Encode(&buffer, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(writer, &packet.Config{}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestLoadTrustedKeysFormats(t *testing.T) {
	first, _ := entities(t)
	want := fingerprint(first)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "armored", data: armoredRing(t, first)},
		{name: "binary", data: binaryRing(t, first)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys, err := deb.LoadTrustedKeys(test.data, []string{want})
			if err != nil {
				t.Fatalf("LoadTrustedKeys: %v", err)
			}
			if len(keys) != 1 {
				t.Fatalf("LoadTrustedKeys returned %d keys, want 1", len(keys))
			}
			if keys[0].Fingerprint != want {
				t.Errorf("fingerprint = %q, want %q", keys[0].Fingerprint, want)
			}
			if keys[0].Entity == nil {
				t.Error("returned key has no OpenPGP entity")
			}
		})
	}
}

func TestLoadTrustedKeysSelectsConfiguredOrder(t *testing.T) {
	first, second := entities(t)
	firstFingerprint, secondFingerprint := fingerprint(first), fingerprint(second)
	data := binaryRing(t, first, second)

	keys, err := deb.LoadTrustedKeys(data, []string{secondFingerprint, firstFingerprint})
	if err != nil {
		t.Fatalf("LoadTrustedKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("LoadTrustedKeys returned %d keys, want 2", len(keys))
	}
	if keys[0].Fingerprint != secondFingerprint || keys[1].Fingerprint != firstFingerprint {
		t.Errorf("fingerprints = %q, want configured order [%s %s]", []string{keys[0].Fingerprint, keys[1].Fingerprint}, secondFingerprint, firstFingerprint)
	}

	only, err := deb.LoadTrustedKeys(data, []string{secondFingerprint})
	if err != nil {
		t.Fatalf("LoadTrustedKeys: %v", err)
	}
	if len(only) != 1 || only[0].Fingerprint != secondFingerprint {
		t.Errorf("selected %d keys, want only %s", len(only), secondFingerprint)
	}
}

func TestLoadTrustedKeysAcceptsLowercase(t *testing.T) {
	first, _ := entities(t)
	want := fingerprint(first)
	keys, err := deb.LoadTrustedKeys(binaryRing(t, first), []string{strings.ToLower(want)})
	if err != nil {
		t.Fatalf("LoadTrustedKeys: %v", err)
	}
	if keys[0].Fingerprint != want {
		t.Errorf("fingerprint = %q, want canonical %q", keys[0].Fingerprint, want)
	}
}

func TestLoadTrustedKeysRejectsFingerprintPolicy(t *testing.T) {
	first, second := entities(t)
	data := binaryRing(t, first)
	full := fingerprint(first)
	short := full[len(full)-16:]
	tests := []struct {
		name         string
		fingerprints []string
		want         string
	}{
		{name: "none", want: "no trusted fingerprints"},
		{name: "short key id", fingerprints: []string{short}, want: "40 or 64"},
		{name: "truncated", fingerprints: []string{full[:39]}, want: "40 or 64"},
		{name: "not hexadecimal", fingerprints: []string{strings.Repeat("G", 40)}, want: "40 or 64"},
		{name: "duplicate", fingerprints: []string{full, strings.ToLower(full)}, want: "duplicate"},
		{name: "missing key", fingerprints: []string{fingerprint(second)}, want: "does not contain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := deb.LoadTrustedKeys(data, test.fingerprints)
			if err == nil {
				t.Fatal("LoadTrustedKeys succeeded, want an error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestLoadTrustedKeysRejectsInvalidSnapshots(t *testing.T) {
	first, second := entities(t)
	full := fingerprint(first)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "empty", want: "empty"},
		{name: "oversized", data: make([]byte, deb.MaxKeySnapshotSize+1), want: "exceeds"},
		{name: "garbage", data: []byte("not a key"), want: "not a valid"},
		{name: "truncated armor", data: armoredRing(t, first)[:300], want: "not a valid"},
		{name: "private key", data: privateRing(t, first), want: "private-key material"},
		{name: "mixed public and private", data: append(binaryRing(t, first), privateBinaryRing(t, second)...), want: "private-key material"},
		{name: "armored trailing private block", data: append(armoredRing(t, first), privateRing(t, second)...), want: "data after the armored key block"},
		{name: "armored trailing private block on end line", data: append(bytes.TrimSuffix(armoredRing(t, first), []byte("\n")), privateRing(t, second)...), want: "data after the armored key block"},
		{name: "armored trailing public block", data: append(armoredRing(t, first), armoredRing(t, second)...), want: "data after the armored key block"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := deb.LoadTrustedKeys(test.data, []string{full})
			if err == nil {
				t.Fatal("LoadTrustedKeys succeeded, want an error")
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestLoadTrustedKeysRejectsDuplicateKey(t *testing.T) {
	first, _ := entities(t)
	_, err := deb.LoadTrustedKeys(binaryRing(t, first, first), []string{fingerprint(first)})
	if err == nil {
		t.Fatal("LoadTrustedKeys succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "duplicate public key fingerprint") {
		t.Errorf("error = %q, want a duplicate-key error", err)
	}
}

func privateBinaryRing(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := entity.SerializePrivate(&buffer, &packet.Config{}); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestParsePublicKey(t *testing.T) {
	entity, _ := entities(t)
	key, err := deb.ParsePublicKey(armoredRing(t, entity))
	if err != nil {
		t.Fatal(err)
	}
	if key.Fingerprint != fingerprint(entity) {
		t.Fatalf("fingerprint = %q, want %q", key.Fingerprint, fingerprint(entity))
	}
	if got := key.KeyID; got != entity.PrimaryKey.KeyIdString() {
		t.Fatalf("key id = %q, want %q", got, entity.PrimaryKey.KeyIdString())
	}
}

func armorPackets(t *testing.T, serialize func(io.Writer) error) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestParsePublicKeyAcceptsStandalonePacket(t *testing.T) {
	entity, _ := entities(t)
	data := armorPackets(t, entity.PrimaryKey.Serialize)
	key, err := deb.ParsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyID != entity.PrimaryKey.KeyIdString() {
		t.Fatalf("key id = %q, want %q", key.KeyID, entity.PrimaryKey.KeyIdString())
	}
}

func TestParsePublicKeyRejectsMixedPrivatePacket(t *testing.T) {
	entity, _ := entities(t)
	data := armorPackets(t, func(writer io.Writer) error {
		if err := entity.PrimaryKey.Serialize(writer); err != nil {
			return err
		}
		return entity.PrivateKey.Serialize(writer)
	})
	if _, err := deb.ParsePublicKey(data); err == nil {
		t.Fatal("expected private key error")
	}
}

// A bound subkey belongs to the key: Debian's archive key signs with one, so a
// snapshot carrying it is the key that was reviewed, not a second key.
func TestParsePublicKeyAcceptsPublicSubkey(t *testing.T) {
	entity, _ := entities(t)
	subkey := *entity.PrimaryKey
	subkey.IsSubkey = true
	data := armorPackets(t, func(writer io.Writer) error {
		if err := entity.PrimaryKey.Serialize(writer); err != nil {
			return err
		}
		return subkey.Serialize(writer)
	})
	key, err := deb.ParsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyID != entity.PrimaryKey.KeyIdString() {
		t.Fatalf("key id = %q, want %q", key.KeyID, entity.PrimaryKey.KeyIdString())
	}
}

func TestParsePublicKeyRejectsPrivateMaterial(t *testing.T) {
	entity, _ := entities(t)
	if _, err := deb.ParsePublicKey(privateRing(t, entity)); err == nil {
		t.Fatal("expected private key error")
	}
}

func TestParsePublicKeyRejectsMultipleKeys(t *testing.T) {
	first, second := entities(t)
	if _, err := deb.ParsePublicKey(armoredRing(t, first, second)); err == nil {
		t.Fatal("expected multiple key error")
	}
}

func TestParsePublicKeyRejectsEmpty(t *testing.T) {
	if _, err := deb.ParsePublicKey(nil); err == nil {
		t.Fatal("expected empty key error")
	}
}

func TestParseKeyring(t *testing.T) {
	first, second := entities(t)
	key, err := deb.ParseKeyring(armoredRing(t, first))
	if err != nil {
		t.Fatal(err)
	}
	if key.Fingerprint != fingerprint(first) {
		t.Fatalf("fingerprint = %q, want %q", key.Fingerprint, fingerprint(first))
	}
	if len(key.Entity.Subkeys) != 0 {
		t.Fatalf("subkeys = %d, want the snapshot's own", len(key.Entity.Subkeys))
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{name: "empty", data: nil, want: "public key snapshot is empty"},
		{name: "oversized", data: make([]byte, deb.MaxKeySnapshotSize+1), want: "exceeds"},
		{name: "two primary keys", data: armoredRing(t, first, second), want: "exactly one public key"},
		{name: "private key", data: privateRing(t, first), want: "private-key material"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := deb.ParseKeyring(test.data); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}
