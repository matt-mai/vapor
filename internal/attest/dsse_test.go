package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// signingKey writes an Ed25519 private key as PKCS#8 PEM and returns it loaded.
func signingKey(t *testing.T) attest.SigningKey {
	t.Helper()
	key := newSigningKey(t)
	path := filepath.Join(t.TempDir(), "signing.pem")
	writePrivateKey(t, path, key)
	loaded, err := attest.LoadSigningKey(path)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	return loaded
}

func newSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writePrivateKey(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err = os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestEnvelope_VerifiesTheSpecificationEncoding pins the pre-authentication encoding
// against the worked example in the DSSE protocol: the bytes signed are
// "DSSEv1 29 http://example.com/HelloWorld 11 hello world". The signature here is built
// by the test from that literal, so a changed encoding fails this test.
func TestEnvelope_VerifiesTheSpecificationEncoding(t *testing.T) {
	key := newSigningKey(t)
	payload := []byte("hello world")
	preAuthentication := append([]byte("DSSEv1 29 http://example.com/HelloWorld 11 "), payload...)
	envelope := attest.Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: "http://example.com/HelloWorld",
		Signatures: []attest.Signature{{
			Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(key, preAuthentication)),
		}},
	}
	verified, err := envelope.Verify(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(verified) != "hello world" {
		t.Fatalf("payload = %q", verified)
	}
	other := []byte("hello worlD")
	envelope.Payload = base64.StdEncoding.EncodeToString(other)
	if _, err := envelope.Verify(key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a changed payload still verified")
	}
}

// TestEnvelope_RefusesBrokenEnvelopes checks that a malformed envelope is refused instead
// of being read as an unsigned one.
func TestEnvelope_RefusesBrokenEnvelopes(t *testing.T) {
	key := newSigningKey(t)
	signed, err := attest.SigningKey{PrivateKey: key}.Sign("application/vnd.in-toto+json",
		[]byte(`{"_type": "https://in-toto.io/Statement/v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		envelope attest.Envelope
		want     string
	}{
		"no payload type": {
			attest.Envelope{Payload: signed.Payload, Signatures: signed.Signatures},
			"no payload type",
		},
		"no signature": {
			attest.Envelope{Payload: signed.Payload, PayloadType: signed.PayloadType},
			"no signatures",
		},
		"payload is not base64": {
			attest.Envelope{
				Payload: "!!!", PayloadType: signed.PayloadType, Signatures: signed.Signatures,
			},
			"payload is not base64",
		},
		"signature is not base64": {
			attest.Envelope{
				Payload: signed.Payload, PayloadType: signed.PayloadType,
				Signatures: []attest.Signature{{Sig: "!!!"}},
			},
			"signature is not base64",
		},
		"signature is over another type": {
			attest.Envelope{
				Payload: signed.Payload, PayloadType: "application/json",
				Signatures: signed.Signatures,
			},
			"does not verify",
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			envelope := test.envelope
			if _, err := envelope.Verify(key.Public().(ed25519.PublicKey)); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := signed.Verify(newSigningKey(t).Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("another key verified the envelope")
	}
}

// TestSign_IsDeterministic checks the promise the plan makes: Ed25519 is deterministic, so
// signing the same bytes twice produces one envelope, not two.
func TestSign_IsDeterministic(t *testing.T) {
	key := signingKey(t)
	payload := []byte(`{"spdxVersion": "SPDX-2.3"}`)
	first, err := key.Sign("https://spdx.dev/Document", payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := key.Sign("https://spdx.dev/Document", payload)
	if err != nil {
		t.Fatal(err)
	}
	left, err := attest.Encode(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := attest.Encode(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("two signatures over one payload differ:\n%s\n%s", left, right)
	}
	var decoded map[string]any
	if err = json.Unmarshal(left, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if decoded["payloadType"] != "https://spdx.dev/Document" {
		t.Fatalf("envelope = %s", left)
	}
	signatures := decoded["signatures"].([]any)
	if len(signatures) != 1 {
		t.Fatalf("signatures = %v", signatures)
	}
	if signatures[0].(map[string]any)["keyid"] != key.KeyID() {
		t.Fatalf("keyid = %v, want %q", signatures[0], key.KeyID())
	}
	verified, err := first.Verify(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(verified, payload) {
		t.Fatalf("payload = %q", verified)
	}
}

// TestSign_RefusesIncompleteInput checks that signing nothing is refused rather than
// producing an envelope that authenticates nothing.
func TestSign_RefusesIncompleteInput(t *testing.T) {
	key := signingKey(t)
	if _, err := key.Sign("", []byte("payload")); err == nil {
		t.Fatal("signing an untyped payload succeeded")
	}
	if _, err := key.Sign("application/json", nil); err == nil {
		t.Fatal("signing an empty payload succeeded")
	}
	if _, err := (&attest.SigningKey{}).Sign("application/json", []byte("payload")); err == nil {
		t.Fatal("signing without a key succeeded")
	}
}

// TestMaybeSigned checks the switch: without a key the payload is returned untouched, and
// with one the same payload comes back out of an envelope that verifies.
func TestMaybeSigned(t *testing.T) {
	payload := []byte(`{"@context": "https://openvex.dev/ns/v0.2.0"}`)
	unsigned, signed, err := attest.MaybeSigned(attest.SigningKey{}, "application/vnd.openvex+json", payload)
	if err != nil {
		t.Fatal(err)
	}
	if signed || !bytes.Equal(unsigned, payload) {
		t.Fatalf("unsigned = %q signed=%v", unsigned, signed)
	}
	key := signingKey(t)
	encoded, signed, err := attest.MaybeSigned(key, "application/vnd.openvex+json", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !signed {
		t.Fatal("a key produced an unsigned payload")
	}
	var envelope attest.Envelope
	if err = json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	verified, err := envelope.Verify(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(verified, payload) {
		t.Fatalf("payload = %q", verified)
	}
	if strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(key.PrivateKey)) {
		t.Fatal("the envelope carries the private key")
	}
}

// TestLoadSigningKey_RefusesBadKeys checks every way a key file can be wrong, because a
// wrong key must stop a build rather than fall back to unsigned output.
func TestLoadSigningKey_RefusesBadKeys(t *testing.T) {
	dir := t.TempDir()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	edKey := newSigningKey(t)
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	edBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER})
	cases := map[string]struct{ path, want string }{
		"not a pem file": {
			write("plain.pem", []byte("not a key")), "not a PEM document",
		},
		"pkcs1 block": {
			write("rsa.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: edDER})),
			"is not a PKCS#8 PRIVATE KEY",
		},
		"not a private key": {
			write("broken.pem", pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY", Bytes: []byte("broken"),
			})),
			"not a valid PKCS#8 private key",
		},
		"another algorithm": {
			write("ec.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})),
			"is not an Ed25519 key",
		},
		"two blocks": {
			write("two.pem", append(append([]byte{}, edBlock...), edBlock...)),
			"more than one PEM block",
		},
		"too large": {
			write("large.pem", bytes.Repeat([]byte("x"), 65<<10)), "too large",
		},
		"a directory": {dir, "not a regular file"},
		// A FIFO with no writer makes a plain open wait forever, so the type has to be
		// refused before the open can block.
		"a named pipe": {filepath.Join(dir, "key.fifo"), "not a regular file"},
		"missing file": {filepath.Join(dir, "absent.pem"), "cannot be read"},
	}
	if err := syscall.Mkfifo(cases["a named pipe"].path, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := attest.LoadSigningKey(test.path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadSigningKey = %v, want %q", err, test.want)
			}
			if strings.Contains(err.Error(), test.path) {
				t.Fatalf("error carries the key path: %v", err)
			}
		})
	}
}

// TestLoadSigningKey_KeepsTheKeyOutOfErrors checks that a refused key does not carry its
// own bytes into an error message.
func TestLoadSigningKey_KeepsTheKeyOutOfErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ec.pem")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err = os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = attest.LoadSigningKey(path)
	if err == nil {
		t.Fatal("an ECDSA key was accepted")
	}
	secret := base64.StdEncoding.EncodeToString(der)[:16]
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error carries the key: %v", err)
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("error carries the key path: %v", err)
	}
}

// TestLoadSigningKey_KeepsTheLabelOutOfErrors checks that a wrong PEM label is refused
// with a fixed message, so the block a caller wrote is not echoed back.
func TestLoadSigningKey_KeepsTheLabelOutOfErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "label.pem")
	label := "SECRET-LABEL-4f2a"
	block := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: []byte("broken")})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := attest.LoadSigningKey(path)
	if err == nil || !strings.Contains(err.Error(), "not a PKCS#8 PRIVATE KEY") {
		t.Fatalf("LoadSigningKey = %v", err)
	}
	if strings.Contains(err.Error(), label) {
		t.Fatalf("error carries the PEM label: %v", err)
	}
}

// TestKeyID_IdentifiesTheKey checks that the key identifier follows the public key and
// nothing else, so it can be published beside a signature.
func TestKeyID_IdentifiesTheKey(t *testing.T) {
	first := signingKey(t)
	second := signingKey(t)
	if first.KeyID() == second.KeyID() {
		t.Fatal("two keys share an identifier")
	}
	if len(first.KeyID()) != 64 {
		t.Fatalf("keyid = %q", first.KeyID())
	}
	reloaded := reload(t, first)
	if reloaded.KeyID() != first.KeyID() {
		t.Fatalf("keyid changed on reload: %q, %q", reloaded.KeyID(), first.KeyID())
	}
}

func reload(t *testing.T, key attest.SigningKey) attest.SigningKey {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.pem")
	encoded, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err = os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := attest.LoadSigningKey(path)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	return loaded
}

// TestSigningKey_Clear checks that the key material can be removed once a run is done,
// and that a cleared key signs nothing.
func TestSigningKey_Clear(t *testing.T) {
	key := signingKey(t)
	key.Clear()
	for position, value := range key.PrivateKey {
		if value != 0 {
			t.Fatalf("byte %d of the key survived", position)
		}
	}
	if _, err := key.Sign("application/vnd.openvex+json", []byte("{}")); err == nil {
		t.Fatal("a cleared key still signed")
	}
	if _, signed, err := attest.MaybeSigned(key, attest.PayloadTypeVEX, []byte("{}")); err != nil || signed {
		t.Fatalf("MaybeSigned on a cleared key: signed=%v err=%v", signed, err)
	}
	if _, signed, err := attest.MaybeSigned(attest.SigningKey{}, "", []byte("{}")); err != nil ||
		signed {
		t.Fatalf("an empty payload type needs no validation when unsigned: signed=%v err=%v",
			signed, err)
	}
}

// TestEnvelope_SignatureIsBase64 checks the wire form the specification requires: base64
// without a URL-safe alphabet, in a document whose fields are spelled as published.
func TestEnvelope_SignatureIsBase64(t *testing.T) {
	key := signingKey(t)
	envelope, err := key.Sign("application/vnd.in-toto+json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"payload": envelope.Payload, "sig": envelope.Signatures[0].Sig,
	} {
		if _, decodeErr := base64.StdEncoding.DecodeString(value); decodeErr != nil {
			t.Fatalf("%s is not standard base64: %v", name, decodeErr)
		}
	}
	encoded, err := attest.Encode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"payloadType"`) ||
		!strings.Contains(string(encoded), `"keyid"`) {
		t.Fatalf("envelope does not use the published field names: %s", encoded)
	}
	expected := fmt.Sprintf(`"signatures":[{"keyid":%q,"sig":`, key.KeyID())
	if !strings.Contains(strings.ReplaceAll(string(encoded), " ", ""), expected) {
		t.Fatalf("envelope = %s", encoded)
	}
}
