package deb_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

const releasePayload = `Origin: Ubuntu
Label: Ubuntu
Suite: resolute
Version: 26.04
Codename: resolute
Date: Thu, 23 Apr 2026 17:07:15 UTC
Valid-Until: Thu, 30 Apr 2026 17:07:15 UTC
Architectures: amd64 arm64
Components: main restricted
Description: Vapor test archive
`

func trustedKeys(t *testing.T, entities ...*openpgp.Entity) []deb.PublicKey {
	t.Helper()
	fingerprints := make([]string, len(entities))
	for i, entity := range entities {
		fingerprints[i] = fingerprint(entity)
	}
	keys, err := deb.LoadTrustedKeys(armoredRing(t, entities...), fingerprints)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func signInRelease(t *testing.T, entity *openpgp.Entity, payload string) []byte {
	return signInReleaseWithConfig(t, entity, payload, nil)
}

func signInReleaseWithConfig(t *testing.T, entity *openpgp.Entity, payload string, config *packet.Config) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := clearsign.Encode(&buffer, entity.PrivateKey, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func signRelease(t *testing.T, entity *openpgp.Entity) []byte {
	return signReleaseWithConfig(t, entity, true, nil)
}

func signReleaseWithConfig(t *testing.T, entity *openpgp.Entity, armored bool, config *packet.Config) []byte {
	t.Helper()
	var buffer bytes.Buffer
	var err error
	if armored {
		err = openpgp.ArmoredDetachSign(&buffer, entity, strings.NewReader(releasePayload), config)
	} else {
		err = openpgp.DetachSign(&buffer, entity, strings.NewReader(releasePayload), config)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func expiredEntity(t *testing.T) (*openpgp.Entity, *packet.Config) {
	t.Helper()
	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEd25519,
		Time:            func() time.Time { return time.Now().Add(-2 * time.Hour) },
		KeyLifetimeSecs: 3600,
		SigLifetimeSecs: 3600,
	}
	entity, err := openpgp.NewEntity("Expired", "", "expired@example.com", config)
	if err != nil {
		t.Fatal(err)
	}
	return entity, config
}

func TestVerifyReleaseExpiryPolicy(t *testing.T) {
	entity, config := expiredEntity(t)
	keys := trustedKeys(t, entity)
	inRelease := signInReleaseWithConfig(t, entity, releasePayload, config)
	armored := signReleaseWithConfig(t, entity, true, config)
	binary := signReleaseWithConfig(t, entity, false, config)
	cases := []struct {
		name   string
		verify func(deb.ExpiryPolicy) (*deb.VerifiedRelease, error)
	}{
		{name: "inrelease", verify: func(policy deb.ExpiryPolicy) (*deb.VerifiedRelease, error) {
			return deb.VerifyInRelease(inRelease, keys, deb.VerifyOptions{Policy: policy})
		}},
		{name: "armored detached", verify: func(policy deb.ExpiryPolicy) (*deb.VerifiedRelease, error) {
			return deb.VerifyDetachedRelease([]byte(releasePayload), armored, keys, deb.VerifyOptions{Policy: policy})
		}},
		{name: "binary detached", verify: func(policy deb.ExpiryPolicy) (*deb.VerifiedRelease, error) {
			return deb.VerifyDetachedRelease([]byte(releasePayload), binary, keys, deb.VerifyOptions{Policy: policy})
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.verify(deb.EnforceExpiry); err == nil {
				t.Fatal("accepted expired key or signature")
			}
			verified, err := test.verify(deb.IgnoreExpiry)
			if err != nil {
				t.Fatal(err)
			}
			if len(verified.Signers) != 1 || verified.Signers[0] != fingerprint(entity) {
				t.Fatalf("signers = %v", verified.Signers)
			}
			if verified.Metadata.Suite != "resolute" {
				t.Fatalf("suite = %q", verified.Metadata.Suite)
			}
		})
	}
}

func TestVerifyReleaseIgnoreExpiryStillRejectsBadSignature(t *testing.T) {
	entity, _ := entities(t)
	signed := signInRelease(t, entity, releasePayload)
	tampered := bytes.Replace(signed, []byte("Suite: resolute"), []byte("Suite: evil"), 1)
	if _, err := deb.VerifyInRelease(tampered, trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.IgnoreExpiry}); err == nil {
		t.Fatal("accepted a tampered signature")
	}
}

func TestVerifyReleaseIgnoreExpiryStillRejectsRevocation(t *testing.T) {
	entity, err := openpgp.NewEntity("Revoked", "", "revoked@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEd25519,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := signInRelease(t, entity, releasePayload)
	if err := entity.RevokeKey(packet.NoReason, "test revocation", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := deb.VerifyInRelease(signed, trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.IgnoreExpiry}); err == nil {
		t.Fatal("accepted a revoked signing key")
	}
}

func TestVerifyInRelease(t *testing.T) {
	entity, _ := entities(t)
	signed := signInRelease(t, entity, releasePayload)

	verified, err := deb.VerifyInRelease(signed, trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Format != deb.ReleaseFormatInRelease {
		t.Fatalf("format = %q", verified.Format)
	}
	if len(verified.Signers) != 1 || verified.Signers[0] != fingerprint(entity) {
		t.Fatalf("signers = %v", verified.Signers)
	}
	if len(verified.Signature) != 0 {
		t.Fatal("InRelease must not have a detached signature")
	}
	if string(verified.SignedBytes) != strings.ReplaceAll(releasePayload, "\n", "\r\n") {
		t.Fatalf("signed bytes = %q", verified.SignedBytes)
	}
	want := deb.Release{
		Origin: "Ubuntu", Label: "Ubuntu", Suite: "resolute", Version: "26.04",
		Codename: "resolute", Date: "Thu, 23 Apr 2026 17:07:15 UTC",
		ValidUntil:    "Thu, 30 Apr 2026 17:07:15 UTC",
		Architectures: []string{"amd64", "arm64"},
		Components:    []string{"main", "restricted"},
	}
	if !reflect.DeepEqual(verified.Metadata, want) {
		t.Fatalf("metadata = %+v", verified.Metadata)
	}
}

func TestVerifyDetachedRelease(t *testing.T) {
	entity, _ := entities(t)
	signature := signRelease(t, entity)

	verified, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Format != deb.ReleaseFormatDetached {
		t.Fatalf("format = %q", verified.Format)
	}
	if len(verified.Signers) != 1 || verified.Signers[0] != fingerprint(entity) {
		t.Fatalf("signers = %v", verified.Signers)
	}
	if !bytes.Equal(verified.Signature, signature) {
		t.Fatal("detached signature was not retained")
	}
	if verified.Metadata.Suite != "resolute" {
		t.Fatalf("suite = %q", verified.Metadata.Suite)
	}
}

func TestVerifyDetachedReleaseBinarySignature(t *testing.T) {
	entity, _ := entities(t)
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, strings.NewReader(releasePayload), nil); err != nil {
		t.Fatal(err)
	}
	verified, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature.Bytes(), trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Metadata.Suite != "resolute" {
		t.Fatalf("suite = %q", verified.Metadata.Suite)
	}
}

func TestVerifyReleaseRejectsWrongKey(t *testing.T) {
	first, second := entities(t)
	signed := signInRelease(t, first, releasePayload)
	if _, err := deb.VerifyInRelease(signed, trustedKeys(t, second), deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified with an unrelated key")
	}
	signature := signRelease(t, first)
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, trustedKeys(t, second), deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified detached signature with an unrelated key")
	}
}

func TestVerifyReleaseRejectsTampering(t *testing.T) {
	entity, _ := entities(t)
	signed := signInRelease(t, entity, releasePayload)
	tampered := bytes.Replace(signed, []byte("Suite: resolute"), []byte("Suite: hostile"), 1)
	if bytes.Equal(signed, tampered) {
		t.Fatal("test payload was not changed")
	}
	if _, err := deb.VerifyInRelease(tampered, trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified tampered InRelease")
	}

	signature := signRelease(t, entity)
	tamperedRelease := bytes.Replace([]byte(releasePayload), []byte("amd64"), []byte("i386"), 1)
	if _, err := deb.VerifyDetachedRelease(tamperedRelease, signature, trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified tampered Release")
	}
}

func TestVerifyReleaseRejectsMalformedInput(t *testing.T) {
	entity, _ := entities(t)
	keys := trustedKeys(t, entity)
	cases := []struct {
		name         string
		inRelease    []byte
		release      []byte
		signature    []byte
		wantDetached bool
		wantError    string
	}{
		{name: "empty InRelease", wantError: "empty"},
		{name: "oversized InRelease", inRelease: make([]byte, deb.MaxReleaseSize+1), wantError: "exceeds"},
		{name: "unsigned plaintext", inRelease: []byte(releasePayload), wantError: "not validly signed"},
		{name: "trailing bytes", inRelease: append(signInRelease(t, entity, releasePayload), []byte("junk")...), wantError: "not validly signed"},
		{name: "no colon", inRelease: signInRelease(t, entity, "Suite resolute\n"), wantError: "malformed"},
		{name: "repeated field", inRelease: signInRelease(t, entity, "Suite: one\nSuite: two\n"), wantError: "repeats"},
		{name: "invalid UTF-8", inRelease: signInRelease(t, entity, "Suite: \xff\n"), wantError: "malformed"},
		{name: "detached empty release", signature: []byte("x"), wantDetached: true, wantError: "empty"},
		{name: "detached empty signature", release: []byte(releasePayload), wantDetached: true, wantError: "signature is empty"},
		{name: "detached garbage signature", release: []byte(releasePayload), signature: []byte("not a signature"), wantDetached: true, wantError: "not valid"},
		{name: "detached oversized signature", release: []byte(releasePayload), signature: make([]byte, deb.MaxReleaseSignatureSize+1), wantDetached: true, wantError: "exceeds"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var (
				verified *deb.VerifiedRelease
				err      error
			)
			if test.wantDetached {
				verified, err = deb.VerifyDetachedRelease(test.release, test.signature, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
			} else {
				verified, err = deb.VerifyInRelease(test.inRelease, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
			}
			if verified != nil {
				t.Fatalf("verified = %+v", verified)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestVerifyReleaseRequiresTrustedKeys(t *testing.T) {
	entity, _ := entities(t)
	signed := signInRelease(t, entity, releasePayload)
	if _, err := deb.VerifyInRelease(signed, nil, deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified without trusted keys")
	}
	signature := signRelease(t, entity)
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, nil, deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified detached signature without trusted keys")
	}
	if _, err := deb.VerifyInRelease(signed, []deb.PublicKey{{Fingerprint: strings.Repeat("0", 40), Entity: entity}}, deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("verified a signer outside the configured fingerprint")
	}
}

func TestVerifyReleaseDebianSuiteShapes(t *testing.T) {
	entity, _ := entities(t)
	keys := trustedKeys(t, entity)

	cases := []struct {
		name     string
		payload  string
		expected deb.ReleaseIdentity
		wantErr  string
	}{
		{
			name: "moving suite for trixie",
			payload: "Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: trixie\n" +
				"Architectures: amd64 arm64\nComponents: main contrib\n",
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
		},
		{
			name: "security suite with prefixed component",
			payload: "Origin: Debian\nLabel: Debian\nSuite: stable-security\nCodename: trixie-security\n" +
				"Architectures: amd64\nComponents: updates/main\n",
			expected: deb.ReleaseIdentity{
				Suite: "trixie-security", Architecture: "amd64", Components: []string{"main"},
				MatchCodename: true, PrefixedComponents: true,
			},
		},
		{
			name: "conflicting codename",
			payload: "Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: bookworm\n" +
				"Architectures: amd64\nComponents: main\n",
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
			wantErr:  `release codename "bookworm" does not match "trixie"`,
		},
		{
			name:     "missing codename",
			payload:  "Origin: Debian\nLabel: Debian\nSuite: stable\nArchitectures: amd64\nComponents: main\n",
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
			wantErr:  "release metadata has no codename",
		},
		{
			name: "missing component",
			payload: "Origin: Debian\nLabel: Debian\nSuite: stable-security\nCodename: trixie-security\n" +
				"Architectures: amd64\nComponents: updates/non-free\n",
			expected: deb.ReleaseIdentity{
				Suite: "trixie-security", Architecture: "amd64", Components: []string{"main"},
				MatchCodename: true, PrefixedComponents: true,
			},
			wantErr: `release metadata does not list component "main"`,
		},
		{
			name: "foreign architecture",
			payload: "Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: trixie\n" +
				"Architectures: i386\nComponents: main\n",
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
			wantErr:  "does not list architecture",
		},
		{
			name: "ubuntu codename still cannot satisfy a suite request",
			payload: "Origin: Ubuntu\nLabel: Ubuntu\nSuite: resolute-updates\nCodename: resolute\n" +
				"Architectures: amd64\nComponents: main\n",
			expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "amd64"},
			wantErr:  "does not match",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			verified, err := deb.VerifyInRelease(signInRelease(t, entity, test.payload), keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
			if err != nil {
				t.Fatal(err)
			}
			err = deb.CheckReleaseIdentity(&verified.Metadata, test.expected)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

// multiSignInRelease clear-signs one payload with several keys in the given order.
func multiSignInRelease(t *testing.T, signing ...signer) []byte {
	t.Helper()
	keys := make([]*packet.PrivateKey, len(signing))
	for i, entry := range signing {
		keys[i] = entry.entity.PrivateKey
	}
	var buffer bytes.Buffer
	writer, err := clearsign.EncodeMulti(&buffer, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(releasePayload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// multiSignRelease writes one binary detached signature per key, in the given order.
func multiSignRelease(t *testing.T, signing ...signer) []byte {
	t.Helper()
	var buffer bytes.Buffer
	for _, entry := range signing {
		if err := openpgp.DetachSign(&buffer, entry.entity, strings.NewReader(releasePayload), entry.config); err != nil {
			t.Fatal(err)
		}
	}
	return buffer.Bytes()
}

type signer struct {
	entity *openpgp.Entity
	config *packet.Config
}

// Replay must land on the signer the lock recorded, not on whichever signature is
// valid today, so ignoring expiry cannot quietly change the evidence.
func TestVerifyReleaseWithSignersKeepsRecordedSigner(t *testing.T) {
	first, second := entities(t)
	expired, config := expiredEntity(t)
	keys := trustedKeys(t, expired, first, second)
	// The recorded signer is the expired one and it comes last, so both
	// packet order and today's expiry point at a different signature.
	signing := []signer{{entity: first}, {entity: second}, {entity: expired, config: config}}
	inRelease := multiSignInRelease(t, signing...)

	replayed, err := deb.VerifyInRelease(inRelease, keys, deb.VerifyOptions{
		Policy:   deb.IgnoreExpiry,
		Accepted: []string{fingerprint(expired)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed.Signers, []string{fingerprint(expired)}) {
		t.Fatalf("signers = %v", replayed.Signers)
	}

	signature := multiSignRelease(t, signing...)
	detached, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, keys, deb.VerifyOptions{
		Policy:   deb.IgnoreExpiry,
		Accepted: []string{fingerprint(expired)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detached.Signers, []string{fingerprint(expired)}) {
		t.Fatalf("signers = %v", detached.Signers)
	}

	if _, err := deb.VerifyInRelease(inRelease, keys, deb.VerifyOptions{
		Policy:   deb.IgnoreExpiry,
		Accepted: []string{strings.Repeat("0", 40)},
	}); err == nil {
		t.Fatal("accepted a signer outside the recorded list")
	}
}

// Release.gpg is one complete file: a signature followed by anything the reader would
// skip is a file nobody signed. The armor library stops at the end of a block, ends a
// block at EOF when its closing line is missing, and skips leading garbage, so the
// envelope is checked here instead.
func TestVerifyDetachedReleaseRejectsAMalformedArmorTail(t *testing.T) {
	trusted, _ := entities(t)
	keys := trustedKeys(t, trusted)
	armored := signRelease(t, trusted)
	opts := deb.VerifyOptions{Policy: deb.EnforceExpiry}
	// The clean block, its checksum removed, and trailing whitespace are all still
	// one well-formed envelope.
	for name, accepted := range map[string][]byte{
		"clean":            armored,
		"without checksum": bytes.Replace(armored, []byte("\n="+armorChecksum(t, armored)), nil, 1),
		"trailing blank":   append(bytes.Clone(armored), []byte("\n \t\n")...),
	} {
		if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), accepted, keys, opts); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, rejected := range map[string][]byte{
		"text after the block":     append(bytes.Clone(armored), []byte("GARBAGE\n")...),
		"a second block":           append(bytes.Clone(armored), armored...),
		"text before the block":    append([]byte("GARBAGE\n"), armored...),
		"no closing line":          bytes.Replace(armored, []byte("-----END PGP SIGNATURE-----"), nil, 1),
		"a blank line in the body": bytes.Replace(armored, []byte("\n\n"), []byte("\n\n\n"), 1),
		"a wrong checksum":         bytes.Replace(armored, []byte("\n="+armorChecksum(t, armored)), []byte("\n=AAAA"), 1),
	} {
		if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), rejected, keys, opts); err == nil {
			t.Fatalf("%s: accepted a malformed armor tail", name)
		}
	}
}

// Every truncation of a signature file, armored or not, is a refusal: a shorter file
// must never read as the signature of a longer one.
func TestVerifyDetachedReleaseRejectsEveryTruncation(t *testing.T) {
	trusted, _ := entities(t)
	keys := trustedKeys(t, trusted)
	opts := deb.VerifyOptions{Policy: deb.EnforceExpiry}
	for name, signature := range map[string][]byte{
		"armored": signRelease(t, trusted),
		"binary":  signReleaseWithConfig(t, trusted, false, nil),
	} {
		for cut := 1; cut < len(signature); cut++ {
			if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature[:cut], keys, opts); err == nil {
				t.Fatalf("%s signature cut to %d bytes was accepted", name, cut)
			}
		}
	}
}

// armorChecksum returns the CRC24 line of an armored signature, so a test can remove
// or damage it without hardcoding a value that changes with every key.
func armorChecksum(t *testing.T, armored []byte) string {
	t.Helper()
	lines := bytes.SplitSeq(armored, []byte("\n"))
	for line := range lines {
		if bytes.HasPrefix(line, []byte("=")) && len(line) == 5 {
			return string(line[1:])
		}
	}
	t.Fatal("the fixture signature has no checksum line")
	return ""
}
