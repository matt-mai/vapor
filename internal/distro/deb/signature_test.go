package deb_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// A release signed twice is accepted whichever packet comes first, and both
// orders record the first trusted signer in packet order.
func TestVerifyReleaseMultipleSignatures(t *testing.T) {
	first, second := entities(t)
	keys := trustedKeys(t, first, second)
	cases := map[string]struct {
		signing []signer
		want    string
	}{
		"first then second": {signing: []signer{{entity: first}, {entity: second}}, want: fingerprint(first)},
		"second then first": {signing: []signer{{entity: second}, {entity: first}}, want: fingerprint(second)},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			inRelease := multiSignInRelease(t, test.signing...)
			verified, err := deb.VerifyInRelease(inRelease, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(verified.Signers, []string{test.want}) {
				t.Fatalf("signers = %v", verified.Signers)
			}
			if verified.Metadata.Suite != "resolute" {
				t.Fatalf("suite = %q", verified.Metadata.Suite)
			}

			signature := multiSignRelease(t, test.signing...)
			detached, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(detached.Signers, []string{test.want}) {
				t.Fatalf("signers = %v", detached.Signers)
			}
		})
	}
}

// A signature from a key this build does not trust is skipped, so a trusted
// signature that follows it still authenticates the release.
func TestVerifyReleaseSkipsUntrustedSignature(t *testing.T) {
	trusted, untrusted := entities(t)
	signing := []signer{{entity: untrusted}, {entity: trusted}}
	inRelease := multiSignInRelease(t, signing...)
	verified, err := deb.VerifyInRelease(inRelease, trustedKeys(t, trusted), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified.Signers, []string{fingerprint(trusted)}) {
		t.Fatalf("signers = %v", verified.Signers)
	}

	signature := multiSignRelease(t, signing...)
	detached, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, trustedKeys(t, trusted), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detached.Signers, []string{fingerprint(trusted)}) {
		t.Fatalf("signers = %v", detached.Signers)
	}
}

// An expired signature beside a valid one does not fail the release: the expired
// one is skipped and the valid one recorded.
func TestVerifyReleaseSkipsExpiredSignature(t *testing.T) {
	expired, config := expiredEntity(t)
	valid, _ := entities(t)
	signing := []signer{{entity: expired, config: config}, {entity: valid}}
	keys := trustedKeys(t, expired, valid)

	inRelease := multiSignInRelease(t, signing...)
	verified, err := deb.VerifyInRelease(inRelease, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified.Signers, []string{fingerprint(valid)}) {
		t.Fatalf("signers = %v", verified.Signers)
	}

	signature := multiSignRelease(t, signing...)
	detached, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detached.Signers, []string{fingerprint(valid)}) {
		t.Fatalf("signers = %v", detached.Signers)
	}
}

// Every packet from a known issuer costs a hash of the whole payload, so the
// number of packets is capped independently of the signature byte limit: a small
// stream of valid signatures cannot multiply verification work.
//
// The cap is only observable at its boundary, because a packet that qualifies
// ends the search: the acceptable signer is placed at the cap and one past it.
func TestVerifyReleaseCapsSignatureAttempts(t *testing.T) {
	first, second := entities(t)
	keys := trustedKeys(t, first, second)
	// Packet order: filler signatures that verify but are not the recorded
	// signer, then the recorded one last, so every filler costs a full pass.
	signing := func(fillers int) []byte {
		entries := make([]signer, 0, fillers+1)
		for range fillers {
			entries = append(entries, signer{entity: first})
		}
		return multiSignInRelease(t, append(entries, signer{entity: second})...)
	}
	opts := deb.VerifyOptions{Policy: deb.IgnoreExpiry, Accepted: []string{fingerprint(second)}}

	if _, err := deb.VerifyInRelease(signing(deb.MaxSignatureAttempts-1), keys, opts); err != nil {
		t.Fatalf("refused a signer on the last allowed attempt: %v", err)
	}
	if _, err := deb.VerifyInRelease(signing(deb.MaxSignatureAttempts), keys, opts); err == nil {
		t.Fatal("accepted a signer past the attempt cap")
	}

	detached := func(fillers int) []byte {
		entries := make([]signer, 0, fillers+1)
		for range fillers {
			entries = append(entries, signer{entity: first})
		}
		return multiSignRelease(t, append(entries, signer{entity: second})...)
	}
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload),
		detached(deb.MaxSignatureAttempts), keys, opts); err == nil {
		t.Fatal("accepted a detached signer past the attempt cap")
	}

	// A stream of filler packets below the byte limit still cannot hold many
	// attempts, so the cap rather than the size is what a caller relies on.
	if size := len(signing(deb.MaxSignatureAttempts)); int64(size) > deb.MaxReleaseSignatureSize {
		t.Fatalf("fixture is %d bytes, more than the signature limit already refuses", size)
	}
}

func TestVerifyReleaseRejectsUntrustedSignatureSet(t *testing.T) {
	trusted, untrusted := entities(t)
	inRelease := multiSignInRelease(t, signer{entity: untrusted})
	if _, err := deb.VerifyInRelease(inRelease, trustedKeys(t, trusted), deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted a release signed only by an untrusted key")
	}
	signature := multiSignRelease(t, signer{entity: untrusted})
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, trustedKeys(t, trusted),
		deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted a detached release signed only by an untrusted key")
	}
}

// Skipping copies that do not qualify must not become skipping damaged data.
// A valid signature at the front must not hide damage behind it: the signer is
// settled first, so nothing further is read on the old path.
func TestVerifyReleaseRejectsDamageAfterAnAcceptableSignature(t *testing.T) {
	trusted, _ := entities(t)
	keys := trustedKeys(t, trusted)
	clean := multiSignRelease(t, signer{entity: trusted})
	damaged := append(append([]byte(nil), clean...), 0x00, 0x01, 0x02)
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), damaged, keys,
		deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted damaged data after a valid signature")
	}
	// The same stream without the damage still verifies, and the signer is the one
	// that signed it.
	verified, err := deb.VerifyDetachedRelease([]byte(releasePayload), clean, keys,
		deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatalf("clean signature: %v", err)
	}
	if len(verified.Signers) != 1 || !strings.EqualFold(verified.Signers[0], fingerprint(trusted)) {
		t.Fatalf("signer = %v", verified.Signers)
	}
	// A non-signature packet after the accepted one is refused as well.
	garbage := append(append([]byte(nil), clean...), 0xC3, 0x01, 0x00)
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), garbage, keys,
		deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted a non-signature packet after a valid signature")
	}
	// Trailing signatures still have to fit the same attempt cap.
	padded := clean
	for range deb.MaxSignatureAttempts {
		padded = append(append([]byte(nil), padded...), clean...)
	}
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), padded, keys,
		deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted a trailing stream past the attempt cap")
	}
}

func TestVerifyReleaseRejectsMalformedSignaturePackets(t *testing.T) {
	trusted, untrusted := entities(t)
	keys := trustedKeys(t, trusted)
	// An untrusted packet forces the reader past it, where the damage lives.
	signature := append(multiSignRelease(t, signer{entity: untrusted}), 0x00, 0x01, 0x02)
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), signature, keys, deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted damaged signature data")
	}
	var armorBuffer bytes.Buffer
	armorWriter, err := armor.Encode(&armorBuffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := trusted.Serialize(armorWriter); err != nil {
		t.Fatal(err)
	}
	if err := armorWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := deb.VerifyDetachedRelease([]byte(releasePayload), armorBuffer.Bytes(), keys,
		deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
		t.Fatal("accepted an armored key block as a signature")
	}
}
