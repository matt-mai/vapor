package deb

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// verifySignatures returns the fingerprint of the first signature, in packet
// order, that a trusted key made, the policy accepts, and, when accepted is not
// empty, that the caller named.
//
// A release may carry several signatures, and an archive rotates keys, so each
// packet is verified on its own. The library stops at the first packet whose
// issuer it knows, which would reject a release whose first signature comes from
// a key this build does not trust. A signature that does not qualify is skipped.
//
// The whole bounded stream is read before any signature settles the answer. A
// valid signature followed by malformed data must not read as a good release, and
// a stream that could only be judged by looking past the accepted signature could
// not be judged at all.
func verifySignatures(signed []byte, signature io.Reader, keys []PublicKey, opts VerifyOptions) (string, error) {
	packets, err := signaturePackets(signature)
	if err != nil {
		return "", err
	}
	keyring := trustedKeyring(keys)
	// The byte limit bounds how large the packet stream may be, not how much work
	// it may cause: every recognized issuer costs one hash of the whole payload,
	// whatever the packet size. The attempt cap is what keeps a padding of valid
	// signatures from turning into unbounded work.
	for _, packet := range packets {
		fingerprint, found, err := verifySignaturePacket(packet, keyring, signed, keys, opts)
		if err != nil {
			return "", err
		}
		if found {
			return fingerprint, nil
		}
	}
	return "", errors.New("release has no acceptable signature")
}

// signaturePackets reads the bounded signature stream and requires it to be nothing
// but signature packets, within the attempt cap. The reader is read directly rather
// than through packet.Reader, which skips unknown packets and reports a truncated one
// as a clean end.
func signaturePackets(signature io.Reader) ([]*packet.Signature, error) {
	reader := bufio.NewReader(signature)
	signatures := make([]*packet.Signature, 0, MaxSignatureAttempts)
	for len(signatures) <= MaxSignatureAttempts {
		next, err := packet.Read(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("release signature is malformed")
		}
		sig, ok := next.(*packet.Signature)
		if !ok {
			return nil, errors.New("release signature is malformed")
		}
		signatures = append(signatures, sig)
	}
	if len(signatures) == 0 {
		return nil, errors.New("release has no acceptable signature")
	}
	if len(signatures) > MaxSignatureAttempts {
		return nil, errors.New("release has too many signatures")
	}
	return signatures, nil
}

// verifySignaturePacket verifies one packet. A signature that does not qualify
// reports found as false rather than an error.
func verifySignaturePacket(sig *packet.Signature, keyring openpgp.EntityList, signed []byte,
	keys []PublicKey, opts VerifyOptions,
) (string, bool, error) {
	// Serialize re-encodes the one packet so the library verifies it in
	// isolation rather than consuming the rest of the stream.
	var encoded bytes.Buffer
	if err := sig.Serialize(&encoded); err != nil {
		return "", false, errors.New("release signature is malformed")
	}
	signer, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(signed), &encoded, opts.config())
	if !acceptedSignature(err, signer, opts.Policy) {
		return "", false, nil
	}
	fingerprint, fingerprintErr := signerFingerprint(signer, keys)
	if fingerprintErr != nil {
		return "", false, nil
	}
	if len(opts.Accepted) != 0 && !slices.Contains(opts.Accepted, fingerprint) {
		return "", false, nil
	}
	return fingerprint, true, nil
}

func acceptedSignature(err error, signer *openpgp.Entity, policy ExpiryPolicy) bool {
	if err == nil {
		return true
	}
	if policy != IgnoreExpiry || signer == nil {
		return false
	}
	return errors.Is(err, pgperrors.ErrSignatureExpired) || errors.Is(err, pgperrors.ErrKeyExpired)
}

func trustedKeyring(keys []PublicKey) openpgp.EntityList {
	keyring := make(openpgp.EntityList, 0, len(keys))
	for _, key := range keys {
		if key.Entity != nil {
			keyring = append(keyring, key.Entity)
		}
	}
	return keyring
}

func signerFingerprint(signer *openpgp.Entity, keys []PublicKey) (string, error) {
	if signer == nil || signer.PrimaryKey == nil {
		return "", errors.New("release signer is not a trusted key")
	}
	fingerprint := strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint))
	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			return fingerprint, nil
		}
	}
	return "", errors.New("release signer is not a trusted key")
}
