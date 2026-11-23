package deb

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MaxReleaseSize bounds signed repository metadata before OpenPGP parsing.
const MaxReleaseSize = 4 << 20

// MaxReleaseSignatureSize bounds a detached release signature before parsing.
const MaxReleaseSignatureSize = 64 << 10

// MaxSignatureAttempts bounds how many signature packets one release may carry.
// Every packet from an issuer this build knows costs a hash over the whole payload,
// so a small signature stream could otherwise multiply verification work. Debian
// signs with three keys and Ubuntu with one; eight is generous for both.
const MaxSignatureAttempts = 8

const sha256Section = "SHA256"

// ExpiryPolicy controls whether key and signature expiry rejects a validly
// signed release. Revocation and every other signature check always apply.
type ExpiryPolicy uint8

const (
	// EnforceExpiry rejects keys or signatures that have expired.
	EnforceExpiry ExpiryPolicy = iota
	// IgnoreExpiry accepts a cryptographically valid signature from an expired
	// key or signature. Use only to replay already-locked historical evidence.
	IgnoreExpiry
)

// Release format names match the lock evidence format.
const (
	ReleaseFormatInRelease = "inrelease"
	ReleaseFormatDetached  = "release-gpg"
)

// Release is the authenticated payload of a Debian Release file.
type Release struct {
	Origin        string
	Label         string
	Suite         string
	Version       string
	Codename      string
	Date          string
	ValidUntil    string
	Architectures []string
	Components    []string
	AcquireByHash bool
	Files         map[string]ReleaseFile
}

// ReleaseFile is one SHA256 entry from authenticated release metadata.
type ReleaseFile struct {
	SHA256 string
	Size   int64
}

// VerifiedRelease is signed metadata after successful authentication.
type VerifiedRelease struct {
	Format      string
	Signers     []string
	SignedBytes []byte
	Signature   []byte
	Metadata    Release
}

// VerifyOptions tunes how a release signature is accepted.
type VerifyOptions struct {
	// Policy decides whether key and signature expiry rejects a signature.
	Policy ExpiryPolicy
	// Accepted restricts the accepted primary fingerprints. Empty accepts any
	// trusted signer.
	Accepted []string
	// Now is the time expiry checks use. Zero reads the current time, which is
	// only right for a live acquisition.
	Now time.Time
}

func (o VerifyOptions) config() *packet.Config {
	if o.Now.IsZero() {
		return nil
	}
	return &packet.Config{Time: func() time.Time { return o.Now }}
}

// VerifyInRelease authenticates an InRelease file and parses its signed payload.
// It accepts the first signature, in packet order, that a trusted key made, after
// checking that the rest of the signature stream is well-formed.
func VerifyInRelease(data []byte, keys []PublicKey, opts VerifyOptions) (*VerifiedRelease, error) {
	if len(data) == 0 {
		return nil, errors.New("InRelease is empty")
	}
	if len(data) > MaxReleaseSize {
		return nil, fmt.Errorf("InRelease exceeds %d bytes", MaxReleaseSize)
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted keys configured")
	}

	block, rest := clearsign.Decode(data)
	if block == nil || block.ArmoredSignature == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("InRelease is not validly signed")
	}
	fingerprint, err := verifySignatures(block.Bytes, block.ArmoredSignature.Body, keys, opts)
	if err != nil {
		return nil, errors.New("InRelease is not validly signed")
	}
	metadata, err := parseRelease(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &VerifiedRelease{
		Format:      ReleaseFormatInRelease,
		Signers:     []string{fingerprint},
		SignedBytes: bytes.Clone(block.Bytes),
		Metadata:    metadata,
	}, nil
}

// VerifyDetachedRelease authenticates a Release file and its Release.gpg
// signature, then parses the signed payload. It accepts the first signature, in
// packet order, that a trusted key made, after checking that the rest of the
// signature stream is well-formed.
func VerifyDetachedRelease(release, signature []byte, keys []PublicKey, opts VerifyOptions) (*VerifiedRelease, error) {
	if len(release) == 0 {
		return nil, errors.New("Release is empty")
	}
	if len(release) > MaxReleaseSize {
		return nil, fmt.Errorf("Release exceeds %d bytes", MaxReleaseSize)
	}
	if len(signature) == 0 {
		return nil, errors.New("Release signature is empty")
	}
	if len(signature) > MaxReleaseSignatureSize {
		return nil, fmt.Errorf("Release signature exceeds %d bytes", MaxReleaseSignatureSize)
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted keys configured")
	}

	body, err := signatureBody(signature)
	if err != nil {
		return nil, errors.New("Release signature is not valid")
	}
	fingerprint, err := verifySignatures(release, body, keys, opts)
	if err != nil {
		return nil, errors.New("Release signature is not valid")
	}
	metadata, err := parseRelease(release)
	if err != nil {
		return nil, err
	}
	return &VerifiedRelease{
		Format:      ReleaseFormatDetached,
		Signers:     []string{fingerprint},
		SignedBytes: bytes.Clone(release),
		Signature:   bytes.Clone(signature),
		Metadata:    metadata,
	}, nil
}
