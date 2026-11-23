package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"
)

// EnvelopeType is the DSSE protocol label of the pre-authentication encoding.
const envelopeType = "DSSEv1"

// maxSigningKeySize bounds the key file read, so a huge or endless file fails fast.
const maxSigningKeySize = 64 << 10

// Envelope is the DSSE JSON envelope: a payload, the type that says how to read it and
// the signatures over both. The payload stays base64 in the document, exactly as signed.
type Envelope struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature over the envelope's payload and payload type.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// SigningKey is an Ed25519 private key read from a PEM file.
type SigningKey struct {
	ed25519.PrivateKey
}

// LoadSigningKey reads a PKCS#8 Ed25519 private key from a PEM file. The key material
// never leaves this function: the file bytes are cleared before returning, and no error
// carries the path, any part of the key or the PEM label a reader chose.
func LoadSigningKey(path string) (SigningKey, error) {
	data, err := readSigningKey(path)
	if err != nil {
		return SigningKey{}, err
	}
	defer clear(data)
	block, _ := pem.Decode(data)
	if block == nil {
		return SigningKey{}, errors.New("attest: signing key is not a PEM document")
	}
	defer clear(block.Bytes)
	if _, rest := pem.Decode(data); rest != nil && len(bytes.TrimSpace(rest)) > 0 {
		return SigningKey{}, errors.New("attest: signing key holds more than one PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return SigningKey{}, errors.New(
			"attest: signing key block is not a PKCS#8 PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return SigningKey{}, errors.New("attest: signing key is not a valid PKCS#8 private key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return SigningKey{}, errors.New("attest: signing key is not an Ed25519 key")
	}
	return SigningKey{PrivateKey: key}, nil
}

// readSigningKey returns the bytes of the key file, refusing anything but a regular
// file within the size bound. The bound is checked on the handle that is read, and the
// read stops one byte past it, so a file that grows or is replaced after the check
// cannot make the read unbounded.
func readSigningKey(path string) ([]byte, error) {
	// O_NONBLOCK prevents a FIFO from blocking the open before its type is checked.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("attest: signing key cannot be read")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("attest: signing key cannot be read")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("attest: signing key is not a regular file")
	}
	if info.Size() > maxSigningKeySize {
		return nil, errors.New("attest: signing key file is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSigningKeySize+1))
	if err != nil {
		return nil, errors.New("attest: signing key cannot be read")
	}
	if len(data) > maxSigningKeySize {
		clear(data)
		return nil, errors.New("attest: signing key file is too large")
	}
	return data, nil
}

// KeyID names the key in a signature. It is a digest of the public key, so it is stable
// across runs and reveals nothing about the private half.
func (key SigningKey) KeyID() string {
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}

// Sign builds a signed envelope over the payload. Ed25519 is deterministic, so the same
// payload and key always produce the same envelope bytes.
func (key SigningKey) Sign(payloadType string, payload []byte) (Envelope, error) {
	if payloadType == "" {
		return Envelope{}, errors.New("attest: DSSE requires a payload type")
	}
	if len(payload) == 0 {
		return Envelope{}, errors.New("attest: DSSE requires a payload")
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("attest: DSSE requires an Ed25519 signing key")
	}
	signature := ed25519.Sign(key.PrivateKey, preAuthenticationEncoding(payloadType, payload))
	return Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: payloadType,
		Signatures: []Signature{{
			KeyID: key.KeyID(),
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	}, nil
}

// Verify checks every signature and returns the payload bytes that were signed. It never
// re-encodes the payload: the bytes given back are the bytes the signature covers.
func (envelope *Envelope) Verify(public ed25519.PublicKey) ([]byte, error) {
	if envelope.PayloadType == "" {
		return nil, errors.New("attest: DSSE envelope has no payload type")
	}
	if len(envelope.Signatures) == 0 {
		return nil, errors.New("attest: DSSE envelope has no signatures")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, errors.New("attest: DSSE payload is not base64")
	}
	encoding := preAuthenticationEncoding(envelope.PayloadType, payload)
	for position := range envelope.Signatures {
		signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[position].Sig)
		if err != nil {
			return nil, errors.New("attest: DSSE signature is not base64")
		}
		if !ed25519.Verify(public, encoding, signature) {
			return nil, errors.New("attest: DSSE signature does not verify")
		}
	}
	return payload, nil
}

// Clear removes the private key from memory once a run is finished with it. The slice is
// dropped as well as zeroed, so a cleared key cannot be used to sign again.
func (key *SigningKey) Clear() {
	if key != nil {
		clear(key.PrivateKey)
		key.PrivateKey = nil
	}
}

// MaybeSigned returns the DSSE envelope of a payload when the key is set, and the payload
// itself otherwise. It is how signing stays optional: the unsigned payload is unchanged
// and only its wrapper depends on the key. The zero SigningKey means "no key".
func MaybeSigned(key SigningKey, payloadType string, payload []byte) ([]byte, bool, error) {
	if len(key.PrivateKey) == 0 {
		return payload, false, nil
	}
	envelope, err := key.Sign(payloadType, payload)
	if err != nil {
		return nil, false, err
	}
	encoded, err := Encode(envelope)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

// preAuthenticationEncoding is the DSSE PAE:
// "DSSEv1" SP len(type) SP type SP len(body) SP body.
func preAuthenticationEncoding(payloadType string, payload []byte) []byte {
	var buffer bytes.Buffer
	buffer.Grow(len(envelopeType) + len(payloadType) + len(payload) + 32)
	buffer.WriteString(envelopeType)
	buffer.WriteByte(' ')
	buffer.WriteString(strconv.Itoa(len(payloadType)))
	buffer.WriteByte(' ')
	buffer.WriteString(payloadType)
	buffer.WriteByte(' ')
	buffer.WriteString(strconv.Itoa(len(payload)))
	buffer.WriteByte(' ')
	buffer.Write(payload)
	return buffer.Bytes()
}
