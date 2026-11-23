package deb

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MaxKeySnapshotSize bounds one public-key snapshot before OpenPGP parsing.
const MaxKeySnapshotSize = 1 << 20

// PublicKey is a parsed public key, its full fingerprint and its declared key
// identifier.
type PublicKey struct {
	Fingerprint string
	KeyID       string
	Entity      *openpgp.Entity
}

// KeySnapshot is a reviewed public-key snapshot and the full fingerprints that
// may be trusted from it.
type KeySnapshot struct {
	Fingerprints []string
	Data         []byte
}

// ParsePublicKey parses exactly one primary public-key packet from an armored
// or binary snapshot without attaching trust to it.
func ParsePublicKey(data []byte) (PublicKey, error) {
	if len(data) == 0 {
		return PublicKey{}, errors.New("public key is empty")
	}
	if len(data) > MaxKeySnapshotSize {
		return PublicKey{}, fmt.Errorf("public key exceeds %d bytes", MaxKeySnapshotSize)
	}
	packets, err := publicKeyPackets(data)
	if err != nil {
		return PublicKey{}, err
	}
	primary, err := readPublicKeyPacket(packets)
	if err != nil {
		return PublicKey{}, err
	}
	fingerprint := primary.Fingerprint
	if len(fingerprint) != 20 && len(fingerprint) != 32 {
		return PublicKey{}, errors.New("public key snapshot has an unsupported fingerprint length")
	}
	return PublicKey{
		Fingerprint: strings.ToUpper(hex.EncodeToString(fingerprint)),
		KeyID:       primary.KeyIdString(),
		Entity:      &openpgp.Entity{PrimaryKey: primary},
	}, nil
}

func publicKeyPackets(data []byte) (io.Reader, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		return bytes.NewReader(data), nil
	}
	blockBytes, err := singleArmorBlock(trimmed)
	if err != nil {
		return nil, err
	}
	block, err := armor.Decode(bytes.NewReader(blockBytes))
	if err != nil || block.Type != openpgp.PublicKeyType {
		return nil, errors.New("public key snapshot is not a valid OpenPGP keyring")
	}
	return block.Body, nil
}

func readPublicKeyPacket(reader io.Reader) (*packet.PublicKey, error) {
	var primary *packet.PublicKey
	for {
		packetValue, err := packet.Read(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("public key snapshot is not a valid OpenPGP keyring")
		}
		if err := recordPublicKeyPacket(packetValue, &primary); err != nil {
			return nil, err
		}
	}
	if primary == nil {
		return nil, errors.New("public key snapshot contains no public key packet")
	}
	return primary, nil
}

func recordPublicKeyPacket(value packet.Packet, primary **packet.PublicKey) error {
	switch key := value.(type) {
	case *packet.PrivateKey:
		return errors.New("public key snapshot contains private-key material")
	case *packet.PublicKey:
		// A bound subkey is part of the key, not a second key: archives sign with a
		// subkey, so a published keyring carries one.
		if key.IsSubkey {
			return nil
		}
		if *primary != nil {
			return errors.New("public key snapshot must contain exactly one public key packet")
		}
		*primary = key
	}
	return nil
}

// ParseKeyring parses one public-key snapshot and returns its single primary key,
// keeping the bound subkeys, because an archive signs with a subkey. A snapshot
// that carries a second key or private material is refused: the shipped bytes must
// be exactly the key that was reviewed.
func ParseKeyring(data []byte) (PublicKey, error) {
	if len(data) == 0 {
		return PublicKey{}, errors.New("public key snapshot is empty")
	}
	if len(data) > MaxKeySnapshotSize {
		return PublicKey{}, fmt.Errorf("public key snapshot exceeds %d bytes", MaxKeySnapshotSize)
	}
	keys, err := parsePublicKeys(data)
	if err != nil {
		return PublicKey{}, err
	}
	if len(keys) != 1 {
		return PublicKey{}, fmt.Errorf("public key snapshot must contain exactly one public key, found %d", len(keys))
	}
	return keys[0], nil
}

// LoadTrustedKeys parses one public-key snapshot and returns the keys whose full
// fingerprints are configured, in configured order. Other keys in the snapshot
// are neither trusted nor returned.
func LoadTrustedKeys(data []byte, fingerprints []string) ([]PublicKey, error) {
	if len(fingerprints) == 0 {
		return nil, errors.New("no trusted fingerprints configured")
	}
	if len(data) == 0 {
		return nil, errors.New("public key snapshot is empty")
	}
	if len(data) > MaxKeySnapshotSize {
		return nil, fmt.Errorf("public key snapshot exceeds %d bytes", MaxKeySnapshotSize)
	}

	if _, err := wantedFingerprints(fingerprints); err != nil {
		return nil, err
	}
	keys, err := parsePublicKeys(data)
	if err != nil {
		return nil, err
	}
	available, err := keyIndex(keys)
	if err != nil {
		return nil, err
	}
	trusted := make([]PublicKey, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		canonical, _ := canonicalFingerprint(fingerprint)
		key, ok := available[canonical]
		if !ok {
			return nil, fmt.Errorf("snapshot does not contain trusted fingerprint %s", canonical)
		}
		trusted = append(trusted, key)
	}
	return trusted, nil
}

func wantedFingerprints(fingerprints []string) (map[string]bool, error) {
	wanted := make(map[string]bool, len(fingerprints))
	for _, fingerprint := range fingerprints {
		canonical, ok := canonicalFingerprint(fingerprint)
		if !ok {
			return nil, errors.New("trusted fingerprint must be 40 or 64 hexadecimal characters")
		}
		if wanted[canonical] {
			return nil, fmt.Errorf("duplicate trusted fingerprint %s", canonical)
		}
		wanted[canonical] = true
	}
	return wanted, nil
}

func keyIndex(keys []PublicKey) (map[string]PublicKey, error) {
	available := make(map[string]PublicKey, len(keys))
	for _, key := range keys {
		if _, duplicate := available[key.Fingerprint]; duplicate {
			return nil, fmt.Errorf("duplicate public key fingerprint %s", key.Fingerprint)
		}
		available[key.Fingerprint] = key
	}
	return available, nil
}

func parsePublicKeys(data []byte) ([]PublicKey, error) {
	entities, err := readKeyring(data)
	if err != nil {
		return nil, err
	}
	keys := make([]PublicKey, 0, len(entities))
	for _, entity := range entities {
		if err := validateEntity(entity); err != nil {
			return nil, err
		}
		fingerprint := entity.PrimaryKey.Fingerprint
		keys = append(keys, PublicKey{
			Fingerprint: strings.ToUpper(hex.EncodeToString(fingerprint)),
			KeyID:       entity.PrimaryKey.KeyIdString(),
			Entity:      entity,
		})
	}
	if len(keys) == 0 {
		return nil, errors.New("public key snapshot contains no keys")
	}
	return keys, nil
}

func readKeyring(data []byte) (openpgp.EntityList, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		entities, err := openpgp.ReadKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("public key snapshot is not a valid OpenPGP keyring")
		}
		return entities, nil
	}
	block, err := singleArmorBlock(trimmed)
	if err != nil {
		return nil, err
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(block))
	if err != nil {
		return nil, errors.New("public key snapshot is not a valid OpenPGP keyring")
	}
	return entities, nil
}

func validateEntity(entity *openpgp.Entity) error {
	if entity.PrivateKey != nil {
		return errors.New("public key snapshot contains private-key material")
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil {
			return errors.New("public key snapshot contains private-key material")
		}
	}
	if entity.PrimaryKey == nil {
		return errors.New("public key snapshot has no primary key")
	}
	fingerprint := entity.PrimaryKey.Fingerprint
	if len(fingerprint) != 20 && len(fingerprint) != 32 {
		return errors.New("public key snapshot has an unsupported fingerprint length")
	}
	return nil
}

func singleArmorBlock(data []byte) ([]byte, error) {
	var blockType string
	for offset := 0; offset < len(data); {
		lineEnd := len(data)
		if next := bytes.IndexByte(data[offset:], '\n'); next >= 0 {
			lineEnd = offset + next + 1
		}
		line := bytes.TrimSpace(data[offset:lineEnd])
		switch {
		case blockType == "":
			const begin = "-----BEGIN PGP "
			if !bytes.HasPrefix(line, []byte(begin)) || !bytes.HasSuffix(line, []byte("-----")) {
				return nil, errors.New("public key snapshot is not a valid OpenPGP keyring")
			}
			blockType = string(line[len(begin) : len(line)-len("-----")])
		case string(line) == "-----END PGP "+blockType+"-----":
			if len(bytes.TrimSpace(data[lineEnd:])) != 0 {
				return nil, errors.New("public key snapshot has data after the armored key block")
			}
			return data[:lineEnd], nil
		case bytes.HasPrefix(line, []byte("-----END PGP ")):
			return nil, errors.New("public key snapshot has data after the armored key block")
		}
		offset = lineEnd
	}
	return nil, errors.New("public key snapshot is not a valid OpenPGP keyring")
}

func canonicalFingerprint(fingerprint string) (string, bool) {
	if len(fingerprint) != 20*2 && len(fingerprint) != 32*2 {
		return "", false
	}
	for i := 0; i < len(fingerprint); i++ {
		if !isHex(fingerprint[i]) {
			return "", false
		}
	}
	return strings.ToUpper(fingerprint), true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
