package slices

import (
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// PublicKey is a declared key. The fingerprint comes from the key bytes; the
// identifier is only a self-consistency check, not a trust decision.
type PublicKey struct {
	ID          string
	Armor       string
	Fingerprint string
}

type rawPublicKey struct {
	ID    string `yaml:"id"`
	Armor string `yaml:"armor"`
}

func parsePublicKeys(rawKeys map[string]rawPublicKey) (map[string]PublicKey, error) {
	keys := make(map[string]PublicKey, len(rawKeys))
	for _, name := range sortedKeys(rawKeys) {
		key, err := parsePublicKey(name, rawKeys[name])
		if err != nil {
			return nil, err
		}
		keys[name] = key
	}
	return keys, nil
}

func parsePublicKey(name string, raw rawPublicKey) (PublicKey, error) {
	if name == "" {
		return PublicKey{}, errors.New("catalogue public key name is empty")
	}
	if !isKeyID(raw.ID) {
		return PublicKey{}, fmt.Errorf("catalogue public key %q has invalid id", name)
	}
	key, err := deb.ParsePublicKey([]byte(raw.Armor))
	if err != nil {
		return PublicKey{}, fmt.Errorf("catalogue public key %q is invalid", name)
	}
	if got := key.KeyID; got != raw.ID {
		return PublicKey{}, fmt.Errorf("catalogue public key %q has id %q, want %q", name, raw.ID, got)
	}
	return PublicKey{ID: raw.ID, Armor: raw.Armor, Fingerprint: key.Fingerprint}, nil
}

func isKeyID(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}
