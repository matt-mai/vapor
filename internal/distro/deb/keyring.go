package deb

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// PublicKeyring encodes only the selected public keys as a deterministic binary keyring.
func PublicKeyring(keys []PublicKey) ([]byte, error) {
	ordered := slices.Clone(keys)
	slices.SortFunc(ordered, func(a, b PublicKey) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	var buffer bytes.Buffer
	for _, key := range ordered {
		if err := writePublicEntity(&buffer, key.Entity); err != nil {
			return nil, fmt.Errorf("encode public keyring: %w", err)
		}
	}
	return buffer.Bytes(), nil
}

func writePublicEntity(w io.Writer, entity *openpgp.Entity) error {
	// Entity.Serialize traverses identities in map order. Write them in name order
	// between the primary key and subkeys, as required by the keyring format.
	primary := *entity
	primary.Identities, primary.Subkeys = nil, nil
	if err := primary.Serialize(w); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(entity.Identities)) {
		identity := entity.Identities[name]
		if err := identity.UserId.Serialize(w); err != nil {
			return err
		}
		for _, signature := range identity.Signatures {
			if err := signature.Serialize(w); err != nil {
				return err
			}
		}
	}
	for index := range entity.Subkeys {
		if err := writePublicSubkey(w, &entity.Subkeys[index]); err != nil {
			return err
		}
	}
	return nil
}

func writePublicSubkey(w io.Writer, subkey *openpgp.Subkey) error {
	if err := subkey.PublicKey.Serialize(w); err != nil {
		return err
	}
	for _, revocation := range subkey.Revocations {
		if err := revocation.Serialize(w); err != nil {
			return err
		}
	}
	return subkey.Sig.Serialize(w)
}
