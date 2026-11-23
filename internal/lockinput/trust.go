package lockinput

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

type trustSet struct {
	records []lock.RepositoryKey
	public  []deb.PublicKey
}

func repositoryTrust(request *Request, binding *slicespkg.Binding) (trustSet, error) {
	if len(binding.Trust) != 0 {
		return explicitTrust(request, binding.Trust)
	}
	return defaultTrust(request, binding.DefaultTrust)
}

func explicitTrust(request *Request, keys []contents.TrustKey) (trustSet, error) {
	var result trustSet
	for i := range keys {
		key := &keys[i]
		input, ok := localInput(request, key.Path)
		if !ok {
			return trustSet{}, fmt.Errorf("trust key %q was not snapshotted", key.Path)
		}
		data, err := readTreeBlob(request.Cache, input.SHA256, input.Size)
		if err != nil {
			return trustSet{}, fmt.Errorf("trust key %q: %w", key.Path, err)
		}
		public, err := deb.LoadTrustedKeys(data, key.Fingerprints)
		if err != nil {
			return trustSet{}, err
		}
		for _, fingerprint := range key.Fingerprints {
			result.records = append(result.records, lock.RepositoryKey{
				Path: key.Path, Fingerprint: fingerprint, SHA256: input.SHA256, Size: input.Size,
			})
		}
		result.public = append(result.public, public...)
	}
	return result, nil
}

func defaultTrust(request *Request, snapshots []deb.KeySnapshot) (trustSet, error) {
	var result trustSet
	for i := range snapshots {
		key := &snapshots[i]
		sum := sha256.Sum256(key.Data)
		digest := hex.EncodeToString(sum[:])
		if err := request.Cache.Store(bytes.NewReader(key.Data), digest,
			int64(len(key.Data))); err != nil {
			return trustSet{}, err
		}
		public, err := deb.LoadTrustedKeys(key.Data, key.Fingerprints)
		if err != nil {
			return trustSet{}, err
		}
		for _, fingerprint := range key.Fingerprints {
			result.records = append(result.records, lock.RepositoryKey{
				Fingerprint: fingerprint, SHA256: digest, Size: int64(len(key.Data)),
			})
		}
		result.public = append(result.public, public...)
	}
	if len(result.records) == 0 {
		return trustSet{}, errors.New("repository has no trust keys")
	}
	return result, nil
}

func localInput(request *Request, keyPath string) (lock.LocalInput, bool) {
	for _, input := range request.Inputs {
		if input.Path == keyPath {
			return input, true
		}
	}
	return lock.LocalInput{}, false
}
