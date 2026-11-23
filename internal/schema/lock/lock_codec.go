package lock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"

	"github.com/matt-mai/vapor/internal/schema/spec"
)

// MaxLockfileSize bounds encoded lock input before YAML node allocation.
const MaxLockfileSize = 4 << 20

// LoadLockfile reads a single strict lock document. It does not verify the lock
// against a spec or authenticate referenced evidence.
func LoadLockfile(path string) (*Lockfile, error) {
	return loadLockfileWithLimit(path, MaxLockfileSize)
}

// loadLockfileWithLimit is LoadLockfile with an explicit byte limit. Decoding a
// multi-megabyte document just to cross the real limit costs seconds under the
// race detector, so the limit test passes a small one.
func loadLockfileWithLimit(path string, maxSize int) (*Lockfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read lock %q: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(maxSize)+1))
	if fileErr := errors.Join(readErr, file.Close()); fileErr != nil {
		return nil, fmt.Errorf("read lock %q: %w", path, fileErr)
	}
	lock, err := decodeLockfileWithLimit(data, maxSize)
	if err != nil {
		return nil, fmt.Errorf("load lock %q: %w", path, err)
	}
	return lock, nil
}

func decodeLockfile(data []byte) (*Lockfile, error) {
	return decodeLockfileWithLimit(data, MaxLockfileSize)
}

func decodeLockfileWithLimit(data []byte, maxSize int) (*Lockfile, error) {
	if err := checkLockfileSizeLimit(len(data), maxSize); err != nil {
		return nil, err
	}
	lock, err := spec.DecodeDocument[Lockfile](data, "lock", func(node *yaml.Node) error {
		return checkLockRequiredFields(node, reflect.TypeFor[Lockfile](), "lock")
	})
	if err != nil {
		return nil, err
	}
	if err := checkLockDuplicates(lock); err != nil {
		return nil, fmt.Errorf("decode lock: %w", err)
	}
	return lock, nil
}

// CanonicalJSON returns the canonical JSON encoding of the lock. It sorts the
// set-like collections on copies, so the caller's lock is not reordered.
func (lock *Lockfile) CanonicalJSON() ([]byte, error) {
	return lock.canonicalJSONWithLimit(MaxLockfileSize)
}

func (lock *Lockfile) canonicalJSONWithLimit(maxSize int) ([]byte, error) {
	canonical, err := canonicalLockfile(lock)
	if err != nil {
		return nil, fmt.Errorf("encode canonical lock JSON: %w", err)
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode canonical lock JSON: %w", err)
	}
	if err := checkLockfileSizeLimit(len(encoded), maxSize); err != nil {
		return nil, err
	}
	return encoded, nil
}

// CanonicalYAML returns the canonical YAML encoding of the lock. It uses the
// same ordering and null rules as CanonicalJSON.
func (lock *Lockfile) CanonicalYAML() ([]byte, error) {
	return lock.canonicalYAMLWithLimit(MaxLockfileSize)
}

func (lock *Lockfile) canonicalYAMLWithLimit(maxSize int) ([]byte, error) {
	canonical, err := canonicalLockfile(lock)
	if err != nil {
		return nil, fmt.Errorf("encode canonical lock YAML: %w", err)
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(canonical); err != nil {
		return nil, fmt.Errorf("encode canonical lock YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("encode canonical lock YAML: %w", err)
	}
	if err := checkLockfileSizeLimit(buffer.Len(), maxSize); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func checkLockfileSizeLimit(size, maxSize int) error {
	if size > maxSize {
		return fmt.Errorf("lock document exceeds %d-byte limit", maxSize)
	}
	return nil
}
