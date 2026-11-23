package locking

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// storedBlob is a blob a test added to a memoryStore, keyed by its own digest.
type storedBlob struct {
	digest string
	size   int64
	data   []byte
}

type memoryStore struct {
	blobs map[string][]byte
}

func newMemoryStore() *memoryStore {
	return &memoryStore{blobs: make(map[string][]byte)}
}

func (s *memoryStore) add(value string) storedBlob {
	data := []byte(value)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	s.blobs[digest] = data
	return storedBlob{digest: digest, size: int64(len(data)), data: data}
}

func (s *memoryStore) Open(digest string, size int64) (io.ReadCloser, error) {
	data, ok := s.blobs[digest]
	if !ok {
		return nil, errors.New("blob not found")
	}
	if int64(len(data)) != size {
		return nil, errors.New("blob size mismatch")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// oversizedStore returns more bytes than the recorded size allows.
type oversizedStore struct{}

func (oversizedStore) Open(string, int64) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("more bytes than recorded")), nil
}
