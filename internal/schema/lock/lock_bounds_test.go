package lock

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The byte-limit tests pass a small limit instead of MaxLockfileSize: decoding a
// multi-megabyte document just to cross the real limit costs seconds under the
// race detector, and the property is "one byte over the limit is refused".
const testLimit = 4 << 10

func TestLockfile_InputLimit(t *testing.T) {
	t.Parallel()
	valid := mustCanonicalYAML(t, canonicalVectorLock())
	atLimit := append(bytes.Clone(valid), '#')
	atLimit = append(atLimit, bytes.Repeat([]byte("x"), testLimit-len(atLimit))...)
	for _, data := range [][]byte{atLimit, append(bytes.Clone(atLimit), 'x'), append(valid, append([]byte("---\n"), atLimit...)...)} {
		path := filepath.Join(t.TempDir(), "vapor.lock")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, load := range []func() (*Lockfile, error){
			func() (*Lockfile, error) { return decodeLockfileWithLimit(data, testLimit) },
			func() (*Lockfile, error) { return loadLockfileWithLimit(path, testLimit) },
		} {
			lock, err := load()
			if len(data) <= testLimit {
				if err != nil || lock == nil {
					t.Fatalf("at-limit lock rejected: %v", err)
				}
			} else if lock != nil || err == nil || !strings.Contains(err.Error(), "byte limit") {
				t.Fatalf("oversized lock: lock=%v err=%v", lock, err)
			}
		}
	}
}

func TestLockfile_CanonicalLimit(t *testing.T) {
	t.Parallel()
	lock := canonicalVectorLock()
	lock.SpecDigest = strings.Repeat("x", testLimit)
	for _, encode := range []func() ([]byte, error){
		func() ([]byte, error) { return lock.canonicalJSONWithLimit(testLimit) },
		func() ([]byte, error) { return lock.canonicalYAMLWithLimit(testLimit) },
	} {
		if data, err := encode(); data != nil || err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("oversized canonical lock: bytes=%d err=%v", len(data), err)
		}
	}
}

func TestDecodeLockfile_LargeClosure(t *testing.T) {
	t.Parallel()
	_, lock := validMultiPlatformLock(t)
	const count = 2000
	lock.Slices[0].Closure = make([]string, count)
	for i := range lock.Slices[0].Closure {
		lock.Slices[0].Closure[i] = fmt.Sprintf("slice-%05d", i)
	}
	data := mustCanonicalYAML(t, lock)
	decoded, err := decodeLockfile(data)
	if err != nil || len(decoded.Slices[0].Closure) != count {
		t.Fatalf("large closure: %v", err)
	}
	lock.Slices[0].Closure[count-1] = lock.Slices[0].Closure[0]
	if decoded, err := decodeLockfile(mustCanonicalYAML(t, lock)); err == nil || decoded != nil {
		t.Fatal("duplicate at end of large closure accepted")
	}
}
