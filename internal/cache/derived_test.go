package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

// plainOf is the digest and length a signed release names for a decoded index.
func plainOf(data []byte) (string, int64) {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data))
}

func TestDerivedRoundTrips(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	blob := []byte("compressed index")
	digest := digestOf(blob)
	if err := c.Store(bytes.NewReader(blob), digest, int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	decoded := []byte("Package: hello\nVersion: 1\n")
	plainSHA256, plainSize := plainOf(decoded)
	if !c.StoreDerived(digest, plainSHA256, plainSize, decoded) {
		t.Fatal("StoreDerived failed")
	}
	got, ok := c.ReadDerived(digest, plainSHA256, plainSize, 1<<20)
	if !ok {
		t.Fatal("ReadDerived missed an entry it just wrote")
	}
	if !bytes.Equal(got, decoded) {
		t.Fatalf("decoded = %q, want %q", got, decoded)
	}
}

func TestDerivedMissesWhenAbsent(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	plainSHA256, plainSize := plainOf([]byte("never stored"))
	if _, ok := c.ReadDerived(digestOf([]byte("never stored")), plainSHA256, plainSize, 1<<20); ok {
		t.Fatal("ReadDerived reported an entry that was never written")
	}
}

// TestDerivedRejectsAnEntryThatDisagreesWithTheRelease is the rule the entry exists for:
// the signed plain index digest and size are the authority, so an edited entry must be
// refused even when its own header and length are consistent.
func TestDerivedRejectsAnEntryThatDisagreesWithTheRelease(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	blob := []byte("compressed index")
	digest := digestOf(blob)
	decoded := []byte("Package: hello\nVersion: 1\n")
	plainSHA256, plainSize := plainOf(decoded)
	if !c.StoreDerived(digest, plainSHA256, plainSize, decoded) {
		t.Fatal("StoreDerived failed")
	}
	edited := bytes.Replace(decoded, []byte("hello"), []byte("evil"), 1)
	payload := make([]byte, derivedHeader+len(edited))
	binary.BigEndian.PutUint64(payload, uint64(len(edited)))
	copy(payload[derivedHeader:], edited)
	if err := c.storeDerived(digest, payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.ReadDerived(digest, plainSHA256, plainSize, 1<<20); ok {
		t.Fatal("ReadDerived accepted an entry the release does not name")
	}
}

func TestDerivedStoresNothingWithoutAManifest(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	decoded := []byte("Package: hello\nVersion: 1\n")
	digest := digestOf([]byte("compressed index"))
	if c.StoreDerived(digest, "", 0, decoded) {
		t.Fatal("StoreDerived recorded a decode no release names")
	}
	if c.StoreDerived(digest, "not-a-digest", int64(len(decoded)), decoded) {
		t.Fatal("StoreDerived accepted an invalid manifest digest")
	}
	if c.StoreDerived(digest, digestOf(decoded), int64(len(decoded))+1, decoded) {
		t.Fatal("StoreDerived accepted a manifest length that does not match")
	}
	if _, ok := c.ReadDerived(digest, "", 0, 1<<20); ok {
		t.Fatal("ReadDerived accepted an empty manifest")
	}
}

// TestDerivedRejectsATruncatedEntry covers the reason the length header exists: a prefix
// of a package index parses as a shorter index, so a half-written entry must not be
// handed back as if it were the whole decode.
func TestDerivedRejectsATruncatedEntry(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	blob := []byte("compressed index")
	digest := digestOf(blob)
	if err := c.Store(bytes.NewReader(blob), digest, int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	decoded := []byte("Package: hello\nVersion: 1\n")
	plainSHA256, plainSize := plainOf(decoded)
	if !c.StoreDerived(digest, plainSHA256, plainSize, decoded) {
		t.Fatal("StoreDerived failed")
	}
	path := c.derivedPath(digest)
	if err := os.Truncate(path, int64(derivedHeader+len(decoded)/2)); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.ReadDerived(digest, plainSHA256, plainSize, 1<<20); ok {
		t.Fatal("ReadDerived accepted an entry shorter than it declares")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a rejected entry should stay for a retry to replace: %v", err)
	}
}

func TestDerivedRejectsAnEntryLongerThanItsHeader(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	blob := []byte("compressed index")
	digest := digestOf(blob)
	if err := c.Store(bytes.NewReader(blob), digest, int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, derivedHeader+4)
	binary.BigEndian.PutUint64(payload, 2)
	copy(payload[derivedHeader:], "abcd")
	if err := c.storeDerived(digest, payload); err != nil {
		t.Fatal(err)
	}
	plainSHA256, plainSize := plainOf([]byte("ab"))
	if _, ok := c.ReadDerived(digest, plainSHA256, plainSize, 1<<20); ok {
		t.Fatal("ReadDerived accepted an entry longer than the length it declares")
	}
}

func TestDerivedRejectsAnOversizedEntry(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	blob := []byte("compressed index")
	digest := digestOf(blob)
	if err := c.Store(bytes.NewReader(blob), digest, int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	decoded := bytes.Repeat([]byte("x"), 16)
	plainSHA256, plainSize := plainOf(decoded)
	if !c.StoreDerived(digest, plainSHA256, plainSize, decoded) {
		t.Fatal("StoreDerived failed")
	}
	// The caller's limit is what protects it: a decode larger than it can accept is not
	// an answer it should get.
	if _, ok := c.ReadDerived(digest, plainSHA256, plainSize, 8); ok {
		t.Fatal("ReadDerived ignored the caller's limit")
	}
	if _, ok := c.ReadDerived(digest, plainSHA256, plainSize, -1); ok {
		t.Fatal("ReadDerived accepted a negative limit")
	}
}

func TestDerivedRejectsAnInvalidDigest(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	decoded := []byte("x")
	plainSHA256, plainSize := plainOf(decoded)
	if c.StoreDerived("not-a-digest", plainSHA256, plainSize, decoded) {
		t.Fatal("StoreDerived accepted an invalid digest")
	}
	if _, ok := c.ReadDerived("not-a-digest", plainSHA256, plainSize, 1<<20); ok {
		t.Fatal("ReadDerived accepted an invalid digest")
	}
}
