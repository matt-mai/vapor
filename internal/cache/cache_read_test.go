package cache

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestReadReturnsVerifiedBytes(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	got, err := c.Read(digest, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("bytes = %q, want %q", got, data)
	}
}

// TestReadRejectsBytesChangedAfterVerification checks the reason Read exists: the bytes a
// caller gets are the bytes that were hashed, so a blob rewritten in place cannot reach a
// parser as unverified content.
func TestReadRejectsBytesChangedAfterVerification(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte("tampered"), data...)
	tampered = tampered[:len(data)]
	if err := os.WriteFile(c.blobPath(digest), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(digest, int64(len(data))); err == nil {
		t.Fatal("Read returned bytes it did not verify")
	} else if !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadRejectsInvalidArguments(t *testing.T) {
	t.Parallel()
	digest := digestOf([]byte("data"))
	var nilCache *Cache
	if _, err := nilCache.Read(digest, 4); err == nil {
		t.Fatal("Read accepted a nil cache")
	}
	c, _ := newTestCache(t)
	for _, tt := range []struct {
		name   string
		digest string
		size   int64
	}{
		{name: "short digest", digest: "abc"},
		{name: "uppercase digest", digest: strings.ToUpper(digest), size: 4},
		{name: "negative size", digest: digest, size: -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := c.Read(tt.digest, tt.size); err == nil {
				t.Fatal("Read accepted invalid arguments")
			}
		})
	}
}

func TestReadMissingAndMismatchedBlob(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	if _, err := c.Read(strings.Repeat("a", 64), 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read error = %v, want fs.ErrNotExist", err)
	}
	data := []byte("verified data")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(digest, int64(len(data))+1); err == nil {
		t.Fatal("Read accepted a blob of another size")
	}
}

// TestOpenRefusesBytesRewrittenInPlace covers the streaming side of the same rule: an
// open handle keeps reading the inode it opened, so a blob rewritten in place after the
// check must fail the read rather than hand a caller unverified bytes.
func TestOpenRefusesBytesRewrittenInPlace(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	reader, err := c.Open(digest, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader(t, reader)
	rewritten := bytes.Repeat([]byte("x"), len(data))
	if err := os.WriteFile(c.blobPath(digest), rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("the handle delivered bytes that were never verified")
	} else if !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("error = %v", err)
	}
}

// TestOpenRefusesBlobExtendedWhileReading checks that a reader cannot walk past the
// recorded size by appending to the file it is streaming.
func TestOpenRefusesBlobExtendedWhileReading(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	reader, err := c.Open(digest, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader(t, reader)
	if _, readErr := reader.Read(make([]byte, 4)); readErr != nil {
		t.Fatal(readErr)
	}
	grown, err := os.OpenFile(c.blobPath(digest), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grown.WriteString("more"); err != nil {
		t.Fatal(err)
	}
	if err := grown.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("the handle read past the recorded size")
	} else if !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("error = %v", err)
	}
}

// TestOpenRefusesCorruptBlobBeforeHandingOutBytes checks the reason Open verifies up
// front: its reader can feed a registry upload session, and bytes already sent cannot be
// taken back when an end-of-file check rejects them. A corrupt blob of the recorded size
// must therefore fail the open, not the last read.
func TestOpenRefusesCorruptBlobBeforeHandingOutBytes(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(c.blobPath(digest), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := c.Open(digest, int64(len(data)))
	if err == nil {
		closeReader(t, reader)
		t.Fatal("Open handed out a reader for bytes it had not verified")
	}
	if !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("error = %v", err)
	}
}

// TestOpenRewindsAfterVerifying checks that the verifying pass leaves the reader at the
// start, so a caller reads the whole blob rather than only what verification skipped.
func TestOpenRewindsAfterVerifying(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t)
	data := []byte("verified cache blob")
	digest := digestOf(data)
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	reader, err := c.Open(digest, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader(t, reader)
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("bytes = %q, want %q", got, data)
	}
}
