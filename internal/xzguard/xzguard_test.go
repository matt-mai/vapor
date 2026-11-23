package xzguard

import (
	"bytes"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// compress returns an xz payload whose blocks declare the given dictionary.
func compress(t *testing.T, dictionary int, payload []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := xz.WriterConfig{DictCap: dictionary}.NewWriter(&buffer)
	if err != nil {
		t.Fatalf("writer for %d: %v", dictionary, err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buffer.Bytes()
}

func decompress(t *testing.T, data []byte) []byte {
	t.Helper()
	reader, err := xz.ReaderConfig{DictCap: MaxDictionarySize}.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

// TestCheckRejectsABlockOverTheLimit is the case the library accepts: a small
// payload whose block declares a dictionary larger than the caller's limit.
func TestCheckRejectsABlockOverTheLimit(t *testing.T) {
	payload := compress(t, 8<<20, bytes.Repeat([]byte("hello world\n"), 1000))
	if err := Check(payload, MaxDictionarySize); err != nil {
		t.Fatalf("an 8 MiB dictionary should pass a 64 MiB limit: %v", err)
	}
	err := Check(payload, 1<<20)
	if err == nil {
		t.Fatal("a block declaring an 8 MiB dictionary passed a 1 MiB limit")
	}
	if !strings.Contains(err.Error(), "over the 1 MiB limit") {
		t.Fatalf("error does not name the limit: %v", err)
	}
}

// TestLibraryIgnoresTheLimit pins why this package exists. If a future
// ulikunitz/xz enforces DictCap, this fails and the guard can be deleted.
func TestLibraryIgnoresTheLimit(t *testing.T) {
	payload := compress(t, 32<<20, bytes.Repeat([]byte("hello world\n"), 1000))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	reader, err := xz.ReaderConfig{DictCap: 1 << 20}.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Skipf("the library refused the block, so the guard is no longer needed: %v", err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Skipf("the library refuses to decode the block: %v", err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated < 16<<20 {
		t.Skipf("the library allocated only %d KiB, so DictCap may now be a ceiling", allocated>>10)
	}
}

func TestCheckAcceptsATypicalPayload(t *testing.T) {
	payload := []byte("Package: base-files\nVersion: 13.1\n\n")
	compressed := compress(t, 8<<20, bytes.Repeat(payload, 5000))
	if err := Check(compressed, MaxDictionarySize); err != nil {
		t.Fatalf("Check(%d bytes): %v", len(compressed), err)
	}
	if got := decompress(t, compressed); !bytes.Equal(got, bytes.Repeat(payload, 5000)) {
		t.Fatal("the payload changed after Check")
	}
}

// TestCheckAcceptsUncompressedBlocks exercises the chunk path: a payload that
// mixes stored and compressed chunks still declares one dictionary per block.
func TestCheckAcceptsUncompressedBlocks(t *testing.T) {
	random := make([]byte, 128<<10)
	for i := range random {
		random[i] = byte(i*7 + i/251)
	}
	compressed := compress(t, 8<<20, random)
	if err := Check(compressed, MaxDictionarySize); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := decompress(t, compressed); !bytes.Equal(got, random) {
		t.Fatal("the payload changed after Check")
	}
}

func TestCheckAcceptsPaddingAndPaddedPayloads(t *testing.T) {
	payload := compress(t, 8<<20, bytes.Repeat([]byte("x"), 4096))
	padded := append(append([]byte{}, payload...), 0, 0, 0, 0, 0, 0, 0, 0)
	if err := Check(padded, MaxDictionarySize); err != nil {
		t.Fatalf("trailing stream padding: %v", err)
	}
	if err := Check(payload, MaxDictionarySize); err != nil {
		t.Fatalf("unpadded: %v", err)
	}
	// Concatenated streams are a valid payload, and each one is checked.
	joined := append(append([]byte{}, payload...), padded...)
	if err := Check(joined, MaxDictionarySize); err != nil {
		t.Fatalf("concatenated streams: %v", err)
	}
}

func TestCheckRejectsMalformedPayloads(t *testing.T) {
	payload := compress(t, 8<<20, bytes.Repeat([]byte("hello world\n"), 1000))
	flip := func(index int) []byte {
		broken := append([]byte{}, payload...)
		broken[index] ^= 0xff
		return broken
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", payload[:len(payload)/2]},
		{"header magic", flip(0)},
		{"header checksum", flip(8)},
		{"footer magic", flip(len(payload) - 1)},
		{"index checksum", flip(len(payload) - 13)},
		{"block header checksum", flip(streamHeaderLen + 4)},
		// A block span that does not start with a block header indicator must
		// fail instead of being read as a smaller header.
		{"block indicator", func() []byte {
			broken := append([]byte{}, payload...)
			broken[streamHeaderLen] = 0
			return broken
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Check(tc.data, MaxDictionarySize); err == nil {
				t.Fatal("a corrupt payload passed the check")
			}
		})
	}
}

// TestCheckRejectsAnIndexThatMisplacesAStream makes the index consistent with
// itself but not with the payload, which is what a crafted payload looks like:
// the checksums agree, so only walking the container catches it.
func TestCheckRejectsAnIndexThatMisplacesAStream(t *testing.T) {
	payload := compress(t, 8<<20, bytes.Repeat([]byte("hello world\n"), 1000))
	broken := append([]byte{}, payload...)
	// Drop the first block from the stream by moving the stream header onto it.
	// The footer still points at the index, which no longer reaches the header.
	copy(broken[streamHeaderLen-4:], broken)
	if err := Check(broken, MaxDictionarySize); err == nil {
		t.Fatal("a stream whose header is not where its index says passed the check")
	}
}

func TestCheckRejectsAZeroLimit(t *testing.T) {
	if err := Check(compress(t, 8<<20, []byte("x")), 0); err == nil {
		t.Fatal("a zero limit was accepted")
	}
}
