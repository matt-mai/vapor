package deb_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestAcquireIndexByHashFallback(t *testing.T) {
	index, content, store, compressed, _ := acquireFixture(t, deb.ByHashPrefer)
	if len(index.AcquirePaths) != 2 {
		t.Fatalf("acquire paths = %v", index.AcquirePaths)
	}
	fetcher := &recordingFetcher{
		data: map[string][]byte{index.AcquirePaths[1]: compressed},
		errs: map[string]error{index.AcquirePaths[0]: errors.New("unavailable")},
	}
	data, err := deb.AcquireIndex(context.Background(), fetcher, store, &index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("data = %q, want %q", data, content)
	}
	want := []string{index.AcquirePaths[0], index.AcquirePaths[1]}
	if len(fetcher.calls) != len(want) || fetcher.calls[0] != want[0] || fetcher.calls[1] != want[1] {
		t.Fatalf("fetch calls = %v, want %v", fetcher.calls, want)
	}
}

func TestAcquireIndexRequireDoesNotFallBack(t *testing.T) {
	index, _, store, _, _ := acquireFixture(t, deb.ByHashRequire)
	if len(index.AcquirePaths) != 1 {
		t.Fatalf("acquire paths = %v", index.AcquirePaths)
	}
	fetcher := &recordingFetcher{errs: map[string]error{index.AcquirePaths[0]: errors.New("unavailable")}}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err == nil {
		t.Fatal("acquisition succeeded without the required by-hash path")
	}
	if len(fetcher.calls) != 1 || fetcher.calls[0] != index.AcquirePaths[0] {
		t.Fatalf("fetch calls = %v, want only %q", fetcher.calls, index.AcquirePaths[0])
	}
}

func TestAcquireIndexRejectsFetchedTampering(t *testing.T) {
	index, _, store, compressed, _ := acquireFixture(t, deb.ByHashPrefer)
	tampered := bytes.Clone(compressed)
	tampered[len(tampered)-1] ^= 0xff
	fetcher := &recordingFetcher{data: map[string][]byte{}}
	for _, path := range index.AcquirePaths {
		fetcher.data[path] = tampered
	}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err == nil {
		t.Fatal("accepted tampered index bytes")
	}
	if _, err := store.Open(index.SHA256, index.Size); err == nil {
		t.Fatal("tampered index entered the cache")
	}
}

func TestAcquireIndexReusesCache(t *testing.T) {
	index, content, store, compressed, _ := acquireFixture(t, deb.ByHashPrefer)
	fetcher := &recordingFetcher{data: map[string][]byte{}}
	for _, path := range index.AcquirePaths {
		fetcher.data[path] = compressed
	}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err != nil {
		t.Fatal(err)
	}
	fetched := len(fetcher.calls)
	data, err := deb.AcquireIndex(context.Background(), fetcher, store, &index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("data = %q, want %q", data, content)
	}
	if len(fetcher.calls) != fetched {
		t.Fatalf("cache hit fetched again: %v", fetcher.calls)
	}
}

func TestAcquireIndexReplacesTamperedCache(t *testing.T) {
	index, content, store, compressed, dir := acquireFixture(t, deb.ByHashPrefer)
	fetcher := &recordingFetcher{data: map[string][]byte{index.AcquirePaths[0]: compressed}}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(compressed)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, "sha256", index.SHA256[:2], index.SHA256), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher.calls = nil
	data, err := deb.AcquireIndex(context.Background(), fetcher, store, &index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("data = %q, want %q", data, content)
	}
	if len(fetcher.calls) != 1 {
		t.Fatalf("fetch calls = %v, want one replacement fetch", fetcher.calls)
	}
	reader, err := store.Open(index.SHA256, index.Size)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestAcquireIndexIgnoresAnEditedDecodedEntry is the rule the decoded entry exists for:
// the signed plain index digest and size are the authority, so an entry that describes
// different packages is not an answer, however well formed it is.
func TestAcquireIndexIgnoresAnEditedDecodedEntry(t *testing.T) {
	index, content, store, compressed, dir := acquireFixture(t, deb.ByHashPrefer)
	fetcher := &recordingFetcher{data: map[string][]byte{index.AcquirePaths[0]: compressed}}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err != nil {
		t.Fatal(err)
	}
	plainSHA256, plainSize := sha256Of(content)
	if _, ok := store.ReadDerived(index.SHA256, plainSHA256, plainSize, 1<<20); !ok {
		t.Fatal("the first acquisition did not remember the decoded index")
	}
	edited := bytes.Replace(content, []byte("Version: 1.0-1"), []byte("Version: 9.9-9"), 1)
	payload := make([]byte, 8+len(edited))
	binary.BigEndian.PutUint64(payload, uint64(len(edited)))
	copy(payload[8:], edited)
	path := filepath.Join(dir, "sha256", index.SHA256[:2], index.SHA256+".decoded")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher.calls = nil
	data, err := deb.AcquireIndex(context.Background(), fetcher, store, &index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("data = %q, want %q", data, content)
	}
	if len(fetcher.calls) != 0 {
		t.Fatalf("fetch calls = %v, want none", fetcher.calls)
	}
}

// TestAcquireIndexRemembersNothingWithoutAPlainIndex states the price of the check above:
// a release that names no plain index gives a decoded entry nothing to be checked
// against, so it is not written and every run decodes the verified bytes itself.
func TestAcquireIndexRemembersNothingWithoutAPlainIndex(t *testing.T) {
	index, content, store, compressed, _ := acquireFixtureWithoutPlain(t)
	if index.PlainSHA256 != "" || index.PlainSize != 0 {
		t.Fatalf("plain = %q/%d, want none", index.PlainSHA256, index.PlainSize)
	}
	fetcher := &recordingFetcher{data: map[string][]byte{index.AcquirePaths[0]: compressed}}
	for range 2 {
		data, err := deb.AcquireIndex(context.Background(), fetcher, store, &index)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, content) {
			t.Fatalf("data = %q, want %q", data, content)
		}
	}
	if _, ok := store.ReadDerived(index.SHA256, "", 0, 1<<20); ok {
		t.Fatal("wrote a decoded entry no release can check")
	}
	if len(fetcher.calls) != 1 {
		t.Fatalf("fetch calls = %v, want one fetch", fetcher.calls)
	}
}

func TestAcquireIndexBoundsFetchedBytes(t *testing.T) {
	index, _, store, compressed, _ := acquireFixture(t, deb.ByHashPrefer)
	reader := &countingReader{data: append(bytes.Clone(compressed), 'x')}
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return reader, nil
	})
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err == nil {
		t.Fatal("accepted oversized index")
	}
	if reader.read != int(index.Size+1) {
		t.Fatalf("read %d bytes, want %d", reader.read, index.Size+1)
	}
}

func TestAcquireIndexRejectsOversizedEvidence(t *testing.T) {
	index, _, store, _, _ := acquireFixture(t, deb.ByHashPrefer)
	index.Size = deb.MaxIndexAcquisitionSize + 1
	fetcher := &recordingFetcher{}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err == nil {
		t.Fatal("accepted oversized index evidence")
	}
	if len(fetcher.calls) != 0 {
		t.Fatalf("oversized evidence fetched: %v", fetcher.calls)
	}
}

func sha256Of(data []byte) (string, int64) {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data))
}

func acquireFixtureWithoutPlain(t *testing.T) (deb.Index, []byte, *cache.Cache, []byte, string) {
	t.Helper()
	content := []byte("Package: demo\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/d/demo/demo_1.0-1_amd64.deb\nSize: 1\nSHA256: " + validSHA256 + "\n\n")
	compressed := gzipData(t, content)
	canonical := "main/binary-amd64/Packages.gz"
	release := releaseWithFiles(map[string]deb.ReleaseFile{canonical: releaseFile(compressed)}, true)
	index, err := deb.SelectIndex(release, "main", "amd64", deb.ByHashPrefer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return index, content, store, compressed, dir
}

func acquireFixture(t *testing.T, policy deb.ByHashPolicy) (deb.Index, []byte, *cache.Cache, []byte, string) {
	t.Helper()
	content := []byte("Package: demo\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/d/demo/demo_1.0-1_amd64.deb\nSize: 1\nSHA256: " + validSHA256 + "\n\n")
	compressed := gzipData(t, content)
	canonical := "main/binary-amd64/Packages.gz"
	// A real release file names the plain index too, which is what lets a decoded
	// index be checked against authenticated metadata.
	release := releaseWithFiles(map[string]deb.ReleaseFile{
		canonical:                    releaseFile(compressed),
		"main/binary-amd64/Packages": releaseFile(content),
	}, true)
	index, err := deb.SelectIndex(release, "main", "amd64", policy)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return index, content, store, compressed, dir
}

type recordingFetcher struct {
	data  map[string][]byte
	errs  map[string]error
	calls []string
}

func (f *recordingFetcher) Fetch(_ context.Context, path string) (io.ReadCloser, error) {
	f.calls = append(f.calls, path)
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	data, ok := f.data[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type fetchFunc func(context.Context, string) (io.ReadCloser, error)

func (f fetchFunc) Fetch(ctx context.Context, path string) (io.ReadCloser, error) {
	return f(ctx, path)
}

type countingReader struct {
	data []byte
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.read += n
	return n, nil
}

func (*countingReader) Close() error {
	return nil
}

// TestAcquireIndexRefusesADecodedEntryOverATamperedBlob states the rule the decoded
// cache rests on: the compressed blob stays the authority. A memo of the bytes a blob
// used to hold must not hide the fact that the blob has since been changed.
func TestAcquireIndexRefusesADecodedEntryOverATamperedBlob(t *testing.T) {
	index, content, store, compressed, dir := acquireFixture(t, deb.ByHashPrefer)
	fetcher := &recordingFetcher{data: map[string][]byte{index.AcquirePaths[0]: compressed}}
	if _, err := deb.AcquireIndex(context.Background(), fetcher, store, &index); err != nil {
		t.Fatal(err)
	}
	// The decoded entry is now warm and would answer on its own.
	plainSHA256, plainSize := sha256Of(content)
	if _, ok := store.ReadDerived(index.SHA256, plainSHA256, plainSize, 1<<20); !ok {
		t.Fatal("the first acquisition did not remember the decoded index")
	}
	tampered := bytes.Clone(compressed)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, "sha256", index.SHA256[:2], index.SHA256), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher.calls = nil
	data, err := deb.AcquireIndex(context.Background(), fetcher, store, &index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("data = %q, want %q", data, content)
	}
	if len(fetcher.calls) != 1 {
		t.Fatalf("fetch calls = %v, want one replacement fetch", fetcher.calls)
	}
}
