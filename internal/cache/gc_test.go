package cache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gcFixture is a cache with named blobs already published.
type gcFixture struct {
	cache *Cache
	dir   string
	now   time.Time
}

func newGCFixture(t *testing.T) *gcFixture {
	t.Helper()
	c, dir := newTestCache(t)
	return &gcFixture{cache: c, dir: dir, now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

// writeBlob stores data and dates the blob relative to the fixture's clock.
func (f *gcFixture) writeBlob(t *testing.T, data string, age time.Duration) string {
	t.Helper()
	content := []byte(data)
	digest := digestOf(content)
	if err := f.cache.Store(bytesReader(content), digest, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	f.setAge(t, f.cache.blobPath(digest), age)
	return digest
}

func (f *gcFixture) setAge(t *testing.T, path string, age time.Duration) {
	t.Helper()
	stamp := f.now.Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func (f *gcFixture) options(apply bool) GCOptions {
	return GCOptions{Now: f.now, MinAge: time.Hour, Apply: apply}
}

// blobAge is long enough to be collected and young enough to be protected.
const (
	blobAge  = 24 * time.Hour
	youngAge = time.Minute
)

func bytesReader(data []byte) *strings.Reader { return strings.NewReader(string(data)) }

func TestGCKeepsMarkedBlobsAndRemovesTheRest(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	marked := f.writeBlob(t, "kept", blobAge)
	stale := f.writeBlob(t, "stale", blobAge)
	young := f.writeBlob(t, "young", youngAge)

	stats, err := f.cache.GC(map[string]struct{}{marked: {}}, f.options(true))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Kept != 1 || stats.Removed != 1 || stats.TooNew != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.RemovedBytes != int64(len("stale")) {
		t.Fatalf("removed bytes = %d", stats.RemovedBytes)
	}
	assertPresent(t, f.cache.blobPath(marked))
	assertPresent(t, f.cache.blobPath(young))
	assertAbsent(t, f.cache.blobPath(stale))
}

func TestGCWithoutApplyDeletesNothing(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	stale := f.writeBlob(t, "stale", blobAge)
	stats, err := f.cache.GC(nil, f.options(false))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Removed != 1 || stats.RemovedBytes != int64(len("stale")) {
		t.Fatalf("stats = %+v", stats)
	}
	assertPresent(t, f.cache.blobPath(stale))
}

func TestGCSkipsEntriesItDoesNotRecognise(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	shard := filepath.Join(f.dir, "sha256", "aa")
	if err := os.MkdirAll(shard, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name string) string {
		path := filepath.Join(shard, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		f.setAge(t, path, blobAge)
		return path
	}
	odd := write("not-a-digest")
	upper := write(strings.Repeat("AA", 32))
	misfiled := write("bb" + strings.Repeat("0", 62))
	nested := filepath.Join(shard, strings.Repeat("c", 64))
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(shard, strings.Repeat("d", 64))
	if err := os.Symlink("/nonexistent", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	stats, err := f.cache.GC(nil, f.options(true))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Skipped != 5 || stats.Removed != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	for _, path := range []string{odd, upper, misfiled, nested, link} {
		assertPresent(t, path)
	}
}

func TestGCRefusesToSweepDuringACacheWrite(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	f.writeBlob(t, "stale", blobAge)
	staging := filepath.Join(f.dir, "sha256", "aa", stagingPrefix+"123")
	if err := os.MkdirAll(filepath.Dir(staging), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staging, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.setAge(t, staging, youngAge)

	if _, err := f.cache.GC(nil, f.options(true)); err == nil {
		t.Fatal("sweep ran while a cache write was in flight")
	}
	stale := f.cache.blobPath(f.writeBlob(t, "also-stale", blobAge))
	assertPresent(t, stale)
	if _, err := f.cache.GC(nil, f.options(false)); err != nil {
		t.Fatalf("report refused: %v", err)
	}
}

func TestGCSweepsAStaleStagingFile(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	staging := filepath.Join(f.dir, "sha256", "aa", stagingPrefix+"123")
	if err := os.MkdirAll(filepath.Dir(staging), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staging, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.setAge(t, staging, blobAge)

	stats, err := f.cache.GC(nil, f.options(true))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Removed != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	assertAbsent(t, staging)
}

func TestGCRemovesEmptiedShards(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	f.writeBlob(t, "stale", blobAge)
	if _, err := f.cache.GC(nil, f.options(true)); err != nil {
		t.Fatal(err)
	}
	shards, err := os.ReadDir(filepath.Join(f.dir, "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) != 0 {
		t.Fatalf("shards = %d, want 0", len(shards))
	}
}

func TestGCLeavesAMarkedBlobOfAnyAgeAlone(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	marked := f.writeBlob(t, "kept", blobAge)
	if _, err := f.cache.GC(map[string]struct{}{marked: {}}, f.options(true)); err != nil {
		t.Fatal(err)
	}
	assertPresent(t, f.cache.blobPath(marked))
}

func TestGCValidation(t *testing.T) {
	t.Parallel()
	var c *Cache
	if _, err := c.GC(nil, GCOptions{}); err == nil {
		t.Fatal("uninitialized cache accepted")
	}
	f := newGCFixture(t)
	if _, err := f.cache.GC(nil, GCOptions{MinAge: -time.Second}); err == nil {
		t.Fatal("negative minimum age accepted")
	}
}

func TestGCReportsRemovalFailures(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	stale := f.writeBlob(t, "stale", blobAge)
	// A read-only shard lets the walk succeed and the removal fail.
	shard := filepath.Dir(f.cache.blobPath(stale))
	if err := os.Chmod(shard, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shard, 0o700) })
	_, err := f.cache.GC(nil, f.options(true))
	if err == nil || !strings.Contains(err.Error(), "remove ") {
		t.Fatalf("removal failure = %v", err)
	}
}

func TestCleanEmptiesEverything(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	f.writeBlob(t, "kept", blobAge)
	staging := filepath.Join(f.dir, "sha256", "zz", stagingPrefix+"x")
	if err := os.MkdirAll(filepath.Dir(staging), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staging, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.dir, "sha256", "nested", "deeper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.cache.Clean(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(f.dir, "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cache still holds %d entries", len(entries))
	}
	if err := f.cache.Store(bytesReader([]byte("after")), digestOf([]byte("after")), 5); err != nil {
		t.Fatalf("cache unusable after clean: %v", err)
	}
}

func TestCleanValidation(t *testing.T) {
	t.Parallel()
	var c *Cache
	if err := c.Clean(); err == nil {
		t.Fatal("uninitialized cache accepted")
	}
}

func assertPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("%s missing: %v", filepath.Base(path), err)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s still present: %v", filepath.Base(path), err)
	}
}

// TestGCSweepsADecodedEntryWithItsBlob keeps a decoded entry tied to the blob it came
// from: it is a pure function of that blob, so keeping one without the other would be
// dead weight and keeping it after the blob is gone would be a stale answer.
func TestGCSweepsADecodedEntryWithItsBlob(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	kept := f.writeBlob(t, "kept", blobAge)
	stale := f.writeBlob(t, "stale", blobAge)
	for _, digest := range []string{kept, stale} {
		decoded := []byte("decoded " + digest)
		plainSHA256, plainSize := plainOf(decoded)
		if !f.cache.StoreDerived(digest, plainSHA256, plainSize, decoded) {
			t.Fatalf("StoreDerived(%q) failed", digest)
		}
		f.setAge(t, f.cache.derivedPath(digest), blobAge)
	}
	stats, err := f.cache.GC(map[string]struct{}{kept: {}}, f.options(true))
	if err != nil {
		t.Fatal(err)
	}
	// One blob and its decoded entry stay; one blob and its decoded entry go.
	if stats.Kept != 2 || stats.Removed != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	assertPresent(t, f.cache.derivedPath(kept))
	assertAbsent(t, f.cache.derivedPath(stale))
}
