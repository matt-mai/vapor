package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// gcWorkspace is a working directory holding one lock that references one cached blob.
type gcWorkspace struct {
	dir      string
	cacheDir string
	lockPath string
	digest   string
}

// newGCWorkspaceFor fills dir with a lock naming one cached blob, and dates that blob so
// the grace window does not protect it.
func newGCWorkspaceFor(t *testing.T, dir string) *gcWorkspace {
	t.Helper()
	cacheDir := filepath.Join(dir, "cache")
	store, err := cache.New(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("locked artifact\n")
	if err := store.Store(bytes.NewReader(payload), cacheDigest(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "image.lock.yaml")
	writeLockReferencing(t, lockPath, cacheDigest(payload))
	stamp := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(filepath.Join(cacheDir, "sha256", cacheDigest(payload)[:2], cacheDigest(payload)), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return &gcWorkspace{dir: dir, cacheDir: cacheDir, lockPath: lockPath, digest: cacheDigest(payload)}
}

// writeLockReferencing writes the smallest lock that names one local input.
func writeLockReferencing(t *testing.T, path, digest string) {
	t.Helper()
	text := "version: 1\nspec: \"" + strings.Repeat("0", 64) + "\"\n" + `
provider: {distro: ubuntu, release: "26.04"}
platforms: [linux/amd64]
local-inputs:
  - role: ca
    path: ca.pem
    sha256: ` + digest + `
    size: 16
catalogues: []
repositories: []
packages: []
slices: []
artifacts: []
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// addGarbageBlob caches one unreferenced blob so a sweep has something to remove.
func (w *gcWorkspace) addGarbageBlob(t *testing.T, payload string) string {
	t.Helper()
	store, err := cache.New(w.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(strings.NewReader(payload), cacheDigest([]byte(payload)), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	digest := cacheDigest([]byte(payload))
	stamp := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(filepath.Join(w.cacheDir, "sha256", digest[:2], digest), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return digest
}

func cacheDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestRun_CacheGCReportsWithoutDeleting(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	garbage := workspace.addGarbageBlob(t, "garbage\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "gc", workspace.lockPath, "--cache-dir", workspace.cacheDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"kept 1 cached blob referenced by 1 lock file", "1 blob deleted with --apply", "repeat with --apply"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if _, err := os.Lstat(filepath.Join(workspace.cacheDir, "sha256", garbage[:2], garbage)); err != nil {
		t.Fatalf("garbage blob was deleted without --apply: %v", err)
	}
}

func TestRun_CacheGCAppliesTheSweepAndKeepsTheLock(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	garbage := workspace.addGarbageBlob(t, "garbage\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "gc", workspace.lockPath, "--cache-dir", workspace.cacheDir, "--apply"},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(workspace.cacheDir, "sha256", garbage[:2], garbage)); !os.IsNotExist(err) {
		t.Fatalf("garbage blob survived --apply: %v", err)
	}
	kept := filepath.Join(workspace.cacheDir, "sha256", workspace.digest[:2], workspace.digest)
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("locked blob was deleted: %v", err)
	}
	if strings.Contains(stdout.String(), "repeat with --apply") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRun_CacheGCReportsAnAbsentBlob(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	kept := filepath.Join(workspace.cacheDir, "sha256", workspace.digest[:2], workspace.digest)
	if err := os.Remove(kept); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "gc", workspace.lockPath, "--cache-dir", workspace.cacheDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 referenced blob absent from the cache") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRun_CacheGCNeedsALockToKeep(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "gc", "--cache-dir", filepath.Join(dir, "cache")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code = %d, stdout = %q", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "name a lock or use vaporize cache clean") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRun_CacheGCCannotSweepWhileLockPublishes(t *testing.T) {
	fixture := newBuildFixture(t)
	t.Chdir(fixture.dir)
	var stderr bytes.Buffer
	if code := run(fixture.args("lock"), io.Discard, &stderr); code != 0 {
		t.Fatalf("seed lock failed: %s", stderr.String())
	}
	index := backdateFixtureIndex(t, fixture)
	workspace := gcWorkspace{cacheDir: fixture.cacheDir}
	garbage := workspace.addGarbageBlob(t, "unreferenced input\n")
	garbagePath := filepath.Join(fixture.cacheDir, "sha256", garbage[:2], garbage)
	resume, result := pauseLockPublication(t, fixture.args("lock"))
	gc := []string{"cache", "gc", "--cache-dir", fixture.cacheDir, "--apply"}
	assertGCBusy(t, gc)
	writeLockReferencing(t, filepath.Join(fixture.dir, "other.lock.yaml"), strings.Repeat("a", 64))
	assertGCBusy(t, gc)
	resume()
	if err := <-result; err != "" {
		t.Fatalf("publish lock failed: %s", err)
	}
	stderr.Reset()
	if code := run(gc, io.Discard, &stderr); code != 0 {
		t.Fatalf("GC after publication failed: %s", stderr.String())
	}
	if _, err := os.Stat(index); err != nil {
		t.Fatalf("newly locked index was deleted: %v", err)
	}
	if _, err := os.Stat(garbagePath); !os.IsNotExist(err) {
		t.Fatalf("unreferenced blob survived GC: %v", err)
	}
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--oci-dir", filepath.Join(fixture.dir, "image")), io.Discard, &stderr); code != 0 {
		t.Fatalf("build after GC failed: %s", stderr.String())
	}
}

func assertGCBusy(t *testing.T, args []string) {
	t.Helper()
	var stderr bytes.Buffer
	if code := run(args, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "cache is busy; retry") {
		t.Fatalf("GC during publication: code = %d, stderr = %q", code, stderr.String())
	}
}

func backdateFixtureIndex(t *testing.T, fixture *buildFixture) string {
	t.Helper()
	seed, err := lock.LoadLockfile(fixture.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := seed.Repositories[0].Indexes[0].SHA256
	index := filepath.Join(fixture.cacheDir, "sha256", digest[:2], digest)
	stamp := time.Now().Add(-24 * time.Hour)
	if timeErr := os.Chtimes(index, stamp, stamp); timeErr != nil {
		t.Fatal(timeErr)
	}
	if removeErr := os.Remove(fixture.lockPath); removeErr != nil {
		t.Fatal(removeErr)
	}
	return index
}

func pauseLockPublication(t *testing.T, args []string) (func(), <-chan string) {
	t.Helper()
	ready, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	result := make(chan string, 1)
	t.Cleanup(func() { resume(); <-done })
	go func() {
		defer close(done)
		writer := &publicationPause{pause: sync.OnceFunc(func() { close(ready); <-release })}
		if code := run(args, io.Discard, writer); code != 0 {
			result <- writer.String()
			return
		}
		result <- ""
	}()
	select {
	case <-ready:
	case err := <-result:
		t.Fatalf("lock exited before publication: %s", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for lock publication")
	}
	return resume, result
}

type publicationPause struct {
	bytes.Buffer
	pause func()
}

func (p *publicationPause) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("write lock")) {
		p.pause()
	}
	return p.Buffer.Write(data)
}

func TestRun_CacheCleanNeedsApply(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "clean", "--cache-dir", workspace.cacheDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "repeat with --apply") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	kept := filepath.Join(workspace.cacheDir, "sha256", workspace.digest[:2], workspace.digest)
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("clean deleted without --apply: %v", err)
	}
	stdout.Reset()
	if code := run([]string{"cache", "clean", "--cache-dir", workspace.cacheDir, "--apply"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(kept); !os.IsNotExist(err) {
		t.Fatalf("clean kept the blob: %v", err)
	}
	if !strings.Contains(stdout.String(), "deleted every cached input") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

// A bundle is how a locked build moves to a machine that never fetched anything. It
// carries only what the lock references, and what arrives is verified rather than
// trusted, so the receiving build is offline and still reads nothing unchecked.
func TestRun_CacheBundleMovesExactlyTheLockedInputs(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	garbage := workspace.addGarbageBlob(t, "garbage\n")
	bundlePath := filepath.Join(workspace.dir, "inputs.tar")
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "bundle", workspace.lockPath, "--cache-dir", workspace.cacheDir,
		"--output", bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("bundle code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wrote 1 blob (16 B)") {
		t.Fatalf("stdout = %q, want one blob reported", stdout.String())
	}
	entries := bundleEntries(t, bundlePath)
	want := "sha256/" + workspace.digest[:2] + "/" + workspace.digest
	if len(entries) != 1 || entries[0] != want {
		t.Fatalf("entries = %v, want only %q", entries, want)
	}
	fresh := filepath.Join(t.TempDir(), "cache")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"cache", "unbundle", bundlePath, "--cache-dir", fresh}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unbundle code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "added 1 blob") {
		t.Fatalf("stdout = %q, want one blob added", stdout.String())
	}
	store, err := cache.New(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Has(workspace.digest) || store.Has(garbage) {
		t.Fatalf("cache holds the wrong blobs: locked %v, garbage %v", store.Has(workspace.digest), store.Has(garbage))
	}
}

func TestRun_CacheUnbundleRefusesAPlantedEntry(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bundle.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(file)
	if err := archive.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "../../escape",
		Size: 3, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte("bad")); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "unbundle", path, "--cache-dir", filepath.Join(t.TempDir(), "cache")},
		&stdout, &stderr)
	if code == 0 {
		t.Fatalf("code = 0, want the planted entry refused: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "is not a cache path") {
		t.Fatalf("stderr = %q, want the entry refused", stderr.String())
	}
}

// bundleEntries lists what a bundle archive holds.
func bundleEntries(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	archive := tar.NewReader(file)
	var names []string
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
}

// A bundle published over the lockfile it was made from would leave an archive where
// the next build reads its inputs, so the output may not be the input.
func TestRun_CacheBundleRefusesTheLockfileAsOutput(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	before, err := os.ReadFile(workspace.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "bundle", workspace.lockPath, "--cache-dir", workspace.cacheDir,
		"--output", workspace.lockPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "is the lockfile being bundled") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	after, err := os.ReadFile(workspace.lockPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("lockfile changed: %v", err)
	}
}

// A cache file at the right path is not the right content. Unbundling onto a damaged
// blob used to count it as present and leave the build unable to replay its lock.
func TestRun_CacheUnbundleRepairsADamagedBlob(t *testing.T) {
	t.Parallel()
	workspace := newGCWorkspaceFor(t, t.TempDir())
	bundlePath := filepath.Join(workspace.dir, "inputs.tar")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "bundle", workspace.lockPath, "--cache-dir", workspace.cacheDir,
		"--output", bundlePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("bundle code = %d, stderr = %q", code, stderr.String())
	}
	damaged := filepath.Join(workspace.cacheDir, "sha256", workspace.digest[:2], workspace.digest)
	if err := os.WriteFile(damaged, []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := run([]string{"cache", "unbundle", bundlePath, "--cache-dir", workspace.cacheDir}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "added 1 blob") {
		t.Fatalf("code = %d stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	store, err := cache.New(workspace.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(workspace.digest, 16); err != nil {
		t.Fatalf("blob was not repaired: %v", err)
	}
}
