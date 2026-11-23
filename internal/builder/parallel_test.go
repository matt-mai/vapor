package builder_test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// twoPlatformSpec declares one artifact per platform, so each platform has content
// of its own and a build for it must actually run. The digests must be the ones the
// payloads really have, because the lock records exactly what the spec declared.
func twoPlatformSpec(amd64Digest, arm64Digest string) string {
	return `version: 1
name: multi
image: example.invalid/multi
distro: ubuntu
release: "26.04"
platforms: [linux/amd64, linux/arm64]
contents:
  artifacts:
    - name: amd64
      platforms: [linux/amd64]
      dest: /usr/bin/amd64
      unpack: false
      sbom: {name: amd64, version: "1"}
      sources:
        - platforms: [linux/amd64]
          url: https://example.invalid/amd64
          sha256: "` + amd64Digest + `"
    - name: arm64
      platforms: [linux/arm64]
      dest: /usr/bin/arm64
      unpack: false
      sbom: {name: arm64, version: "1"}
      sources:
        - platforms: [linux/arm64]
          url: https://example.invalid/arm64
          sha256: "` + arm64Digest + `"
`
}

// parallelFixture publishes one payload per platform and returns a lock that names
// them, so no catalogue or repository is involved.
func parallelFixture(t *testing.T) (*builder.Inputs, *cache.Cache) {
	t.Helper()
	inputs, _ := fixture(t)
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	amd64, amd64Size := storeFile(t, store, []byte("amd64 payload\n"))
	arm64, arm64Size := storeFile(t, store, []byte("arm64 payload\n"))
	inputs.Spec = loadSpec(t, twoPlatformSpec(amd64, arm64))
	digest, err := inputs.Spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	inputs.Blobs = store
	inputs.Lockfile = &lock.Lockfile{
		Version:    1,
		Provider:   lock.Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:  []string{"linux/amd64", "linux/arm64"},
		SpecDigest: digest,
		Artifacts: []lock.Artifact{
			{Name: "amd64", Platform: "linux/amd64", URL: "https://example.invalid/amd64",
				SHA256: amd64, Size: amd64Size, Dest: "/usr/bin/amd64",
				Unpack: new(contents.ArtifactUnpackStandalone), Mode: new("0644"),
				SBOM: contents.ArtifactIdentity{Name: "amd64", Version: "1"}},
			{Name: "arm64", Platform: "linux/arm64", URL: "https://example.invalid/arm64",
				SHA256: arm64, Size: arm64Size, Dest: "/usr/bin/arm64",
				Unpack: new(contents.ArtifactUnpackStandalone), Mode: new("0644"),
				SBOM: contents.ArtifactIdentity{Name: "arm64", Version: "1"}},
		},
	}
	return inputs, store
}

func TestBuildEach_SeparateJobsProduceIdenticalBytes(t *testing.T) {
	inputs, _ := parallelFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("serial build: %v", err)
	}
	concurrent, err := input.BuildEach(context.Background(), oci.DefaultCompression, 4,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("concurrent build: %v", err)
	}
	if len(serial) != 2 || len(concurrent) != 2 {
		t.Fatalf("built %d and %d images", len(serial), len(concurrent))
	}
	for index := range serial {
		if serial[index].Layer.Digest != concurrent[index].Layer.Digest ||
			serial[index].Image.ManifestDigest != concurrent[index].Image.ManifestDigest {
			t.Fatalf("platform %s changed with concurrency", serial[index].Platform)
		}
	}
	firstIndex, err := builder.BuildIndex(serial)
	if err != nil {
		t.Fatal(err)
	}
	secondIndex, err := builder.BuildIndex(concurrent)
	if err != nil {
		t.Fatal(err)
	}
	if firstIndex.Digest != secondIndex.Digest {
		t.Fatalf("index changed with concurrency: %s then %s", firstIndex.Digest, secondIndex.Digest)
	}
}

func TestBuildEach_ReportsEveryPlatformOnce(t *testing.T) {
	inputs, _ := parallelFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]string, 0, 2)
	_, err = input.BuildEach(context.Background(), oci.DefaultCompression, 2,
		func(platform oci.Platform) error {
			seen = append(seen, platform.String())
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	// Reports follow completion, so their order is not the declaration order; every
	// platform must still be reported exactly once.
	slices.Sort(seen)
	if strings.Join(seen, ",") != "linux/amd64,linux/arm64" {
		t.Fatalf("reported %v", seen)
	}
}

// gateStore holds one digest until the test releases it, so a test can decide which
// platform finishes first.
type gateStore struct {
	inner   builder.BlobStore
	digest  string
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gateStore) Open(digest string, size int64) (io.ReadCloser, error) {
	if digest == s.digest {
		s.once.Do(func() { close(s.reached) })
		<-s.release
	}
	return s.inner.Open(digest, size)
}

// The callback must run while the other platform is still building, not once every
// platform has finished.
func TestBuildEach_ReportsAPlatformBeforeTheOthersFinish(t *testing.T) {
	inputs, store := parallelFixture(t)
	gate := &gateStore{inner: store, digest: inputs.Lockfile.Artifacts[1].SHA256,
		reached: make(chan struct{}), release: make(chan struct{})}
	inputs.Blobs = gate
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan string, 2)
	build := make(chan error, 1)
	go func() {
		_, buildErr := input.BuildEach(context.Background(), oci.DefaultCompression, 2,
			func(platform oci.Platform) error {
				reported <- platform.String()
				return nil
			})
		build <- buildErr
	}()
	<-gate.reached
	select {
	case platform := <-reported:
		if platform != "linux/amd64" {
			t.Fatalf("reported %q while linux/arm64 was still building", platform)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no platform was reported while the other was still building")
	}
	close(gate.release)
	if err := <-build; err != nil {
		t.Fatal(err)
	}
	if second := <-reported; second != "linux/arm64" {
		t.Fatalf("second report was %q", second)
	}
}

// A cancellation caused by a sibling's failure must never be the reported cause: the
// caller has to see what actually went wrong.
func TestBuildEach_ReportsTheFailureNotTheCancellation(t *testing.T) {
	inputs, store := parallelFixture(t)
	inputs.Blobs = &failingStore{BlobStore: store, digest: inputs.Lockfile.Artifacts[0].SHA256}
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = input.BuildEach(context.Background(), oci.DefaultCompression, 2,
		func(oci.Platform) error { return nil })
	if err == nil {
		t.Fatal("a missing payload did not fail the build")
	}
	if !strings.Contains(err.Error(), "blob is missing") {
		t.Fatalf("error = %v, want the missing blob", err)
	}
}

// barrierStore proves the builds really overlap: the first two reads cannot both
// finish until both have started.
type barrierStore struct {
	inner   builder.BlobStore
	arrived chan struct{}
	once    sync.Once
	opened  atomic.Int32
}

func (s *barrierStore) Open(digest string, size int64) (io.ReadCloser, error) {
	if s.opened.Add(1) >= 2 {
		s.once.Do(func() { close(s.arrived) })
	}
	select {
	case <-s.arrived:
	case <-time.After(10 * time.Second):
	}
	return s.inner.Open(digest, size)
}

func TestBuildEach_RunsPlatformsConcurrently(t *testing.T) {
	inputs, store := parallelFixture(t)
	gate := &barrierStore{inner: store, arrived: make(chan struct{})}
	inputs.Blobs = gate
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(context.Background(), oci.DefaultCompression, 2,
		func(oci.Platform) error { return nil }); err != nil {
		t.Fatalf("build: %v", err)
	}
	select {
	case <-gate.arrived:
	default:
		t.Fatal("the two platforms never read at the same time")
	}
}

// failingStore fails one digest, so one platform cannot build while the other can.
type failingStore struct {
	builder.BlobStore
	digest string
}

func (s *failingStore) Open(digest string, size int64) (io.ReadCloser, error) {
	if digest == s.digest {
		return nil, errors.New("blob is missing")
	}
	return s.BlobStore.Open(digest, size)
}

type cancellationStore struct {
	failingStore
	sibling string
	started chan struct{}
	release chan struct{}
}

func (s *cancellationStore) Open(digest string, size int64) (io.ReadCloser, error) {
	switch digest {
	case s.digest:
		<-s.started
	case s.sibling:
		close(s.started)
		<-s.release
	}
	return s.failingStore.Open(digest, size)
}

func TestBuildEach_CancelsTheOtherPlatformOnFailure(t *testing.T) {
	inputs, store := parallelFixture(t)
	synctest.Test(t, func(t *testing.T) {
		gate := &cancellationStore{
			BlobStore: store, digest: inputs.Lockfile.Artifacts[0].SHA256,
			sibling: inputs.Lockfile.Artifacts[1].SHA256,
			started: make(chan struct{}), release: make(chan struct{}),
		}
		inputs.Blobs = gate
		ctx := t.Context()
		input, err := builder.Open(ctx, inputs)
		if err != nil {
			t.Fatal(err)
		}
		platforms, err := input.Platforms()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		var failures []error
		var buildErr error
		go func() {
			defer close(done)
			failures, buildErr = input.ParallelErrorsForTest(ctx, platforms)
		}()
		// The sibling cannot leave its read until the failure has been collected.
		synctest.Wait()
		close(gate.release)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the platform builds did not finish")
		}
		if buildErr == nil || len(failures) != 2 || !errors.Is(failures[1], context.Canceled) {
			t.Fatalf("build error = %v; platform errors = %v; want canceled sibling", buildErr, failures)
		}
		if ctx.Err() != nil {
			t.Fatal("the build canceled the caller's context")
		}
	})
}
