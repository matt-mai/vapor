package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// pushFixture reuses the build fixture but points the specification's repository at
// a local registry and declares tags.
func pushFixture(t *testing.T) (*buildFixture, string) {
	t.Helper()
	fixture := newBuildFixture(t)
	server := httptest.NewTLSServer(registry.New(
		registry.Logger(log.New(io.Discard, "", 0)),
		registry.WithReferrersSupport(true),
	))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "https://")
	rewriteSpec(t, fixture.specPath, host+"/built")
	return fixture, host
}

// rewriteSpec replaces the repository line and appends tags, leaving the rest of the
// generated specification untouched.
func rewriteSpec(t *testing.T, path, repository string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(data), "image: example.invalid/built", "image: "+repository, 1)
	text = strings.Replace(text, "release: \"26.04\"", "release: \"26.04\"\ntags: [v1, \"26.04\"]", 1)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRun_BuildPushesTheIndex(t *testing.T) {
	t.Parallel()
	fixture, host := pushFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--push"), &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	digest := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("build printed %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "push image") {
		t.Fatalf("build did not report the push: %q", stderr.String())
	}
	// Push is the last planned step of a build with no export flag: three phases plus
	// the push, so [4/4] and not a fifth that never comes.
	if !strings.Contains(stderr.String(), "[4/4] push image") {
		t.Fatalf("push was not the last planned step: %q", stderr.String())
	}
	for _, tag := range []string{"v1", "26.04"} {
		reference, err := name.NewTag(host + "/built:" + tag)
		if err != nil {
			t.Fatal(err)
		}
		pulled, err := remote.Index(reference, remote.WithAuth(authn.Anonymous), remote.WithTransport(testTransport))
		if err != nil {
			t.Fatalf("pull %s: %v", tag, err)
		}
		pulledDigest, err := pulled.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if pulledDigest.String() != digest {
			t.Fatalf("tag %s holds %s, build reported %s", tag, pulledDigest, digest)
		}
	}
}

func TestRun_BuildPushesOnlyWhatItBuilt(t *testing.T) {
	fixture, host := pushFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	if err := os.RemoveAll(fixture.cacheDir); err != nil {
		t.Fatal(err)
	}
	t.Chdir(fixture.dir)
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--push"), &stdout, &stderr); code != 1 {
		t.Fatalf("build without inputs code=%d stderr=%q", code, stderr.String())
	}
	reference, err := name.NewTag(host + "/built:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Index(reference, remote.WithAuth(authn.Anonymous), remote.WithTransport(testTransport)); err == nil {
		t.Fatal("a failed build still pushed something")
	}
}

func TestRun_BuildRefusesPushWithoutTags(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--push"), &stdout, &stderr); code != 1 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "at least one tag") {
		t.Fatalf("build reported %q", stderr.String())
	}
}

func TestRun_BuildReportsAFailedPush(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	rewriteSpec(t, fixture.specPath, "127.0.0.1:1/built")
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--push"), &stdout, &stderr); code != 1 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "build failed") {
		t.Fatalf("build reported %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("build printed a digest after a failed push: %q", stdout.String())
	}
}

func TestRun_BuildRefusesCleartextRegistryRequests(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"fallback", "redirect", "token realm"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			var requests atomic.Int32
			cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer cleartext.Close()
			address := cleartext.URL
			if mode != "fallback" {
				tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "redirect" {
						http.Redirect(w, r, cleartext.URL, http.StatusFound)
						return
					}
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+cleartext.URL+`/token"`)
					w.WriteHeader(http.StatusUnauthorized)
				}))
				defer tlsServer.Close()
				address = tlsServer.URL
			}
			fixture := newBuildFixture(t)
			_, host, _ := strings.Cut(address, "://")
			rewriteSpec(t, fixture.specPath, host+"/built")
			var stderr bytes.Buffer
			if code := run(fixture.args("lock"), io.Discard, &stderr); code != 0 {
				t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
			}
			stderr.Reset()
			if code := run(append(fixture.args("build"), "--push"), io.Discard, &stderr); code != 1 ||
				!strings.Contains(stderr.String(), "push to "+host+"/built failed") {
				t.Fatalf("build code=%d stderr=%q", code, stderr.String())
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("cleartext server received %d requests", got)
			}
		})
	}
}

// TestRun_BuildStopsBeforeTagsWhenAttachmentsCannotBeListed checks the rule for a
// registry without the Referrers API: the build stops instead of rewriting the shared
// fallback tag that another push could race, and no tag moves before the refusal.
func TestRun_BuildStopsBeforeTagsWhenAttachmentsCannotBeListed(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	server := httptest.NewTLSServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "https://")
	rewriteSpec(t, fixture.specPath, host+"/built")
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--push"), &stdout, &stderr); code != 1 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Referrers API") ||
		!strings.Contains(stderr.String(), "--image-only") {
		t.Fatalf("build reported %q", stderr.String())
	}
	reference, err := name.NewTag(host + "/built:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Index(reference, remote.WithAuth(authn.Anonymous), remote.WithTransport(testTransport)); err == nil {
		t.Fatal("the tag was moved before the refusal")
	}
}

func TestRun_BuildReportsPartialTagPublication(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var indexStaged, taggedEarly atomic.Bool
	var referrersChecked atomic.Int32
	backend := registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(true))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/built/referrers/") {
			if !indexStaged.Load() {
				t.Error("checked referrers before staging the image index by digest")
			}
			referrersChecked.Add(1)
		}
		if r.Method == http.MethodPut {
			switch {
			case r.URL.Path == "/v2/built/manifests/v1":
				taggedEarly.Store(referrersChecked.Load() < 2)
			case r.URL.Path == "/v2/built/manifests/26.04":
				http.Error(w, "tag rejected", http.StatusForbidden)
				return
			case strings.HasPrefix(r.URL.Path, "/v2/built/manifests/sha256:") &&
				r.Header.Get("Content-Type") == string(types.OCIImageIndex):
				indexStaged.Store(true)
			}
		}
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "https://") + "/built"
	rewriteSpec(t, fixture.specPath, repo)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), io.Discard, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--push"), &stdout, &stderr); code != 1 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if taggedEarly.Load() || stdout.Len() != 0 {
		t.Fatalf("tagged before referrers: %t; stdout after failure: %q", taggedEarly.Load(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "tag "+repo+":26.04 not confirmed") ||
		!strings.Contains(stderr.String(), "confirmed tags for sha256:") ||
		!strings.Contains(stderr.String(), ": "+repo+":v1") {
		t.Fatalf("build reported %q", stderr.String())
	}
	reference, err := name.NewTag(repo + ":v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Index(reference, remote.WithAuth(authn.Anonymous), remote.WithTransport(testTransport)); err != nil {
		t.Fatalf("first tag is not readable: %v", err)
	}
}

// TestRun_BuildImageOnlyPushesWithoutReferrers checks the other half of the rule: an
// image-only push writes the image and its tags and needs no Referrers API.
func TestRun_BuildImageOnlyPushesWithoutReferrers(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	server := httptest.NewTLSServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "https://")
	rewriteSpec(t, fixture.specPath, host+"/built")
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	attestationsDir := filepath.Join(fixture.dir, "statements")
	if code := run(append(fixture.args("build"), "--push", "--image-only", "--attestations-dir", attestationsDir),
		&stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	files, err := os.ReadDir(attestationsDir)
	if err != nil || len(files) < 2 {
		t.Fatalf("local attestations: %v (%v)", files, err)
	}
	for _, tag := range []string{"v1", "26.04"} {
		reference, err := name.NewTag(host + "/built:" + tag)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := remote.Index(reference, remote.WithAuth(authn.Anonymous), remote.WithTransport(testTransport)); err != nil {
			t.Fatalf("tag %s: %v", tag, err)
		}
	}
}

// TestRun_BuildRefusesImageOnlyWithoutPush keeps the flag from looking like it did
// something when no push was asked for.
func TestRun_BuildRefusesImageOnlyWithoutPush(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stderr bytes.Buffer
	if code := run(append(fixture.args("build"), "--image-only"), io.Discard, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "--image-only requires --push") {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
}
