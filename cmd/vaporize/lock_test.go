package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/retry"
)

func TestFetcherClient_StalledDownloadDoesNotPublish(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			const payload = "archive"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if phase == "body" {
					if _, err := fmt.Fprint(w, payload[:1]); err != nil {
						t.Error(err)
						return
					}
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error(err)
						return
					}
				}
				<-req.Context().Done()
			}))
			defer server.Close()

			client, transport := fetcherClient(), lockTransport()
			if client.Timeout <= 0 || transport.ResponseHeaderTimeout <= 0 {
				t.Fatal("lock client requires both response header and total request timeouts")
			}
			client.Transport = transport
			if phase == "headers" {
				transport.ResponseHeaderTimeout = 250 * time.Millisecond
			} else {
				client.Timeout = 250 * time.Millisecond
			}
			fetcher := acquire.HTTPFetcher{Client: client, Policy: retry.Policy{Attempts: 1}}
			store, err := cache.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(payload))
			digest := hex.EncodeToString(sum[:])
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err = acquire.Packages(ctx, fetcher, store, []acquire.Package{{
				Name: "pkg", Platform: "linux/amd64", Version: "1", Architecture: "amd64",
				URL: server.URL + "/pkg.deb", SHA256: digest, Size: int64(len(payload)),
			}}, nil)
			if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				t.Fatalf("acquire error = %v, context error = %v; want client timeout", err, ctx.Err())
			}
			if phase == "body" && !strings.Contains(err.Error(), "write cache blob") {
				t.Fatalf("timed out before reading the body: %v", err)
			}
			if store.Has(digest) {
				t.Fatal("incomplete payload was cached")
			}
		})
	}
}

func TestRun_LockAndInspectArtifact(t *testing.T) {
	t.Parallel()
	payload := []byte("artifact payload\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	dir := t.TempDir()
	sum := sha256.Sum256(payload)
	specText := fmt.Sprintf(`version: 1
name: smoke
image: example.invalid/smoke
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
contents:
  artifacts:
    - name: server
      dest: /app/server
      unpack: false
      sbom: {name: smoke, version: "1.0"}
      sources:
        - platforms: [linux/amd64]
          url: %s/server
          sha256: %s
`, server.URL, hex.EncodeToString(sum[:]))

	specPath := filepath.Join(dir, "image.yaml")
	if err := os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")
	var stdout, stderr bytes.Buffer
	code := run([]string{"lock", "--spec", specPath, "--cache-dir", cacheDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	lockPath := filepath.Join(dir, "image.lock.yaml")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "collect inputs") || !strings.Contains(stderr.String(), "audit cache") {
		t.Fatalf("lock did not report progress: %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inspect", "--lock", lockPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("inspect code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "smoke") || !strings.Contains(stdout.String(), "artifact") {
		t.Fatalf("inspect output=%q", stdout.String())
	}
}

func TestRun_LockDeterministicAndOutputFailure(t *testing.T) {
	t.Parallel()
	payload := []byte("payload")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	dir := t.TempDir()
	sum := sha256.Sum256(payload)

	specPath := filepath.Join(dir, "image.yaml")
	text := fmt.Sprintf(`version: 1
name: deterministic
image: example.invalid/deterministic
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
contents:
  artifacts:
    - name: payload
      dest: /payload
      unpack: false
      sbom: {name: payload, version: "1"}
      sources:
        - platforms: [linux/amd64]
          url: %s/payload
          sha256: %s
`, server.URL, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"lock", "--spec", specPath, "--cache-dir", filepath.Join(dir, "cache")}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("first lock code=%d stderr=%q", code, stderr.String())
	}
	first, err := os.ReadFile(filepath.Join(dir, "image.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("second lock code=%d stderr=%q", code, stderr.String())
	}
	second, err := os.ReadFile(filepath.Join(dir, "image.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("lock output is not deterministic")
	}
	stdout.Reset()
	stderr.Reset()
	blocked := filepath.Join(dir, "missing", "image.lock.yaml")
	if code := run([]string{"lock", "--spec", specPath, "--cache-dir", filepath.Join(dir, "cache"),
		"--output", blocked}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("output failure code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(blocked), "image.lock.yaml")); !os.IsNotExist(err) {
		t.Fatalf("failed lock wrote output: %v", err)
	}
}

func TestRun_LockRefusesOutputThatIsItsSpec(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "image.yaml")
	text := `version: 1
name: aliased
image: example.invalid/aliased
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
`
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		specPath,
		filepath.Join(dir, ".", "image.yaml"),
		filepath.Join(alias, "image.yaml"),
	} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"lock", "--spec", specPath, "--cache-dir", filepath.Join(dir, "cache"),
			"--output", output}, &stdout, &stderr); code != 2 || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "a lock cannot replace its input") {
			t.Fatalf("output %q: code=%d stdout=%q stderr=%q", output, code, stdout.String(), stderr.String())
		}
	}
	if data, err := os.ReadFile(specPath); err != nil || string(data) != text {
		t.Fatalf("spec changed: %v %q", err, data)
	}
}

func TestRun_InspectMissingLock(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inspect", filepath.Join(t.TempDir(), "absent.lock.yaml")}, &stdout, &stderr); code != 1 ||
		stdout.Len() != 0 || !strings.Contains(stderr.String(), "read lock") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRun_LockSignedRepositoryAndSlices(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entity := testEntity(t)
	keyBuffer := writeTestKey(t, dir, entity)
	payloadPath := "main/binary-amd64/Packages"
	debBytes := []byte("package payload")
	debSum := sha256.Sum256(debBytes)
	packages := fmt.Sprintf("Package: base-files\nVersion: 26.04\nArchitecture: amd64\nFilename: pool/base-files.deb\nSize: %d\nSHA256: %s\n\n",
		len(debBytes), hex.EncodeToString(debSum[:]))
	packagesSum := sha256.Sum256([]byte(packages))
	release := fmt.Sprintf("Suite: test\nCodename: test\nArchitectures: amd64\nComponents: main\nSHA256:\n %s %d %s\n",
		hex.EncodeToString(packagesSum[:]), len(packages), payloadPath)
	var signed bytes.Buffer
	clearWriter, err := clearsign.Encode(&signed, entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := clearWriter.Write([]byte(release)); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := clearWriter.Close(); writeErr != nil {
		t.Fatal(writeErr)
	}
	files := map[string][]byte{
		"/dists/test/InRelease":      signed.Bytes(),
		"/dists/test/" + payloadPath: []byte(packages),
		"/pool/base-files.deb":       debBytes,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	catalogueDir := filepath.Join(dir, "catalogue")
	if writeErr := os.MkdirAll(filepath.Join(catalogueDir, "slices"), 0o700); writeErr != nil {
		t.Fatal(writeErr)
	}
	armorText := indentArmor(keyBuffer)
	keyID := keyID(entity)
	chisel := fmt.Sprintf(`format: v3
maintenance:
  standard: 2026-04-23
  expanded: 2031-05-29
  legacy: 2036-04-23
  end-of-life: 2038-04-27
archives:
  ubuntu:
    version: "26.04"
    suites: [test]
    components: [main]
    priority: 10
    public-keys: [test]
public-keys:
  test:
    id: "%s"
    armor: |
%s
`, keyID, armorText)
	if writeErr := os.WriteFile(filepath.Join(catalogueDir, "chisel.yaml"), []byte(chisel), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	sdf := `package: base-files
archive: ubuntu
slices:
  data:
    contents:
      /etc/base-files: {text: "fixture\n"}
`
	if writeErr := os.WriteFile(filepath.Join(catalogueDir, "slices", "base-files.yaml"), []byte(sdf), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	specText := fmt.Sprintf(`version: 1
name: signed
image: example.invalid/signed
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
contents:
  catalogues:
    - name: local
      path: ../catalogue
      archives: {ubuntu: main}
  slices:
    - package: base-files
      slice: data
  repositories:
    - name: main
      suites: [test]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: %s
      trust:
        keys:
          - path: ../keys/test.asc
            fingerprints: [%s]
`, server.URL, hex.EncodeToString(entity.PrimaryKey.Fingerprint))

	// The spec lives in its own directory and names the key, the catalogue and the
	// lock stays beside it, so a trust key declared above the spec is covered.
	specPath := filepath.Join(dir, "app", "image.yaml")
	if mkdirErr := os.MkdirAll(filepath.Dir(specPath), 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if writeErr := os.WriteFile(specPath, []byte(specText), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"lock", "--spec", specPath, "--cache-dir", filepath.Join(dir, "cache")},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	lockData, err := os.ReadFile(filepath.Join(dir, "app", "image.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lockData), "base-files") || !strings.Contains(string(lockData), "data") {
		t.Fatalf("lock missing slice evidence:\n%s", lockData)
	}
	if !strings.Contains(string(lockData), "path: ../keys/test.asc") {
		t.Fatalf("lock does not record the key above the spec:\n%s", lockData)
	}
}

func TestRun_LockCheckAndDiff(t *testing.T) {
	t.Parallel()
	payload := []byte("check payload\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	dir := t.TempDir()
	sum := sha256.Sum256(payload)
	specText := fmt.Sprintf(`version: 1
name: check
image: example.invalid/check
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
contents:
  artifacts:
    - name: payload
      dest: /payload
      unpack: false
      sbom: {name: payload, version: "1"}
      sources:
        - platforms: [linux/amd64]
          url: %s/payload
          sha256: %s
`, server.URL, hex.EncodeToString(sum[:]))
	specPath := filepath.Join(dir, "image.yaml")
	if err := os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"lock", "--spec", specPath, "--cache-dir", cacheDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	lockPath := filepath.Join(dir, "image.lock.yaml")
	original, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	check := []string{"lock", "--check", "--spec", specPath, "--cache-dir", cacheDir}
	stdout.Reset()
	stderr.Reset()
	if code := run(check, &stdout, &stderr); code != 0 {
		t.Fatalf("check code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lock", "--diff", "--spec", specPath, "--cache-dir", cacheDir}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "no drift") {
		t.Fatalf("diff code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if code := run([]string{"lock", "--check", "--diff", "--spec", specPath}, &stdout, &stderr); code != 2 {
		t.Fatalf("conflicting flags code=%d", code)
	}

	changed := strings.Replace(specText, "dest: /payload", "dest: /other", 1)
	if writeErr := os.WriteFile(specPath, []byte(changed), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(check, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "lock drift detected") {
		t.Fatalf("drift check code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lock", "--diff", "--spec", specPath, "--cache-dir", cacheDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("drift diff code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "changed:") || !strings.Contains(stdout.String(), "dest") {
		t.Fatalf("diff output=%q", stdout.String())
	}
	after, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("check/diff changed the lock")
	}
}

func TestRun_LockCheckMissingOrInvalidLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	specText := `version: 1
name: check
image: example.invalid/check
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
`
	specPath := filepath.Join(dir, "image.yaml")
	if err := os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"lock", "--check", "--spec", specPath, "--cache-dir", filepath.Join(dir, "cache")}, &stdout, &stderr); code != 1 {
		t.Fatalf("missing lock code=%d stderr=%q", code, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "image.lock.yaml"), []byte("not: a lock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lock", "--check", "--spec", specPath, "--cache-dir", filepath.Join(dir, "cache")}, &stdout, &stderr); code != 1 {
		t.Fatalf("invalid lock code=%d stderr=%q", code, stderr.String())
	}
}

func TestRun_LockSelectsProviderAndWarns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	specText := `version: 1
name: provider
image: example.invalid/provider
distro: %s
release: "26.10"
platforms: [linux/amd64]
`
	write := func(name, distro string) string {
		path := filepath.Join(dir, name)
		text := fmt.Sprintf(specText, distro)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"lock", "--spec", write("untested.yaml", "ubuntu"), "--cache-dir", filepath.Join(dir, "cache")},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("untested release code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "not a tested baseline") {
		t.Fatalf("lock did not warn about an untested release: %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"lock", "--spec", write("unsupported.yaml", "alpine"), "--cache-dir", filepath.Join(dir, "cache")},
		&stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not supported") {
		t.Fatalf("unsupported distro code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"lock", "--spec", write("bad-release.yaml", "debian"), "--cache-dir", filepath.Join(dir, "cache")},
		&stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not a known version number") {
		t.Fatalf("unsupported debian release code=%d stderr=%q", code, stderr.String())
	}
}
