package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// offlineFixture is one specification that uses every input kind at once — a whole
// package, two slices (one of them mutable and mutated), a per-platform artifact, VEX
// claims and the statements a build attaches — serviced by a local archive that can be
// taken away.
type offlineFixture struct {
	dir          string
	specPath     string
	lockPath     string
	cacheDir     string
	catalogueDir string
	keysDir      string
	server       *httptest.Server
	offlineMode  atomic.Bool
	requests     atomic.Int64
	// artifact is the per-platform tool the specification declares, served by the same
	// archive.
	artifact map[string][]byte
	// files is what the server answers with; a test may replace entries to model an
	// upstream change.
	files   map[string][]byte
	filesMu sync.RWMutex
	// refused, when set, makes the server answer 404 for a path, so a test can prove a
	// command did not need it.
	refused func(path string) bool
}

// TestRun_OfflineWorkflow runs the commands a release needs, in order, in one
// directory: init writes a specification, the specification is edited to name local
// inputs, lock resolves them, build assembles both platforms, and inspect reports what
// was recorded. The CLI runs in-process; the mutation worker runs separately.
func TestRun_OfflineWorkflow(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	// init owns the directory until the specification is edited: it refuses to
	// overwrite, so an edited specification replaces the generated one the way a user
	// would.
	var stdout, stderr bytes.Buffer
	if code := run(initArgs(fixture.dir), &stdout, &stderr); code != 0 {
		t.Fatalf("init code=%d stderr=%q", code, stderr.String())
	}
	generated := filepath.Join(fixture.dir, "image.yaml")
	if _, err := os.Stat(generated); err != nil {
		t.Fatalf("init wrote no specification: %v", err)
	}
	fixture.install(t)
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	layoutDir := filepath.Join(fixture.dir, "out")
	statementsDir := filepath.Join(fixture.dir, "attestations")
	buildArgs := append(fixture.args("build"), "--oci-dir", layoutDir,
		"--attestations-dir", statementsDir)
	stdout.Reset()
	stderr.Reset()
	if code := run(buildArgs, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	digest := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("build printed %q, want an index digest", digest)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inspect", fixture.lockPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("inspect code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "linux/arm64") {
		t.Fatalf("inspect did not report the arm64 inputs: %q", stdout.String())
	}
	// One specification produced both platforms, and both carry the content the
	// declaration selected.
	platforms := fixture.checkPlatformLayers(t, layoutDir, digest)
	if want := []string{"linux/amd64", "linux/arm64"}; !slices.Equal(platforms, want) {
		t.Fatalf("index platforms = %v, want %v", platforms, want)
	}
	files, err := os.ReadDir(statementsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 6 {
		// Three formats per platform: SPDX, provenance and the VEX claim.
		t.Fatalf("attestation files = %d, want 6", len(files))
	}
}

// TestRun_BuildNeedsNoNetworkAfterLock is the offline proof: the archive is gone, the
// catalogue directory, the trust key and every other local input are deleted, and the
// same lock still rebuilds the same image. Only the verified cache is left.
func TestRun_BuildNeedsNoNetworkAfterLock(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	before := fixture.requests.Load()
	online := fixture.buildDigest(t)
	fixture.offline(t)
	offline := fixture.buildDigest(t)
	if attempts := fixture.requests.Load() - before; attempts != 0 {
		t.Fatalf("builds made %d requests to the archive and artifact server; want 0", attempts)
	}
	if online != offline {
		t.Fatalf("rebuild from the same lock produced %s, want %s", offline, online)
	}
}

func TestRun_LockRejectsVendorSuiteWithoutCodenameMatching(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	image := strings.Replace(fixture.specYAML(t), "      suite-match: codename\n", "", 1)
	if err := os.WriteFile(fixture.specPath, []byte(image), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), `repository "vendor": release suite "stable" does not match "test"`) {
		t.Fatalf("lock code=%d stderr=%q, want vendor suite mismatch", code, stderr.String())
	}
}

func TestRun_LockRejectsDuplicateCatalogueDefinitions(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	second := filepath.Join(fixture.dir, "second")
	if err := os.MkdirAll(filepath.Join(second, "slices"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(second, "chisel.yaml"), string(readTestKey(t, filepath.Join(fixture.catalogueDir, "chisel.yaml"))))
	write(filepath.Join(second, "slices", "hello.yaml"), `package: hello
archive: ubuntu
slices:
  bins:
    contents:
      /usr/bin/hello: {copy: /usr/bin/hello}
`)
	const unused = `package: unused
archive: ubuntu
slices:
  data:
    contents:
      /unused: {text: unused}
`
	write(filepath.Join(fixture.catalogueDir, "slices", "unused.yaml"), unused)
	duplicate := filepath.Join(second, "slices", "unused.yaml")
	write(duplicate, unused)
	image := strings.Replace(fixture.specYAML(t), "  repositories:", `    - name: second
      path: second
      archives: {ubuntu: vendor}
  repositories:`, 1)
	image = strings.Replace(image, "  packages:\n    - name: hello\n  slices:", `  slices:
    - package: hello
      slice: bins
      catalogue: second`, 1)
	image = strings.ReplaceAll(image, "    - package: base-files\n      slice:", "    - package: base-files\n      catalogue: local\n      slice:")
	write(fixture.specPath, image)

	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), `catalogue package "unused" is defined by both "local" and "second"`) {
		t.Fatalf("lock code=%d stderr=%q, want duplicate definition error", code, stderr.String())
	}
	if _, err := os.Stat(fixture.lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock file should not exist: %v", err)
	}
	if err := os.Remove(duplicate); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	fixture.offline(t)
	if err := os.RemoveAll(second); err != nil {
		t.Fatal(err)
	}
	fixture.buildDigest(t)
}

// buildDigest builds into a fresh layout and returns the index digest.
func (f *offlineFixture) buildDigest(t *testing.T) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	layoutDir := filepath.Join(t.TempDir(), "out")
	args := append(f.args("build"), "--oci-dir", layoutDir)
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	digest := strings.TrimSpace(stdout.String())
	readLayoutBlob(t, layoutDir, digest)
	return digest
}

// offline removes every input a lock captured from outside the cache, and stops serving
// the files the cache was seeded from.
func (f *offlineFixture) offline(t *testing.T) {
	t.Helper()
	f.offlineMode.Store(true)
	for _, dir := range []string{f.catalogueDir, f.keysDir} {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *offlineFixture) args(command string) []string {
	return []string{command, "--spec", f.specPath, "--cache-dir", f.cacheDir}
}

// install writes the specification, its catalogue and its trust key over the
// directory init prepared.
func (f *offlineFixture) install(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.specPath, []byte(f.specYAML(t)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *offlineFixture) specYAML(t *testing.T) string {
	t.Helper()
	entity := testEntity(t)
	return fmt.Sprintf(`version: 1
name: e2e
image: example.invalid/e2e
tags: [v1]
distro: ubuntu
release: "26.04"
platforms: [linux/amd64, linux/arm64]
container:
  user: "65532:65532"
contents:
  catalogues:
    - name: local
      path: catalogue
      archives: {ubuntu: main}
  repositories:
    - name: main
      suites: [test]
      components: [main]
      endpoints:
        - platforms: [linux/amd64, linux/arm64]
          url: %s
      trust:
        keys:
          - path: keys/test.asc
            fingerprints: [%s]
    - name: vendor
      suites: [test]
      suite-match: codename
      components: [main]
      endpoints:
        - platforms: [linux/amd64, linux/arm64]
          url: %[1]s/vendor
      trust:
        keys:
          - path: keys/test.asc
            fingerprints: [%[2]s]
  packages:
    - name: hello
  slices:
    - package: base-files
      slice: release-info
    - package: base-files
      slice: state
  artifacts:
    - name: demo-tool
      unpack: false
      dest: /usr/bin/demo-tool
      mode: "0755"
      sbom: {name: demo-tool, version: "1.0"}
      sources:
        - platforms: [linux/amd64]
          url: %s/artifacts/demo-amd64
          sha256: %s
        - platforms: [linux/arm64]
          url: %s/artifacts/demo-arm64
          sha256: %s
  slices-engine:
    max-steps: 5000
vex:
  assertions:
    - vulnerability: CVE-2026-1
      package: base-files
      status: fixed
      statement: Rebuilt from 26.04
`, f.server.URL, hex.EncodeToString(entity.PrimaryKey.Fingerprint),
		f.server.URL, digestOf(f.artifact["amd64"]),
		f.server.URL, digestOf(f.artifact["arm64"]))
}

func readLayoutBlob(t *testing.T, layoutDir, digest string) []byte {
	t.Helper()
	hash, ok := strings.CutPrefix(digest, "sha256:")
	if _, err := hex.DecodeString(hash); !ok || len(hash) != 64 || err != nil {
		t.Fatalf("invalid layout digest %q", digest)
	}
	body, err := os.ReadFile(filepath.Join(layoutDir, "blobs", "sha256", hash))
	if err != nil {
		t.Fatal(err)
	}
	if got := digestOf(body); got != hash {
		t.Fatalf("layout blob digest = %s, want %s", got, hash)
	}
	return body
}

func (f *offlineFixture) checkPlatformLayers(t *testing.T, layoutDir, digest string) []string {
	t.Helper()
	body := readLayoutBlob(t, layoutDir, digest)
	var index struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatal(err)
	}
	platforms := make([]string, 0, len(index.Manifests))
	for _, descriptor := range index.Manifests {
		if descriptor.Platform.Architecture == "" {
			continue
		}
		platform := descriptor.Platform.OS + "/" + descriptor.Platform.Architecture
		platforms = append(platforms, platform)
		t.Run(platform, func(t *testing.T) {
			checkWorkflowLayer(t, layoutDir, descriptor.Digest, f.artifact[descriptor.Platform.Architecture])
		})
	}
	slices.Sort(platforms)
	return platforms
}

func checkWorkflowLayer(t *testing.T, layoutDir, digest string, artifact []byte) {
	t.Helper()
	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(readLayoutBlob(t, layoutDir, digest), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) != 1 {
		t.Fatalf("got %d layers, want one", len(manifest.Layers))
	}
	gz, err := gzip.NewReader(bytes.NewReader(readLayoutBlob(t, layoutDir, manifest.Layers[0].Digest)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	want := map[string][]byte{"usr/bin/demo-tool": artifact, "etc/vapor-state": []byte("ready")}
	tarReader := tar.NewReader(gz)
	for {
		header, readErr := tarReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		expected, ok := want[header.Name]
		if !ok {
			continue
		}
		data, readErr := io.ReadAll(tarReader)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if expected == nil || !bytes.Equal(data, expected) {
			t.Errorf("%s contains %q, want %q", header.Name, data, expected)
		}
		delete(want, header.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing layer files: %v", want)
	}
}

func newOfflineFixture(t *testing.T) *offlineFixture {
	t.Helper()
	dir := t.TempDir()
	fixture := &offlineFixture{
		dir: dir, specPath: filepath.Join(dir, "image.yaml"),
		lockPath:     filepath.Join(dir, "image.lock.yaml"),
		cacheDir:     filepath.Join(dir, "cache"),
		catalogueDir: filepath.Join(dir, "catalogue"),
		keysDir:      filepath.Join(dir, "keys"),
		artifact:     map[string][]byte{"amd64": []byte("amd64 tool\n"), "arm64": []byte("arm64 tool\n")},
	}
	writeTestKey(t, dir, testEntity(t))
	fixture.files = fixture.archive(t)
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		fixture.filesMu.RLock()
		data, ok := fixture.files[r.URL.Path]
		refuse := fixture.refused
		fixture.filesMu.RUnlock()
		if !ok || fixture.offlineMode.Load() || (refuse != nil && refuse(r.URL.Path)) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *offlineFixture) archive(t *testing.T) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	addOfflineArchive(t, files, "", "base-files", "Suite: test\n")
	addOfflineArchive(t, files, "/vendor", "hello", "Suite: stable\nCodename: test\n")
	for arch, payload := range f.artifact {
		files["/artifacts/demo-"+arch] = payload
	}
	f.writeCatalogue(t)
	return files
}

func addOfflineArchive(t *testing.T, files map[string][]byte, prefix, name, releaseFields string) {
	t.Helper()
	addOfflineArchiveVersion(t, files, prefix, name, releaseFields, "26.04")
}

func addOfflineArchiveVersion(t *testing.T, files map[string][]byte, prefix, name, releaseFields, version string) {
	t.Helper()
	release := releaseFields + "Architectures: amd64 arm64\nComponents: main\nSHA256:\n"
	for _, arch := range []string{"amd64", "arm64"} {
		payload := encodeFixtureDeb(t, name, version, arch, map[string]string{
			"etc/os-release": "PRETTY_NAME=\"Ubuntu " + version + "\"\n",
			"etc/base-files": "fixture\n",
			"usr/bin/hello":  "hello from " + arch + "\n",
		})
		path := fmt.Sprintf("pool/%s_%s.deb", name, arch)
		files[prefix+"/"+path] = payload
		packages := []byte(fmt.Sprintf(
			"Package: %s\nVersion: %s\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\n\n",
			name, version, arch, path, len(payload), digestOf(payload)))
		index := "main/binary-" + arch + "/Packages"
		files[prefix+"/dists/test/"+index] = packages
		release += fmt.Sprintf(" %s %d %s\n", digestOf(packages), len(packages), index)
	}
	var signed bytes.Buffer
	clearWriter, err := clearsign.Encode(&signed, testEntity(t).PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clearWriter.Write([]byte(release)); err != nil {
		t.Fatal(err)
	}
	if err := clearWriter.Close(); err != nil {
		t.Fatal(err)
	}
	files[prefix+"/dists/test/InRelease"] = signed.Bytes()
}

func (f *offlineFixture) writeCatalogue(t *testing.T) {
	t.Helper()
	slicesDir := filepath.Join(f.catalogueDir, "slices")
	if err := os.MkdirAll(slicesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	armorText := indentArmor(string(readTestKey(t, filepath.Join(f.keysDir, "test.asc"))))
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
`, keyID(testEntity(t)), armorText)
	if err := os.WriteFile(filepath.Join(f.catalogueDir, "chisel.yaml"), []byte(chisel), 0o600); err != nil {
		t.Fatal(err)
	}
	sdf := `package: base-files
archive: ubuntu
slices:
  release-info:
    contents:
      /etc/os-release: {copy: /etc/os-release}
  state:
    contents:
      /etc/vapor-state: {text: "", mutable: true}
    mutate: |
      content.write("/etc/vapor-state", "ready")
`
	if err := os.WriteFile(filepath.Join(slicesDir, "base-files.yaml"), []byte(sdf), 0o600); err != nil {
		t.Fatal(err)
	}
}

// upgrade re-serves the archive with a newer version of one package.
func (f *offlineFixture) upgrade(t *testing.T, name, version string) {
	t.Helper()
	files := f.archive(t)
	addOfflineArchiveVersion(t, files, "/vendor", name, "Suite: stable\nCodename: test\n", version)
	f.setFiles(files)
}

// refuse makes the server answer 404 for any path the predicate matches.
func (f *offlineFixture) refuse(t *testing.T, predicate func(path string) bool) {
	t.Helper()
	f.filesMu.Lock()
	f.refused = predicate
	f.filesMu.Unlock()
}

func (f *offlineFixture) setFiles(files map[string][]byte) {
	f.filesMu.Lock()
	f.files = files
	f.filesMu.Unlock()
}

func encodeFixtureDeb(t *testing.T, name, version, arch string, files map[string]string) []byte {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n", name, version, arch)
	buffer := &bytes.Buffer{}
	buffer.WriteString("!<arch>\n")
	for _, member := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", gzipBytes(t, filesTar(t, map[string]string{"control": control}))},
		{"data.tar.gz", gzipBytes(t, filesTar(t, files))},
	} {
		fmt.Fprintf(buffer, "%-16s%-12s%-6s%-6s%-8s%-10s`\n",
			member.name, "0", "0", "0", "100644", fmt.Sprint(len(member.body)))
		buffer.Write(member.body)
		if len(member.body)%2 == 1 {
			buffer.WriteByte('\n')
		}
	}
	return buffer.Bytes()
}

// filesTar archives the map in sorted order, so the same map produces the same bytes.
func filesTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := tar.NewWriter(buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		body := files[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644,
			Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := gzip.NewWriter(buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func readTestKey(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestRun_LockWarnsAboutAnExpiredCatalogue proves the maintenance gap is closed: an
// end-of-life catalogue locks successfully and says so. The warning is a diagnostic, so
// it must not reach the lock, and the same lock has to build the same image.
func TestRun_LockWarnsAboutAnExpiredCatalogue(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	// Past every stage: standard, expanded, legacy and end-of-life.
	catalogue := readTestKey(t, filepath.Join(fixture.catalogueDir, "chisel.yaml"))
	worn := strings.Replace(string(catalogue), "end-of-life: 2038-04-27",
		"end-of-life: 2001-01-01", 1)
	if worn == string(catalogue) {
		t.Fatal("fixture catalogue has no end-of-life date")
	}
	if err := os.WriteFile(filepath.Join(fixture.catalogueDir, "chisel.yaml"), []byte(worn), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "end-of-life") {
		t.Fatalf("lock did not warn about the expired catalogue: %q", stderr.String())
	}
	locked := readTestKey(t, fixture.lockPath)
	if strings.Contains(string(locked), "end-of-life") {
		t.Fatalf("the lock recorded the maintenance warning")
	}
	fixture.buildDigest(t)
}

// TestRun_OfflineWorkflowFailures drives the failure paths through the same commands
// and directory the workflow uses, so drift, tampering and a missing cache are seen as a
// user would meet them rather than one package at a time. Every case leaves the lock
// untouched, because a failure must not rewrite what it failed to reproduce.
func TestRun_OfflineWorkflowFailures(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	locked := readTestKey(t, fixture.lockPath)
	blob := firstBlob(t, fixture.cacheDir)

	// Drift: the specification now describes a different file than the lock recorded.
	spec := readTestKey(t, fixture.specPath)
	drifted := strings.Replace(string(spec), "dest: /usr/bin/demo-tool",
		"dest: /usr/bin/other-tool", 1)
	if drifted == string(spec) {
		t.Fatal("fixture specification has no artifact dest to change")
	}
	if err := os.WriteFile(fixture.specPath, []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("lock"), "--check"), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "drift") {
		t.Fatalf("drift check code=%d stderr=%q", code, stderr.String())
	}
	if !bytes.Equal(locked, readTestKey(t, fixture.lockPath)) {
		t.Fatal("a failed check rewrote the lock")
	}
	// Drift is also caught at build time, because the lock records the spec digest.
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--oci-dir", filepath.Join(t.TempDir(), "out")),
		&stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "spec digest") {
		t.Fatalf("drifted build code=%d stderr=%q", code, stderr.String())
	}
	if err := os.WriteFile(fixture.specPath, spec, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tampering: a cached payload no longer matches the digest the lock recorded.
	if err := os.WriteFile(blob, []byte("poisoned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertBuildFails := func(reason string) {
		t.Helper()
		output := filepath.Join(t.TempDir(), "out")
		stdout.Reset()
		stderr.Reset()
		if code := run(append(fixture.args("build"), "--oci-dir", output), &stdout, &stderr); code != 1 ||
			stdout.Len() != 0 || !strings.Contains(stderr.String(), "build failed") {
			t.Fatalf("%s build code=%d stdout=%q stderr=%q", reason, code, stdout.String(), stderr.String())
		}
		if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s build: stat output = %v; want not exist", reason, err)
		}
	}
	assertBuildFails("poisoned cache")

	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	assertBuildFails("missing cache")

	// Inspect reads the lock, never the cache, so it still answers.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inspect", fixture.lockPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("inspect code=%d stderr=%q", code, stderr.String())
	}
	if !bytes.Equal(locked, readTestKey(t, fixture.lockPath)) {
		t.Fatal("the failure path rewrote the lock")
	}
}
