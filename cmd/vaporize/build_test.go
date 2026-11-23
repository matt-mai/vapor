package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/matt-mai/vapor/internal/oci"
)

// buildFixture publishes a signed repository, a catalogue and one slice, then locks
// it so the test can build from what the lock recorded.
type buildFixture struct {
	dir      string
	specPath string
	lockPath string
	cacheDir string
}

func TestRun_BuildFromLockedInputs(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.args("build"), &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "sha256:") {
		t.Fatalf("build did not print an index digest: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "assemble image") {
		t.Fatalf("build did not report its phases: %q", stderr.String())
	}
	// Assembly reports the step before the first platform is built, so its opening line
	// carries no count. A step that first speaks when a platform finishes would open with
	// "1/1" and be replaced by the tick in the same instant, leaving nothing to watch.
	opening := "running [build] [2/3] assemble image"
	if !strings.Contains(stderr.String(), opening+"\n") {
		t.Fatalf("assembly did not open before building: %q", stderr.String())
	}
}

func TestRun_BuildRefusesSliceMissingFromSignedIndex(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(fixture.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(data, []byte("pool/base-files.deb"), []byte("pool/other.deb"), 1)
	if bytes.Equal(data, altered) {
		t.Fatal("fixture lock is missing the slice archive path")
	}
	if err := os.WriteFile(fixture.lockPath, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.args("build"), &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "payload is not present in its authenticated repository index") {
		t.Fatalf("build code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

// firstBlob returns one cached payload, so a test can remove or corrupt it.
func firstBlob(t *testing.T, cacheDir string) string {
	t.Helper()
	var found string
	err := filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found != "" {
			return nil
		}
		if info.Size() > 0 {
			found = path
		}
		return nil
	})
	if err != nil || found == "" {
		t.Fatalf("cache %q holds no blob: %v", cacheDir, err)
	}
	return found
}

func (f *buildFixture) args(command string) []string {
	return []string{command, "--spec", f.specPath, "--cache-dir", f.cacheDir}
}

func newBuildFixture(t *testing.T) *buildFixture {
	t.Helper()
	dir := t.TempDir()
	entity := testEntity(t)
	keyBuffer := writeTestKey(t, dir, entity)
	payload := fixtureDeb(t, "base-files", "26.04", "fixture\n")
	packages := fmt.Sprintf("Package: base-files\nVersion: 26.04\nArchitecture: amd64\nFilename: pool/base-files.deb\nSize: %d\nSHA256: %s\n\n",
		len(payload), digestOf(payload))
	indexPath := "main/binary-amd64/Packages"
	release := fmt.Sprintf("Suite: test\nCodename: test\nArchitectures: amd64\nComponents: main\nSHA256:\n %s %d %s\n",
		digestOf([]byte(packages)), len(packages), indexPath)
	var signed bytes.Buffer
	clearWriter, err := clearsign.Encode(&signed, entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clearWriter.Write([]byte(release)); err != nil {
		t.Fatal(err)
	}
	if err := clearWriter.Close(); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"/dists/test/InRelease":    signed.Bytes(),
		"/dists/test/" + indexPath: []byte(packages),
		"/pool/base-files.deb":     payload,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)
	catalogueDir := filepath.Join(dir, "catalogue")
	if err := os.MkdirAll(filepath.Join(catalogueDir, "slices"), 0o700); err != nil {
		t.Fatal(err)
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
	if err := os.WriteFile(filepath.Join(catalogueDir, "chisel.yaml"), []byte(chisel), 0o600); err != nil {
		t.Fatal(err)
	}
	sdf := `package: base-files
archive: ubuntu
slices:
  data:
    contents:
      /etc/base-files: {copy: /etc/base-files}
`
	if err := os.WriteFile(filepath.Join(catalogueDir, "slices", "base-files.yaml"), []byte(sdf), 0o600); err != nil {
		t.Fatal(err)
	}
	specText := fmt.Sprintf(`version: 1
name: built
image: example.invalid/built
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
contents:
  catalogues:
    - name: local
      path: catalogue
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
          - path: keys/test.asc
            fingerprints: [%s]
`, server.URL, hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	specPath := filepath.Join(dir, "image.yaml")
	if err := os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	return &buildFixture{
		dir: dir, specPath: specPath,
		lockPath: filepath.Join(dir, "image.lock.yaml"),
		cacheDir: filepath.Join(dir, "cache"),
	}
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fixtureDeb assembles a DEB whose data member holds one file, so a build can
// actually extract it.
func fixtureDeb(t *testing.T, name, version, body string) []byte {
	t.Helper()
	return encodeFixtureDeb(t, name, version, "amd64", map[string]string{"etc/base-files": body})
}

func TestRun_BuildWritesLayouts(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	ociDir := filepath.Join(fixture.dir, "out", "image")
	tarball := filepath.Join(fixture.dir, "out", "image.tar")
	stdout.Reset()
	stderr.Reset()
	args := append(fixture.args("build"), "--oci-dir", ociDir, "--tarball", tarball)
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write OCI layout") {
		t.Fatalf("build did not report the export: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "write tarball") {
		t.Fatalf("build did not report the tarball: %q", stderr.String())
	}
	// The count is the steps this build planned: three plus the export it was asked for,
	// so the last step is 4 and no reader waits for a fifth.
	if !strings.Contains(stderr.String(), "[4/4] write tarball") {
		t.Fatalf("export was not the last planned step: %q", stderr.String())
	}
	// index.json also lists the attached statements, so the build index is the blob
	// the printed digest names rather than the file itself.
	buildIndex, err := os.ReadFile(filepath.Join(ociDir, "blobs", "sha256",
		strings.TrimPrefix(strings.TrimSpace(stdout.String()), "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	if got := "sha256:" + digestOf(buildIndex); got != strings.TrimSpace(stdout.String()) {
		t.Fatalf("printed digest %q does not describe the build index (%s)", stdout.String(), got)
	}
	if info, err := os.Stat(tarball); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("tarball = %v %v", info, err)
	}
}

func TestRun_BuildRefusesTarballOverAnInput(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stderr bytes.Buffer
	if code := run(fixture.args("lock"), io.Discard, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	keyPath := filepath.Join(fixture.dir, "signing-key.pem")
	if err := os.WriteFile(keyPath, testPKCS8Key(t), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "inputs")
	if err := os.Symlink(fixture.dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.specPath, fixture.lockPath, keyPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			dst := filepath.Join(alias, filepath.Base(path))
			args := append(fixture.args("build"), "--tarball", dst, "--sign-key", keyPath)
			if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), "already exists; choose a new path") {
				t.Fatalf("build code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
				t.Fatalf("input changed: %v", err)
			}
		})
	}
}

func TestRun_BuildRefusesDuplicateSinks(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	target := filepath.Join(t.TempDir(), "same")
	if code := run([]string{"build", "--oci-dir", target, "--tarball", target}, &stdout, &stderr); code != 1 {
		t.Fatalf("duplicate sinks code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "different destinations") {
		t.Fatalf("duplicate sinks reported %q", stderr.String())
	}
}

func TestRun_BuildKeepsThePreviousLayoutWhenExportFails(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	ociDir := filepath.Join(fixture.dir, "out")
	if code := run(append(fixture.args("build"), "--oci-dir", ociDir), &stdout, &stderr); code != 0 {
		t.Fatalf("first build code=%d stderr=%q", code, stderr.String())
	}
	before, err := os.ReadFile(filepath.Join(ociDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--oci-dir", ociDir), &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "already exists; choose a new path") {
		t.Fatalf("occupied build code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(filepath.Join(ociDir, "index.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("previous layout changed: %v", err)
	}
}

// TestRun_BuildAttachesStatements checks that a build attaches the metadata the
// specification enabled and writes the same bytes when asked for a directory.
func TestRun_BuildAttachesStatements(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	ociDir := filepath.Join(fixture.dir, "out", "image")
	attestationsDir := filepath.Join(fixture.dir, "out", "attestations")
	stdout.Reset()
	stderr.Reset()
	args := append(fixture.args("build"), "--oci-dir", ociDir, "--attestations-dir", attestationsDir)
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "render attestations") {
		t.Fatalf("build did not report rendering: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "attestations=spdx,provenance") {
		t.Fatalf("build did not list the attached statements: %q", stderr.String())
	}
	indexJSON, err := os.ReadFile(filepath.Join(ociDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Manifests []struct {
			Digest       string            `json:"digest"`
			ArtifactType string            `json:"artifactType"`
			Annotations  map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if unmarshalErr := json.Unmarshal(indexJSON, &index); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	attached := 0
	for _, descriptor := range index.Manifests {
		if descriptor.ArtifactType == "" {
			continue
		}
		attached++
	}
	if attached != 2 {
		t.Fatalf("index lists %d attachments, want 2 (spdx and provenance)", attached)
	}
	files, err := os.ReadDir(attestationsDir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name())
	}
	slices.Sort(names)
	want := []string{
		"example.invalid-built-linux-amd64-provenance.json",
		"example.invalid-built-linux-amd64-spdx.json",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("attestation files = %v, want %v", names, want)
	}
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(attestationsDir, name))
		if err != nil {
			t.Fatal(err)
		}
		document := map[string]any{}
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s is not JSON: %v", name, err)
		}
		if _, wrapped := document["_type"]; wrapped {
			t.Fatalf("%s is an in-toto statement, want the bare document", name)
		}
		// A bare document stands on its own: SPDX states its version, provenance
		// states its build definition.
		if strings.HasSuffix(name, "-spdx.json") && document["spdxVersion"] != "SPDX-2.3" {
			t.Fatalf("%s spdxVersion = %v", name, document["spdxVersion"])
		}
		if strings.HasSuffix(name, "-provenance.json") {
			if _, ok := document["buildDefinition"].(map[string]any); !ok {
				t.Fatalf("%s has no buildDefinition", name)
			}
		}
	}
}

// TestRun_BuildAttachesNothingForADisabledSBOM checks that switching SPDX off leaves
// provenance in place, so the two formats are independent.
func TestRun_BuildAttachesNothingForADisabledSBOM(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	body, err := os.ReadFile(fixture.specPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.specPath, append(body,
		[]byte("\nsbom:\n  enabled: false\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	ociDir := filepath.Join(fixture.dir, "out", "image")
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--oci-dir", ociDir), &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "attestations=provenance ") {
		t.Fatalf("build listed %q", stderr.String())
	}
}

// TestRun_BuildRefusesAnUnreadableStatementInput checks that a broken VEX input stops
// the build before anything is written.
func TestRun_BuildRefusesAnUnreadableStatementInput(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	if err := os.RemoveAll(fixture.cacheDir); err != nil {
		t.Fatal(err)
	}
	ociDir := filepath.Join(fixture.dir, "out", "image")
	stdout.Reset()
	stderr.Reset()
	if code := run(append(fixture.args("build"), "--oci-dir", ociDir), &stdout, &stderr); code != 1 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(ociDir); err == nil {
		t.Fatal("a failed build left a layout behind")
	}
}

// TestRun_BuildSignsAttachedStatements checks that --sign-key wraps every attachment in a
// DSSE envelope and that both descriptors in the image say so: a media-type-aware reader
// would skip or misparse a bare in-toto label on an envelope. The directory output stays
// a bare document, because a scanner reads it and a signature covers the attachment.
func TestRun_BuildSignsAttachedStatements(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	keyPath := filepath.Join(fixture.dir, "signing.pem")
	if err := os.WriteFile(keyPath, testPKCS8Key(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	ociDir := filepath.Join(fixture.dir, "out", "image")
	attestationsDir := filepath.Join(fixture.dir, "out", "attestations")
	stdout.Reset()
	stderr.Reset()
	args := append(fixture.args("build"), "--oci-dir", ociDir, "--sign-key", keyPath,
		"--attestations-dir", attestationsDir)
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	files, err := os.ReadDir(attestationsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("attestation files = %d, want 2", len(files))
	}
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(attestationsDir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, wrapped := documentOf(t, body)["payloadType"]; wrapped {
			t.Fatalf("%s is a DSSE envelope, want the bare document", file.Name())
		}
		kind := strings.TrimSuffix(file.Name()[strings.LastIndex(file.Name(), "-")+1:],
			".json")
		descriptor, layer := attachmentMediaTypes(t, ociDir, kind)
		if descriptor != oci.MediaTypeDSSE || layer != oci.MediaTypeDSSE {
			t.Fatalf("%s descriptors say %q and %q, want the DSSE envelope",
				file.Name(), descriptor, layer)
		}
	}
}

// documentOf decodes a JSON object from an attestation file so a test can assert on it.
func documentOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	document := map[string]any{}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("decode attestation: %v", err)
	}
	return document
}

// attachmentMediaTypes returns the media type the index uses for the attachment of one
// kind and the media type its layer carries, so a signed image can be checked to label
// the envelope as an envelope everywhere a consumer reads.
func attachmentMediaTypes(t *testing.T, ociDir, kind string) (string, string) {
	t.Helper()
	indexJSON, err := os.ReadFile(filepath.Join(ociDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Manifests []struct {
			Digest       string `json:"digest"`
			ArtifactType string `json:"artifactType"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexJSON, &index); err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range index.Manifests {
		body, err := os.ReadFile(filepath.Join(ociDir, "blobs", "sha256",
			strings.TrimPrefix(descriptor.Digest, "sha256:")))
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			ArtifactType string `json:"artifactType"`
			Layers       []struct {
				MediaType   string            `json:"mediaType"`
				Annotations map[string]string `json:"annotations"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(body, &manifest); err != nil {
			t.Fatal(err)
		}
		if len(manifest.Layers) == 1 &&
			manifest.Layers[0].Annotations["org.opencontainers.image.title"] ==
				kind+".json" {
			return descriptor.ArtifactType, manifest.Layers[0].MediaType
		}
	}
	t.Fatalf("the image lists no %s attachment", kind)
	return "", ""
}

// testPKCS8Key writes one Ed25519 private key as the PEM file --sign-key expects.
func testPKCS8Key(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

// TestRun_BuildRetiresAWithdrawnStatement checks that reuse of an attestations
// directory does not leave a claim behind. A VEX statement the previous build wrote is
// removed when this build writes none, while a file this image cannot have produced is
// left for its owner.
func TestRun_BuildRetiresAWithdrawnStatement(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	attestationsDir := filepath.Join(fixture.dir, "out", "attestations")
	stdout.Reset()
	stderr.Reset()
	args := append(fixture.args("build"), "--oci-dir", filepath.Join(fixture.dir, "out", "first"),
		"--attestations-dir", attestationsDir)
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	stale := filepath.Join(attestationsDir, "example.invalid-built-linux-amd64-vex.json")
	foreign := filepath.Join(attestationsDir, "unrelated-image-linux-amd64-spdx.json")
	for _, path := range []string{stale, foreign} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	args = append(fixture.args("build"), "--oci-dir", filepath.Join(fixture.dir, "out", "second"),
		"--attestations-dir", attestationsDir)
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("withdrawn VEX statement still in the directory: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("another image's statement was touched: %v", err)
	}
}
