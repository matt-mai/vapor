package lockinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro/debian"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/distro/ubuntu/pro"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func TestCollectSignedRepositoryAndSlices(t *testing.T) {
	dir := t.TempDir()
	entity, err := openpgp.NewEntity("Vapor test", "", "test@example.invalid", debianEntityConfig)
	if err != nil {
		t.Fatal(err)
	}
	entity.Subkeys = nil
	keyPath := filepath.Join(dir, "keys", "test.asc")
	if err = os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	var keyBuffer bytes.Buffer
	armorWriter, err := armor.Encode(&keyBuffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = entity.Serialize(armorWriter); err != nil {
		t.Fatal(err)
	}
	if err = armorWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, keyBuffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	payloadPath := "main/binary-amd64/Packages"
	debBytes := []byte("package payload")
	debSum := sha256.Sum256(debBytes)
	wholeBytes := []byte("whole package payload")
	wholeSum := sha256.Sum256(wholeBytes)
	packages := fmt.Sprintf("Package: base-files\nVersion: 26.04\nArchitecture: amd64\nFilename: pool/base-files.deb\nSize: %d\nSHA256: %s\n\n"+
		"Package: openssl\nVersion: 3.0\nArchitecture: amd64\nFilename: pool/openssl.deb\nSize: %d\nSHA256: %s\n\n",
		len(debBytes), hex.EncodeToString(debSum[:]), len(wholeBytes), hex.EncodeToString(wholeSum[:]))
	packagesSum := sha256.Sum256([]byte(packages))
	release := fmt.Sprintf("Suite: test\nCodename: test\nArchitectures: amd64\nComponents: main\nSHA256:\n %s %d %s\n",
		hex.EncodeToString(packagesSum[:]), len(packages), payloadPath)
	var signed bytes.Buffer
	clearWriter, err := clearsign.Encode(&signed, entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clearWriter.Write([]byte(release)); err != nil {
		t.Fatal(err)
	}
	if err = clearWriter.Close(); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"/dists/test/InRelease":      signed.Bytes(),
		"/dists/test/" + payloadPath: []byte(packages),
		"/pool/base-files.deb":       debBytes,
		"/pool/openssl.deb":          wholeBytes,
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
	originalTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = originalTransport }()
	catalogueDir := filepath.Join(dir, "catalogue")
	if err = os.MkdirAll(filepath.Join(catalogueDir, "slices"), 0o700); err != nil {
		t.Fatal(err)
	}
	armorText := "      " + strings.ReplaceAll(strings.TrimSuffix(keyBuffer.String(), "\n"), "\n", "\n      ")
	keyID := fmt.Sprintf("%016X", entity.PrimaryKey.KeyId)
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
	if err = os.WriteFile(filepath.Join(catalogueDir, "chisel.yaml"), []byte(chisel), 0o600); err != nil {
		t.Fatal(err)
	}
	sdf := `package: base-files
archive: ubuntu
slices:
  data:
    contents:
      /etc/base-files: {text: "fixture\n"}
`
	if err = os.WriteFile(filepath.Join(catalogueDir, "slices", "base-files.yaml"), []byte(sdf), 0o600); err != nil {
		t.Fatal(err)
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
      path: catalogue
      archives: {ubuntu: main}
  packages:
    - name: openssl
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
	if err = os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cache.New(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := Collect(context.Background(), &Request{
		Spec:     loaded,
		SpecDir:  dir,
		Provider: ubuntu.New(loaded.Release),
		Cache:    store,
		Repository: func(url string, restricted bool) (Fetcher, error) {
			if restricted {
				return nil, fmt.Errorf("unexpected restricted archive")
			}
			return pro.NewFetcher(nil, url, pro.Credentials{})
		},
		Artifacts: acquire.HTTPFetcher{},
		Git:       catalogue.CommandGit{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.LocalInputs) != 1 || len(evidence.Catalogues) != 1 || len(evidence.Repositories) != 1 {
		t.Fatalf("evidence counts: inputs=%d catalogues=%d repositories=%d",
			len(evidence.LocalInputs), len(evidence.Catalogues), len(evidence.Repositories))
	}
	if len(evidence.Slices) != 1 || len(evidence.Slices[0].Selected) != 1 || evidence.Slices[0].Selected[0] != "data" {
		t.Fatalf("slices = %#v", evidence.Slices)
	}
	if len(evidence.Repositories[0].Indexes) != 1 {
		t.Fatalf("indexes = %#v", evidence.Repositories[0].Indexes)
	}
}

func TestCollectWholePackagesFromPlatformScopedRepositories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entity := debianEntity(t)
	writeArmoredKey(t, filepath.Join(dir, "test.asc"), entity)
	specText, clients := scopedRepositories(t, entity)
	specPath := filepath.Join(dir, "image.yaml")
	if err := os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	provider := ubuntu.New(loaded.Release)
	evidence, err := Collect(t.Context(), &Request{
		Spec: loaded, SpecDir: dir, Provider: provider, Cache: store,
		Repository: func(url string, _ bool) (Fetcher, error) {
			client := clients[url]
			if client == nil {
				return nil, fmt.Errorf("unexpected repository %s", url)
			}
			return pro.NewFetcher(client, url, pro.Credentials{})
		},
		Artifacts: acquire.HTTPFetcher{},
		Git:       catalogue.CommandGit{},
	})
	if err != nil {
		t.Fatal(err)
	}
	locked, err := locking.AssembleWithDefaults(loaded, provider, evidence, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(locked.Catalogues) != 0 || len(locked.Packages) != 2 || len(locked.Repositories) != 2 {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
	for _, pkg := range locked.Packages {
		payload := "openssl payload for " + strings.TrimPrefix(pkg.Platform, "linux/")
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
		if pkg.Content.SHA256 != digest {
			t.Fatalf("wrong payload selected for %s: %+v", pkg.Platform, pkg.Content)
		}
		reader, openErr := store.Open(digest, int64(len(payload)))
		if openErr != nil {
			t.Fatalf("whole package for %s was not acquired: %v", pkg.Platform, openErr)
		}
		_ = reader.Close()
	}
}

func scopedRepositories(t *testing.T, entity *openpgp.Entity) (string, map[string]*http.Client) {
	t.Helper()
	var specText strings.Builder
	specText.WriteString(`version: 1
name: whole
image: example.invalid/whole
distro: ubuntu
release: "26.04"
platforms: [linux/amd64, linux/arm64]
contents:
  packages:
    - name: openssl
  repositories:
`)
	clients := make(map[string]*http.Client)
	for _, arch := range []string{"amd64", "arm64"} {
		server := signedWholeRepository(t, entity, arch)
		clients[server.URL] = server.Client()
		fmt.Fprintf(&specText, `    - name: test-%[1]s
      platforms: [linux/%[1]s]
      suites: [test]
      components: [main]
      endpoints:
        - platforms: [linux/%[1]s]
          url: %[2]s
      trust:
        keys:
          - path: test.asc
            fingerprints: [%[3]x]
`, arch, server.URL, entity.PrimaryKey.Fingerprint)
	}
	return specText.String(), clients
}

func signedWholeRepository(t *testing.T, entity *openpgp.Entity, arch string) *httptest.Server {
	t.Helper()
	payload := []byte("openssl payload for " + arch)
	packages := fmt.Sprintf("Package: openssl\nVersion: 3.0\nArchitecture: %s\nFilename: pool/openssl.deb\nSize: %d\nSHA256: %x\n\n",
		arch, len(payload), sha256.Sum256(payload))
	index := "main/binary-" + arch + "/Packages"
	release := fmt.Sprintf("Suite: test\nCodename: test\nArchitectures: %s\nComponents: main\nSHA256:\n %x %d %s\n",
		arch, sha256.Sum256([]byte(packages)), len(packages), index)
	var signed bytes.Buffer
	writer, err := clearsign.Encode(&signed, entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte(release)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"/dists/test/InRelease": signed.Bytes(), "/dists/test/" + index: []byte(packages), "/pool/openssl.deb": payload,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(data)
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// debianAcquisition runs one collection against a signed local archive whose release
// metadata carries the given suite and codename, with the Debian provider.
// debianAcquisition replaces http.DefaultTransport for the duration of the run, so
// these tests are not parallel: a parallel test would read the transport while it is
// being swapped.
func debianAcquisition(t *testing.T, suite, codename string) error {
	t.Helper()
	dir := t.TempDir()
	entity, err := openpgp.NewEntity("Vapor test", "", "test@example.invalid", debianEntityConfig)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "keys", "test.asc")
	if err = os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	var keyBuffer bytes.Buffer
	armorWriter, err := armor.Encode(&keyBuffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = entity.Serialize(armorWriter); err != nil {
		t.Fatal(err)
	}
	if err = armorWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, keyBuffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	debBytes := []byte("package payload")
	debSum := sha256.Sum256(debBytes)
	packages := fmt.Sprintf("Package: openssl\nVersion: 3.0\nArchitecture: amd64\nFilename: pool/openssl.deb\n"+
		"Size: %d\nSHA256: %s\n\n", len(debBytes), hex.EncodeToString(debSum[:]))
	packagesSum := sha256.Sum256([]byte(packages))
	release := fmt.Sprintf("Suite: %s\nCodename: %s\nArchitectures: amd64\nComponents: main\nSHA256:\n"+
		" %s %d main/binary-amd64/Packages\n", suite, codename, hex.EncodeToString(packagesSum[:]), len(packages))
	var signed bytes.Buffer
	clearWriter, err := clearsign.Encode(&signed, entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clearWriter.Write([]byte(release)); err != nil {
		t.Fatal(err)
	}
	if err = clearWriter.Close(); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"/dists/trixie/InRelease":                  signed.Bytes(),
		"/dists/trixie/main/binary-amd64/Packages": []byte(packages),
		"/pool/openssl.deb":                        debBytes,
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
	originalTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = originalTransport }()
	specText := fmt.Sprintf(`version: 1
name: debian-acquisition
image: example.invalid/debian-acquisition
distro: debian
release: "trixie"
platforms: [linux/amd64]
contents:
  packages:
    - name: openssl
  repositories:
    - name: debian
      suites: [trixie]
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
	if err = os.WriteFile(specPath, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cache.New(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := debian.New(loaded.Release)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Collect(context.Background(), &Request{
		Spec: loaded, SpecDir: dir, Provider: provider, Cache: store,
		Repository: func(url string, _ bool) (Fetcher, error) {
			return pro.NewFetcher(nil, url, pro.Credentials{})
		},
		Artifacts: acquire.HTTPFetcher{},
		Git:       catalogue.CommandGit{},
	})
	return err
}

// A Debian release signs the moving suite `stable` beside the fixed codename, so
// acquisition matches the codename and locks against the suite the request named.
func TestCollectDebianMatchesSignedCodename(t *testing.T) {
	if err := debianAcquisition(t, "stable", "trixie"); err != nil {
		t.Fatalf("codename matching failed: %v", err)
	}
}

// A release whose codename is another release is refused even when its suite matches,
// because a fixed codename is the identity that matters.
func TestCollectDebianRejectsOtherCodename(t *testing.T) {
	err := debianAcquisition(t, "trixie", "bookworm")
	if err == nil || !strings.Contains(err.Error(), "codename") {
		t.Fatalf("err = %v", err)
	}
}

// A release without a codename cannot satisfy a Debian request, even when its suite
// happens to match the locked suite.
func TestCollectDebianRejectsMissingCodename(t *testing.T) {
	err := debianAcquisition(t, "trixie", "")
	if err == nil || !strings.Contains(err.Error(), "codename") {
		t.Fatalf("err = %v", err)
	}
}
