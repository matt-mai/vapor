package lockinput

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/debian"
	"github.com/matt-mai/vapor/internal/distro/ubuntu/pro"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/verify"
)

// debianNow is a fixed clock inside every deadline the fixture signs, so these tests
// never depend on when they run.
var debianNow = time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)

// debianDeadline is the Valid-Until the security suite signs: a week after debianNow.
const debianDeadline = "Fri, 27 Nov 2026 16:02:59 UTC"

// localDebian points the real Debian provider at a local archive. Only the endpoint
// and the trust change: the suites, codename matching and prefixed components stay
// the reviewed policy.
type localDebian struct {
	*debian.Provider
	url          string
	securityURL  string
	keys         []deb.KeySnapshot
	securityKeys []deb.KeySnapshot
}

func (p *localDebian) DefaultTrust() []deb.KeySnapshot {
	return append(append([]deb.KeySnapshot(nil), p.keys...), p.securityKeys...)
}

// Archives keeps the reviewed suite and component policy and points every archive
// at the local server, signed by the fixture's one key.
func (p *localDebian) Archives() []deb.SignedArchive {
	archives := p.Provider.Archives()
	for i := range archives {
		url, keys := p.url, p.keys
		if archives[i].Name == "debian-security" {
			url, keys = p.securityURL, p.securityKeys
		}
		archives[i].Endpoints = map[string]string{deb.PlatformAMD64: url, deb.PlatformARM64: url}
		archives[i].Keys = keys
	}
	return archives
}
func (p *localDebian) ProTrust(string) []deb.KeySnapshot { return nil }
func (p *localDebian) ReleaseWarnings() []string         { return nil }

// debianArchive is a local signed Debian archive shaped like the real one: a moving
// Suite beside a fixed Codename, a security suite whose components carry the updates/
// prefix, and a second signature from a key no lock trusts.
type debianArchive struct {
	dir     string
	server  *httptest.Server
	trusted *openpgp.Entity
	// security signs the security archive, so the fixture also exercises per-archive
	// key scoping: the main key cannot authenticate a security suite.
	security *openpgp.Entity
	files    map[string][]byte
	main     string
	secure   string
}

// debianSuiteDecl describes one suite the fixture serves.
type debianSuiteDecl struct {
	suite     string
	codename  string
	validity  string
	packages  []debianPackage
	component string
	// signedSuite overrides the moving suite name the release claims.
	signedSuite string
}

// debianPackage is one package entry plus the files its payload carries.
type debianPackage struct {
	name     string
	filename string
	files    map[string]string
	// version overrides the 1.0 every fixture package gets by default.
	version string
}

func (p debianPackage) publishedVersion() string {
	if p.version != "" {
		return p.version
	}
	return "1.0"
}

func newDebianArchive(t *testing.T, suites ...debianSuiteDecl) *debianArchive {
	t.Helper()
	trusted, untrusted := debianEntity(t), debianEntity(t)
	security := debianEntity(t)
	archive := &debianArchive{
		dir: t.TempDir(), trusted: trusted, security: security, files: map[string][]byte{},
	}
	for _, suite := range suites {
		prefix := "debian"
		if suite.component != "" {
			prefix = suite.component
		}
		archive.addSuite(t, prefix, archive.keyFor(suite), untrusted, suite)
	}
	archive.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := archive.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(archive.server.Close)
	archive.main = archive.server.URL + "/debian"
	archive.secure = archive.server.URL + "/security"
	directory := filepath.Join(archive.dir, "keys")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeArmoredKey(t, filepath.Join(directory, "test.asc"), trusted)
	return archive
}

// keyFor returns the key that signs a suite: the security archive has its own.
func (a *debianArchive) keyFor(suite debianSuiteDecl) *openpgp.Entity {
	if suite.component != "" {
		return a.security
	}
	return a.trusted
}

// addSuite stores every payload, builds the index over them, then signs the release
// that authenticates that index. Order matters: signing before the index is final
// would authenticate bytes the archive no longer serves.
func (a *debianArchive) addSuite(t *testing.T, prefix string, trusted, untrusted *openpgp.Entity,
	suite debianSuiteDecl,
) {
	t.Helper()
	root := "/" + prefix + "/dists/" + suite.suite
	var index strings.Builder
	for _, pkg := range suite.packages {
		payload := debianDeb(t, pkg.name, pkg.files)
		a.files["/"+prefix+"/"+pkg.filename] = payload
		sum := sha256.Sum256(payload)
		fmt.Fprintf(&index, "Package: %s\nVersion: %s\nArchitecture: amd64\nFilename: %s\nSize: %d\nSHA256: %s\n\n",
			pkg.name, pkg.publishedVersion(), pkg.filename, len(payload), hex.EncodeToString(sum[:]))
	}
	packages := []byte(index.String())
	a.files[root+"/main/binary-amd64/Packages"] = packages
	sum := sha256.Sum256(packages)
	component := "main"
	if suite.component != "" {
		component = "updates/main"
	}
	headers := fmt.Sprintf("Suite: %s\nCodename: %s\nArchitectures: amd64\nComponents: %s\n",
		debianSuiteName(suite), suite.codename, component)
	if suite.validity != "" {
		headers += "Valid-Until: " + suite.validity + "\n"
	}
	a.files[root+"/InRelease"] = debianRelease(t, trusted, untrusted, headers,
		fmt.Sprintf(" %s %d main/binary-amd64/Packages\n", hex.EncodeToString(sum[:]), len(packages)))
}

// debianSuiteName gives the moving suite the archive signs beside the codename.
func debianSuiteName(suite debianSuiteDecl) string {
	if suite.signedSuite != "" {
		return suite.signedSuite
	}
	if suite.component != "" {
		return "stable-security"
	}
	if strings.HasSuffix(suite.codename, "-updates") {
		return "stable-updates"
	}
	return "stable"
}

// debianRelease cross-signs one payload, untrusted key first, so reading it means
// skipping a packet this build cannot check.
func debianRelease(t *testing.T, trusted, untrusted *openpgp.Entity, headers, files string) []byte {
	t.Helper()
	payload := "Origin: Debian\nLabel: Debian\n" + headers + "SHA256:\n" + files
	signed := &bytes.Buffer{}
	writer, err := clearsign.EncodeMulti(signed,
		[]*packet.PrivateKey{untrusted.PrivateKey, trusted.PrivateKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return signed.Bytes()
}

// debianEntityConfig switches key generation from RSA-2048 to Ed25519, which is
// orders of magnitude faster and exercises the same sign/verify path.
var debianEntityConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEd25519}

func debianEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	entity, err := openpgp.NewEntity("Debian test", "", "debian@example.invalid", debianEntityConfig)
	if err != nil {
		t.Fatal(err)
	}
	entity.Subkeys = nil
	return entity
}

// debianDeb builds a DEB whose data member holds the given files.
func debianDeb(t *testing.T, name string, files map[string]string) []byte {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nVersion: 1.0\nArchitecture: amd64\n", name)
	buffer := &bytes.Buffer{}
	buffer.WriteString("!<arch>\n")
	for _, member := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", debianGzip(t, debianTar(t, map[string]string{"control": control}))},
		{"data.tar.gz", debianGzip(t, debianTar(t, files))},
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

func debianTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := tar.NewWriter(buffer)
	names := slices.Sorted(func(yield func(string) bool) {
		for name := range files {
			if !yield(name) {
				return
			}
		}
	})
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

func debianGzip(t *testing.T, data []byte) []byte {
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

// writeArmoredKey writes the public half of entity at path.
func writeArmoredKey(t *testing.T, path string, entity *openpgp.Entity) {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer, err := armor.Encode(buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// debianFixture assembles a specification, its catalogue and a provider over the
// local archive, then runs acquisition with the fixed clock.
type debianFixture struct {
	archive  *debianArchive
	dir      string
	specPath string
	provider *localDebian
	spec     *spec.Spec
	store    *cache.Cache
}

// newDebianFixture builds the three-archive layout the plan describes: an implicit
// main archive, its updates suite, and an explicitly bound security archive.
func newDebianFixture(t *testing.T, securityValidity string) *debianFixture {
	t.Helper()
	archive := newDebianArchive(t,
		debianSuiteDecl{suite: "trixie", codename: "trixie", packages: []debianPackage{
			{name: "base-files", filename: "pool/base-files.deb", files: map[string]string{
				"usr/lib/os-release": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n"}},
			{name: "base-passwd", filename: "pool/base-passwd.deb", files: map[string]string{
				"etc/passwd": "root:x:0:0:root:/root:/bin/sh\n" +
					"_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n"}},
			{name: "apt", filename: "pool/apt.deb", files: map[string]string{"usr/bin/apt": "apt\n"}},
		}},
		debianSuiteDecl{suite: "trixie-updates", codename: "trixie-updates", packages: []debianPackage{
			{name: "bash", filename: "pool/bash.deb", files: map[string]string{"usr/bin/bash": "bash\n"}},
		}},
		debianSuiteDecl{suite: "trixie-security", codename: "trixie-security", component: "security",
			validity: securityValidity, packages: []debianPackage{
				{name: "openssl", filename: "pool/openssl.deb", files: map[string]string{
					"usr/bin/openssl": "openssl\n"}},
			}},
	)
	dir := t.TempDir()
	writeDebianCatalogue(t, dir, archive)
	specPath := filepath.Join(dir, "image.yaml")
	writeDebianSpec(t, specPath, archive)
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cache.New(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := debian.New("13")
	if err != nil {
		t.Fatal(err)
	}
	return &debianFixture{
		archive: archive, dir: dir, specPath: specPath, spec: loaded, store: store,
		provider: &localDebian{
			Provider: provider, url: archive.main, securityURL: archive.secure,
			keys:         debianKeySnapshot(t, archive.trusted),
			securityKeys: debianKeySnapshot(t, archive.security),
		},
	}
}

// collect runs acquisition with the fixed clock and assembles a lockfile from it.
func (f *debianFixture) collect(t *testing.T) (*lock.Lockfile, error) {
	t.Helper()
	provider := f.provider
	evidence, err := Collect(context.Background(), &Request{
		Spec: f.spec, SpecDir: f.dir, Provider: provider, Cache: f.store, Now: debianNow,
		Repository: func(url string, restricted bool) (Fetcher, error) {
			if restricted {
				return nil, fmt.Errorf("debian has no pro archive")
			}
			return pro.NewFetcher(f.archive.server.Client(), url, pro.Credentials{})
		},
		Artifacts: acquire.HTTPFetcher{Client: f.archive.server.Client()},
		Git:       catalogue.CommandGit{},
	})
	if err != nil {
		return nil, err
	}
	defaults, err := verify.ProviderDefaults(context.Background(), provider, f.spec,
		evidence.Catalogues, evidence.Repositories, f.store)
	if err != nil {
		return nil, err
	}
	return locking.AssembleWithDefaults(f.spec, provider, evidence, defaults)
}

// build assembles every platform from the lock, which is the offline stage: it reads
// only verified cached bytes.
func (f *debianFixture) build(t *testing.T, locked *lock.Lockfile) *builder.Input {
	t.Helper()
	input, err := builder.Open(context.Background(), &builder.Inputs{
		Spec: f.spec, Lockfile: locked, Provider: f.provider, Blobs: f.store,
	})
	if err != nil {
		t.Fatalf("open build: %v", err)
	}
	return input
}

func debianKeySnapshot(t *testing.T, entity *openpgp.Entity) []deb.KeySnapshot {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer, err := armor.Encode(buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return []deb.KeySnapshot{{
		Fingerprints: []string{fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)},
		Data:         buffer.Bytes(),
	}}
}

// writeDebianCatalogue writes a custom catalogue: Debian names the codename as the
// archive version, and the security archive is a second entry.
func writeDebianCatalogue(t *testing.T, dir string, archive *debianArchive) {
	t.Helper()
	catalogueDir := filepath.Join(dir, "catalogue")
	if err := os.MkdirAll(filepath.Join(catalogueDir, "slices"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyArmor := strings.ReplaceAll(
		strings.TrimSuffix(readArmoredKey(t, filepath.Join(archive.dir, "keys", "test.asc")), "\n"), "\n", "\n      ")
	root := fmt.Sprintf(`format: v3
maintenance:
  standard: 2025-08-09
  end-of-life: 2030-06-30
archives:
  debian:
    version: trixie
    suites: [trixie, trixie-updates]
    components: [main]
    priority: 10
    public-keys: [test]
  debian-security:
    version: trixie
    suites: [trixie-security]
    components: [main]
    priority: 20
    public-keys: [test]
public-keys:
  test:
    id: "%016X"
    armor: |
      %s
`, archive.trusted.PrimaryKey.KeyId, keyArmor)
	if err := os.WriteFile(filepath.Join(catalogueDir, "chisel.yaml"), []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"base-files": "package: base-files\narchive: debian\nslices:\n  release-info:\n" +
			"    contents:\n      /usr/lib/os-release: {copy: /usr/lib/os-release}\n",
		"openssl": "package: openssl\narchive: debian-security\nslices:\n  binary:\n" +
			"    contents:\n      /usr/bin/openssl: {copy: /usr/bin/openssl}\n",
	} {
		if err := os.WriteFile(filepath.Join(catalogueDir, "slices", name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cert := filepath.Join(dir, "certs")
	if err := os.MkdirAll(cert, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cert, "ca.pem"), debianCertificate(t), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readArmoredKey(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// debianCertificate returns a self-signed certificate, so the CA bundle source is
// real certificate material rather than a placeholder.
func debianCertificate(t *testing.T) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vapor test root"},
		NotBefore:    debianNow.Add(-24 * time.Hour),
		NotAfter:     debianNow.Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeDebianSpec declares slices from both archives, two whole packages and a CA
// bundle, so one build exercises every path the plan names.
func writeDebianSpec(t *testing.T, path string, archive *debianArchive) {
	t.Helper()
	text := fmt.Sprintf(`version: 1
name: debian-pipeline
image: example.invalid/debian-pipeline
distro: debian
release: "13"
platforms: [linux/amd64]
contents:
  catalogues:
    - name: local
      path: catalogue
      archives:
        debian-security: security
  packages:
    - name: apt
    - name: base-passwd
  slices:
    - catalogue: local
      package: base-files
      slice: release-info
    - catalogue: local
      package: openssl
      slice: binary
  repositories:
    - name: security
      suites: [trixie-security]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: %s
filesystem:
  ca:
    mode: append
    sources: [certs/ca.pem]
`, archive.secure)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An explicitly declared repository picks its own endpoint and keys, but the release
// decides which suites may be read. A trixie image therefore cannot lock a bookworm
// package, even from a repository that is signed correctly and declared openly.
func TestDebianRejectsForeignReleaseRepository(t *testing.T) {
	fixture := newDebianFixture(t, debianDeadline)
	// The archive really serves bookworm and signs it with the key the spec trusts, so
	// only the release rule stands between the image and another release's packages.
	fixture.archive.addSuite(t, "debian", fixture.archive.trusted, fixture.archive.trusted,
		debianSuiteDecl{suite: "bookworm", codename: "bookworm", packages: []debianPackage{
			{name: "apt", filename: "pool/bookworm-apt.deb", files: map[string]string{
				"usr/bin/apt": "bookworm apt\n"}},
		}})
	text := `version: 1
name: debian-foreign
image: example.invalid/debian-foreign
distro: debian
release: "13"
platforms: [linux/amd64]
contents:
  packages:
    - name: apt
  repositories:
    - name: bookworm
      suites: [bookworm]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: ` + fixture.archive.main + `
      trust:
        keys:
          - path: keys/test.asc
            fingerprints: ["` + fmt.Sprintf("%X", fixture.archive.trusted.PrimaryKey.Fingerprint) + `"]
filesystem:
  ca:
    mode: append
    sources: [certs/ca.pem]
`
	keys := filepath.Join(fixture.dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(fixture.archive.dir, "keys", "test.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(filepath.Join(keys, "test.asc"), key, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	specPath := filepath.Join(fixture.dir, "foreign.yaml")
	if writeErr := os.WriteFile(specPath, []byte(text), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.spec = loaded
	if _, err := fixture.collect(t); err == nil ||
		!strings.Contains(err.Error(), `repository "bookworm" suite "bookworm" is not served by release "trixie"`) {
		t.Fatalf("collect = %v", err)
	}
}

// Replay rejects a slice from an archive other than the one the catalogue bound, and a
// security suite placed on the implicit provider endpoint, which that endpoint never
// serves. The implicit provider archive needs no declaration, so without these checks
// its record was never compared with the archive the catalogue describes.
func TestDebianReplayRejectsSliceFromForeignArchiveScope(t *testing.T) {
	for name, tamper := range map[string]func(*lock.Repository){
		"suite": func(repository *lock.Repository) {
			repository.Suite = "trixie-security"
			repository.Release.Path = "dists/trixie-security/InRelease"
		},
		"component": func(repository *lock.Repository) {
			repository.Indexes[0].Component = "contrib"
			repository.Indexes[0].Path = "contrib/binary-amd64/Packages.xz"
		},
	} {
		fixture := newDebianFixture(t, debianDeadline)
		locked, err := fixture.collect(t)
		if err != nil {
			t.Fatalf("%s: collect: %v", name, err)
		}
		defaults, err := verify.ProviderDefaults(context.Background(), fixture.provider, fixture.spec,
			locked.Catalogues, locked.Repositories, fixture.store)
		if err != nil {
			t.Fatal(err)
		}
		target := slices.IndexFunc(locked.Repositories, func(repository lock.Repository) bool {
			return repository.Name == "debian"
		})
		if target < 0 {
			t.Fatal("no implicit provider repository")
		}
		repository := &locked.Repositories[target]
		before := repository.ID
		tamper(repository)
		repository.ID = lock.RepositoryID(repository.Name, repository.Platform, repository.Architecture,
			repository.URL, repository.Suite)
		for i := range locked.Slices {
			if locked.Slices[i].Repository == before {
				locked.Slices[i].Repository = repository.ID
			}
		}
		for i := range locked.Packages {
			if locked.Packages[i].Repository == before {
				locked.Packages[i].Repository = repository.ID
			}
		}
		err = lock.VerifyLockfileForProvider(fixture.spec, locked, fixture.provider.Release(), defaults)
		want := `suite is not served by the provider archive`
		if name == "component" {
			want = `is not a component of archive`
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: verify = %v", name, err)
		}
	}
}

// With no archive map at all, the old checks compared nothing about the implicit
// archive, so a slice could name any repository. The binding rebuilt from the verified
// catalogue is what makes that case checkable.
func TestDebianReplayChecksTheImplicitArchive(t *testing.T) {
	fixture := newDebianFixture(t, debianDeadline)
	writeImplicitCatalogue(t, fixture)
	text := `version: 1
name: debian-implicit
image: example.invalid/debian-implicit
distro: debian
release: "13"
platforms: [linux/amd64]
contents:
  catalogues:
    - name: local
      path: catalogue
  slices:
    - catalogue: local
      package: base-files
      slice: release-info
filesystem:
  ca:
    mode: append
    sources: [certs/ca.pem]
`
	specPath := filepath.Join(fixture.dir, "implicit.yaml")
	writeErr := os.WriteFile(specPath, []byte(text), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.spec = loaded
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defaults, err := verify.ProviderDefaults(context.Background(), fixture.provider, loaded,
		locked.Catalogues, locked.Repositories, fixture.store)
	if err != nil {
		t.Fatal(err)
	}
	if len(locked.Slices) != 1 || locked.Slices[0].Archive != "debian" {
		t.Fatalf("slices = %#v", locked.Slices)
	}
	repository := &locked.Repositories[0]
	before := repository.ID
	repository.Suite = "trixie-security"
	repository.Release.Path = "dists/trixie-security/InRelease"
	repository.ID = lock.RepositoryID(repository.Name, repository.Platform, repository.Architecture,
		repository.URL, repository.Suite)
	locked.Slices[0].Repository = repository.ID
	err = lock.VerifyLockfileForProvider(loaded, locked, fixture.provider.Release(), defaults)
	if err == nil || !strings.Contains(err.Error(), "suite is not served by the provider archive") {
		t.Fatalf("verify = %v (was %s)", err, before)
	}
}

// writeImplicitCatalogue replaces the fixture catalogue with one that declares only the
// provider archive, so a specification can leave the archive map out entirely.
func writeImplicitCatalogue(t *testing.T, fixture *debianFixture) {
	t.Helper()
	catalogueDir := filepath.Join(fixture.dir, "catalogue")
	if err := os.RemoveAll(catalogueDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(catalogueDir, "slices"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyArmor := strings.ReplaceAll(
		strings.TrimSuffix(readArmoredKey(t, filepath.Join(fixture.archive.dir, "keys", "test.asc")), "\n"),
		"\n", "\n      ")
	root := fmt.Sprintf(`format: v3
maintenance:
  standard: 2025-08-09
  end-of-life: 2030-06-30
archives:
  debian:
    version: trixie
    suites: [trixie, trixie-updates]
    components: [main]
    priority: 10
    public-keys: [test]
public-keys:
  test:
    id: "%016X"
    armor: |
      %s
`, fixture.archive.trusted.PrimaryKey.KeyId, keyArmor)
	writeErr := os.WriteFile(filepath.Join(catalogueDir, "chisel.yaml"), []byte(root), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	body := "package: base-files\narchive: debian\nslices:\n  release-info:\n" +
		"    contents:\n      /usr/lib/os-release: {copy: /usr/lib/os-release}\n"
	writeErr = os.WriteFile(filepath.Join(catalogueDir, "slices", "base-files.yaml"), []byte(body), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
}

// A Debian lock resolves slices from the implicit main archive and the explicitly
// bound security archive, and the offline build reproduces both.
func TestDebianPipelineLocksAndBuildsOffline(t *testing.T) {
	fixture := newDebianFixture(t, debianDeadline)
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if locked.Provider.Distro != "debian" || locked.Provider.Release != "trixie" {
		t.Fatalf("provider = %#v", locked.Provider)
	}
	// Only the suites the specification actually reads are recorded, so the unused
	// updates suite leaves no repository behind.
	suites := make([]string, 0, len(locked.Repositories))
	for _, repository := range locked.Repositories {
		suites = append(suites, repository.Suite)
	}
	if want := []string{"trixie", "trixie-security"}; !slices.Equal(suites, want) {
		t.Fatalf("repositories serve %v, want %v", suites, want)
	}
	for _, repository := range locked.Repositories {
		if len(repository.Release.Signers) != 1 {
			t.Fatalf("repository %q recorded %d signers, want the one trusted key",
				repository.Name, len(repository.Release.Signers))
		}
	}
	components := make(map[string]string)
	for _, repository := range locked.Repositories {
		components[repository.Suite] = repository.Indexes[0].Component
	}
	if components["trixie-security"] != "main" {
		t.Fatalf("security index component = %q, want the plain component", components["trixie-security"])
	}

	input := fixture.build(t, locked)
	content, err := input.Content(context.Background(), "linux/amd64")
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	tree, err := input.Assemble(context.Background(), content, "linux/amd64")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	release, err := tree.Read("/usr/lib/os-release")
	if err != nil {
		t.Fatalf("os-release: %v", err)
	}
	for _, want := range []string{`ID="debian"`, `VERSION_CODENAME="trixie"`, `VERSION_ID="13"`} {
		if !bytes.Contains(release, []byte(want)) {
			t.Fatalf("os-release %q does not contain %q", release, want)
		}
	}
	if _, ok := tree.Lookup(fixture.provider.CABundlePath()); !ok {
		t.Fatalf("CA bundle missing at %s", fixture.provider.CABundlePath())
	}
	passwd, err := tree.Read("/etc/passwd")
	if err != nil {
		t.Fatalf("passwd: %v", err)
	}
	if count := bytes.Count(passwd, []byte("_apt:")); count != 1 {
		t.Fatalf("_apt appears %d times, want the single line base-passwd provides: %q", count, passwd)
	}
}

// Freshness follows the declared policy: a suite without Valid-Until satisfies the
// default and fails require, while a suite with a future deadline satisfies both.
func TestDebianFreshnessPolicies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		security  string
		main      string
		safety    string
		wantError string
	}{
		// Main signs no deadline, so the default policy accepts it and require
		// refuses it.
		{name: "main default", security: debianDeadline},
		{name: "main require", security: debianDeadline, main: "require",
			wantError: "release valid-until is required"},
		// The security suite signs a future deadline, so both policies accept it.
		{name: "security default", security: debianDeadline},
		{name: "security require", security: debianDeadline, safety: "require"},
		{name: "security expired", security: "Thu, 01 Jan 2004 00:00:00 UTC", safety: "require",
			wantError: "release metadata has expired"},
		{name: "security malformed", security: "not a date", safety: "if-present",
			wantError: "release valid-until is not a valid date"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDebianFixture(t, testCase.security)
			if testCase.main != "" || testCase.safety != "" {
				fixture.declareFreshness(t, testCase.main, testCase.safety)
			}
			_, err := fixture.collect(t)
			if testCase.wantError == "" {
				if err != nil {
					t.Fatalf("collect: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("err = %v, want %q", err, testCase.wantError)
			}
		})
	}
}

// declareFreshness chooses the policy for one declared repository, because only a
// declared repository can pick one other than the default.
func (f *debianFixture) declareFreshness(t *testing.T, main, security string) {
	t.Helper()
	mainFreshness := ""
	if main != "" {
		mainFreshness = "      freshness:\n        valid-until: " + main + "\n"
	}
	securityFreshness := ""
	if security != "" {
		securityFreshness = "      freshness:\n        valid-until: " + security + "\n"
	}
	text := fmt.Sprintf(`version: 1
name: debian-pipeline
image: example.invalid/debian-pipeline
distro: debian
release: "13"
platforms: [linux/amd64]
contents:
  catalogues:
    - name: local
      path: catalogue
      archives:
        debian: main
        debian-security: security
  packages:
    - name: apt
    - name: base-passwd
  slices:
    - catalogue: local
      package: base-files
      slice: release-info
    - catalogue: local
      package: openssl
      slice: binary
  repositories:
    - name: main
      suites: [trixie, trixie-updates]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: %s
%s    - name: security
      suites: [trixie-security]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: %s
%s`, f.archive.main, mainFreshness, f.archive.secure, securityFreshness)
	if err := os.WriteFile(f.specPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(f.specPath)
	if err != nil {
		t.Fatal(err)
	}
	f.spec = loaded
}

// A previously accepted lock still builds after its metadata expired: replay checks
// what the lock recorded and never consults the clock.
func TestDebianLockBuildsAfterExpiry(t *testing.T) {
	fixture := newDebianFixture(t, debianDeadline)
	fixture.declareFreshness(t, "", "require")
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	input := fixture.build(t, locked)
	if _, err := input.Content(context.Background(), "linux/amd64"); err != nil {
		t.Fatalf("offline content: %v", err)
	}
}

// A catalogue naming a repository the specification does not declare is refused
// before anything is fetched.
func TestDebianRejectsUndeclaredRepository(t *testing.T) {
	t.Parallel()
	fixture := newDebianFixture(t, debianDeadline)
	text := strings.Replace(readSpec(t, fixture.specPath), "debian-security: security", "debian-security: missing", 1)
	if err := os.WriteFile(fixture.specPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := spec.LoadSpec(fixture.specPath); err == nil || !strings.Contains(err.Error(),
		"catalogue archive binding references an undefined repository") {
		t.Fatalf("err = %v, want an undeclared repository", err)
	}
}

// A slice request without a catalogue cannot be resolved, which is a schema refusal
// rather than an acquisition failure.
func TestDebianSliceWithoutCatalogueIsRefused(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "image.yaml")
	text := `version: 1
name: no-catalogue
image: example.invalid/no-catalogue
distro: debian
release: "13"
contents:
  packages:
    - name: openssl
  slices:
    - package: base-files
      slice: release-info
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := spec.LoadSpec(path); err == nil ||
		!strings.Contains(err.Error(), "unambiguous declared catalogue") {
		t.Fatalf("err = %v, want a refusal without a catalogue", err)
	}
}

func readSpec(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A whole-package-only specification needs no catalogue: the provider default binds
// the repository and supplies the trust.
func TestDebianWholePackageWithoutCatalogue(t *testing.T) {
	t.Parallel()
	archive := newDebianArchive(t, debianSuiteDecl{suite: "trixie", codename: "trixie",
		packages: []debianPackage{
			{name: "openssl", filename: "pool/openssl.deb", files: map[string]string{
				"usr/bin/openssl": "openssl\n"}},
		}})
	dir := t.TempDir()
	specPath := filepath.Join(dir, "image.yaml")
	text := fmt.Sprintf(`version: 1
name: whole
image: example.invalid/whole
distro: debian
release: trixie
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
`, archive.main)
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
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
	provider, err := debian.New("trixie")
	if err != nil {
		t.Fatal(err)
	}
	local := &localDebian{Provider: provider, url: archive.main, securityURL: archive.secure,
		keys: debianKeySnapshot(t, archive.trusted), securityKeys: debianKeySnapshot(t, archive.security)}
	evidence, err := Collect(context.Background(), &Request{
		Spec: loaded, SpecDir: dir, Provider: local, Cache: store, Now: debianNow,
		Repository: func(url string, restricted bool) (Fetcher, error) {
			if restricted {
				return nil, fmt.Errorf("debian has no pro archive")
			}
			return pro.NewFetcher(archive.server.Client(), url, pro.Credentials{})
		},
		Artifacts: acquire.HTTPFetcher{Client: archive.server.Client()},
		Git:       catalogue.CommandGit{},
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(evidence.Repositories) != 1 || len(evidence.Repositories[0].Trust.Keys) != 1 {
		t.Fatalf("evidence = %#v", evidence.Repositories)
	}
	if len(evidence.Packages) != 1 || evidence.Packages[0].Name != "openssl" {
		t.Fatalf("packages = %#v", evidence.Packages)
	}
	defaults, err := verify.ProviderDefaults(context.Background(), local, loaded,
		evidence.Catalogues, evidence.Repositories, store)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := locking.AssembleWithDefaults(loaded, local, evidence, defaults)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, err := builder.Open(context.Background(), &builder.Inputs{
		Spec: loaded, Lockfile: locked, Provider: local, Blobs: store,
	}); err != nil {
		t.Fatalf("offline open: %v", err)
	}
}

// A whole-package-only specification needs nothing declared at all: the provider
// archive is bound for it, and the same run locks, authenticates the cached
// repository evidence, and builds offline.
// A package-only specification gets the reviewed archives of its release, main and
// security included, and each archive's record is signed by that archive's own key.
func TestDebianWholePackagesFromBothReviewedArchives(t *testing.T) {
	t.Parallel()
	archive := newDebianArchive(t,
		debianSuiteDecl{suite: "trixie", codename: "trixie", packages: []debianPackage{
			{name: "base-files", filename: "pool/base-files.deb", files: map[string]string{
				"usr/lib/os-release": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n"}},
		}},
		debianSuiteDecl{suite: "trixie-updates", codename: "trixie-updates"},
		debianSuiteDecl{suite: "trixie-security", codename: "trixie-security", component: "security",
			validity: debianDeadline, packages: []debianPackage{
				{name: "openssl", filename: "pool/openssl.deb", files: map[string]string{
					"usr/bin/openssl": "openssl\n"}},
			}})
	fixture := newWholePackageFixture(t, archive, `    - name: base-files
    - name: openssl
`)
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// One record per archive, each with its own suite, endpoint and key: the security
	// archive is served from another endpoint and signed by another key.
	want := map[string]struct{ suite, url, fingerprint string }{
		"debian":          {suite: "trixie", url: archive.main, fingerprint: fingerprintOf(archive.trusted)},
		"debian-security": {suite: "trixie-security", url: archive.secure, fingerprint: fingerprintOf(archive.security)},
	}
	seen := make(map[string]bool, len(locked.Repositories))
	for i := range locked.Repositories {
		repository := &locked.Repositories[i]
		expected, ok := want[repository.Name]
		if !ok {
			t.Fatalf("unexpected repository %#v", repository)
		}
		seen[repository.Name] = true
		if repository.Suite != expected.suite || repository.URL != expected.url {
			t.Fatalf("repository %q = suite %q url %q", repository.Name, repository.Suite, repository.URL)
		}
		if len(repository.Trust.Keys) != 1 ||
			!strings.EqualFold(repository.Trust.Keys[0].Fingerprint, expected.fingerprint) {
			t.Fatalf("repository %q trust = %#v, want only its own archive key", repository.Name, repository.Trust)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("repositories = %#v, want main and security", locked.Repositories)
	}
	if names := packageNames(locked.Packages); !slices.Equal(names, []string{"base-files", "openssl"}) {
		t.Fatalf("locked packages = %v", names)
	}
	// The offline replay accepts the lock, and refuses it once one archive's record
	// claims the other archive's key.
	fixture.build(t, locked)
	swapped := *locked
	swapped.Repositories = slices.Clone(locked.Repositories)
	mainTrust := want["debian"].fingerprint
	for i := range swapped.Repositories {
		if swapped.Repositories[i].Name == "debian" {
			mainTrust = swapped.Repositories[i].Trust.Keys[0].Fingerprint
		}
	}
	for i := range swapped.Repositories {
		if swapped.Repositories[i].Name != "debian-security" {
			continue
		}
		swapped.Repositories[i].Trust = lock.RepositoryTrust{
			Keys: []lock.RepositoryKey{{Fingerprint: mainTrust,
				SHA256: swapped.Repositories[i].Trust.Keys[0].SHA256,
				Size:   swapped.Repositories[i].Trust.Keys[0].Size}},
		}
	}
	if err := lock.VerifyLockfileForProvider(fixture.spec, &swapped, fixture.provider.Release(),
		fixture.defaults(t)); err == nil || !strings.Contains(err.Error(), "trust does not match") {
		t.Fatalf("security record signed by the main key: err = %v", err)
	}
}

func fingerprintOf(entity *openpgp.Entity) string {
	return fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
}

// newWholePackageFixture writes a package-only specification against a local archive
// and returns the fixture for it.
func newWholePackageFixture(t *testing.T, archive *debianArchive, packages string) *debianFixture {
	t.Helper()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "image.yaml")
	text := `version: 1
name: whole
image: example.invalid/whole
distro: debian
release: trixie
platforms: [linux/amd64]
contents:
  packages:
` + packages
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
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
	provider, err := debian.New("trixie")
	if err != nil {
		t.Fatal(err)
	}
	return &debianFixture{
		archive: archive, dir: dir, specPath: specPath, spec: loaded, store: store,
		provider: &localDebian{
			Provider: provider, url: archive.main, securityURL: archive.secure,
			keys:         debianKeySnapshot(t, archive.trusted),
			securityKeys: debianKeySnapshot(t, archive.security),
		},
	}
}

// defaults rebuilds the provider defaults the lock was assembled with.
func (f *debianFixture) defaults(t *testing.T) *lock.DefaultRepository {
	t.Helper()
	defaults, err := verify.ProviderDefaults(context.Background(), f.provider, f.spec,
		nil, nil, f.store)
	if err != nil {
		t.Fatal(err)
	}
	return defaults
}

func TestDebianWholePackageWithImplicitArchive(t *testing.T) {
	t.Parallel()
	archive := newDebianArchive(t,
		debianSuiteDecl{suite: "trixie", codename: "trixie", packages: []debianPackage{
			{name: "openssl", filename: "pool/openssl.deb", files: map[string]string{
				"usr/bin/openssl": "openssl\n"}},
			{name: "base-files", filename: "pool/base-files.deb", files: map[string]string{
				"usr/lib/os-release": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n"}},
		}},
		debianSuiteDecl{suite: "trixie-updates", codename: "trixie-updates"},
		// The security suite serves nothing here, but the release's reviewed defaults
		// include the security archive, so it is read and has to answer.
		debianSuiteDecl{suite: "trixie-security", codename: "trixie-security", component: "security",
			validity: debianDeadline})
	dir := t.TempDir()
	specPath := filepath.Join(dir, "image.yaml")
	text := `version: 1
name: whole
image: example.invalid/whole
distro: debian
release: trixie
platforms: [linux/amd64]
contents:
  packages:
    - name: openssl
    - name: base-files
`
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
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
	provider, err := debian.New("trixie")
	if err != nil {
		t.Fatal(err)
	}
	local := &localDebian{Provider: provider, url: archive.main, securityURL: archive.secure,
		keys: debianKeySnapshot(t, archive.trusted), securityKeys: debianKeySnapshot(t, archive.security)}
	evidence, err := Collect(context.Background(), &Request{
		Spec: loaded, SpecDir: dir, Provider: local, Cache: store, Now: debianNow,
		Repository: func(url string, restricted bool) (Fetcher, error) {
			if restricted {
				return nil, fmt.Errorf("debian has no pro archive")
			}
			return pro.NewFetcher(archive.server.Client(), url, pro.Credentials{})
		},
		Artifacts: acquire.HTTPFetcher{Client: archive.server.Client()},
		Git:       catalogue.CommandGit{},
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// One repository at the provider endpoint, holding the provider's trust, and the
	// suite the specification actually read. The updates suite resolved versions but
	// nothing came from it, so it leaves no record behind.
	if len(evidence.Repositories) != 1 {
		t.Fatalf("repositories = %#v, want the implicit provider archive only", evidence.Repositories)
	}
	repository := evidence.Repositories[0]
	if repository.Name != "debian" || repository.URL != archive.main || repository.Suite != "trixie" {
		t.Fatalf("repository = %#v, want the provider archive on its main suite", repository)
	}
	if repository.Release.SHA256 == "" || len(repository.Indexes) != 1 ||
		repository.Indexes[0].Component != "main" {
		t.Fatalf("repository evidence = %#v, want an authenticated main index", repository)
	}
	if suite := repository.Indexes[0].Path; suite != "main/binary-amd64/Packages" {
		t.Fatalf("index path = %q", suite)
	}
	if len(repository.Trust.Keys) != 1 || repository.Trust.Keys[0].Path != "" {
		t.Fatalf("trust = %#v, want the provider key with no local path", repository.Trust.Keys)
	}
	// The cached bytes the lock names must be the bytes the archive served, or the
	// offline build below is reading something nobody authenticated.
	reader, err := store.Open(repository.Release.SHA256, repository.Release.Size)
	if err != nil {
		t.Fatalf("release evidence was not cached: %v", err)
	}
	_ = reader.Close()

	defaults, err := verify.ProviderDefaults(context.Background(), local, loaded,
		evidence.Catalogues, evidence.Repositories, store)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := locking.AssembleWithDefaults(loaded, local, evidence, defaults)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(locked.Repositories) != 1 || locked.Repositories[0].Suite != "trixie" {
		t.Fatalf("lock repositories = %#v", locked.Repositories)
	}
	if names := packageNames(locked.Packages); !slices.Equal(names, []string{"base-files", "openssl"}) {
		t.Fatalf("locked packages = %v", names)
	}

	// The archive goes away before the build, so anything it still needed would fail
	// rather than be fetched again.
	archive.server.Close()
	input, err := builder.Open(context.Background(), &builder.Inputs{
		Spec: loaded, Lockfile: locked, Provider: local, Blobs: store,
	})
	if err != nil {
		t.Fatalf("offline open: %v", err)
	}
	content, err := input.Content(context.Background(), "linux/amd64")
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	tree, err := input.Assemble(context.Background(), content, "linux/amd64")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, ok := tree.Lookup("/usr/bin/openssl"); !ok {
		t.Fatal("openssl binary missing from the image")
	}
	release, err := tree.Read("/usr/lib/os-release")
	if err != nil {
		t.Fatalf("os-release: %v", err)
	}
	for _, want := range []string{`ID="debian"`, `VERSION_CODENAME="trixie"`, `VERSION_ID="13"`} {
		if !bytes.Contains(release, []byte(want)) {
			t.Fatalf("os-release %q does not contain %q", release, want)
		}
	}
}

func packageNames(packages []lock.Package) []string {
	names := make([]string, 0, len(packages))
	for i := range packages {
		names = append(names, packages[i].Name)
	}
	slices.Sort(names)
	return names
}

// A Debian lock is the whole build input, so two builds of one lock have to produce the
// same OCI index. The runs differ in their working directory and worker count, which is
// what a rebuild in another checkout meets.
func TestDebianBuildDigestRepeatsAcrossRuns(t *testing.T) {
	fixture := newDebianFixture(t, debianDeadline)
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	first := fixture.indexDigest(t, locked, 1)
	copied := copyDebianFixture(t, fixture)
	second := copied.indexDigest(t, locked, 3)
	if first != second {
		t.Fatalf("index digest changed between builds of one lock: %s then %s", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("index digest %q is not a sha256 digest", first)
	}
}

// indexDigest builds every declared platform from the lock and hashes the index the
// export would write.
func (f *debianFixture) indexDigest(t *testing.T, locked *lock.Lockfile, jobs int) string {
	t.Helper()
	input := f.build(t, locked)
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, jobs,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	layout, err := builder.Layout(images, []string{"v1"})
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	return layout.Index.Digest
}

// copyDebianFixture moves the specification, its local inputs and the verified cache to
// a second directory. The lock is not copied: its recorded paths are relative to the
// specification, so the same lock drives both builds.
func copyDebianFixture(t *testing.T, fixture *debianFixture) *debianFixture {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"catalogue", "certs", "cache"} {
		copyTree(t, filepath.Join(fixture.dir, name), filepath.Join(dir, name))
	}
	specPath := filepath.Join(dir, "image.yaml")
	copyFile(t, fixture.specPath, specPath)
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cache.New(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	return &debianFixture{archive: fixture.archive, dir: dir, specPath: specPath,
		spec: loaded, store: store, provider: fixture.provider}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		copyFile(t, path, target)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeVendorFixture builds a vendor repository beside the reviewed Debian archives:
// it signs its own release identity and carries one extra package.
func writeVendorFixture(t *testing.T, securityValidity string) (*debianFixture, *debianArchive) {
	t.Helper()
	fixture := newDebianFixture(t, securityValidity)
	fixture.archive.addSuite(t, "vendor", fixture.archive.trusted, fixture.archive.trusted,
		debianSuiteDecl{suite: "stable", codename: "vendor", signedSuite: "vendor", packages: []debianPackage{
			{name: "nginx", filename: "pool/nginx.deb", files: map[string]string{
				"usr/sbin/nginx": "nginx\n"}},
			// The vendor also publishes a base package, newer than the reviewed one, so
			// only the declared scope keeps it out of the image.
			{name: "apt", filename: "pool/vendor-apt.deb", files: map[string]string{
				"usr/bin/apt": "vendor apt\n"}, version: "2.0"},
		}})
	key, err := os.ReadFile(filepath.Join(fixture.archive.dir, "keys", "test.asc"))
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(fixture.dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "vendor.asc"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	return fixture, fixture.archive
}

// vendorText is the specification of a vendor-scoped repository: its own identity and
// the names it may supply.
func vendorText(fixture *debianFixture, base, url, packages string) string {
	return fmt.Sprintf(`version: 1
name: vendor
image: example.invalid/vendor
distro: debian
release: "13"
platforms: [linux/amd64]
contents:
  packages:
    - name: apt
    - name: nginx
  repositories:
    - name: debian
      suites: [trixie]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: %s
    - name: vendor
      suites: [stable]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: %s
      identity: own
      packages:
%s
      trust:
        keys:
          - path: keys/vendor.asc
            fingerprints: ["%X"]
filesystem:
  ca:
    mode: append
    sources: [certs/ca.pem]
`, base, url, packages, fixture.archive.trusted.PrimaryKey.Fingerprint)
}

// A vendor repository names a suite and codename the base release never serves. It
// locks because its own keys authenticate that identity, and its packages may only
// come from the archive the specification named.
func TestDebianVendorRepositoryLocksItsOwnSuite(t *testing.T) {
	t.Parallel()
	fixture, archive := writeVendorFixture(t, debianDeadline)
	specPath := filepath.Join(fixture.dir, "vendor.yaml")
	text := vendorText(fixture, archive.main, archive.server.URL+"/vendor", "      - nginx\n")
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	fixture.spec = loaded
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var vendor *lock.Repository
	for i := range locked.Repositories {
		if locked.Repositories[i].Name == "vendor" {
			vendor = &locked.Repositories[i]
		}
	}
	if vendor == nil {
		t.Fatalf("repositories = %#v, want the vendor archive", locked.Repositories)
	}
	if vendor.Suite != "stable" || vendor.URL != archive.server.URL+"/vendor" {
		t.Fatalf("vendor = suite %q url %q", vendor.Suite, vendor.URL)
	}
	if names := packageNames(locked.Packages); !slices.Contains(names, "nginx") {
		t.Fatalf("packages = %v, want nginx", names)
	}
	if _, err := builder.Open(context.Background(), &builder.Inputs{
		Spec: loaded, Lockfile: locked, Provider: fixture.provider, Blobs: fixture.store,
	}); err != nil {
		t.Fatalf("offline open: %v", err)
	}
}

// The scope list, not the archive, decides which names a vendor repository may
// supply: an archive that also publishes a base package cannot replace it.
func TestDebianVendorRepositoryScopeExcludesUnlistedNames(t *testing.T) {
	t.Parallel()
	fixture, archive := writeVendorFixture(t, debianDeadline)
	specPath := filepath.Join(fixture.dir, "vendor.yaml")
	text := vendorText(fixture, archive.main, archive.server.URL+"/vendor", "      - nginx\n")
	if err := os.WriteFile(specPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(specPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	fixture.spec = loaded
	locked, err := fixture.collect(t)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// The lock records a repository by ID, so the origin has to be resolved before it
	// can be named: comparing the ID with a repository name never matches.
	vendorID := ""
	for i := range locked.Repositories {
		if locked.Repositories[i].Name == "vendor" {
			vendorID = locked.Repositories[i].ID
		}
	}
	if vendorID == "" {
		t.Fatalf("repositories = %#v, want the vendor archive", locked.Repositories)
	}
	for i := range locked.Packages {
		if locked.Packages[i].Name != "apt" {
			continue
		}
		// The vendor publishes apt 2.0, newer than the reviewed 1.0, so only the
		// scope keeps it out of the image.
		if locked.Packages[i].Version != "1.0" || locked.Packages[i].Repository == vendorID {
			t.Fatalf("apt came from the vendor archive: %#v", locked.Packages[i])
		}
	}
}
