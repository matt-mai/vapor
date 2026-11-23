package builder_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	gostd "slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/distro/slices"
	schemacontents "github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

// contentSpec declares one whole package and one slice from the fixture catalogue,
// so both kinds of payload reach the same platform tree.
const contentSpec = minimalSpec + `contents:
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
      archives:
        ubuntu: main
  packages:
    - name: openssl
  slices:
    - package: base-files
      slice: release-info
      catalogue: custom
  repositories:
    - name: main
      suites: [resolute]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: https://example.invalid/ubuntu
      trust:
        keys:
          - path: keys/test.asc
            fingerprints: [` + testFingerprint + `]
filesystem:
  paths:
    - path: /etc/vapor
      type: directory
      mode: "0750"
`

const testFingerprint = "F6ECB3762474EDA9D21B7022871920D1991BC93C"

const testHash = "1111111111111111111111111111111111111111111111111111111111111111"

// testRepositoryID is the derived identity of the fixture repository.
func testRepositoryID() string {
	return lock.RepositoryID("main", "linux/amd64", "amd64", "https://example.invalid/ubuntu", "resolute")
}

func contentLock(packageDigest string, packageSize int64, catalogue lock.Catalogue,
	slice lock.Slice, key lock.RepositoryKey) *lock.Lockfile {
	return &lock.Lockfile{
		Version:   1,
		Provider:  lock.Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms: []string{"linux/amd64"},
		LocalInputs: []lock.LocalInput{{
			Role: "trust-key", Path: key.Path, SHA256: key.SHA256, Size: key.Size,
		}},
		Catalogues: []lock.Catalogue{catalogue},
		Repositories: []lock.Repository{{
			ID:   testRepositoryID(),
			Name: "main", Platform: "linux/amd64", Architecture: "amd64",
			URL: "https://example.invalid/ubuntu", Suite: "resolute",
			Trust: lock.RepositoryTrust{Keys: []lock.RepositoryKey{key}},
			Release: lock.RepositoryRelease{
				Format: "inrelease", Path: "dists/resolute/InRelease",
				SHA256: testHash, Size: 4096, Signers: []string{testFingerprint},
			},
			Indexes: []lock.Index{{
				Component: "main", Path: "main/binary-amd64/Packages", SHA256: testHash, Size: 512,
			}},
		}},
		Packages: []lock.Package{{
			Platform: "linux/amd64", Name: "openssl", Version: "3.0-1", Architecture: "amd64",
			Repository: testRepositoryID(),
			Content:    lock.Content{Path: "pool/openssl.deb", SHA256: packageDigest, Size: packageSize},
		}},
		Slices: []lock.Slice{slice},
	}
}

// contentFixture publishes one whole package and one slice payload, then builds the
// lock slice record from the catalogue definition the builder will re-read.
func contentFixture(t *testing.T) (*builder.Inputs, *cache.Cache) {
	t.Helper()
	inputs, store := fixture(t)
	inputs.Spec = loadSpec(t, contentSpec)
	digest, err := inputs.Spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	whole := debBytes(t, "openssl", "3.0-1",
		tarMember{name: "./usr/bin/openssl", body: []byte("binary"), mode: 0o755},
		tarMember{name: "./usr/share/doc/openssl/README", body: []byte("docs"), mode: 0o644})
	wholeDigest, wholeSize := storeFile(t, store, whole)
	payload := debBytes(t, "base-files", "26.04",
		tarMember{name: "./etc/os-release", body: []byte("PRETTY_NAME=\"Ubuntu\"\n"), mode: 0o644},
		debArchitecture("all"))
	payloadDigest, payloadSize := storeFile(t, store, payload)
	catalogue, manifest := fixtureCatalogue(t, store)
	definition := definitionDigest(t, manifest, "release-info")
	keyDigest, keySize := storeFile(t, store, inputs.Provider.DefaultTrust()[0].Data)
	key := lock.RepositoryKey{Fingerprint: testFingerprint, Path: "keys/test.asc", SHA256: keyDigest, Size: keySize}
	lockfile := contentLock(wholeDigest, wholeSize, *catalogue, lock.Slice{
		Platform: "linux/amd64", Package: "base-files", Version: "26.04", Architecture: "all",
		Catalogue: "custom", Archive: "ubuntu", Repository: testRepositoryID(),
		Content:          lock.Content{Path: "pool/base-files.deb", SHA256: payloadDigest, Size: payloadSize},
		Selected:         []string{"release-info"},
		Closure:          []string{"release-info"},
		DefinitionDigest: definition,
	}, key)
	lockfile.SpecDigest = digest
	inputs.Lockfile = lockfile
	return inputs, store
}

// definitionDigest recomputes the catalogue definition identity the lock records.
// Every fixture uses the one slice file, so the path is not a parameter.
func definitionDigest(t *testing.T, manifest []lock.CatalogueEntry, names ...string) string {
	t.Helper()
	const path = "slices/base-files.yaml"
	for _, entry := range manifest {
		if entry.Path != path {
			continue
		}
		digest, err := slices.DefinitionDigest(path, entry.SHA256, entry.Size, names)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	t.Fatalf("%s is not in the fixture manifest", path)
	return ""
}

// tarMember is one entry a test writes into a fixture archive.
type tarMember struct {
	name     string
	body     []byte
	mode     int64
	uid, gid int
	typeflag byte
}

func tarBytes(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := tar.NewWriter(buffer)
	for _, member := range members {
		header := &tar.Header{Name: member.name, Mode: member.mode, Size: int64(len(member.body)),
			Uid: member.uid, Gid: member.gid, Typeflag: member.typeflag}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(member.body); err != nil {
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

// debArchitecture overrides the architecture a synthesized DEB control stanza
// declares, so a package locked as "all" is described honestly.
func debArchitecture(architecture string) tarMember {
	return tarMember{name: "\x00architecture", body: []byte(architecture)}
}

// debBytes assembles a DEB whose control member names the package and version. A
// debArchitecture member, which is never a real archive member, replaces the
// default architecture.
func debBytes(t *testing.T, name, version string, members ...tarMember) []byte {
	t.Helper()
	architecture := "amd64"
	data := make([]tarMember, 0, len(members))
	for _, member := range members {
		if member.name == "\x00architecture" {
			architecture = string(member.body)
			continue
		}
		data = append(data, member)
	}
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n", name, version, architecture)
	return debWithControl(t, control, data)
}

// debWithControl builds a DEB around a caller-supplied control stanza.
func debWithControl(t *testing.T, control string, members []tarMember) []byte {
	t.Helper()
	return debArchive(t, []tarMember{{name: "control", body: []byte(control), mode: 0o644}}, members...)
}

// debArchive builds a DEB from explicit control members and data members, so a test
// can leave the control stanza out altogether.
func debArchive(t *testing.T, control []tarMember, data ...tarMember) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	buffer.WriteString("!<arch>\n")
	for _, member := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", gzipBytes(t, tarBytes(t, control...))},
		{"data.tar.gz", gzipBytes(t, tarBytes(t, data...))},
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

func TestContent_WholeAndSlicedContent(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	content, err := input.Content(context.Background(), "linux/amd64")
	if err != nil {
		t.Fatalf("Content: %v", err)
	}
	entry, ok := content.Tree.Lookup("/usr/bin/openssl")
	if !ok || entry.Kind != vfs.File || entry.Mode.Perm() != 0o755 {
		t.Fatalf("whole package entry = %+v, ok=%v", entry, ok)
	}
	released, ok := content.Tree.Lookup("/etc/os-release")
	if !ok || released.Origins == nil {
		t.Fatalf("slice entry = %+v, ok=%v", released, ok)
	}
	// Both selections describe themselves: the whole package is installed, the
	// sliced one is only unpacked.
	statuses := map[string]synthesis.PackageStatus{}
	for _, pkg := range content.Packages {
		if len(pkg.Control) == 0 {
			t.Fatalf("package %q kept no control stanza", pkg.Name)
		}
		statuses[pkg.Name] = pkg.Status
	}
	want := map[string]synthesis.PackageStatus{
		"openssl":    synthesis.StatusInstalled,
		"base-files": synthesis.StatusUnpacked,
	}
	if len(statuses) != len(want) {
		t.Fatalf("packages = %+v", content.Packages)
	}
	for name, status := range want {
		if statuses[name] != status {
			t.Fatalf("package %q status = %q, want %q", name, statuses[name], status)
		}
	}
}

func TestContent_RefusesUndeclaredPlatform(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Content(context.Background(), "linux/arm64"); err == nil {
		t.Fatal("accepted a platform the spec does not declare")
	}
}

func TestContent_RefusesChangedDefinition(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Lockfile.Slices[0].DefinitionDigest = "sha256:" + strings.Repeat("0", 64)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = input.Content(context.Background(), "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "locked digest") {
		t.Fatalf("accepted a changed catalogue definition: %v", err)
	}
}

func TestContent_RefusesMissingPayload(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Lockfile.Packages[0].Content.SHA256 = strings.Repeat("2", 64)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Content(context.Background(), "linux/amd64"); err == nil {
		t.Fatal("accepted a package whose payload is not cached")
	}
}

// A sliced package's record is derived from the same control stanza a whole package
// uses, and two slices of one package share one record: dpkg knows the package, not
// the slice.
func TestContent_RecordsOneStatePerDistinctSlicePackage(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Contents.Slices = append(inputs.Spec.Contents.Slices, schemacontents.SliceRequest{
		Package: "base-files", Slice: "state", Catalogue: new("custom"),
	})
	inputs.Lockfile.Slices[0].Selected = []string{"release-info", "state"}
	inputs.Lockfile.Slices[0].Closure = []string{"release-info", "state"}
	inputs.Lockfile.Slices[0].DefinitionDigest = definitionDigest(t,
		inputs.Lockfile.Catalogues[0].Manifest, "release-info", "state")
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	content, err := input.Content(context.Background(), "linux/amd64")
	if err != nil {
		t.Fatalf("Content: %v", err)
	}
	names := make([]string, 0, len(content.Packages))
	for _, pkg := range content.Packages {
		names = append(names, pkg.Name)
		if pkg.Status != synthesis.StatusInstalled && pkg.Status != synthesis.StatusUnpacked {
			t.Fatalf("%s status = %q", pkg.Name, pkg.Status)
		}
		if len(pkg.Control) == 0 {
			t.Fatalf("%s was recorded without a control stanza", pkg.Name)
		}
	}
	gostd.Sort(names)
	if want := []string{"base-files", "openssl"}; !gostd.Equal(names, want) {
		t.Fatalf("recorded packages = %v, want %v (one record per package, not per slice)",
			names, want)
	}
}

// A payload without a control stanza cannot describe itself, so the stage that
// produced it fails instead of recording a nameless package.
func TestContent_RefusesAPayloadWithoutControl(t *testing.T) {
	inputs, store := contentFixture(t)
	whole := debArchive(t, []tarMember{{name: "md5sums", body: []byte("\n"), mode: 0o644}},
		tarMember{name: "./usr/bin/openssl", body: []byte("binary"), mode: 0o755})
	digest, size := storeFile(t, store, whole)
	inputs.Lockfile.Packages[0].Content = lock.Content{Path: "pool/openssl.deb", SHA256: digest, Size: size}
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Content(context.Background(), "linux/amd64"); err == nil ||
		!strings.Contains(err.Error(), "has no control stanza") {
		t.Fatalf("Content error = %v, want the missing stanza refused", err)
	}
}

// A package definition that pins its archive is a statement about where the package
// may come from. Replay checks the lock against the catalogue's archive bindings, but
// only the pin says which archive the catalogue itself chose, so the content stage
// compares the two before extracting anything. The lock here is entirely valid: its
// archive is bound and its repository evidence is what it recorded.
func TestContent_RefusesAnArchiveTheCatalogueDoesNotPin(t *testing.T) {
	inputs, store := contentFixture(t)
	root := strings.Replace(chiselYAML(newRootKey(t)), "public-keys:\n", `  esm-apps:
    version: "26.04"
    suites: [resolute-apps]
    components: [main]
    priority: 20
    pro: esm-apps
    public-keys: [test]
public-keys:
`, 1)
	catalogue, manifest := catalogueWithRoot(t, store, root,
		strings.Replace(sliceYAML, "archive: ubuntu", "archive: esm-apps", 1))
	inputs.Lockfile.Catalogues = []lock.Catalogue{*catalogue}
	inputs.Lockfile.Slices[0].DefinitionDigest = definitionDigest(t, manifest, "release-info")
	reseal(t, inputs)
	// The lock stays acceptable: its archive is bound, and its repository evidence is
	// what the lock recorded. Only the pin disagrees.
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = input.Content(context.Background(), "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "is not the archive the catalogue pins") {
		t.Fatalf("Content error = %v, want the pinned archive enforced", err)
	}
}

// A package artifact places its payload and records itself exactly like a fetched
// package, because both describe themselves with the same control stanza.
func TestContent_InstallsAPackageArtifact(t *testing.T) {
	inputs := packageArtifactFixture(t, debBytes(t, "myapp", "1.0",
		tarMember{name: "./usr/bin/myapp", body: []byte("tool"), mode: 0o755}))
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	content, err := input.Content(context.Background(), "linux/amd64")
	if err != nil {
		t.Fatalf("Content: %v", err)
	}
	entry, ok := content.Tree.Lookup("/usr/bin/myapp")
	if !ok || entry.Kind != vfs.File || entry.Mode.Perm() != 0o755 {
		t.Fatalf("package artifact entry = %+v, ok=%v", entry, ok)
	}
	var installed *synthesis.PackageState
	for i := range content.Packages {
		if content.Packages[i].Name == "myapp" {
			installed = &content.Packages[i]
		}
	}
	if installed == nil {
		t.Fatalf("package artifact was not recorded: %+v", content.Packages)
	}
	if installed.Version != "1.0" || installed.Architecture != "amd64" ||
		installed.Status != synthesis.StatusInstalled || len(installed.Control) == 0 {
		t.Fatalf("package artifact state = %+v", installed)
	}
}

// A package artifact is published under the name it was declared with, even when the
// package inside it calls itself something else: the SPDX document reads the
// contributor of each path back from that declaration, so a document built from the
// control stanza alone would name a contributor that is not in the lock.
func TestContent_AttributesAPackageArtifactToItsDeclaration(t *testing.T) {
	declared := strings.Replace(contentSpec, "\nfilesystem:", `
  artifacts:
    - name: myapp
      unpack: package
      sbom:
        name: myapp-binary
        version: "1.0"
      sources:
        - platforms: [linux/amd64]
          path: files/myapp.deb
          sha256: DIGEST

filesystem:`, 1)
	inputs := packageArtifactFixtureNamed(t, declared, "myapp",
		schemacontents.ArtifactIdentity{Name: "myapp-binary", Version: "1.0"},
		debBytes(t, "myapp-binary", "1.0",
			tarMember{name: "./usr/bin/myapp", body: []byte("tool"), mode: 0o755}))
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	content, err := input.Content(context.Background(), "linux/amd64")
	if err != nil {
		t.Fatalf("Content: %v", err)
	}
	entry, ok := content.Tree.Lookup("/usr/bin/myapp")
	if !ok || entry.Origins[0].Package != "myapp" {
		t.Fatalf("package artifact origin = %+v, ok=%v, want the declared name", entry, ok)
	}
	// The package record keeps the identity the payload states, so the dpkg database
	// and the package element still describe the package that was installed.
	if !gostd.ContainsFunc(content.Packages, func(state synthesis.PackageState) bool {
		return state.Name == "myapp-binary" && state.Status == synthesis.StatusInstalled
	}) {
		t.Fatalf("packages = %+v", content.Packages)
	}
}

// A package artifact must describe the package it claims, so a lock whose identity
// disagrees with the payload fails rather than recording the wrong version.
func TestContent_RefusesAPackageArtifactWithoutControl(t *testing.T) {
	inputs := packageArtifactFixture(t, debArchive(t,
		[]tarMember{{name: "md5sums", body: []byte("\n"), mode: 0o644}},
		tarMember{name: "./usr/bin/myapp", body: []byte("tool"), mode: 0o755}))
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = input.Content(context.Background(), "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "has no control stanza") {
		t.Fatalf("Content error = %v, want the missing stanza refused", err)
	}
}

// packageArtifactFixture declares one package artifact beside the fixture package
// and slice, so the lock can record the artifact and the builder can install it.
func packageArtifactFixture(t *testing.T, payload []byte) *builder.Inputs {
	t.Helper()
	template := strings.Replace(contentSpec, "\nfilesystem:", fmt.Sprintf(`
  artifacts:
    - name: myapp
      unpack: package
      sbom:
        name: myapp
        version: "1.0"
      sources:
        - platforms: [linux/amd64]
          path: files/myapp.deb
          sha256: %s

filesystem:`, "DIGEST"), 1)
	return packageArtifactFixtureNamed(t, template, "myapp",
		schemacontents.ArtifactIdentity{Name: "myapp", Version: "1.0"}, payload)
}

// packageArtifactFixtureNamed pins payload to files/myapp.deb and locks declared, which
// names the digest as DIGEST so the fixture can fill it in after storing the payload.
// The declaration and the identity it states are parameters because a package artifact
// may declare one name while the package inside it calls itself another.
func packageArtifactFixtureNamed(t *testing.T, declared, name string, identity schemacontents.ArtifactIdentity,
	payload []byte) *builder.Inputs {
	t.Helper()
	inputs, store := contentFixture(t)
	digest, size := storeFile(t, store, payload)
	inputs.Spec = loadSpec(t, strings.Replace(declared, "DIGEST", digest, 1))
	specDigest, err := inputs.Spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	unpack := schemacontents.ArtifactUnpackPackage
	inputs.Lockfile.SpecDigest = specDigest
	inputs.Lockfile.Artifacts = []lock.Artifact{{
		Name: name, Platform: "linux/amd64", Path: "files/myapp.deb",
		SHA256: digest, Size: size, Unpack: &unpack, SBOM: identity,
	}}
	return inputs
}
