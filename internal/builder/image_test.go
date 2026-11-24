package builder_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

func TestBuild_OneImageAndIndex(t *testing.T) {
	inputs, store := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("BuildEach: %v", err)
	}
	index, err := builder.BuildIndex(images)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("images = %d", len(images))
	}
	if images[0].Platform.String() != "linux/amd64" {
		t.Fatalf("platform = %s", images[0].Platform)
	}
	if images[0].Layer.Digest == "" || images[0].Image.ManifestDigest == "" || index.Digest == "" {
		t.Fatalf("identities = %+v / %+v / %+v", images[0].Layer, images[0].Image, index)
	}
	// The published layer is readable from the same store the build read from.
	if _, err := store.Open(strings.TrimPrefix(images[0].Layer.Digest, "sha256:"),
		images[0].Layer.Size); err != nil {
		t.Fatalf("layer was not published: %v", err)
	}
}

func TestBuild_PreservesSliceParentInLayer(t *testing.T) {
	t.Parallel()
	inputs, store := contentFixture(t)
	catalogue, manifest := catalogueWithSlices(t, store, `package: base-files
archive: ubuntu
slices:
  release-info:
    contents:
      /private/token:
`)
	inputs.Lockfile.Catalogues = []lock.Catalogue{*catalogue}
	record := &inputs.Lockfile.Slices[0]
	record.DefinitionDigest = definitionDigest(t, manifest, "release-info")
	payload := debBytes(t, record.Package, record.Version, debArchitecture(record.Architecture),
		tarMember{name: "./private/", typeflag: tar.TypeDir, mode: 0o700, uid: 7, gid: 8},
		tarMember{name: "./private/token", mode: 0o644, body: []byte("private")})
	record.Content.SHA256, record.Content.Size = storeFile(t, store, payload)
	input, err := builder.Open(t.Context(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	image, err := input.BuildPlatform(t.Context(), oci.Platform{OS: "linux", Architecture: "amd64"}, oci.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if parent, ok := image.Tree.Lookup("/private"); !ok || !parent.Implicit {
		t.Fatalf("parent must remain implicit: %+v", parent)
	}
	blob, err := store.Open(strings.TrimPrefix(image.Layer.Digest, "sha256:"), image.Layer.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blob.Close() }()
	compressed, err := gzip.NewReader(blob)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = compressed.Close() }()
	assertLayerParent(t, tar.NewReader(compressed))
}

func assertLayerParent(t *testing.T, layer *tar.Reader) {
	t.Helper()
	for {
		header, err := layer.Next()
		if err != nil {
			t.Fatalf("layer has no private/ entry: %v", err)
		}
		if header.Name != "private/" {
			continue
		}
		if header.Typeflag != tar.TypeDir || header.Mode != 0o700 || header.Uid != 7 || header.Gid != 8 {
			t.Fatalf("parent header = %+v, want mode 0700 and owner 7:8", header)
		}
		return
	}
}

func TestBuild_IsByteStable(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	first, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	firstIndex, err := builder.BuildIndex(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	secondIndex, err := builder.BuildIndex(second)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Layer.Digest != second[0].Layer.Digest ||
		first[0].Image.ManifestDigest != second[0].Image.ManifestDigest ||
		firstIndex.Digest != secondIndex.Digest {
		t.Fatal("a repeated build produced different identities")
	}
}

func TestBuild_AppliesDeclaredPaths(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := images[0].Tree.Lookup("/etc/vapor")
	if !ok || entry.Kind != vfs.Dir || entry.Mode.Perm() != 0o750 {
		t.Fatalf("declared entry = %+v, ok=%v", entry, ok)
	}
	if len(entry.Origins) == 0 || entry.Origins[len(entry.Origins)-1].Path != "filesystem.paths" {
		t.Fatalf("declared entry origins = %+v", entry.Origins)
	}
}

func TestBuild_SynthesizesReleaseState(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// The selected slice already ships /etc/os-release, so synthesis updates that file
	// rather than adding the standard location beside it.
	content, err := images[0].Tree.Read("/etc/os-release")
	if err != nil || !strings.Contains(string(content), `ID="ubuntu"`) {
		t.Fatalf("release content = %q, err=%v", content, err)
	}
}

// reseal re-digests a spec a test changed, so the lock still describes it.
// keepSources opts an image into the runtime package sources.
func keepSources(t *testing.T, inputs *builder.Inputs) {
	t.Helper()
	inputs.Spec.Hardening.KeepPackageSources = new(true)
}

func reseal(t *testing.T, inputs *builder.Inputs) {
	t.Helper()
	digest, err := inputs.Spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	inputs.Lockfile.SpecDigest = digest
}

func TestBuild_AppliesDeclaredSymlink(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Filesystem.Paths = append(inputs.Spec.Filesystem.Paths, filesystem.Path{
		Path: "/usr/bin/tool", Type: "symlink", Mode: new("0777"), Target: new("/usr/bin/openssl"),
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := images[0].Tree.Lookup("/usr/bin/tool")
	if !ok || entry.Kind != vfs.Symlink || entry.Target != "/usr/bin/openssl" {
		t.Fatalf("declared symlink = %+v, ok=%v", entry, ok)
	}
}

func TestBuild_RefusesConflictingDeclaredPath(t *testing.T) {
	inputs, _ := contentFixture(t)
	// The selected slice ships /etc/os-release as a file, so declaring it as a
	// directory must fail instead of replacing the package's content.
	inputs.Spec.Filesystem.Paths = append(inputs.Spec.Filesystem.Paths, filesystem.Path{
		Path: "/etc/os-release", Type: "directory", Mode: new("0755"),
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err == nil {
		t.Fatal("accepted a declaration that contradicts package content")
	}
}

func TestBuild_RunsSliceMutation(t *testing.T) {
	inputs, _ := contentFixture(t)
	catalogue := "custom"
	inputs.Spec.Contents.Slices = append(inputs.Spec.Contents.Slices, contents.SliceRequest{
		Package: "base-files", Slice: "state", Catalogue: &catalogue,
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
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	content, err := images[0].Tree.Read("/etc/vapor-state")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "ready" {
		t.Fatalf("mutation output = %q", content)
	}
}

// A builder image installs packages at runtime, and the source list it needs is the
// one the lock was acquired against rather than something declared by hand.
func TestBuild_WritesLockedPackageSources(t *testing.T) {
	inputs, _ := contentFixture(t)
	keepSources(t, inputs)
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := images[0].Tree.Lookup(synthesis.APTSourcesPath)
	if !ok || entry.Kind != vfs.File {
		t.Fatalf("package sources = %+v, ok=%v", entry, ok)
	}
	raw, err := images[0].Tree.Read(synthesis.APTSourcesPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "Types: deb\nURIs: https://example.invalid/ubuntu\nSuites: resolute\nComponents: main\nSigned-By: "
	keyring, ok := strings.CutPrefix(string(raw), want)
	keyring = strings.TrimSuffix(keyring, "\n")
	if !ok || !strings.HasPrefix(keyring, "/etc/apt/keyrings/vapor-") {
		t.Fatalf("package sources are %q", raw)
	}
	body, err := images[0].Tree.Read(keyring)
	if err != nil {
		t.Fatal(err)
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(body))
	if err != nil || len(entities) != 1 {
		t.Fatalf("keyring must contain exactly one public key: %v", err)
	}
	if _, err := deb.LoadTrustedKeys(body, []string{testFingerprint}); err != nil {
		t.Fatalf("keyring does not contain the locked public fingerprint: %v", err)
	}
}

// An image that installs nothing at runtime has no use for a source list, so it is
// not written unless the specification asks for it.
func TestBuild_WritesNoPackageSourcesByDefault(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if entry, ok := images[0].Tree.Lookup(synthesis.APTSourcesPath); ok {
		t.Fatalf("runtime image gained package sources: %+v", entry)
	}
}

func TestBuild_RejectsMissingPackageSourceKey(t *testing.T) {
	inputs, _ := contentFixture(t)
	keepSources(t, inputs)
	reseal(t, inputs)
	inputs.Lockfile.LocalInputs[0].SHA256 = testHash
	inputs.Lockfile.Repositories[0].Trust.Keys[0].SHA256 = testHash
	input, err := builder.Open(t.Context(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(t.Context(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "open key evidence failed") {
		t.Fatalf("build with missing key: %v", err)
	}
}

// A package manager needs the dpkg status database: without it `dpkg-query` and
// `apt-extracttemplates` fail, and installing a package inside the image breaks.
func TestBuild_WritesThePackageDatabase(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := images[0].Tree.Read(synthesis.StatusPath)
	if err != nil {
		t.Fatalf("reading the status database: %v", err)
	}
	status := string(raw)
	for _, want := range []string{"Package: base-files\n", "Status: install ok unpacked\n",
		"Package: openssl\n", "Status: install ok installed\n"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status database is missing %q:\n%s", want, status)
		}
	}
}

// dpkg warns about every package whose file list is missing, so each record needs
// the list of what it contributed. The list is written after hardening, so it names
// only paths the image still has.
func TestBuild_WritesPackageFileLists(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Hardening.StripDocs = new(false)
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for name, want := range map[string]string{
		"openssl.list":    "/usr/bin/openssl\n/usr/share/doc/openssl/README\n",
		"base-files.list": "/etc/os-release\n",
	} {
		raw, err := images[0].Tree.Read(synthesis.InfoDir + "/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if string(raw) != want {
			t.Fatalf("%s = %q, want %q", name, raw, want)
		}
	}
}

// Hardening removes a package's documentation, so the list that survives it must
// not name those paths any more: dpkg --verify would report every one as missing.
func TestBuild_FileListsFollowHardening(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := images[0].Tree.Read(synthesis.InfoDir + "/openssl.list")
	if err != nil {
		t.Fatalf("reading openssl.list: %v", err)
	}
	if string(raw) != "/usr/bin/openssl\n" {
		t.Fatalf("openssl.list = %q, want only the file hardening kept", raw)
	}
}

// apt drops to an unprivileged user while it downloads, which its maintainer script
// would have created. A build that never runs scripts has to supply the account, or
// every `apt-get install` in the image warns and fetches as root.
func TestBuild_GivesAPTFetcherTheSandboxAccount(t *testing.T) {
	inputs, store := contentFixture(t)
	inputs.Spec.Contents.Packages = append(inputs.Spec.Contents.Packages, contents.PackageRequest{Name: "apt"})
	payload := debBytes(t, "apt", "2.8.3",
		tarMember{name: "./usr/bin/apt-get", body: []byte("binary"), mode: 0o755},
		tarMember{name: "./usr/bin/apt", body: []byte("binary"), mode: 0o755})
	digest, size := storeFile(t, store, payload)
	inputs.Lockfile.Packages = append(inputs.Lockfile.Packages, lock.Package{
		Platform: "linux/amd64", Name: "apt", Version: "2.8.3", Architecture: "amd64",
		Repository: testRepositoryID(),
		Content:    lock.Content{Path: "pool/apt.deb", SHA256: digest, Size: size},
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	passwd, err := images[0].Tree.Read(synthesis.PasswdPath)
	if err != nil {
		t.Fatalf("reading passwd: %v", err)
	}
	if !strings.Contains(string(passwd), "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n") {
		t.Fatalf("passwd does not hold the sandbox account:\n%s", passwd)
	}
}

// base-passwd fills the account databases in a maintainer script, so a build that never
// runs one has to copy the masters in: without them apt cannot chown its download
// directories to `root` and falls back to fetching as root.
func TestBuild_CopiesTheBaseAccountMasters(t *testing.T) {
	inputs, store := contentFixture(t)
	inputs.Spec.Contents.Packages = append(inputs.Spec.Contents.Packages, contents.PackageRequest{Name: "base-passwd"})
	payload := debBytes(t, "base-passwd", "3.6.7",
		tarMember{name: "./usr/share/base-passwd/passwd.master",
			body: []byte("root:*:0:0:root:/root:/bin/bash\n"), mode: 0o644},
		tarMember{name: "./usr/share/base-passwd/group.master",
			body: []byte("root:*:0:\n"), mode: 0o644})
	digest, size := storeFile(t, store, payload)
	inputs.Lockfile.Packages = append(inputs.Lockfile.Packages, lock.Package{
		Platform: "linux/amd64", Name: "base-passwd", Version: "3.6.7", Architecture: "amd64",
		Repository: testRepositoryID(),
		Content:    lock.Content{Path: "pool/base-passwd.deb", SHA256: digest, Size: size},
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	passwd, err := images[0].Tree.Read(synthesis.PasswdPath)
	if err != nil {
		t.Fatalf("reading passwd: %v", err)
	}
	if string(passwd) != "root:*:0:0:root:/root:/bin/bash\n" {
		t.Fatalf("passwd = %q", passwd)
	}
	group, err := images[0].Tree.Read(synthesis.GroupPath)
	if err != nil {
		t.Fatalf("reading group: %v", err)
	}
	if string(group) != "root:*:0:\n" {
		t.Fatalf("group = %q", group)
	}
}

// An image that carries no fetcher gains nothing from the account, so hardening of a
// metadata-only image stays as small as it was.
func TestBuild_SkipsTheSandboxAccountWithoutAPTFetcher(t *testing.T) {
	inputs, _ := contentFixture(t)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := images[0].Tree.Lookup(synthesis.PasswdPath); ok {
		t.Fatal("an image without a fetcher gained an account database")
	}
}

// A declaration can point through a package's regular file, which no import saw
// because the two were separate trees until assembly.
func TestBuild_RejectsALinkThatCrossesAFile(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Filesystem.Paths = append(inputs.Spec.Filesystem.Paths, filesystem.Path{
		Path: "/sbin/inside", Type: "symlink", Mode: new("0777"),
		Target: new("/usr/bin/openssl/inside"),
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "symlinks: ") || !strings.Contains(err.Error(), "non-directory") {
		t.Fatalf("build error = %v, want the crossed link refused by the link check", err)
	}
}

// A reader treats a ".wh." name as a deletion marker, so serialization refuses it.
// The error has to reach the build rather than produce a layer that deletes content.
func TestBuild_RejectsAWhiteoutName(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Filesystem.Paths = append(inputs.Spec.Filesystem.Paths, filesystem.Path{
		Path: "/usr/bin/.wh.openssl", Type: "file", Mode: new("0644"),
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "whiteout") {
		t.Fatalf("build error = %v, want the whiteout refused", err)
	}
}

// Declared annotations belong on the manifest; they are the only metadata a reader
// sees without pulling the image.
func TestBuild_WritesDeclaredAnnotations(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Annotations = map[string]string{
		"org.opencontainers.image.description": "minimal demo",
		"com.example.build":                    "",
	}
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(images[0].Image.Manifest))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	want := inputs.Spec.Annotations
	if len(manifest.Annotations) != len(want) {
		t.Fatalf("annotations = %v, want %v", manifest.Annotations, want)
	}
	for key, value := range want {
		if manifest.Annotations[key] != value {
			t.Fatalf("annotation %q = %q, want %q", key, manifest.Annotations[key], value)
		}
	}
}

// The reserved tag key is refused where the manifest is built, so a specification
// that declares it fails the build instead of producing a manifest.
func TestBuild_RefusesTheReservedTagAnnotation(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Annotations = map[string]string{oci.RefNameAnnotation: "v1"}
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "the tag list sets it") {
		t.Fatalf("build error = %v, want the reserved annotation refused", err)
	}
}

// A slice script can assert without declaring a mutable or temporary path. Skipping
// the stage on those paths alone would drop the failure it reports.
func TestBuild_RunsScriptsWithoutMutableOrTemporaryPaths(t *testing.T) {
	inputs := scriptFixture(t, `fail("assertion from the slice")`)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err == nil {
		t.Fatal("a failing slice script did not fail the build")
	} else if !strings.Contains(err.Error(), "assertion from the slice") {
		t.Fatalf("build error = %v", err)
	}
}

// A script with nothing to change still runs, and the tree it saw reaches the image.
func TestBuild_RunsAReadOnlyScript(t *testing.T) {
	inputs := scriptFixture(t, `if content.read("/etc/os-release") == "": fail("empty os-release")`)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil }); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

// scriptFixture gives the locked slice the supplied script, which declares no
// mutable or temporary path, and returns inputs the builder accepts.
func scriptFixture(t *testing.T, script string) *builder.Inputs {
	t.Helper()
	inputs, store := contentFixture(t)
	file := "package: base-files\narchive: ubuntu\nslices:\n  release-info:\n" +
		"    contents:\n      /etc/os-release:\n    mutate: |\n      " + script + "\n"
	catalogue, manifest := catalogueWithSlices(t, store, file)
	inputs.Lockfile.Catalogues = []lock.Catalogue{*catalogue}
	inputs.Lockfile.Slices[0].DefinitionDigest =
		definitionDigest(t, manifest, "release-info")
	reseal(t, inputs)
	return inputs
}

// Hardening can remove the last regular file a package contributed, which here is a
// documentation directory with no copyright notice. The status database then may not
// claim the package, because nothing of it is left in the image, while a database
// written before hardening still did. The two records have to agree with the image.
func TestBuild_StatusDatabaseFollowsHardening(t *testing.T) {
	inputs, store := contentFixture(t)
	// A whole package whose payload is stripped documentation and man pages, with no
	// copyright notice: hardening removes every regular file it contributed.
	payload := debBytes(t, "docsonly", "1.0",
		tarMember{name: "./usr/share/doc/docsonly/README", body: []byte("readme"), mode: 0o644},
		tarMember{name: "./usr/share/man/man1/docsonly.1", body: []byte("manual"), mode: 0o644})
	digest, size := storeFile(t, store, payload)
	inputs.Spec.Contents.Packages = append(inputs.Spec.Contents.Packages, contents.PackageRequest{Name: "docsonly"})
	inputs.Lockfile.Packages = append(inputs.Lockfile.Packages, lock.Package{
		Platform: "linux/amd64", Name: "docsonly", Version: "1.0", Architecture: "amd64",
		Repository: testRepositoryID(),
		Content:    lock.Content{Path: "pool/docsonly.deb", SHA256: digest, Size: size},
	})
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := images[0].Tree.Read(synthesis.StatusPath)
	if err != nil {
		t.Fatalf("reading the status database: %v", err)
	}
	if strings.Contains(string(raw), "Package: docsonly\n") {
		t.Fatalf("hardening left no file, but the database claims the package:\n%s", raw)
	}
	if _, err := images[0].Tree.Read(synthesis.InfoDir + "/docsonly.list"); err == nil {
		t.Fatal("a file list was written for a package hardening emptied")
	}
}
