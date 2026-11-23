package attest_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// provenanceDocument decodes the SLSA predicate so a test can assert on it. The in-toto
// wrapper around it is built by DocumentStatement, which statement_test.go covers.
type provenanceDocument struct {
	BuildDefinition struct {
		BuildType            string         `json:"buildType"`
		ExternalParameters   map[string]any `json:"externalParameters"`
		ResolvedDependencies []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID      string            `json:"id"`
			Version map[string]string `json:"version"`
		} `json:"builder"`
		Metadata   map[string]any `json:"metadata"`
		Byproducts []any          `json:"byproducts"`
	} `json:"runDetails"`
}

func decodeProvenance(t *testing.T, payload []byte) provenanceDocument {
	t.Helper()
	var document provenanceDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode provenance: %v", err)
	}
	return document
}

// newProvenanceFixture locks one package, one slice, one artifact, one catalogue, one
// key and one repository on amd64, and adds a package on arm64 to prove platform
// isolation.
func newProvenanceFixture() *attest.ProvenanceInput {
	hash := func(seed string) string { return strings.Repeat(seed, 64) }
	lockfile := &lock.Lockfile{
		Version:    1,
		SpecDigest: "sha256:" + hash("1"),
		Provider:   lock.Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:  []string{"linux/amd64", "linux/arm64"},
		Catalogues: []lock.Catalogue{
			{Name: "slices", Source: lock.CatalogueSource{Type: "remote", URL: "https://example.invalid/x"},
				Tree: "sha256:" + hash("2")},
			{Name: "local", Source: lock.CatalogueSource{Type: "local", Path: "catalogue"},
				Tree: "sha256:" + hash("3")},
		},
		LocalInputs: []lock.LocalInput{
			{Role: "key", Path: "keys/ubuntu.gpg", SHA256: hash("4"), Size: 10},
			{Role: "vex", Path: "vex/claims.json", SHA256: hash("5"), Size: 11},
		},
		Repositories: []lock.Repository{{
			ID: "sha256:" + hash("6"), Name: "ubuntu", Platform: "linux/amd64",
			Architecture: "amd64", URL: "https://example.invalid/archive", Suite: "resolute",
			Release: lock.RepositoryRelease{SHA256: hash("7"), Size: 12, Format: "inrelease"},
		}},
		Packages: []lock.Package{
			{Platform: "linux/amd64", Name: "coreutils", Version: "9.4", Architecture: "amd64",
				Content: lock.Content{Path: "pool/coreutils.deb", SHA256: hash("a"), Size: 100}},
			{Platform: "linux/arm64", Name: "coreutils", Version: "9.4", Architecture: "arm64",
				Content: lock.Content{Path: "pool/coreutils.deb", SHA256: hash("b"), Size: 100}},
		},
		Slices: []lock.Slice{
			{Platform: "linux/amd64", Package: "libc6", Version: "2.41", Architecture: "amd64",
				Catalogue: "slices", Archive: "libc6", Content: lock.Content{Path: "pool/libc6.deb",
					SHA256: hash("c"), Size: 200}, Selected: []string{"libc6_libs"},
				DefinitionDigest: "sha256:" + hash("d")},
		},
		Artifacts: []lock.Artifact{
			{Name: "cert", Platform: "linux/amd64", URL: "https://example.invalid/cert.pem",
				SHA256: hash("e"), Size: 300, Dest: "/usr/local/share/ca-certificates",
				Unpack: new(contents.ArtifactUnpackStandalone)},
		},
	}
	return &attest.ProvenanceInput{
		Name: "my-image", Platform: "linux/amd64", Subject: "sha256:" + strings.Repeat("f", 64),
		Lock:      lockfile,
		Toolchain: attest.Toolchain{Name: "vaporize", Version: "1.2.3"},
	}
}

// TestProvenance_IsThePredicate checks that the payload is the SLSA predicate itself, so
// a reader gets the claim without unwrapping anything.
func TestProvenance_IsThePredicate(t *testing.T) {
	payload, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode provenance: %v", err)
	}
	if _, wrapped := document["predicate"]; wrapped {
		t.Fatal("the payload is an in-toto statement, not a predicate")
	}
	if _, found := document["buildDefinition"]; !found {
		t.Fatalf("the payload has no buildDefinition: %v", document)
	}
	if got := decodeProvenance(t, payload).BuildDefinition.BuildType; got != "https://mattnet.de/vapor/build/v1" {
		t.Fatalf("buildType = %q", got)
	}
}

// TestProvenance_DescribesTheBuild checks the fields SLSA requires at Build L1: a build
// type, external parameters and a builder identity.
func TestProvenance_DescribesTheBuild(t *testing.T) {
	payload, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	document := decodeProvenance(t, payload)
	definition := document.BuildDefinition
	if definition.BuildType != "https://mattnet.de/vapor/build/v1" {
		t.Fatalf("buildType = %q", definition.BuildType)
	}
	if got := definition.ExternalParameters["spec"]; got != "sha256:"+strings.Repeat("1", 64) {
		t.Fatalf("externalParameters.spec = %v", got)
	}
	if got := document.RunDetails.Builder.ID; got != "https://mattnet.de/vapor" {
		t.Fatalf("builder.id = %q", got)
	}
	if got := document.RunDetails.Builder.Version["vaporize"]; got != "1.2.3" {
		t.Fatalf("builder.version = %q", got)
	}
}

// TestProvenance_NoClockOrHostData checks the refusal list: no timestamps, no
// byproducts, no invocation ID and nothing that would differ between two runs.
func TestProvenance_NoClockOrHostData(t *testing.T) {
	payload, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	for _, forbidden := range []string{"startedOn", "finishedOn", "invocationId",
		"/home/", "/tmp/", "example.invalid", "pool/"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("payload contains %q", forbidden)
		}
	}
	document := decodeProvenance(t, payload)
	if len(document.RunDetails.Metadata) != 0 {
		t.Fatalf("metadata = %v, want none", document.RunDetails.Metadata)
	}
}

// TestProvenance_CoversEveryLockedInput checks that each locked input of the platform
// is a resolved dependency and that another platform's inputs are absent.
func TestProvenance_CoversEveryLockedInput(t *testing.T) {
	input := newProvenanceFixture()
	payload, err := attest.Provenance(input)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	found := map[string]string{}
	document := decodeProvenance(t, payload)
	for _, dependency := range document.BuildDefinition.ResolvedDependencies {
		found[dependency.Name] = dependency.Digest["sha256"]
	}
	hash := func(seed string) string { return strings.Repeat(seed, 64) }
	wanted := map[string]string{
		"lock":                           "",
		"catalogue/slices":               hash("2"),
		"catalogue/local":                hash("3"),
		"input/key/keys/ubuntu.gpg":      hash("4"),
		"input/vex/vex/claims.json":      hash("5"),
		"repository/sha256:" + hash("6"): hash("7"),
		"package/coreutils":              hash("a"),
		"slice/libc6":                    hash("c"),
		"artifact/cert":                  hash("e"),
	}
	for name, want := range wanted {
		got, present := found[name]
		if !present {
			t.Fatalf("%s is missing from resolvedDependencies: %v", name, found)
		}
		if want != "" && got != want {
			t.Fatalf("%s digest = %s, want %s", name, got, want)
		}
	}
	if len(found) != len(wanted) {
		t.Fatalf("dependencies = %v, want %d entries", found, len(wanted))
	}
	for name := range found {
		if strings.Contains(name, "arm64") {
			t.Fatalf("%s belongs to another platform", name)
		}
	}
	if found["package/coreutils"] == hash("b") {
		t.Fatal("dependency uses the arm64 package digest")
	}
}

// TestProvenance_LockDigestIsTheCanonicalLock checks that the lock dependency is the
// canonical lock bytes, so a reader can compare it with a lockfile it already holds.
func TestProvenance_LockDigestIsTheCanonicalLock(t *testing.T) {
	input := newProvenanceFixture()
	payload, err := attest.Provenance(input)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	canonical, err := input.Lock.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimPrefix(attest.Digest(canonical), "sha256:")
	for _, dependency := range decodeProvenance(t, payload).BuildDefinition.ResolvedDependencies {
		if dependency.Name == "lock" {
			if dependency.Digest["sha256"] != want {
				t.Fatalf("lock digest = %s, want %s", dependency.Digest["sha256"], want)
			}
			return
		}
	}
	t.Fatal("the lock is not a resolved dependency")
}

// TestProvenance_IsByteStable checks that two generations produce identical bytes, which
// is what lets a rebuild reproduce the attestation.
func TestProvenance_IsByteStable(t *testing.T) {
	first, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	second, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("two generations differ")
	}
}

// TestProvenance_RefusesBrokenInputs checks the inputs a statement cannot be built
// from: a missing subject, an unknown platform and an incomplete toolchain.
func TestProvenance_RefusesBrokenInputs(t *testing.T) {
	cases := map[string]func(*attest.ProvenanceInput){
		"no subject":     func(input *attest.ProvenanceInput) { input.Subject = "" },
		"subject digest": func(input *attest.ProvenanceInput) { input.Subject = "deadbeef" },
		"no lock":        func(input *attest.ProvenanceInput) { input.Lock = nil },
		"no name":        func(input *attest.ProvenanceInput) { input.Name = "" },
		"unknown platform": func(input *attest.ProvenanceInput) {
			input.Platform = "linux/riscv64"
		},
		"no toolchain": func(input *attest.ProvenanceInput) {
			input.Toolchain = attest.Toolchain{}
		},
		"unsafe name": func(input *attest.ProvenanceInput) { input.Name = "my image" },
		"no platform": func(input *attest.ProvenanceInput) { input.Platform = "" },
		"unsafe platform": func(input *attest.ProvenanceInput) {
			input.Platform = "linux/amd64\x00"
			input.Lock.Platforms = append(input.Lock.Platforms, input.Platform)
		},
	}
	for name, breakIt := range cases {
		input := newProvenanceFixture()
		breakIt(input)
		if _, err := attest.Provenance(input); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestProvenance_RefusesAContentGap checks that a locked input whose digest is unusable
// fails rather than producing a statement with a hole in it.
func TestProvenance_RefusesAContentGap(t *testing.T) {
	input := newProvenanceFixture()
	input.Lock.Packages[0].Content.SHA256 = "not-a-digest"
	if _, err := attest.Provenance(input); err == nil {
		t.Fatal("a bad package digest was accepted")
	}
}

// TestProvenance_TwoPlatformsDiffer checks that the arm64 statement describes the arm64
// manifest and the arm64 inputs, not the amd64 ones.
func TestProvenance_TwoPlatformsDiffer(t *testing.T) {
	amd64, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance amd64: %v", err)
	}
	arm := newProvenanceFixture()
	arm.Platform = "linux/arm64"
	arm.Subject = "sha256:" + strings.Repeat("9", 64)
	arm64, err := attest.Provenance(arm)
	if err != nil {
		t.Fatalf("Provenance arm64: %v", err)
	}
	if bytes.Equal(amd64, arm64) {
		t.Fatal("the two platforms produced the same predicate")
	}
	armDependencies := decodeProvenance(t, arm64).BuildDefinition.ResolvedDependencies
	for _, dependency := range armDependencies {
		if dependency.Name == "artifact/cert" || dependency.Name == "slice/libc6" {
			t.Fatalf("%s is an amd64 input", dependency.Name)
		}
	}
}

// TestProvenance_HasOnlyPublishedFields checks the statement against the field set the
// published SLSA v1 predicate defines. SLSA publishes no JSON Schema, only a
// specification and an informative CUE summary, so the field names are checked here:
// a field that is not in the specification would be invisible to every consumer.
func TestProvenance_HasOnlyPublishedFields(t *testing.T) {
	payload, err := attest.Provenance(newProvenanceFixture())
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]map[string]bool{
		"": {
			"buildDefinition": true, "runDetails": true,
		},
		"buildDefinition": {
			"buildType": true, "externalParameters": true, "internalParameters": true,
			"resolvedDependencies": true,
		},
		"runDetails": {"builder": true, "metadata": true, "byproducts": true},
		"runDetails.builder": {
			"id": true, "builderDependencies": true, "version": true,
		},
		"buildDefinition.resolvedDependencies": {
			"name": true, "uri": true, "digest": true, "content": true,
			"downloadLocation": true, "mediaType": true, "annotations": true,
		},
	}
	checkFields(t, document, "", allowed)
}

// checkFields walks the payload and reports the first object whose keys are not in the
// allowlist for its path.
func checkFields(t *testing.T, value any, path string, allowed map[string]map[string]bool) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if permitted, known := allowed[path]; known {
			for name := range typed {
				if !permitted[name] {
					t.Fatalf("%s: %s is not a published field", path, name)
				}
			}
		}
		for name, child := range typed {
			nested := path
			if nested != "" {
				nested += "."
			}
			checkFields(t, child, nested+name, allowed)
		}
	case []any:
		for _, item := range typed {
			checkFields(t, item, path, allowed)
		}
	}
}

// TestProvenance_RefusesDuplicateInputs checks that two locked inputs with the same name
// are reported rather than silently merged, since a merged entry would claim one digest
// for two different things.
func TestProvenance_RefusesDuplicateInputs(t *testing.T) {
	input := newProvenanceFixture()
	input.Lock.Packages = append(input.Lock.Packages, input.Lock.Packages[0])
	if _, err := attest.Provenance(input); err == nil {
		t.Fatal("a duplicate package was accepted")
	}
}

// TestProvenance_RefusesAnUnencodableLock checks that a lock whose canonical bytes
// cannot be produced fails loudly: the statement would otherwise name a digest of
// nothing.
func TestProvenance_RefusesAnUnencodableLock(t *testing.T) {
	input := newProvenanceFixture()
	input.Lock.Artifacts[0].Unpack = nil
	if _, err := attest.Provenance(input); err == nil {
		t.Fatal("a lock without an unpack decision was accepted")
	}
}

// TestProvenance_RemoteCatalogueUsesItsArchive checks that a remote catalogue is
// identified by the archive that was actually read, not by the tree inside it.
func TestProvenance_RemoteCatalogueUsesItsArchive(t *testing.T) {
	input := newProvenanceFixture()
	input.Lock.Catalogues[0].Archive = &lock.Archive{
		SHA256: strings.Repeat("7", 64), Size: 99,
	}
	payload, err := attest.Provenance(input)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	for _, dependency := range decodeProvenance(t, payload).BuildDefinition.ResolvedDependencies {
		if dependency.Name == "catalogue/slices" {
			if dependency.Digest["sha256"] != strings.Repeat("7", 64) {
				t.Fatalf("catalogue digest = %s, want the archive digest",
					dependency.Digest["sha256"])
			}
			return
		}
	}
	t.Fatal("the remote catalogue is missing")
}
