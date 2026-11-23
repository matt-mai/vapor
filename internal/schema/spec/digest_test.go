package spec

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readDigestVector(t *testing.T, name, suffix string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "spec-digest", name+suffix))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func digestVectorSpec(t *testing.T) *Spec {
	t.Helper()
	spec, err := loadText(t, string(readDigestVector(t, "rich", ".yaml")))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func requireDigest(t *testing.T, spec *Spec) string {
	t.Helper()
	digest, err := spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestSpecDigest_Vectors(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"minimal", "rich"} {
		t.Run(name, func(t *testing.T) {
			input := readDigestVector(t, name, ".yaml")
			want := readDigestVector(t, name, ".json")
			wantDigest := strings.TrimSpace(string(readDigestVector(t, name, ".sha256")))
			spec, err := decodeSpec(input)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalSpec(spec)
			if err != nil || !bytes.Equal(canonical, want) {
				t.Fatalf("canonical bytes differ from pinned vector: %v", err)
			}
			independent := fmt.Sprintf("sha256:%x", sha256.Sum256(want))
			if got := requireDigest(t, spec); got != wantDigest || independent != wantDigest {
				t.Fatalf("digest got %s, independent %s, want %s", got, independent, wantDigest)
			}
			if bytes.HasSuffix(canonical, []byte("\n")) || !json.Valid(canonical) {
				t.Fatal("canonical bytes must be compact valid JSON without trailing newline")
			}
		})
	}
}

func TestSpecDigest_YAMLKeyOrder(t *testing.T) {
	t.Parallel()
	first, err := loadText(t, minimalSpec+"annotations: {z: last, a: first}\ncontainer: {env: {Z: last, A: first}}")
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadText(t, "container: {env: {A: first, Z: last}}\nannotations: {a: first, z: last}\nrelease: '26.04'\ndistro: ubuntu\nimage: ghcr.io/example/ubuntu-minimal\nname: ubuntu-minimal\nversion: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if requireDigest(t, first) != requireDigest(t, second) {
		t.Fatal("YAML object key order changed identity")
	}
}

func TestSpecDigest_OptionalEmptyAndExplicitDefaults(t *testing.T) {
	t.Parallel()
	spec, err := decodeSpec([]byte(minimalSpec))
	if err != nil {
		t.Fatal(err)
	}
	want := requireDigest(t, spec)
	spec.Tags, spec.Annotations = []string{}, map[string]string{}
	spec.Container = Container{Entrypoint: []string{}, Cmd: []string{}, Ports: []string{}, Env: map[string]string{}}
	spec.Contents.Packages, spec.Contents.Slices = []PackageRequest{}, []SliceRequest{}
	spec.Contents.Catalogues, spec.Contents.Repositories, spec.Contents.Artifacts = []CatalogueSource{}, []Repository{}, []Artifact{}
	spec.Filesystem.Paths, spec.Filesystem.OSRelease = []Path{}, map[string]string{}
	spec.Filesystem.Accounts = Accounts{Users: []UserAccount{}, Groups: []GroupAccount{}}
	spec.VEX.Inputs = []string{}
	spec.VEX.Assertions = []VEXAssertion{}
	applyDefaults(spec)
	if requireDigest(t, spec) != want {
		t.Fatal("optional nil/empty or explicit default values changed identity")
	}
	claim := digestVectorSpec(t)
	claim.VEX.CheckAbsentPaths, claim.VEX.Assertions[0].AbsentPaths = new(false), nil
	want = requireDigest(t, claim)
	claim.VEX.Assertions[0].AbsentPaths = []string{}
	if requireDigest(t, claim) != want {
		t.Fatal("waived nil/empty absence list changed identity")
	}
}

func TestSpecDigest_Immutability(t *testing.T) {
	t.Parallel()
	for _, input := range []string{minimalSpec, string(readDigestVector(t, "rich", ".yaml")), strings.Replace(minimalSpec, "version: 1", "version: 2", 1)} {
		spec, err := decodeSpec([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		before, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		platforms, enabled := spec.Platforms, spec.SBOM.Enabled
		_, digestErr := spec.SpecDigest()
		if (spec.Version == 1) != (digestErr == nil) {
			t.Fatalf("unexpected digest validation result: %v", digestErr)
		}
		after, err := json.Marshal(spec)
		if err != nil || !bytes.Equal(before, after) || spec.SBOM.Enabled != enabled {
			t.Fatalf("caller modified: %v", err)
		}
		if len(platforms) != 0 && &platforms[0] != &spec.Platforms[0] {
			t.Fatal("caller slice replaced")
		}
	}
}

func TestSpecDigest_RelocationAndUnchangedDeclarations(t *testing.T) {
	t.Parallel()
	var want string
	for i := range 2 {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "vex"), 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(root, "vex", "review.json")
		filename := filepath.Join(root, "image.yaml")
		if err := os.WriteFile(filename, readDigestVector(t, "rich", ".yaml"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(input, []byte("not a valid VEX document"), 0o600); err != nil {
			t.Fatal(err)
		}
		spec, err := LoadSpec(filename)
		if err != nil {
			t.Fatal(err)
		}
		got := requireDigest(t, spec)
		if i == 0 {
			want = got
		}
		if err := os.WriteFile(input, []byte("changed external input"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got != want || requireDigest(t, spec) != want {
			t.Fatal("host location or external bytes changed declarative identity")
		}
	}
}
