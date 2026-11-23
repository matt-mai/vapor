package spec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const minimalSpec = `version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: "26.04"
`

func loadText(t *testing.T, content string) (*Spec, error) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadSpec(filename)
}

func TestLoadSpec_CoreAndDefaults(t *testing.T) {
	t.Parallel()
	want := &Spec{
		Version: 1, Name: "ubuntu-minimal", Image: "ghcr.io/example/ubuntu-minimal",
		Distro: "ubuntu", Release: "26.04", Platforms: []string{"linux/amd64"},
		Hardening: Hardening{StripDocs: new(true), StripShells: new(true), StripAptDpkg: new(true), RemoveSUIDSGID: new(true), KeepPackageSources: new(false)},
		Contents:  Contents{SlicesEngine: SliceEngine{MaxSteps: new(100_000)}},
		SBOM:      SBOM{Enabled: new(true)}, VEX: VEX{CheckAbsentPaths: new(true)},
	}
	for _, suffix := range []string{"", "container: {}\n", "# comment\n...\n"} {
		t.Run(suffix, func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+suffix)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spec, want) {
				t.Fatalf("got %#v, want %#v", spec, want)
			}
		})
	}
}

func TestLoadSpec_ContainerAndOrder(t *testing.T) {
	t.Parallel()
	spec, err := loadText(t, minimalSpec+`platforms: [linux/arm64, linux/amd64]
container:
  user: "65532:65532"
  entrypoint: [/app/server, --listen]
  cmd: ["", "8080"]
  workdir: /app
  ports: ["8080", "8080/udp", "9000/sctp"]
  stop-signal: SIGTERM
  env:
    ANSWER: "42"
    ENABLED: "true"
    MESSAGE: "first\nsecond"
`)
	if err != nil {
		t.Fatal(err)
	}
	want := Container{
		User: "65532:65532", Entrypoint: []string{"/app/server", "--listen"},
		Cmd: []string{"", "8080"}, Workdir: "/app", Ports: []string{"8080", "8080/udp", "9000/sctp"},
		StopSignal: "SIGTERM", Env: map[string]string{"ANSWER": "42", "ENABLED": "true", "MESSAGE": "first\nsecond"},
	}
	if !reflect.DeepEqual(spec.Container, want) || !reflect.DeepEqual(spec.Platforms, []string{"linux/arm64", "linux/amd64"}) {
		t.Fatalf("configuration/order changed: %#v", spec)
	}
}

func TestLoadSpec_ExplicitStringTag(t *testing.T) {
	t.Parallel()
	input := strings.Replace(minimalSpec, `"26.04"`, "!!str 26.04", 1)
	spec, err := loadText(t, input)
	if err != nil || spec.Release != "26.04" {
		t.Fatalf("explicit YAML string tag: spec=%#v err=%v", spec, err)
	}
}

func TestLoadSpec_DefaultsDoNotShareState(t *testing.T) {
	t.Parallel()
	first, err := loadText(t, minimalSpec)
	if err != nil {
		t.Fatal(err)
	}
	first.Platforms[0] = "changed"
	second, err := loadText(t, minimalSpec)
	if err != nil {
		t.Fatal(err)
	}
	if second.Platforms[0] != "linux/amd64" {
		t.Fatal("defaults shared across loads")
	}
}

func TestLoadSpec_ReadErrors(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "missing.yaml")
	spec, err := LoadSpec(filename)
	if spec != nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), filename) {
		t.Fatalf("missing file: spec=%#v, err=%v", spec, err)
	}
	spec, err = LoadSpec(t.TempDir())
	if spec != nil || err == nil || !strings.Contains(err.Error(), "read spec") {
		t.Fatalf("directory: spec=%#v, err=%v", spec, err)
	}
}

func TestSpecRejectsOversizedInputBeforeYAML(t *testing.T) {
	t.Parallel()
	text := "[" + strings.Repeat(" ", MaxSpecSize)
	want := fmt.Sprintf("spec document exceeds %d-byte limit", MaxSpecSize)
	if decoded, err := DecodeSpec([]byte(text)); decoded != nil || err == nil || err.Error() != want {
		t.Fatalf("DecodeSpec = %v, %v; want %s", decoded, err, want)
	}
	if loaded, err := loadText(t, text); loaded != nil || err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("LoadSpec = %v, %v; want %s", loaded, err, want)
	}
}

func TestLoadSpec_StrictYAML(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, content, message string }{
		{"empty", "", "decode spec document"},
		{"comment only", "# no document", "decode spec document"},
		{"empty document", "---\n", "YAML mapping"},
		{"scalar root", "hello", "YAML mapping"},
		{"sequence root", "[]", "YAML mapping"},
		{"invalid syntax", "version: [", "decode spec document"},
		{"extra document", minimalSpec + "---\n{}", "exactly one YAML document"},
		{"empty extra document", minimalSpec + "---\n", "exactly one YAML document"},
		{"trailing syntax error", minimalSpec + "---\n[", "trailing spec document"},
		{"duplicate root", minimalSpec + "name: other\n", "duplicate key"},
		{"duplicate container", minimalSpec + "container: {user: a, user: b}", "duplicate key"},
		{"duplicate environment", minimalSpec + "container: {env: {A: a, A: b}}", "duplicate key"},
		{"unknown root", minimalSpec + "future: value\n", `unknown field "future"`},
		{"unknown container", minimalSpec + "container: {future: value}", `unknown field "future"`},
		{"unknown contents field", minimalSpec + "contents: {future: value}", `unknown field "future"`},
		{"unknown filesystem field", minimalSpec + "filesystem: {future: value}", `unknown field "future"`},
		{"numeric mapping key", minimalSpec + "container: {env: {1: a}}", "mapping keys"},
		{"complex mapping key", minimalSpec + "? [a, b]\n: c", "mapping keys"},
		{"interpolated identity", strings.Replace(minimalSpec, "ubuntu-minimal", "${NAME}", 1), "interpolation"},
		{"interpolated argument", minimalSpec + "container: {cmd: ['${ARG}']}", "interpolation"},
		{"interpolated env value", minimalSpec + "container: {env: {A: '${SECRET}'}}", "interpolation"},
		{"interpolated env key", minimalSpec + "container: {env: {'${KEY}': a}}", "interpolation"},
		{"interpolated platform", minimalSpec + "platforms: ['${ARCH}']", "interpolation"},
		{"interpolated workdir", minimalSpec + "container: {workdir: '/${DIR}'}", "interpolation"},
		{"numeric release", strings.Replace(minimalSpec, `"26.04"`, "26.04", 1), "expected a string"},
		{"numeric env", minimalSpec + "container: {env: {A: 42}}", "expected a string"},
		{"boolean env", minimalSpec + "container: {env: {A: true}}", "expected a string"},
		{"null container", minimalSpec + "container: null", "expected a mapping"},
		{"null platforms", minimalSpec + "platforms: null", "expected a sequence"},
		{"null env", minimalSpec + "container: {env: {A: null}}", "expected a string"},
		{"numeric argument", minimalSpec + "container: {cmd: [42]}", "expected a string"},
		{"numeric port", minimalSpec + "container: {ports: [80]}", "expected a string"},
		{"anchor", minimalSpec + "container: &config {}", "anchors and aliases"},
		{"alias", minimalSpec + "platforms: [*missing]", "decode spec document"},
		{"merge", minimalSpec + "container: {<<: {user: nobody}}", "YAML merges"},
		{"custom scalar tag", minimalSpec + "container: {user: !custom nobody}", "expected a string"},
		{"custom map tag", minimalSpec + "container: !custom {}", "custom YAML tags"},
		{"custom seq tag", minimalSpec + "platforms: !custom []", "custom YAML tags"},
		{"NUL", minimalSpec + "container: {cmd: [\"a\\0b\"]}", "NUL"},
		{"wrong container type", minimalSpec + "container: []", "expected a mapping"},
		{"wrong env type", minimalSpec + "container: {env: []}", "expected a mapping"},
		{"wrong list type", minimalSpec + "platforms: linux/amd64", "expected a sequence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := loadText(t, tt.content)
			if err == nil || spec != nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("want nil spec and %q error, got %#v, %v", tt.message, spec, err)
			}
		})
	}
}

func FuzzDecodeSpec_NoPanic(f *testing.F) {
	for _, seed := range []string{minimalSpec, contentsFixture, filesystemFixture, policiesFixture, minimalSpec + attestationFixture, minimalSpec + "tags: [v1]\nannotations: {custom: value}", "", "---\n", "&a [*a]", minimalSpec + "container: {env: {A: '${BAD}'}}"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		spec, err := decodeSpec(data)
		if (err == nil) != (spec != nil) {
			t.Fatalf("inconsistent result: spec=%#v, err=%v", spec, err)
		}
	})
}
