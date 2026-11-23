package spec

import (
	"strconv"
	"strings"
	"testing"
)

func TestLoadSpec_InvalidCoreFields(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, old, replacement, message string }{
		{"version zero", "version: 1", "version: 0", "version must be 1"},
		{"future version", "version: 1", "version: 2", "version must be 1"},
		{"missing version", "version: 1\n", "", "version must be 1"},
		{"string version", "version: 1", "version: '1'", "expected an integer"},
		{"float version", "version: 1", "version: 1.0", "expected an integer"},
		{"empty name", "name: ubuntu-minimal", "name: ''", "name has invalid syntax"},
		{"missing name", "name: ubuntu-minimal\n", "", "name has invalid syntax"},
		{"name whitespace", "name: ubuntu-minimal", "name: 'two names'", "name has invalid syntax"},
		{"name traversal", "name: ubuntu-minimal", "name: ../other", "name has invalid syntax"},
		{"name too long", "name: ubuntu-minimal", "name: " + strings.Repeat("a", 129), "name has invalid syntax"},
		{"missing image", "image: ghcr.io/example/ubuntu-minimal\n", "", "image must be"},
		{"empty image", "image: ghcr.io/example/ubuntu-minimal", "image: ''", "image must be"},
		{"unqualified image", "ghcr.io/example/ubuntu-minimal", "example/minimal", "image must be"},
		{"image URL", "ghcr.io/example/ubuntu-minimal", "https://ghcr.io/example/minimal", "image registry port"},
		{"image empty hostname", "ghcr.io/example/ubuntu-minimal", ":5000/app", "image registry must include a hostname"},
		{"image empty registry port", "ghcr.io/example/ubuntu-minimal", "ghcr.io:/app", "image registry port"},
		{"image tag", "ghcr.io/example/ubuntu-minimal", "ghcr.io/example/minimal:latest", "image must be"},
		{"image digest", "ghcr.io/example/ubuntu-minimal", "ghcr.io/example/minimal@sha256:" + strings.Repeat("a", 64), "image must be"},
		{"image uppercase", "ghcr.io/example/ubuntu-minimal", "ghcr.io/Example/minimal", "image must be"},
		{"image empty component", "ghcr.io/example/ubuntu-minimal", "ghcr.io/example//minimal", "image repository component"},
		{"image traversal", "ghcr.io/example/ubuntu-minimal", "ghcr.io/example/../minimal", "image repository component"},
		{"image leading separator", "ghcr.io/example/ubuntu-minimal", "ghcr.io/example/-minimal", "image repository component"},
		{"missing distro", "distro: ubuntu\n", "", "distro has invalid syntax"},
		{"empty distro", "distro: ubuntu", "distro: ''", "distro has invalid syntax"},
		{"distro whitespace", "distro: ubuntu", "distro: 'ubuntu debian'", "distro has invalid syntax"},
		{"distro uppercase", "distro: ubuntu", "distro: Ubuntu", "distro has invalid syntax"},
		{"missing release", "release: \"26.04\"\n", "", "release has invalid syntax"},
		{"empty release", `"26.04"`, "''", "release has invalid syntax"},
		{"moving latest", `"26.04"`, "latest", "release has invalid syntax"},
		{"moving stable", `"26.04"`, "stable", "release has invalid syntax"},
		{"moving testing", `"26.04"`, "testing", "release has invalid syntax"},
		{"moving unstable", `"26.04"`, "unstable", "release has invalid syntax"},
		{"moving sid", `"26.04"`, "sid", "release has invalid syntax"},
		{"uppercase codename", `"26.04"`, "Resolute", "release has invalid syntax"},
		{"codename underscore", `"26.04"`, "resolute_testing", "release has invalid syntax"},
		{"malformed release", `"26.04"`, "'26..04'", "release has invalid syntax"},
		{"empty platforms", "release: \"26.04\"", "release: \"26.04\"\nplatforms: []", "platforms must not be empty"},
		{"unsupported platform", "release: \"26.04\"", "release: \"26.04\"\nplatforms: [linux/riscv64]", "unsupported platform"},
		{"package all", "release: \"26.04\"", "release: \"26.04\"\nplatforms: [all]", "unsupported platform"},
		{"platform variant", "release: \"26.04\"", "release: \"26.04\"\nplatforms: [linux/arm64/v8]", "unsupported platform"},
		{"duplicate platform", "release: \"26.04\"", "release: \"26.04\"\nplatforms: [linux/amd64, linux/amd64]", "duplicate platform"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Replace(minimalSpec, tt.old, tt.replacement, 1)
			spec, err := loadText(t, input)
			if err == nil || spec != nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("want nil spec and %q error, got %#v, %v", tt.message, spec, err)
			}
		})
	}
}

func TestLoadSpec_ReleaseForms(t *testing.T) {
	t.Parallel()
	for _, release := range []string{"26.04", "26", "resolute", "trixie"} {
		t.Run(release, func(t *testing.T) {
			input := strings.Replace(minimalSpec, `"26.04"`, strconv.Quote(release), 1)
			spec, err := loadText(t, input)
			if err != nil || spec.Release != release {
				t.Fatalf("release %q: spec=%#v err=%v", release, spec, err)
			}
		})
	}
}

func TestLoadSpec_SyntaxIsNotProviderSupport(t *testing.T) {
	t.Parallel()
	for _, distro := range []string{"debian", "future-distro"} {
		t.Run(distro, func(t *testing.T) {
			input := strings.Replace(minimalSpec, "distro: ubuntu", "distro: "+distro, 1)
			input = strings.Replace(input, `"26.04"`, `'13'`, 1)
			spec, err := loadText(t, input)
			if err != nil || spec.Distro != distro || spec.Release != "13" {
				t.Fatalf("schema must not resolve providers: spec=%#v err=%v", spec, err)
			}
		})
	}
}

func TestLoadSpec_ImageRepositories(t *testing.T) {
	t.Parallel()
	for _, image := range []string{"localhost:5000/demo", "docker.io/library/ubuntu", "ghcr.io/org/demo__one--two.three", "[::1]:5000/app", "[::1]/app"} {
		t.Run(image, func(t *testing.T) {
			input := strings.Replace(minimalSpec, "ghcr.io/example/ubuntu-minimal", strconv.Quote(image), 1)
			spec, err := loadText(t, input)
			if err != nil || spec.Image != image {
				t.Fatalf("image was rejected or rewritten: spec=%#v err=%v", spec, err)
			}
		})
	}
}
