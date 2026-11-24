package lock

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/spec"
)

const minimalSpec = `version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: "26.04"
`

const contentsFixture = minimalSpec + `platforms: [linux/amd64, linux/arm64]
contents:
  packages:
    - name: openssl
      version: "= 3.0-1"
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
      archives: {ubuntu: main}
  slices:
    - package: base-files
      slice: release-info
  repositories:
    - name: main
      suites: [resolute, resolute-updates]
      components: [main, universe]
      endpoints:
        - platforms: [linux/amd64]
          url: https://example.com/ubuntu
        - platforms: [linux/arm64]
          url: http://ports.example.com/ubuntu-ports
      trust:
        keys:
          - path: keys/repo.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
  artifacts:
    - name: server
      dest: /usr/bin/server
      unpack: false
      sources:
        - platforms: [linux/amd64]
          url: https://example.com/server-amd64
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        - platforms: [linux/arm64]
          url: https://example.com/server-arm64
          sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      sbom: {name: server, version: "1.0"}
`

// contentsFixtureWithCPE declares the CPE on the whole-package request, so a lock record
// that states it matches.
const contentsFixtureWithCPE = minimalSpec + `platforms: [linux/amd64, linux/arm64]
contents:
  packages:
    - name: openssl
      version: "= 3.0-1"
      cpe: ` + nodeCPEForLock + `
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
      archives: {ubuntu: main}
  slices:
    - package: base-files
      slice: release-info
  repositories:
    - name: main
      suites: [resolute, resolute-updates]
      components: [main, universe]
      endpoints:
        - platforms: [linux/amd64]
          url: https://example.com/ubuntu
        - platforms: [linux/arm64]
          url: http://ports.example.com/ubuntu-ports
      trust:
        keys:
          - path: keys/repo.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
  artifacts:
    - name: server
      dest: /usr/bin/server
      unpack: false
      sources:
        - platforms: [linux/amd64]
          url: https://example.com/server-amd64
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        - platforms: [linux/arm64]
          url: https://example.com/server-arm64
          sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      sbom: {name: server, version: "1.0"}
`

// nodeCPEForLock is a declared CPE a lock record can be compared against.
const nodeCPEForLock = "cpe:2.3:a:openssl:openssl:3.0-1:*:*:*:*:*:*:*"

func loadText(t *testing.T, content string) (*spec.Spec, error) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return spec.LoadSpec(filename)
}
