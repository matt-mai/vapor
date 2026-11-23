package locking

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

const minimalSpec = `version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: resolute
`

type testProvider struct {
	distro  string
	release string
}

func (p testProvider) Distro() string  { return p.distro }
func (p testProvider) Release() string { return p.release }

func loadSpec(t *testing.T, content string) *spec.Spec {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(filename)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestAssembleCanonicalizesRelease(t *testing.T) {
	t.Parallel()
	loaded := loadSpec(t, minimalSpec)
	provider := testProvider{distro: "ubuntu", release: "26.04"}
	assembled, err := AssembleWithDefaults(loaded, provider, &Evidence{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if assembled.Provider.Release != "26.04" || assembled.Provider.Distro != "ubuntu" {
		t.Fatalf("provider = %+v", assembled.Provider)
	}
	want, err := loaded.SpecDigestForRelease("26.04")
	if err != nil {
		t.Fatal(err)
	}
	if assembled.SpecDigest != want {
		t.Fatalf("spec digest = %s, want %s", assembled.SpecDigest, want)
	}
	if err := lock.VerifyLockfileForProvider(loaded, assembled, "26.04", nil); err != nil {
		t.Fatalf("canonical verification failed: %v", err)
	}
	if err := lock.VerifyLockfileForProvider(loaded, assembled, loaded.Release, nil); err == nil {
		t.Fatal("raw codename spelling verified against the canonical lock")
	}
}

func TestAssembleCanonicalFormsMatch(t *testing.T) {
	t.Parallel()
	codename := loadSpec(t, minimalSpec)
	version := loadSpec(t, strings.Replace(minimalSpec, "release: resolute", `release: "26.04"`, 1))
	provider := testProvider{distro: "ubuntu", release: "26.04"}
	a, err := AssembleWithDefaults(codename, provider, &Evidence{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AssembleWithDefaults(version, provider, &Evidence{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.SpecDigest != b.SpecDigest {
		t.Fatalf("digests differ: %s != %s", a.SpecDigest, b.SpecDigest)
	}
}

func TestAssembleRejectsMissingEvidence(t *testing.T) {
	t.Parallel()
	loaded := loadSpec(t, minimalSpec+`contents:
  artifacts:
    - name: server
      dest: /usr/bin/server
      unpack: false
      sources:
        - platforms: [linux/amd64]
          url: https://example.com/server
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      sbom: {name: server, version: "1.0"}
`)
	if _, err := AssembleWithDefaults(loaded, testProvider{"ubuntu", "26.04"}, &Evidence{}, nil); err == nil {
		t.Fatal("assembled lock without required artifact evidence")
	}
}

func TestAssembleValidation(t *testing.T) {
	t.Parallel()
	loaded := loadSpec(t, minimalSpec)
	if _, err := AssembleWithDefaults(nil, testProvider{"ubuntu", "26.04"}, &Evidence{}, nil); err == nil {
		t.Fatal("nil spec accepted")
	}
	if _, err := AssembleWithDefaults(loaded, nil, &Evidence{}, nil); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := AssembleWithDefaults(loaded, testProvider{"ubuntu", "26.04"}, nil, nil); err == nil {
		t.Fatal("nil evidence accepted")
	}
}

// Debian's two spellings name one release, so a lock records the codename whichever
// the specification used, and the canonical release verifies the lock while the raw
// spelling does not.
func TestAssembleCanonicalizesDebianRelease(t *testing.T) {
	t.Parallel()
	const debianSpec = `version: 1
name: debian-minimal
image: ghcr.io/example/debian-minimal
distro: debian
release: %s
`
	codename := loadSpec(t, fmt.Sprintf(debianSpec, "trixie"))
	version := loadSpec(t, fmt.Sprintf(debianSpec, `"13"`))
	provider, err := distro.Select("debian", "13")
	if err != nil {
		t.Fatal(err)
	}
	a, err := AssembleWithDefaults(codename, provider, &Evidence{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AssembleWithDefaults(version, provider, &Evidence{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Provider != (lock.Provider{Distro: "debian", Release: "trixie"}) {
		t.Fatalf("provider = %+v", a.Provider)
	}
	if a.SpecDigest != b.SpecDigest {
		t.Fatalf("digests differ: %s != %s", a.SpecDigest, b.SpecDigest)
	}
	if err := lock.VerifyLockfileForProvider(codename, a, provider.Release(), nil); err != nil {
		t.Fatalf("canonical verification failed: %v", err)
	}
	if err := lock.VerifyLockfileForProvider(version, a, provider.Release(), nil); err != nil {
		t.Fatalf("version-spelled spec failed to verify: %v", err)
	}
	if err := lock.VerifyLockfileForProvider(version, a, "13", nil); err == nil {
		t.Fatal("raw version spelling verified the canonical lock")
	}
}
