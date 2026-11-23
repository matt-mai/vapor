package lockinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

// A local artifact is read from the specification directory, so the lock records the
// path and the fetcher is never asked to download it.
func TestAcquireArtifactsReadsALocalPayload(t *testing.T) {
	t.Parallel()
	specDir := t.TempDir()
	payload := []byte("local server payload")
	if err := os.MkdirAll(filepath.Join(specDir, "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(specDir, "files", "server"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	unpack := contents.ArtifactUnpackStandalone
	request := &Request{
		SpecDir: specDir,
		Spec: &spec.Spec{
			Platforms: []string{"linux/amd64"},
			Contents: contents.Contents{Artifacts: []contents.Artifact{{
				Name: "server", Platforms: []string{"linux/amd64"}, Unpack: &unpack,
				Dest: "/usr/bin/server", Mode: new("0644"),
				SBOM: contents.ArtifactIdentity{Name: "server", Version: "1.0"},
				Sources: []contents.ArtifactSource{{
					Platforms: []string{"linux/amd64"}, Path: "files/server",
					SHA256: hex.EncodeToString(sum[:]),
				}},
			}}},
		},
		Cache:     newStore(t),
		Artifacts: failingFetcher{},
	}
	locked, _, err := acquireArtifacts(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(locked) != 1 || locked[0].Path != "files/server" || locked[0].URL != "" ||
		locked[0].Size != int64(len(payload)) {
		t.Fatalf("locked = %#v", locked)
	}
	reader, err := request.Cache.Open(hex.EncodeToString(sum[:]), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	cached, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil || !bytes.Equal(cached, payload) {
		t.Fatalf("cached = %q, %v", cached, readErr)
	}
}

func TestAcquireArtifactsRefusesALocalPayloadWithTheWrongDigest(t *testing.T) {
	t.Parallel()
	specDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(specDir, "server"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	unpack := contents.ArtifactUnpackStandalone
	request := &Request{
		SpecDir: specDir,
		Spec: &spec.Spec{
			Platforms: []string{"linux/amd64"},
			Contents: contents.Contents{Artifacts: []contents.Artifact{{
				Name: "server", Unpack: &unpack, Dest: "/usr/bin/server", Mode: new("0644"),
				SBOM: contents.ArtifactIdentity{Name: "server", Version: "1.0"},
				Sources: []contents.ArtifactSource{{
					Platforms: []string{"linux/amd64"}, Path: "server",
					SHA256: hex.EncodeToString(make([]byte, 32)),
				}},
			}}},
		},
		Cache:     newStore(t),
		Artifacts: failingFetcher{},
	}
	if _, _, err := acquireArtifacts(context.Background(), request); err == nil {
		t.Fatal("mismatched local payload accepted")
	}
}

func newStore(t *testing.T) *cache.Cache {
	t.Helper()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type failingFetcher struct{}

func (failingFetcher) Fetch(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("must not download")
}

// A package artifact is checked against the package it claims to be, so a payload
// that is not that package is refused before the build rather than at runtime.
func TestAcquireArtifactsChecksAPackagePayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		payload  func(*testing.T) []byte
		declared contents.ArtifactIdentity
		want     string
	}{
		{
			name: "identity",
			payload: func(t *testing.T) []byte {
				return controlDeb(t, "myapp", "1.0", "amd64", "")
			},
			declared: contents.ArtifactIdentity{Name: "myapp", Version: "2.0"},
			want:     `declares myapp 2.0, but its payload is myapp 1.0`,
		},
		{
			name: "architecture",
			payload: func(t *testing.T) []byte {
				return controlDeb(t, "myapp", "1.0", "arm64", "")
			},
			declared: contents.ArtifactIdentity{Name: "myapp", Version: "1.0"},
			want:     `is architecture "arm64", which does not fit linux/amd64`,
		},
		{
			name: "not a package",
			payload: func(*testing.T) []byte {
				return []byte("not a deb")
			},
			declared: contents.ArtifactIdentity{Name: "myapp", Version: "1.0"},
			want:     `artifact "myapp"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload := tt.payload(t)
			err := checkPackageArtifact(t, payload, tt.declared)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// A package artifact whose dependencies are met by another declared package locks.
func TestAcquireArtifactsAcceptsSatisfiedDependencies(t *testing.T) {
	t.Parallel()
	specDir := t.TempDir()
	packages := map[string][]byte{
		"myapp":   controlDeb(t, "myapp", "1.0", "amd64", "Depends: libssl3 (>= 3.0)\n"),
		"libssl3": controlDeb(t, "libssl3", "3.1", "amd64", ""),
	}
	artifacts := make([]contents.Artifact, 0, len(packages))
	for _, name := range slices.Sorted(maps.Keys(packages)) {
		payload := packages[name]
		if err := os.WriteFile(filepath.Join(specDir, name+".deb"), payload, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(payload)
		unpack := contents.ArtifactUnpackPackage
		artifacts = append(artifacts, contents.Artifact{
			Name: name, Platforms: []string{"linux/amd64"}, Unpack: &unpack,
			SBOM: contents.ArtifactIdentity{Name: name, Version: map[string]string{
				"myapp": "1.0", "libssl3": "3.1"}[name]},
			Sources: []contents.ArtifactSource{{
				Platforms: []string{"linux/amd64"}, Path: name + ".deb",
				SHA256: hex.EncodeToString(sum[:]),
			}},
		})
	}
	request := &Request{
		SpecDir: specDir,
		Spec: &spec.Spec{
			Platforms: []string{"linux/amd64"},
			Contents:  contents.Contents{Artifacts: artifacts},
		},
		Cache:     newStore(t),
		Artifacts: failingFetcher{},
	}
	locked, checked, err := acquireArtifacts(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(locked) != 2 || len(checked) != 2 {
		t.Fatalf("locked = %#v, checked = %#v", locked, checked)
	}
	if err := checkArtifactPackages(checked, nil); err != nil {
		t.Fatalf("dependencies met by the other local package: %v", err)
	}
}

// A local package's dependency is satisfied by a whole package the same build
// selects. Only another local package counted before, so an ordinary application
// that depends on a repository library failed to lock.
func TestAcquireArtifactsAcceptsADependencyOnAWholePackage(t *testing.T) {
	t.Parallel()
	payload := controlDeb(t, "myapp", "1.0", "amd64", "Depends: libssl3 (>= 3.0)\n")
	locked, checked, err := checkPackageArtifactRequest(t, payload,
		contents.ArtifactIdentity{Name: "myapp", Version: "1.0"})
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if len(locked) != 1 || len(checked) != 1 {
		t.Fatalf("locked = %#v, checked = %#v", locked, checked)
	}
	whole := []lock.Package{{
		Platform: "linux/amd64", Name: "libssl3", Version: "3.1", Architecture: "amd64",
	}}
	if err := checkArtifactPackages(checked, whole); err != nil {
		t.Fatalf("dependency met by a selected whole package: %v", err)
	}
}

// A whole package of another platform does not satisfy the dependency, and neither
// does a version too old: the platform and the version both still decide it.
func TestAcquireArtifactsRefusesAnUnsatisfiedDependency(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		whole lock.Package
	}{
		{
			name: "other platform",
			whole: lock.Package{
				Platform: "linux/arm64", Name: "libssl3", Version: "3.1", Architecture: "arm64",
			},
		},
		{
			name: "older version",
			whole: lock.Package{
				Platform: "linux/amd64", Name: "libssl3", Version: "2.9", Architecture: "amd64",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload := controlDeb(t, "myapp", "1.0", "amd64", "Depends: libssl3 (>= 3.0)\n")
			_, checked, err := checkPackageArtifactRequest(t, payload,
				contents.ArtifactIdentity{Name: "myapp", Version: "1.0"})
			if err != nil {
				t.Fatalf("lock: %v", err)
			}
			err = checkArtifactPackages(checked, []lock.Package{tt.whole})
			want := `local package "myapp" depends on "libssl3 (>= 3.0)", which no selected package provides`
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}

// checkPackageArtifact locks one package artifact and returns the check's error.
func checkPackageArtifact(t *testing.T, payload []byte, declared contents.ArtifactIdentity) error {
	t.Helper()
	_, _, err := checkPackageArtifactRequest(t, payload, declared)
	return err
}

// checkPackageArtifactRequest locks one package artifact and returns the lock and the
// local package records the caller still has to hold to the selected packages.
func checkPackageArtifactRequest(t *testing.T, payload []byte,
	declared contents.ArtifactIdentity) ([]lock.Artifact, []packageArtifact, error) {
	t.Helper()
	specDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(specDir, "myapp.deb"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	unpack := contents.ArtifactUnpackPackage
	request := &Request{
		SpecDir: specDir,
		Spec: &spec.Spec{
			Platforms: []string{"linux/amd64"},
			Contents: contents.Contents{Artifacts: []contents.Artifact{{
				Name: "myapp", Platforms: []string{"linux/amd64"}, Unpack: &unpack, SBOM: declared,
				Sources: []contents.ArtifactSource{{
					Platforms: []string{"linux/amd64"}, Path: "myapp.deb",
					SHA256: hex.EncodeToString(sum[:]),
				}},
			}}},
		},
		Cache:     newStore(t),
		Artifacts: failingFetcher{},
	}
	locked, checked, err := acquireArtifacts(context.Background(), request)
	return locked, checked, err
}

// controlDeb builds a DEB whose control stanza carries the given fields.
func controlDeb(t *testing.T, name, version, architecture, extra string) []byte {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n%s", name, version, architecture, extra)
	buffer := &bytes.Buffer{}
	buffer.WriteString("!<arch>\n")
	members := []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", debianGzip(t, debianTar(t, map[string]string{"control": control}))},
		{"data.tar.gz", debianGzip(t, debianTar(t, map[string]string{"usr/share/doc/" + name: name + "\n"}))},
	}
	for _, member := range members {
		fmt.Fprintf(buffer, "%-16s%-12s%-6s%-6s%-8s%-10s`\n",
			member.name, "0", "0", "0", "100644", fmt.Sprint(len(member.body)))
		buffer.Write(member.body)
		if len(member.body)%2 == 1 {
			buffer.WriteByte('\n')
		}
	}
	return buffer.Bytes()
}
