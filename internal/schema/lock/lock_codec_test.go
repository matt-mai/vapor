package lock

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

func TestDecodeLockfile_Strict(t *testing.T) {
	t.Parallel()
	valid := string(mustCanonicalYAML(t, canonicalVectorLock()))
	tests := []struct {
		name    string
		content string
		message string
	}{
		{"empty", "", "decode lock document"},
		{"scalar root", "hello", "YAML mapping"},
		{"sequence root", "[]", "YAML mapping"},
		{"extra document", valid + "---\n{}", "exactly one YAML document"},
		{"invalid syntax", "version: [", "decode lock document"},
		{"unknown root", valid + "future: value\n", `unknown field "future"`},
		{"unknown provider", strings.Replace(valid, "distro: ubuntu", "distro: ubuntu\n  future: value", 1), `unknown field "future"`},
		{"duplicate root", strings.Replace(valid, "version: 1", "version: 1\nversion: 1", 1), "duplicate key"},
		{"null platform", strings.Replace(valid, "platforms:\n  - linux/amd64", "platforms: null", 1), "expected a sequence"},
		{"missing root collection", strings.Replace(valid, "packages: []\n", "", 1), `required field "packages"`},
		{"wrong platform type", strings.Replace(valid, "  - linux/amd64", "  - 42", 1), "expected a string"},
		{"wrong size type", strings.Replace(valid, "artifacts: []", "artifacts:\n  - name: x\n    platform: linux/amd64\n    url: https://example.com/x\n    sha256: "+strings.Repeat("a", 64)+"\n    size: huge\n    dest: /x\n    unpack: false\n    uid: 0\n    gid: 0\n    sbom: {name: x, version: '1'}", 1), "expected an integer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock, err := decodeLockfile([]byte(tt.content))
			if err == nil || lock != nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("want nil lock and %q error, got %#v, %v", tt.message, lock, err)
			}
		})
	}
}

func TestDecodeLockfile_DuplicateRecords(t *testing.T) {
	t.Parallel()
	base := canonicalVectorLock()
	base.LocalInputs = []LocalInput{{Role: "ca", Path: "ca.pem", SHA256: strings.Repeat("a", 64), Size: 1}}
	base.Catalogues = []Catalogue{{Name: "custom", Source: CatalogueSource{Type: "local", Path: "catalogue"}, Tree: "sha256:" + strings.Repeat("b", 64)}}
	base.Packages = []Package{{Platform: "linux/amd64", Name: "a", Version: "1", Architecture: "amd64", Repository: "sha256:" + strings.Repeat("c", 64), Content: Content{Path: "a.deb", SHA256: strings.Repeat("d", 64), Size: 1}}}
	base.Artifacts = []Artifact{{Name: "a", Platform: "linux/amd64", URL: "https://example.com/a", SHA256: strings.Repeat("e", 64), Size: 1, Dest: "/a", Unpack: new(contents.ArtifactUnpackStandalone), UID: 0, GID: 0, Mode: new("0644"), SBOM: contents.ArtifactIdentity{Name: "a", Version: "1"}}}
	tests := []struct {
		name   string
		mutate func(*Lockfile)
	}{
		{"local input", func(lock *Lockfile) { lock.LocalInputs = append(lock.LocalInputs, lock.LocalInputs[0]) }},
		{"catalogue", func(lock *Lockfile) { lock.Catalogues = append(lock.Catalogues, lock.Catalogues[0]) }},
		{"package", func(lock *Lockfile) { lock.Packages = append(lock.Packages, lock.Packages[0]) }},
		{"artifact", func(lock *Lockfile) { lock.Artifacts = append(lock.Artifacts, lock.Artifacts[0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock := *base
			lock.LocalInputs = append([]LocalInput(nil), base.LocalInputs...)
			lock.Catalogues = append([]Catalogue(nil), base.Catalogues...)
			lock.Packages = append([]Package(nil), base.Packages...)
			lock.Artifacts = append([]Artifact(nil), base.Artifacts...)
			tt.mutate(&lock)
			data, err := lock.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeLockfile(data); err == nil {
				t.Fatal("duplicate record accepted")
			}
		})
	}
}

func TestDecodeLockfile_ReorderedMappings(t *testing.T) {
	t.Parallel()
	lock := canonicalVectorLock()
	canonical, err := lock.CanonicalYAML()
	if err != nil {
		t.Fatal(err)
	}
	reordered := strings.Join([]string{
		"artifacts: []",
		"slices: []",
		"packages: []",
		"repositories: []",
		"catalogues: []",
		"local-inputs: []",
		"platforms:",
		"  - linux/amd64",
		"provider:",
		`  release: "26.04"`,
		"  distro: ubuntu",
		"spec: sha256:" + strings.Repeat("a", 64),
		"version: 1",
		"",
	}, "\n")
	decoded, err := decodeLockfile([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := decoded.CanonicalYAML()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, encoded) {
		t.Fatalf("reordered mapping did not canonicalize:\nwant:\n%s\ngot:\n%s", canonical, encoded)
	}
}

func TestLoadLockfile_Valid(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "vapor.lock")
	data := mustCanonicalYAML(t, canonicalVectorLock())
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := LoadLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := lock.CanonicalYAML()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("loaded lock changed:\nwant:\n%s\ngot:\n%s", data, got)
	}
}

func TestLoadLockfile_ReadErrors(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.lock")
	lock, err := LoadLockfile(path)
	if lock != nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), path) {
		t.Fatalf("missing lock: lock=%#v err=%v", lock, err)
	}
	lock, err = LoadLockfile(t.TempDir())
	if lock != nil || err == nil || !strings.Contains(err.Error(), "read lock") {
		t.Fatalf("directory: lock=%#v err=%v", lock, err)
	}
}

func mustCanonicalYAML(t *testing.T, lock *Lockfile) []byte {
	t.Helper()
	data, err := lock.CanonicalYAML()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
