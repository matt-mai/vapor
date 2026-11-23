package lock

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func canonicalVectorLock() *Lockfile {
	return &Lockfile{
		Version:    1,
		SpecDigest: "sha256:" + strings.Repeat("a", 64),
		Provider:   Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:  []string{"linux/amd64"},
	}
}

const (
	canonicalVectorJSON = `{"version":1,"spec":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider":{"distro":"ubuntu","release":"26.04"},"platforms":["linux/amd64"],"local-inputs":[],"catalogues":[],"repositories":[],"packages":[],"slices":[],"artifacts":[]}`
	canonicalVectorYAML = `version: 1
spec: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
provider:
  distro: ubuntu
  release: "26.04"
platforms:
  - linux/amd64
local-inputs: []
catalogues: []
repositories: []
packages: []
slices: []
artifacts: []
`
)

func TestCanonicalLockfile_Vectors(t *testing.T) {
	t.Parallel()
	lock := canonicalVectorLock()
	jsonBytes, err := lock.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(jsonBytes) != canonicalVectorJSON {
		t.Fatalf("canonical JSON changed:\nwant:\n%s\ngot:\n%s", canonicalVectorJSON, jsonBytes)
	}
	yamlBytes, err := lock.CanonicalYAML()
	if err != nil {
		t.Fatal(err)
	}
	if string(yamlBytes) != canonicalVectorYAML {
		t.Fatalf("canonical YAML changed:\nwant:\n%s\ngot:\n%s", canonicalVectorYAML, yamlBytes)
	}
}

func TestLockfile_CanonicalRoundTrip(t *testing.T) {
	t.Parallel()
	_, multi := validMultiPlatformLock(t)
	multi.LocalInputs = append(multi.LocalInputs, LocalInput{Role: "ca", Path: "ca.pem", SHA256: strings.Repeat("f", 64), Size: 7})
	multi.Catalogues = append(multi.Catalogues, Catalogue{
		Name:    "alpha",
		Source:  CatalogueSource{Type: "local", Path: "alpha"},
		Tree:    "sha256:" + strings.Repeat("9", 64),
		Archive: nil,
	})
	for _, lock := range []*Lockfile{canonicalVectorLock(), multi} {
		for _, encode := range []struct {
			name string
			fn   func(*Lockfile) ([]byte, error)
		}{
			{"json", (*Lockfile).CanonicalJSON},
			{"yaml", (*Lockfile).CanonicalYAML},
		} {
			first, err := encode.fn(lock)
			if err != nil {
				t.Fatalf("%s encode: %v", encode.name, err)
			}
			decoded, err := decodeLockfile(first)
			if err != nil {
				t.Fatalf("%s decode: %v", encode.name, err)
			}
			second, err := encode.fn(decoded)
			if err != nil {
				t.Fatalf("%s re-encode: %v", encode.name, err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("%s round trip changed bytes:\nfirst:  %s\nsecond: %s", encode.name, first, second)
			}
			decodedAgain, err := decodeLockfile(second)
			if err != nil {
				t.Fatalf("%s second decode: %v", encode.name, err)
			}
			if !reflect.DeepEqual(decoded, decodedAgain) {
				t.Fatalf("%s second decode differs", encode.name)
			}
		}
	}
}

func TestLockfile_CanonicalDoesNotMutate(t *testing.T) {
	t.Parallel()
	_, lock := validMultiPlatformLock(t)
	before, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if _, encodeErr := lock.CanonicalJSON(); encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if _, encodeErr := lock.CanonicalYAML(); encodeErr != nil {
		t.Fatal(encodeErr)
	}
	after, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("canonical encoding mutated the lock")
	}
}

func TestLockfile_CanonicalNil(t *testing.T) {
	t.Parallel()
	var lock *Lockfile
	if _, err := lock.CanonicalJSON(); err == nil {
		t.Fatal("nil lock JSON accepted")
	}
	if _, err := lock.CanonicalYAML(); err == nil {
		t.Fatal("nil lock YAML accepted")
	}
}

func TestCanonicalLockfile_SortsAndPreserves(t *testing.T) {
	t.Parallel()
	_, lock := validMultiPlatformLock(t)
	lock.LocalInputs = append(lock.LocalInputs,
		LocalInput{Role: "ca", Path: "z.pem", SHA256: strings.Repeat("1", 64), Size: 1},
		LocalInput{Role: "ca", Path: "a.pem", SHA256: strings.Repeat("2", 64), Size: 2},
	)
	lock.Catalogues[0].Name = "z"
	lock.Catalogues = append(lock.Catalogues, Catalogue{Name: "a", Source: CatalogueSource{Type: "local", Path: "a"}, Tree: lock.Catalogues[0].Tree})
	lock.Platforms = []string{"linux/arm64", "linux/amd64"}
	lock.Packages[0], lock.Packages[1] = lock.Packages[1], lock.Packages[0]
	lock.Slices[0].Selected = []string{"release-info", "copyright"}
	lock.Slices[0].Closure = []string{"release-info", "copyright", "etc", "lib"}

	encoded, err := lock.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeLockfile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Platforms, []string{"linux/arm64", "linux/amd64"}) {
		t.Fatalf("platform order changed: %v", decoded.Platforms)
	}
	if decoded.LocalInputs[0].Path != "a.pem" || decoded.LocalInputs[1].Path != "z.pem" || decoded.LocalInputs[2].Path != "keys/repo.asc" {
		t.Fatalf("local inputs not sorted: %+v", decoded.LocalInputs)
	}
	if decoded.Catalogues[0].Name != "a" || decoded.Catalogues[1].Name != "z" {
		t.Fatalf("catalogues not sorted: %+v", decoded.Catalogues)
	}
	if decoded.Packages[0].Platform != "linux/amd64" || decoded.Packages[1].Platform != "linux/arm64" {
		t.Fatalf("packages not sorted: %+v", decoded.Packages)
	}
	if !reflect.DeepEqual(decoded.Slices[0].Selected, []string{"release-info", "copyright"}) {
		t.Fatalf("selected order changed: %v", decoded.Slices[0].Selected)
	}
	if !reflect.DeepEqual(decoded.Slices[0].Closure, []string{"release-info", "copyright", "etc", "lib"}) {
		t.Fatalf("closure order changed: %v", decoded.Slices[0].Closure)
	}
}

func TestLockfile_CanonicalRejectsInvalidText(t *testing.T) {
	t.Parallel()
	lock := canonicalVectorLock()
	lock.SpecDigest = "\xff"
	if _, err := lock.CanonicalJSON(); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	lock = canonicalVectorLock()
	lock.Artifacts = []Artifact{{Name: "x", Platform: "linux/amd64"}}
	if _, err := lock.CanonicalJSON(); err == nil {
		t.Fatal("nil unpack accepted")
	}
}
