package slices_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestFixtures_ProvenanceAndIntegrity(t *testing.T) {
	const root = "testdata/chisel-v3"
	data, readErr := os.ReadFile(filepath.Join(root, "provenance.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var provenance struct {
		License   string `json:"license"`
		Baselines map[string]struct {
			Commit string `json:"commit"`
		} `json:"baselines"`
		Files map[string]string `json:"files"`
	}
	if decodeErr := json.Unmarshal(data, &provenance); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if provenance.License != "CC0-1.0" {
		t.Fatalf("unexpected fixture license %q", provenance.License)
	}
	for repo, commit := range map[string]string{
		"chisel":          "0a817bd22133d928ff8c3f3fcd5241ca877cbe06",
		"chisel-releases": "5500a569c5cf448afda69b25079230d4049fb530",
	} {
		if got := provenance.Baselines[repo].Commit; got != commit {
			t.Fatalf("%s pin = %q, want %q; refresh baselines deliberately", repo, got, commit)
		}
	}
	if len(provenance.Files) == 0 {
		t.Fatal("fixture inventory is empty")
	}
	for name, want := range provenance.Files {
		t.Run(name, func(t *testing.T) {
			if !fs.ValidPath(name) {
				t.Fatalf("invalid fixture path %q", name)
			}
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
				t.Fatalf("fixture SHA256 = %s, want %s; review before updating provenance", got, want)
			}
			if filepath.Ext(name) == ".json" && !json.Valid(data) {
				t.Fatal("invalid JSON fixture")
			}
		})
	}
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk fixtures: %w", err)
		}
		if entry.IsDir() || entry.Name() == "README.md" || entry.Name() == "provenance.json" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relative fixture path: %w", err)
		}
		if _, ok := provenance.Files[filepath.ToSlash(rel)]; !ok {
			return fmt.Errorf("fixture %s is missing from provenance", rel)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
}
