package lock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestCatalogueTree_DocumentedVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../../docs/developer/lock-schema.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "### Catalogue tree\n")
	if !ok {
		t.Fatal("catalogue tree section missing")
	}
	section, _, _ = strings.Cut(section, "### Selected-definition closure\n")
	pattern := regexp.MustCompile("(?s)```json\n(.*?)\n```\n\nDigest:\n\n```text\n(sha256:[a-f0-9]{64})\n```")
	vectors := pattern.FindAllStringSubmatch(section, -1)
	if len(vectors) != 3 {
		t.Fatalf("got %d tree vectors, want 3", len(vectors))
	}
	for _, vector := range vectors {
		var payload map[string][]map[string]any
		decoder := json.NewDecoder(strings.NewReader(vector[1]))
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			t.Fatal(err)
		}
		entries := payload["entries"]
		checkDocumentedTreeParents(t, entries)
		canonical, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != vector[1] {
			t.Fatal("tree vector is not canonical JSON")
		}
		sum := sha256.Sum256(append([]byte("vapor.lock.catalogue-tree.v1\x00"), canonical...))
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != vector[2] {
			t.Fatalf("tree digest = %s, want %s", got, vector[2])
		}
		slices.Reverse(entries)
		slices.SortFunc(entries, func(a, b map[string]any) int { return strings.Compare(a["path"].(string), b["path"].(string)) })
		reordered, err := json.Marshal(payload)
		if err != nil || !bytes.Equal(canonical, reordered) {
			t.Fatalf("tree enumeration order changed canonical bytes: %v", err)
		}
	}
}

func checkDocumentedTreeParents(t *testing.T, entries []map[string]any) {
	t.Helper()
	kinds := make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry["path"].(string)
		if name == "." || path.IsAbs(name) || path.Clean(name) != name || kinds[name] != "" {
			t.Fatalf("invalid or duplicate vector path %q", name)
		}
		kinds[name] = entry["kind"].(string)
	}
	for name := range kinds {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if kinds[parent] != "dir" {
				t.Fatalf("vector path %q has missing/non-directory parent %q", name, parent)
			}
		}
	}
}
