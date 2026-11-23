package catalogue_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/catalogue"
)

func TestTree_DocumentedVectors(t *testing.T) {
	t.Parallel()
	base := []catalogue.Entry{
		{Path: "slices", Kind: catalogue.KindDir},
		{Path: "slices/base-files.yaml", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Size: 120},
		{Path: "latest", Kind: catalogue.KindSymlink, Target: "slices/base-files.yaml"},
		{Path: "bin/tool", Kind: catalogue.KindFile, Executable: true, SHA256: strings.Repeat("b", 64), Size: 5},
		{Path: "bin", Kind: catalogue.KindDir},
	}
	tree, err := catalogue.NewTree(base)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := tree.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"entries":[{"kind":"dir","path":"bin"},{"executable":true,"kind":"file","path":"bin/tool","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":5},{"kind":"symlink","path":"latest","target":"slices/base-files.yaml"},{"kind":"dir","path":"slices"},{"executable":false,"kind":"file","path":"slices/base-files.yaml","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":120}]}`
	if string(canonical) != wantJSON {
		t.Fatalf("canonical JSON = %s", canonical)
	}
	got, digestErr := tree.Digest()
	if digestErr != nil || got != "sha256:7bac2edcea6f86c9ffa94891ff7c7dce121ad2e5d0cf154a23e2fbb8ce6c7439" {
		t.Fatalf("digest = %q, %v", got, err)
	}
	empty, err := catalogue.NewTree(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := empty.Digest(); err != nil || got != "sha256:c338023bbf847fbe40c47eb5edef75f54618867cc9925ebe655dee07e78e9d88" {
		t.Fatalf("empty digest = %q, %v", got, err)
	}
}

func TestNewTree_SortsAndAddsParents(t *testing.T) {
	t.Parallel()
	tree, err := catalogue.NewTree([]catalogue.Entry{
		{Path: "z/y/file", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Size: 1},
		{Path: "a", Kind: catalogue.KindDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := tree.Entries()
	want := []catalogue.Entry{
		{Path: "a", Kind: catalogue.KindDir},
		{Path: "z", Kind: catalogue.KindDir},
		{Path: "z/y", Kind: catalogue.KindDir},
		{Path: "z/y/file", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Size: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %#v", got)
	}
	clone := tree.Entries()
	clone[0].Path = "changed"
	if tree.Entries()[0].Path != "a" {
		t.Fatal("Entries exposed internal storage")
	}
}

func TestNewTree_ResolvesNestedLinkComponents(t *testing.T) {
	t.Parallel()
	entries := []catalogue.Entry{
		{Path: "d", Kind: catalogue.KindDir},
		{Path: "x", Kind: catalogue.KindDir},
		{Path: "x/file", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Size: 1},
		{Path: "d/s", Kind: catalogue.KindSymlink, Target: "../x"},
		{Path: "link", Kind: catalogue.KindSymlink, Target: "d/s/file"},
	}
	if _, err := catalogue.NewTree(entries); err != nil {
		t.Fatal(err)
	}
}

func TestTree_ImplicitParentEntriesBounded(t *testing.T) {
	t.Parallel()
	entries := make([]catalogue.Entry, 0, 60)
	for index := range 60 {
		path := fmt.Sprintf("p%02d", index)
		for range 1990 {
			path += "/x"
		}
		entries = append(entries, catalogue.Entry{Path: path, Kind: catalogue.KindDir})
	}
	_, err := catalogue.NewTree(entries)
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("error = %v", err)
	}
}
