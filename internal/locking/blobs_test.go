package locking

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// digestOf returns a fake but well-formed digest that differs by seed.
func digestOf(seed string) string {
	return strings.Repeat(seed, 64/len(seed))[:64]
}

func TestBlobsListsEveryLockedReference(t *testing.T) {
	t.Parallel()
	file := lock.CatalogueEntry{Path: "chisel.yaml", Kind: string(catalogue.KindFile), SHA256: digestOf("a"), Size: 1}
	link := lock.CatalogueEntry{Path: "main", Kind: string(catalogue.KindSymlink), Target: "chisel.yaml"}
	tree, err := catalogue.NewTree([]catalogue.Entry{
		{Path: file.Path, Kind: catalogue.KindFile, SHA256: file.SHA256, Size: file.Size},
		{Path: link.Path, Kind: catalogue.KindSymlink, Target: link.Target},
	})
	if err != nil {
		t.Fatal(err)
	}
	treeDigest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	lockfile := &lock.Lockfile{
		LocalInputs: []lock.LocalInput{{Role: "ca", Path: "ca.pem", SHA256: digestOf("b"), Size: 2}},
		Catalogues: []lock.Catalogue{{
			Name: "custom", Tree: treeDigest, Manifest: []lock.CatalogueEntry{file, link},
			Archive: &lock.Archive{SHA256: digestOf("c"), Size: 3},
		}},
		Repositories: []lock.Repository{{
			Name:    "debian",
			Trust:   lock.RepositoryTrust{Keys: []lock.RepositoryKey{{Fingerprint: "fpr", SHA256: digestOf("d"), Size: 4}}},
			Release: lock.RepositoryRelease{SHA256: digestOf("e"), Size: 5, Signature: &lock.Content{SHA256: digestOf("f"), Size: 6}},
			Indexes: []lock.Index{{Path: "main/binary-amd64/Packages.xz", SHA256: digestOf("0"), Size: 7}},
		}},
		Packages: []lock.Package{{Name: "openssl", Content: lock.Content{SHA256: digestOf("1"), Size: 8}}},
		Slices:   []lock.Slice{{Package: "base-files", Content: lock.Content{SHA256: digestOf("2"), Size: 9}}},
		Artifacts: []lock.Artifact{
			{Name: "tool", URL: "https://example.com/tool", SHA256: digestOf("3"), Size: 10},
			{Name: "tool", Platform: "linux/arm64", SHA256: digestOf("3"), Size: 10},
		},
	}
	blobs, err := Blobs(lockfile)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{
		`local input "ca.pem"`:                                      2,
		`catalogue "custom" file "chisel.yaml"`:                     1,
		`catalogue "custom" archive`:                                3,
		`repository "debian" key "fpr"`:                             4,
		`repository "debian" release`:                               5,
		`repository "debian" release signature`:                     6,
		`repository "debian" index "main/binary-amd64/Packages.xz"`: 7,
		`package "openssl"`:                                         8,
		`slice "base-files"`:                                        9,
		`artifact "tool"`:                                           10,
	}
	// The same artifact digest on two platforms stays two entries so the audit still
	// counts both records, so the second one is expected twice.
	if len(blobs) != len(want)+1 {
		t.Fatalf("blobs = %d, want %d: %+v", len(blobs), len(want)+1, blobs)
	}
	seen := make(map[string]int, len(want)+1)
	for i := range blobs {
		size, ok := want[blobs[i].Label]
		if !ok {
			t.Fatalf("unexpected blob %q", blobs[i].Label)
		}
		seen[blobs[i].Label]++
		if seen[blobs[i].Label] > 1 && blobs[i].Label != `artifact "tool"` {
			t.Fatalf("blob %q repeated", blobs[i].Label)
		}
		if blobs[i].Size != size {
			t.Fatalf("blob %q size = %d, want %d", blobs[i].Label, blobs[i].Size, size)
		}
		if len(blobs[i].Digest) != 64 {
			t.Fatalf("blob %q digest = %q", blobs[i].Label, blobs[i].Digest)
		}
	}
	if blobs[0].Read {
		t.Fatal("repository evidence is marked for reading; verification already read it")
	}
	if blobs[len(blobs)-1].Digest != blobs[len(blobs)-2].Digest {
		t.Fatal("artifact entries do not share a digest")
	}
}

func TestBlobsReadsEveryNonRepositoryEntry(t *testing.T) {
	t.Parallel()
	lockfile := &lock.Lockfile{
		LocalInputs: []lock.LocalInput{{Path: "ca.pem", SHA256: digestOf("b"), Size: 2}},
		Packages:    []lock.Package{{Name: "openssl", Content: lock.Content{SHA256: digestOf("1"), Size: 8}}},
	}
	blobs, err := Blobs(lockfile)
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range blobs {
		if !blob.Read {
			t.Fatalf("blob %q is not audited", blob.Label)
		}
	}
}

func TestBlobsRejectsAManifestThatDoesNotMatchItsTree(t *testing.T) {
	t.Parallel()
	_, err := Blobs(&lock.Lockfile{Catalogues: []lock.Catalogue{{
		Name:     "custom",
		Tree:     digestOf("f"),
		Manifest: []lock.CatalogueEntry{{Path: "chisel.yaml", Kind: string(catalogue.KindFile), SHA256: digestOf("a"), Size: 1}},
	}}})
	if err == nil || !strings.Contains(err.Error(), `catalogue "custom" manifest`) {
		t.Fatalf("mismatched manifest = %v", err)
	}
}

func TestBlobsRejectsNilLock(t *testing.T) {
	t.Parallel()
	if _, err := Blobs(nil); err == nil {
		t.Fatal("nil lock accepted")
	}
}
