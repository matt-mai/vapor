package locking

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/lock"
)

func comparisonLock() *lock.Lockfile {
	return &lock.Lockfile{
		Version: 1, SpecDigest: "sha256:spec", Provider: lock.Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:   []string{"linux/amd64"},
		LocalInputs: []lock.LocalInput{{Role: "trust-key", Path: "key.asc", SHA256: "sha256:key", Size: 1}},
		Catalogues: []lock.Catalogue{{
			Name: "catalogue", Source: lock.CatalogueSource{Type: "remote", URL: "https://example.test/c", Commit: "aaa"},
			Tree: "sha256:tree", Archive: &lock.Archive{SHA256: "sha256:archive", Size: 1},
		}},
		Packages: []lock.Package{{Platform: "linux/amd64", Name: "base-files", Version: "1", Architecture: "amd64"}},
	}
}

func TestCompareIdenticalLocks(t *testing.T) {
	t.Parallel()
	comparison, err := Compare(comparisonLock(), comparisonLock())
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.Empty() || comparison.String() != "no drift" {
		t.Fatalf("comparison = %#v (%s)", comparison, comparison)
	}
}

func TestCompareMovedRefIsReportedSeparately(t *testing.T) {
	t.Parallel()
	previous := comparisonLock()
	current := comparisonLock()
	current.Catalogues[0].Source.Commit = "bbb"
	current.Catalogues[0].Tree = "sha256:moved-tree"
	current.Catalogues[0].Archive = &lock.Archive{SHA256: "sha256:moved-archive", Size: 2}
	comparison, err := Compare(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Refs) != 1 || comparison.Refs[0].From != "aaa" || comparison.Refs[0].To != "bbb" {
		t.Fatalf("refs = %#v", comparison.Refs)
	}
	if len(comparison.Changes) != 0 {
		t.Fatalf("unexpected content changes = %#v", comparison.Changes)
	}
	if !strings.Contains(comparison.String(), `ref moved: catalogue "catalogue" commit aaa -> bbb`) {
		t.Fatalf("text = %s", comparison)
	}
}

func TestCompareContentAndLocalInputDrift(t *testing.T) {
	t.Parallel()
	previous := comparisonLock()
	current := comparisonLock()
	current.LocalInputs[0].SHA256 = "sha256:changed-key"
	current.Packages[0].Version = "2"
	comparison, err := Compare(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Refs) != 0 {
		t.Fatalf("refs = %#v", comparison.Refs)
	}
	if len(comparison.Changes) != 2 {
		t.Fatalf("changes = %#v", comparison.Changes)
	}
	if comparison.Changes[0].Section != "local-input" || comparison.Changes[0].Field != "sha256" {
		t.Fatalf("local input change = %#v", comparison.Changes[0])
	}
	if comparison.Changes[1].Section != "package" || comparison.Changes[1].Field != "version" {
		t.Fatalf("package change = %#v", comparison.Changes[1])
	}
}

func TestCompareRejectsNil(t *testing.T) {
	t.Parallel()
	if _, err := Compare(nil, comparisonLock()); err == nil {
		t.Fatal("nil previous accepted")
	}
	if _, err := Compare(comparisonLock(), nil); err == nil {
		t.Fatal("nil current accepted")
	}
}
