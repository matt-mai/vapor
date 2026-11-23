package vfs

import (
	"strings"
	"testing"
)

// seededParent is the Attrs a slice uses to fit an implicit parent to its archive. A
// private parent is the case that matters: 0700 is what must not be widened.
func seededParent() Attrs {
	return Attrs{Mode: 0o700, UID: 7, GID: 8, Implicit: true, Origin: Origin{Package: "private", Slice: "private_p"}}
}

// A parent a source seeded is not an empty placeholder, so a second source that
// disagrees about its mode or owner is a conflict rather than a rewrite. Treating
// it as a placeholder is how /private seeded 0700 becomes 0755.
func TestDir_SeededParentRejectsConflictingMetadata(t *testing.T) {
	conflicts := map[string]Attrs{
		"wider mode":  {Mode: 0o755, UID: 7, GID: 8, Implicit: true, Origin: Origin{Package: "other", Slice: "other_p"}},
		"other owner": {Mode: 0o700, UID: 0, GID: 0, Implicit: true, Origin: Origin{Package: "other", Slice: "other_p"}},
	}
	for name, conflict := range conflicts {
		t.Run(name, func(t *testing.T) {
			tree := New()
			if err := tree.File("/private/token", nil, attrs(0o644)); err != nil {
				t.Fatal(err)
			}
			if err := tree.Dir("/private", seededParent()); err != nil {
				t.Fatalf("seed: %v", err)
			}
			err := tree.Dir("/private", conflict)
			if err == nil || !strings.Contains(err.Error(), "conflicts with seeded") {
				t.Fatalf("error = %v", err)
			}
			parent, _ := tree.Lookup("/private")
			if parent.Mode != 0o700 || parent.UID != 7 {
				t.Fatalf("parent was rewritten: %+v", parent)
			}
		})
	}
}

// A declared directory is the image's own statement about the parent, so a
// declaration that arrives after a seed still wins. Seeding a declared parent is
// refused here; the slice applier checks first and never attempts it.
func TestDir_DeclaredParentReplacesASeededOne(t *testing.T) {
	tree := New()
	if err := tree.File("/private/token", nil, attrs(0o644)); err != nil {
		t.Fatal(err)
	}
	if err := tree.Dir("/private", seededParent()); err != nil {
		t.Fatal(err)
	}
	if err := tree.Dir("/private", attrs(0o750)); err != nil {
		t.Fatalf("declare: %v", err)
	}
	parent, _ := tree.Lookup("/private")
	if parent.Mode != 0o750 || parent.Implicit {
		t.Fatalf("parent = %+v", parent)
	}
}

// The same seeded metadata from a second source is agreement, so the path keeps
// both origins and later stages can attribute it.
func TestDir_SeededParentAcceptsAgreement(t *testing.T) {
	tree := New()
	if err := tree.File("/private/token", nil, attrs(0o644)); err != nil {
		t.Fatal(err)
	}
	first := seededParent()
	if err := tree.Dir("/private", first); err != nil {
		t.Fatal(err)
	}
	second := seededParent()
	second.Origin = Origin{Package: "other", Slice: "other_p"}
	if err := tree.Dir("/private", second); err != nil {
		t.Fatalf("agreement was refused: %v", err)
	}
	parent, _ := tree.Lookup("/private")
	if len(parent.Origins) != 2 || !parent.Implicit || parent.Mode != 0o700 {
		t.Fatalf("parent = %+v", parent)
	}
}

// A synthetic parent stays replaceable: it carries nothing of its own, which is
// what keeps the seeding above possible at all.
func TestDir_SyntheticParentIsStillReplaceable(t *testing.T) {
	tree := New()
	if err := tree.File("/private/token", nil, attrs(0o644)); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []Attrs{seededParent(), attrs(0o750)} {
		if err := tree.Dir("/private", replacement); err != nil {
			t.Fatalf("replace synthetic parent with %v: %v", replacement, err)
		}
	}
	parent, _ := tree.Lookup("/private")
	if parent.Mode != 0o750 || parent.Implicit {
		t.Fatalf("parent = %+v", parent)
	}
}
