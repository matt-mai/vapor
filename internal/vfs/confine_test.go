package vfs

import (
	"strings"
	"testing"
)

// Each package payload is confined on its own at import, so a tree can be valid
// alone and invalid once another package's entries are merged into it.
func TestConfineLinks_ChecksTheMergedTree(t *testing.T) {
	tests := []struct {
		name  string
		first func(*Tree) error
		other func(*Tree) error
		want  string
	}{
		{
			name: "cycle through two packages",
			first: func(tree *Tree) error {
				return tree.Symlink("/a", "/b", attrs(0o777))
			},
			other: func(tree *Tree) error {
				return tree.Symlink("/b", "/a", attrs(0o777))
			},
			want: "symlink cycle",
		},
		{
			name: "link that climbs out of the root",
			first: func(tree *Tree) error {
				return tree.Symlink("/link", "/a/b", attrs(0o777))
			},
			other: func(tree *Tree) error {
				return tree.Symlink("/a", "../../etc/shadow", attrs(0o777))
			},
			want: "escapes the image root",
		},
		{
			name: "link that crosses a regular file",
			first: func(tree *Tree) error {
				return tree.Symlink("/link", "/a/b", attrs(0o777))
			},
			other: func(tree *Tree) error {
				return tree.File("/a", []byte("x"), attrs(0o644))
			},
			want: "passes through non-directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Each package is valid on its own, which import already established;
			// the second package is what makes the combined tree fail.
			tree := mustTree(t, test.first)
			other := mustTree(t, test.other)
			if err := tree.Merge(other); err != nil {
				t.Fatalf("merge: %v", err)
			}
			err := tree.ConfineLinks()
			if err == nil {
				t.Fatal("the merged tree accepted a link it should refuse")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// A link to nothing is a normal image state, so the check reports only links that
// cannot work.
func TestConfineLinks_AllowsAMissingTarget(t *testing.T) {
	tree := mustTree(t, func(tree *Tree) error {
		return tree.Symlink("/link", "/missing", attrs(0o777))
	})
	if err := tree.ConfineLinks(); err != nil {
		t.Fatalf("ConfineLinks: %v", err)
	}
}
