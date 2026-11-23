package vfs

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
)

// Kind is one image entry kind.
type Kind string

// Image entry kinds.
const (
	Dir     Kind = "directory"
	File    Kind = "file"
	Symlink Kind = "symlink"
)

// Origin identifies the input that declared an entry, so later conflicts and
// manifests can attribute a path to its contributor.
type Origin struct {
	Package string
	Slice   string
	Path    string
}

// Attrs is the metadata declared for one entry. A zero Mode is not a default:
// callers supply the resolved mode, so an omitted declaration cannot silently
// become mode 0.
type Attrs struct {
	Mode   fs.FileMode
	UID    uint32
	GID    uint32
	Origin Origin
	// Implicit marks a directory created only as a parent, so a caller can seed
	// one from source metadata without claiming the image declared it. It is
	// ignored for every other kind.
	Implicit bool
}

// Entry is one path in the tree. Traversal returns entries sorted by path.
type Entry struct {
	Path     string
	Kind     Kind
	Mode     fs.FileMode
	UID      uint32
	GID      uint32
	Size     int64
	Target   string
	Origins  []Origin
	Implicit bool
}

// Entries returns every path except the implicit root, sorted bytewise, so
// traversal never depends on declaration order or map iteration.
func (t *Tree) Entries() []Entry {
	result := make([]Entry, 0, len(t.entries))
	for name, found := range t.entries {
		if name == "/" {
			continue
		}
		result = append(result, Entry{
			Path:     name,
			Kind:     found.node.kind,
			Mode:     found.node.mode,
			UID:      found.node.uid,
			GID:      found.node.gid,
			Size:     int64(len(found.node.data)),
			Target:   found.node.target,
			Origins:  append([]Origin(nil), found.origins...),
			Implicit: found.node.implicit,
		})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result
}

// Children returns the sorted immediate entry paths of directory p, not bare
// names. Directory paths are suffixed with "/" so a caller can tell them apart
// without a lookup.
func (t *Tree) Children(p string) ([]string, error) {
	found, ok := t.entries[p]
	if !ok {
		return nil, fmt.Errorf("vfs directory %q: %w", p, ErrNotExist)
	}
	if found.node.kind != Dir {
		return nil, fmt.Errorf("vfs directory %q is a %s", p, found.node.kind)
	}
	names := make([]string, 0)
	for name, child := range t.entries {
		if name == p || path.Dir(name) != p {
			continue
		}
		if child.node.kind == Dir {
			name += "/"
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// Lookup returns the entry at p without following symlinks.
func (t *Tree) Lookup(p string) (Entry, bool) {
	found, ok := t.entries[p]
	if !ok {
		return Entry{}, false
	}
	return Entry{
		Path:     p,
		Kind:     found.node.kind,
		Mode:     found.node.mode,
		UID:      found.node.uid,
		GID:      found.node.gid,
		Size:     int64(len(found.node.data)),
		Target:   found.node.target,
		Origins:  append([]Origin(nil), found.origins...),
		Implicit: found.node.implicit,
	}, true
}

// Inodes assigns every distinct inode a stable identifier. Identifiers follow
// sorted path order, so the same tree always yields the same numbering, and two
// paths that share an inode share an identifier.
func (t *Tree) Inodes() map[string]uint64 {
	entries := t.Entries()
	ids := make(map[*node]uint64, len(entries))
	numbers := make(map[string]uint64, len(entries))
	for _, entry := range entries {
		shared := t.entries[entry.Path].node
		id, ok := ids[shared]
		if !ok {
			id = uint64(len(ids)) + 1
			ids[shared] = id
		}
		numbers[entry.Path] = id
	}
	return numbers
}
