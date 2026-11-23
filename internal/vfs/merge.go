package vfs

import (
	"errors"
	"fmt"
	"slices"
)

// Merge applies every declared entry of other to t. Entries that already exist
// are accepted only when they are identical, in which case both origins are
// kept; anything else is a conflict. A whole-package replacement therefore
// cannot overwrite a path it does not reproduce byte for byte.
//
// Source-seeded parents keep their metadata, but never replace declared entries.
func (t *Tree) Merge(other *Tree) error {
	if other == nil {
		return nil
	}
	staged := t.clone()
	shared := make(map[*node]string, len(other.entries))
	entries := other.Entries()
	for i := range entries {
		entry := &entries[i]
		if entry.Implicit && !staged.needsParentSeed(entry) {
			continue
		}
		if err := staged.mergeEntry(other, entry, shared); err != nil {
			return err
		}
	}
	t.entries = staged.entries
	return nil
}

// Clone returns an independent copy of the tree. Nodes are shared because nothing
// in the package mutates a node in place; a caller that needs to change content
// uses ReplaceFile, which replaces the node instead.
func (t *Tree) Clone() *Tree {
	return t.clone()
}

// Replace swaps the tree's contents for other's, so a staged tree can be committed
// in one step. It fails rather than silently doing nothing when other is not a
// tree.
func (t *Tree) Replace(other *Tree) error {
	if other == nil {
		return errors.New("vfs replace requires a tree")
	}
	t.entries = other.clone().entries
	return nil
}

// ReplaceFile swaps one regular file's bytes, keeping its metadata and origins.
// The node is replaced rather than mutated, so trees that share it are unaffected.
func (t *Tree) ReplaceFile(p string, data []byte) error {
	found, ok := t.entries[p]
	if !ok {
		return fmt.Errorf("vfs path %q: %w", p, ErrNotExist)
	}
	if found.node.kind != File {
		return fmt.Errorf("vfs %s %q is not a regular file", found.node.kind, p)
	}
	replacement := *found.node
	replacement.data = append([]byte{}, data...)
	found.node = &replacement
	return nil
}

// clone copies the path table so a failed merge can be discarded. Nodes are
// shared because merging never mutates them.
func (t *Tree) clone() *Tree {
	entries := make(map[string]*entry, len(t.entries))
	for name, found := range t.entries {
		entries[name] = &entry{node: found.node, origins: slices.Clone(found.origins)}
	}
	return &Tree{entries: entries}
}

func (t *Tree) needsParentSeed(seed *Entry) bool {
	// Synthetic parents have no origin; applying their children recreates them.
	existing := t.entries[seed.Path]
	return len(seed.Origins) != 0 && (existing == nil || (existing.node.implicit && len(existing.origins) == 0))
}

func (t *Tree) mergeEntry(other *Tree, entry *Entry, shared map[*node]string) error {
	source := other.entries[entry.Path]
	switch entry.Kind {
	case Dir:
		return t.add(entry.Path, source.node, source.origins)
	case Symlink:
		return t.add(entry.Path, &node{kind: Symlink, mode: SymlinkMode, uid: entry.UID,
			gid: entry.GID, target: entry.Target}, source.origins)
	case File:
		if existing, ok := shared[source.node]; ok {
			return t.addHardlink(entry.Path, existing, source.origins)
		}
		shared[source.node] = entry.Path
		return t.add(entry.Path, &node{kind: File, mode: entry.Mode, uid: entry.UID, gid: entry.GID,
			data: append([]byte{}, source.node.data...)}, source.origins)
	default:
		return fmt.Errorf("vfs merge of %q has unsupported kind %q", entry.Path, entry.Kind)
	}
}
