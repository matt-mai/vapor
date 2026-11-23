// Package vfs is an in-memory image filesystem with deterministic traversal.
package vfs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// ImplicitDirMode is the mode of a directory created only as a parent.
	ImplicitDirMode fs.FileMode = 0o755
	// SymlinkMode is the mode reported for every symlink.
	SymlinkMode fs.FileMode = 0o777

	permissionBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
)

// ErrNotExist reports a path the tree does not contain. Callers that treat a
// missing path as ordinary state match it with errors.Is instead of inspecting
// the message.
var ErrNotExist = errors.New("vfs path does not exist")

// node is one inode. Hard links are several paths naming the same node.
type node struct {
	kind     Kind
	mode     fs.FileMode
	uid, gid uint32
	data     []byte
	target   string
	implicit bool
}

// entry is one path name and the inputs that declared it.
type entry struct {
	node    *node
	origins []Origin
}

// Tree is a mutable image filesystem keyed by clean absolute path.
type Tree struct {
	entries map[string]*entry
}

// New returns a tree containing only the implicit root directory. Root is not a
// traversable entry, so it is never serialized; it exists so that lookups and
// listings of "/" behave like any other directory.
func New() *Tree {
	return &Tree{entries: map[string]*entry{
		"/": {node: &node{kind: Dir, mode: ImplicitDirMode, implicit: true}},
	}}
}

// Dir creates a directory, or applies explicit metadata to an implicit parent.
//
// An implicit directory is one created only as a parent. It is reported as
// implicit and is not removable, so a caller that seeds a parent from a source
// archive's metadata still marks it implicit: the image never declared it.
func (t *Tree) Dir(p string, attrs Attrs) error {
	return t.add(p, &node{kind: Dir, mode: attrs.Mode, uid: attrs.UID, gid: attrs.GID,
		implicit: attrs.Implicit}, []Origin{attrs.Origin})
}

// File creates a regular file holding a copy of data.
func (t *Tree) File(p string, data []byte, attrs Attrs) error {
	return t.add(p, &node{kind: File, mode: attrs.Mode, uid: attrs.UID, gid: attrs.GID,
		data: append([]byte{}, data...)}, []Origin{attrs.Origin})
}

// Symlink creates a symbolic link. Link modes are not settable, so attrs.Mode is
// ignored and SymlinkMode is reported instead.
func (t *Tree) Symlink(p, target string, attrs Attrs) error {
	if err := validateTarget(target); err != nil {
		return fmt.Errorf("vfs symlink %q: %w", p, err)
	}
	return t.add(p, &node{kind: Symlink, mode: SymlinkMode, uid: attrs.UID, gid: attrs.GID,
		target: target}, []Origin{attrs.Origin})
}

// ClearModeBits removes bits from the mode of every entry that has one, in a
// single pass over the tree. Each distinct inode is replaced once and every name
// of a hard link is repointed to the same replacement, so the names keep sharing
// an inode. Clearing one path at a time would rescan the tree per file, which is
// quadratic on a tree with many privileged files.
func (t *Tree) ClearModeBits(bits fs.FileMode) error {
	if bits&^permissionBits != 0 {
		return errors.New("vfs mode bits include non-permission bits")
	}
	replacements := make(map[*node]*node)
	for _, entry := range t.entries {
		if entry.node.kind == Symlink || entry.node.mode&bits == 0 {
			continue
		}
		if _, done := replacements[entry.node]; done {
			continue
		}
		replacement := *entry.node
		replacement.mode = entry.node.mode &^ bits
		replacements[entry.node] = &replacement
	}
	for _, entry := range t.entries {
		if replacement, ok := replacements[entry.node]; ok {
			entry.node = replacement
		}
	}
	return nil
}

// Hardlink adds p as another name for the regular file at target. Both names
// then share one inode, so they also share mode, ownership and content.
func (t *Tree) Hardlink(p, target string, origin Origin) error {
	if err := validatePath(p, false); err != nil {
		return err
	}
	if err := validatePath(target, false); err != nil {
		return fmt.Errorf("vfs hardlink %q: %w", p, err)
	}
	shared, ok := t.entries[target]
	if !ok {
		return fmt.Errorf("vfs hardlink %q: target %q does not exist", p, target)
	}
	if shared.node.kind != File {
		return fmt.Errorf("vfs hardlink %q: target %q is a %s", p, target, shared.node.kind)
	}
	return t.addHardlink(p, target, []Origin{origin})
}

// Read returns a copy of the content of the regular file at p.
func (t *Tree) Read(p string) ([]byte, error) {
	data, err := t.fileData(p)
	if err != nil {
		return nil, err
	}
	return append([]byte{}, data...), nil
}

// OpenFile reads the current regular-file contents without copying them. Replacing
// the file does not change an already opened reader.
func (t *Tree) OpenFile(p string) (*bytes.Reader, error) {
	data, err := t.fileData(p)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

func (t *Tree) fileData(p string) ([]byte, error) {
	found, ok := t.entries[p]
	if !ok {
		return nil, fmt.Errorf("vfs path %q: %w", p, ErrNotExist)
	}
	if found.node.kind != File {
		return nil, fmt.Errorf("vfs path %q is a %s", p, found.node.kind)
	}
	return found.node.data, nil
}

// Remove deletes one path. Root and implicit parents cannot be removed, because
// they are not declarations. Removing one name of a hard link leaves the other
// names and the content intact.
func (t *Tree) Remove(p string) error {
	found, ok := t.entries[p]
	if !ok {
		return fmt.Errorf("vfs path %q: %w", p, ErrNotExist)
	}
	if p == "/" || found.node.implicit {
		return fmt.Errorf("vfs path %q is implicit and cannot be removed", p)
	}
	delete(t.entries, p)
	return nil
}

func (t *Tree) add(p string, n *node, origins []Origin) error {
	if err := validatePath(p, n.kind == Dir); err != nil {
		return err
	}
	if n.mode&^permissionBits != 0 {
		return fmt.Errorf("vfs %s %q: mode has non-permission bits", n.kind, p)
	}
	if err := t.resolveParent(p); err != nil {
		return err
	}
	if err := t.addParents(p); err != nil {
		return err
	}
	existing, exists := t.entries[p]
	if !exists {
		t.entries[p] = &entry{node: n, origins: slices.Clone(origins)}
		return nil
	}
	if existing.node.implicit && n.kind == Dir {
		return t.adoptImplicit(p, existing, n, origins)
	}
	if !sameNode(existing.node, n) {
		return fmt.Errorf("vfs %s %q conflicts with existing %s", n.kind, p, existing.node.kind)
	}
	for _, origin := range origins {
		existing.origins = appendOrigin(existing.origins, origin)
	}
	return nil
}

// adoptImplicit records a directory that replaces an implicit parent. A parent the
// image never declared but a source did seed is not an empty placeholder: it carries
// that source's mode and owner, so a second source must agree about them instead of
// replacing them. Replacing is how a 0700 parent becomes 0755 just because the wider
// source arrived second.
func (t *Tree) adoptImplicit(p string, existing *entry, n *node, origins []Origin) error {
	if p == "/" {
		return errors.New("vfs root directory is implicit and cannot be declared")
	}
	if !n.implicit || len(existing.origins) == 0 {
		t.entries[p] = &entry{node: n, origins: slices.Clone(origins)}
		return nil
	}
	if !sameNode(existing.node, n) {
		return fmt.Errorf("vfs directory %q: metadata %v %d:%d conflicts with seeded %v %d:%d",
			p, n.mode, n.uid, n.gid, existing.node.mode, existing.node.uid, existing.node.gid)
	}
	for _, origin := range origins {
		existing.origins = appendOrigin(existing.origins, origin)
	}
	return nil
}

// addHardlink adds p as another name for an existing regular file node.
func (t *Tree) addHardlink(p, target string, origins []Origin) error {
	if err := validatePath(p, false); err != nil {
		return err
	}
	if err := t.resolveParent(p); err != nil {
		return err
	}
	if err := t.addParents(p); err != nil {
		return err
	}
	wanted := t.entries[target].node
	if existing, exists := t.entries[p]; exists {
		if existing.node != wanted {
			if !sameNode(existing.node, wanted) {
				return fmt.Errorf("vfs hardlink %q conflicts with existing %s", p, existing.node.kind)
			}
			// The path already holds identical content in its own inode, so the two
			// link groups are reconciled rather than refused. Every name on the old
			// inode moves with it: repointing only p would split a group this tree
			// already declared.
			t.repointNode(existing.node, wanted)
		}
		for _, origin := range origins {
			existing.origins = appendOrigin(existing.origins, origin)
		}
		return nil
	}
	t.entries[p] = &entry{node: wanted, origins: slices.Clone(origins)}
	return nil
}

// repointNode makes every name on one inode share another, which merges two link
// groups without changing any content.
func (t *Tree) repointNode(from, to *node) {
	for _, found := range t.entries {
		if found.node == from {
			found.node = to
		}
	}
}

// addParents creates missing ancestor directories. An ancestor that exists as a
// non-directory is a conflict rather than a reason to replace it.
func (t *Tree) addParents(p string) error {
	for parent := path.Dir(p); parent != "/"; parent = path.Dir(parent) {
		existing, exists := t.entries[parent]
		if exists {
			if existing.node.kind != Dir {
				return fmt.Errorf("vfs path %q has non-directory ancestor %q", p, parent)
			}
			continue
		}
		t.entries[parent] = &entry{node: &node{kind: Dir, mode: ImplicitDirMode, implicit: true}}
	}
	return nil
}

func sameNode(left, right *node) bool {
	return left.kind == right.kind && left.mode == right.mode && left.uid == right.uid &&
		left.gid == right.gid && left.target == right.target && bytes.Equal(left.data, right.data)
}

func appendOrigin(origins []Origin, origin Origin) []Origin {
	if slices.Contains(origins, origin) {
		return origins
	}
	return append(origins, origin)
}

// validatePath requires a clean absolute POSIX path. Root is a directory only.
func validatePath(value string, allowRoot bool) error {
	if value == "" || !path.IsAbs(value) || path.Clean(value) != value || value == "/" && !allowRoot ||
		strings.Contains(value, "\\") || strings.ContainsFunc(value, unicode.IsControl) ||
		!utf8.ValidString(value) {
		return fmt.Errorf("vfs path %q is not a clean absolute POSIX path", value)
	}
	return nil
}
