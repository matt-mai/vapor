package synthesis

import (
	"fmt"

	"github.com/matt-mai/vapor/internal/vfs"
)

// The helpers here replace image state rather than merging into it. A synthesis
// pass owns the paths it writes: a selected package may have supplied a
// different kind of entry, and the declared state wins.

// writeFile writes content at a path, creating it if absent and replacing
// whatever was there otherwise.
func writeFile(tree *vfs.Tree, location string, content []byte, origin vfs.Origin) error {
	entry, ok := tree.Lookup(location)
	if !ok {
		return tree.File(location, content, vfs.Attrs{Mode: 0o644, Origin: origin})
	}
	if entry.Kind == vfs.File {
		return tree.ReplaceFile(location, content)
	}
	if err := replaceable(tree, location); err != nil {
		return err
	}
	if err := tree.Remove(location); err != nil {
		return err
	}
	return tree.File(location, content, vfs.Attrs{Mode: 0o644, Origin: origin})
}

// replaceable refuses to replace a directory that still holds entries. Removing it
// would leave its children under a non-directory, which is not a filesystem tree
// at all; the caller has to decide what to do with them.
func replaceable(tree *vfs.Tree, location string) error {
	entry, ok := tree.Lookup(location)
	if !ok || entry.Kind != vfs.Dir {
		return nil
	}
	children, err := tree.Children(location)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return fmt.Errorf("%s is a nonempty directory and cannot be replaced", location)
	}
	return nil
}

// replaceWithSymlink points a path at a target, replacing a different entry.
func replaceWithSymlink(tree *vfs.Tree, location, target string, origin vfs.Origin) error {
	entry, ok := tree.Lookup(location)
	if ok && entry.Kind == vfs.Symlink && entry.Target == target {
		return nil
	}
	if ok {
		if err := replaceable(tree, location); err != nil {
			return err
		}
		if err := tree.Remove(location); err != nil {
			return err
		}
	}
	return tree.Symlink(location, target, vfs.Attrs{Origin: origin})
}
