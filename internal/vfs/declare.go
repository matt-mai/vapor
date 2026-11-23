package vfs

import (
	"errors"
	"fmt"
)

// Declare applies one declared filesystem entry without destroying existing
// content. An absent directory is created, an absent file becomes an empty
// regular file, and an absent symlink is created with target. An existing entry
// keeps its bytes and receives only the declared metadata; a different kind or a
// different symlink target is a conflict.
//
// Symlink metadata applies to the link itself, never to its target, so declaring
// ownership of a link does not touch whatever it points at.
func (t *Tree) Declare(p string, kind Kind, attrs Attrs, target string) error {
	if err := validateDeclaration(p, kind, attrs, target); err != nil {
		return err
	}
	if err := t.resolveParent(p); err != nil {
		return err
	}
	if err := t.addParents(p); err != nil {
		return err
	}
	existing, exists := t.entries[p]
	if !exists {
		return t.create(p, kind, attrs, target)
	}
	if err := existing.merge(p, kind, attrs, target); err != nil {
		return err
	}
	existing.origins = appendOrigin(existing.origins, attrs.Origin)
	return nil
}

func validateDeclaration(p string, kind Kind, attrs Attrs, target string) error {
	switch kind {
	case Dir, File, Symlink:
	default:
		return fmt.Errorf("vfs declared path %q has unsupported kind %q", p, kind)
	}
	if err := validatePath(p, kind == Dir); err != nil {
		return err
	}
	if p == "/" {
		return errors.New("vfs root directory is implicit and cannot be declared")
	}
	if kind != Symlink {
		if target != "" {
			return fmt.Errorf("vfs %s %q must not declare a target", kind, p)
		}
	} else if err := validateTarget(target); err != nil {
		return fmt.Errorf("vfs symlink %q: %w", p, err)
	}
	if attrs.Mode&^permissionBits != 0 {
		return fmt.Errorf("vfs %s %q: mode has non-permission bits", kind, p)
	}
	return nil
}

// merge applies declared metadata to an existing compatible entry, keeping its
// content. A different kind or symlink target is a conflict, never a replacement.
// The node is copied rather than mutated, because a clone shares nodes with the
// tree it was cloned from.
func (e *entry) merge(p string, kind Kind, attrs Attrs, target string) error {
	if e.node.kind != kind {
		return fmt.Errorf("vfs declared %s %q conflicts with existing %s", kind, p, e.node.kind)
	}
	if kind == Symlink && e.node.target != target {
		return fmt.Errorf("vfs declared symlink %q conflicts with existing target %q", p, e.node.target)
	}
	merged := *e.node
	if kind == Symlink {
		merged.mode = SymlinkMode
	} else {
		merged.mode = attrs.Mode
	}
	merged.uid, merged.gid = attrs.UID, attrs.GID
	merged.implicit = false
	e.node = &merged
	return nil
}

func (t *Tree) create(p string, kind Kind, attrs Attrs, target string) error {
	switch kind {
	case Dir:
		return t.Dir(p, attrs)
	case File:
		return t.File(p, nil, attrs)
	default:
		return t.Symlink(p, target, attrs)
	}
}
