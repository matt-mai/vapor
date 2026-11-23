package slices

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// copy copies one entry from a verified source. Directory selection is not
// recursive: only the named directory is copied, and its children arrive through
// their own declarations.
func (a *contentApplier) copy(contentPath string, info *PathInfo) error {
	sourcePath := info.Info
	if sourcePath == "" {
		sourcePath = contentPath
	}
	return a.copyEntry(sourcePath, contentPath, info)
}

// copyFile places one regular file, reusing an entry already placed from the same
// source inode so the source's hard links stay hard links.
func (a *contentApplier) copyFile(source *Source, found *vfs.Entry, sourcePath, contentPath string,
	info *PathInfo,
) error {
	attrs := vfs.Attrs{Mode: copiedMode(info, found.Mode), UID: found.UID, GID: found.GID,
		Origin: a.origin(sourcePath)}
	key := linkedInode{pkg: a.slice.Package, inode: a.sourceInode(source.Tree, sourcePath)}
	if first, ok := a.linked[key]; ok {
		return a.linkExisting(contentPath, first, attrs)
	}
	content, err := source.Tree.Read(sourcePath)
	if err != nil {
		return err
	}
	if err := a.result.Tree.File(contentPath, content, attrs); err != nil {
		return err
	}
	a.linked[key] = contentPath
	return nil
}

// lookupSource resolves a declared source path against a verified package tree.
// A directory source is normally spelled with a trailing slash while the tree
// stores clean paths, so the slash is checked against the entry instead of being
// used as a lookup key.
func (a *contentApplier) lookupSource(source *Source, sourcePath string) (vfs.Entry, string, error) {
	wantsDir := strings.HasSuffix(sourcePath, "/")
	sourcePath = strings.TrimSuffix(sourcePath, "/")
	found, ok := source.Tree.Lookup(sourcePath)
	if !ok {
		return vfs.Entry{}, "", fmt.Errorf("slice %s path %s is missing from package %q",
			a.sliceKey(), sourcePath, source.Package)
	}
	if wantsDir && found.Kind != vfs.Dir {
		return vfs.Entry{}, "", fmt.Errorf("slice %s path %s is not a directory in package %q",
			a.sliceKey(), sourcePath, source.Package)
	}
	return found, sourcePath, nil
}

// linkExisting adds contentPath as another name for an entry already placed from
// the same source inode. A hard link shares one mode and one owner, so a
// declaration that disagrees about either is a conflict rather than an override.
func (a *contentApplier) linkExisting(contentPath, first string, attrs vfs.Attrs) error {
	existing, ok := a.result.Tree.Lookup(first)
	if !ok {
		return fmt.Errorf("slice %s path %s lost its placed source %s", a.sliceKey(), contentPath, first)
	}
	if existing.Mode != attrs.Mode || existing.UID != attrs.UID || existing.GID != attrs.GID {
		return fmt.Errorf("slice %s path %s conflicts with existing copy at %s", a.sliceKey(), contentPath, first)
	}
	return a.result.Tree.Hardlink(contentPath, first, attrs.Origin)
}

// copyEntry reproduces one source entry at targetPath. A glob uses the source
// path as its own target, while an explicit copy may rename.
func (a *contentApplier) copyEntry(sourcePath, contentPath string, info *PathInfo) error {
	source, err := a.source(a.slice.Package)
	if err != nil {
		return err
	}
	found, sourcePath, err := a.lookupSource(source, sourcePath)
	if err != nil {
		return err
	}
	if err := a.seedParents(source, sourcePath, contentPath); err != nil {
		return err
	}
	switch found.Kind {
	case vfs.Dir:
		if info.Mode != 0 {
			return fmt.Errorf("slice %s path %s sets a mode on a copied directory", a.sliceKey(), contentPath)
		}
		return a.result.Tree.Dir(contentPath, vfs.Attrs{Mode: found.Mode, UID: found.UID, GID: found.GID,
			Origin: a.origin(sourcePath)})
	case vfs.File:
		return a.copyFile(source, &found, sourcePath, contentPath, info)
	case vfs.Symlink:
		if err := a.result.Tree.Symlink(contentPath, found.Target, vfs.Attrs{UID: found.UID, GID: found.GID,
			Origin: a.origin(sourcePath)}); err != nil {
			return err
		}
		_, err := a.result.Tree.Resolve(contentPath)
		return err
	default:
		return fmt.Errorf("slice %s path %s has unsupported kind %q", a.sliceKey(), sourcePath, found.Kind)
	}
}

// seedParents creates the ancestors of a copied entry from the source archive's
// directory metadata when the declaration did not name them. Selecting only
// /private/token from an archive whose /private is 0700 must not widen /private to
// the implicit 0755, which would make the copied file readable to every user in
// the image.
//
// A seeded parent is implicit: the image did not declare it, so it is not
// removable and is reported as a parent rather than as content. An ancestor the
// image declared explicitly is left alone, which keeps the explicit-parent
// conflict rules intact: a declaration that names the parent wins over the
// source. An ancestor that is only implicit was created as a side effect of an
// earlier declaration, so it is seeded too: a synthetic 0755 parent must not
// outrank the archive's 0700 just because it appeared first.
func (a *contentApplier) seedParents(source *Source, sourcePath, contentPath string) error {
	// Each target ancestor pairs with the source ancestor at the same distance from
	// the entry, so a copy that renames still reads the right directory.
	var seeds []parentSeed
	target, from := path.Dir(contentPath), path.Dir(sourcePath)
	for target != "/" {
		seeds = append(seeds, parentSeed{target: target, source: from})
		target, from = path.Dir(target), path.Dir(from)
	}
	// Shallowest first: creating a deep parent creates its ancestors as implicit
	// 0755 entries, so seeding in the other order would leave them at that mode.
	slices.Reverse(seeds)
	for _, seed := range seeds {
		if existing, exists := a.result.Tree.Lookup(seed.target); exists && !existing.Implicit {
			continue
		}
		found, ok := source.Tree.Lookup(seed.source)
		if !ok || found.Kind != vfs.Dir || found.Implicit {
			continue
		}
		attrs := vfs.Attrs{Mode: found.Mode, UID: found.UID, GID: found.GID, Implicit: true,
			Origin: a.origin(seed.source)}
		if err := a.result.Tree.Dir(seed.target, attrs); err != nil {
			return err
		}
	}
	return nil
}

// parentSeed pairs a target ancestor with the source ancestor it is seeded from.
type parentSeed struct {
	target string
	source string
}

// copiedMode applies an explicit mode override. An omitted mode forwards the
// source mode, which is the documented resolution of the upstream ambiguity: the
// copy keeps the permissions it was extracted with.
func copiedMode(info *PathInfo, sourceMode fs.FileMode) fs.FileMode {
	if info.Mode == 0 {
		return sourceMode
	}
	return fileMode(info.Mode)
}
