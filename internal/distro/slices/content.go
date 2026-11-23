package slices

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// DefaultSynthesizedDirMode is the mode of a directory created by `make`.
const DefaultSynthesizedDirMode fs.FileMode = 0o755

// DefaultSynthesizedFileMode is the mode of a file created by `text`.
const DefaultSynthesizedFileMode fs.FileMode = 0o644

// Source is one verified package payload, already extracted into a tree. The
// tree is read-only for selection: content operations copy from it and never
// modify it.
type Source struct {
	Package string
	Tree    *vfs.Tree
}

// SelectedContent is the result of applying the content declarations of one
// selected slice.
type SelectedContent struct {
	// Tree holds exactly the selected entries. Every entry carries the slice
	// that declared it, so later conflicts and manifests can attribute it.
	Tree *vfs.Tree
	// Temporary lists the paths that every declaration gave `until: mutate`, so
	// later removal deletes them. A path one slice keeps permanently is not
	// temporary, however many other slices asked for it to go.
	Temporary []string
	// Mutable lists the paths declared mutable, which only the mutation stage
	// may rewrite.
	Mutable []string
	// Original records the selected bytes of every mutable path, so a later
	// mutation can tell an unchanged file from one that was rewritten and
	// reverted.
	Original map[string]string
}

// ApplyContent applies the content declarations of the selected slices to a new
// tree, copying from verified sources. Slices are applied in the given order, so
// callers pass the dependency-first order from SelectSlices. Declarations
// filtered out by architecture are skipped. It never runs a script and never
// mutates a source tree.
//
// catalogue is the validated package set the selection came from, and it is how a
// preference chain is traversed through providers the image does not contain: a
// chain aaa -> bbb -> ccc still decides between aaa and ccc when bbb is not
// selected. A nil catalogue falls back to the selected slices alone, which only
// resolves preferences whose every link is selected.
func ApplyContent(selected []Slice, sources map[string]*Source, architecture string,
	catalogue map[string]*Package) (*SelectedContent, error) {
	if len(selected) == 0 {
		return nil, errors.New("content selection requires a selected slice")
	}
	preferred, err := selectionPreferences(selected, architecture, catalogue)
	if err != nil {
		return nil, err
	}
	result := &SelectedContent{Tree: vfs.New(), Original: make(map[string]string)}
	applier := &contentApplier{sources: sources, result: result, preferred: preferred,
		retained: make(map[string]bool), linked: make(map[linkedInode]string),
		inodes: make(map[*vfs.Tree]map[string]uint64)}
	for i := range selected {
		if err := applier.applySlice(&selected[i], architecture); err != nil {
			return nil, err
		}
	}
	result.Temporary = applier.temporaryPaths()
	slices.Sort(result.Mutable)
	return result, nil
}

type contentApplier struct {
	slice     *Slice
	sources   map[string]*Source
	result    *SelectedContent
	preferred map[string]string
	// retained records paths that some declaration keeps permanently, so a
	// temporary declaration of the same path cannot remove them.
	retained map[string]bool
	// linked maps a source inode to the first target that carried it, so a source
	// hard link stays a hard link instead of becoming an independent copy. The key
	// includes the package because two packages number their inodes separately.
	linked map[linkedInode]string
	// inodes caches each source tree's numbering. A source is unchanged while it is
	// applied, and a broad slice copies hundreds of files from one package, so the
	// numbering is built once per source rather than once per file.
	inodes map[*vfs.Tree]map[string]uint64
}

// sourceInode returns the inode identifier of one path in a source tree, numbering the
// tree the first time it is asked.
func (a *contentApplier) sourceInode(tree *vfs.Tree, p string) uint64 {
	ids, ok := a.inodes[tree]
	if !ok {
		ids = tree.Inodes()
		a.inodes[tree] = ids
	}
	return ids[p]
}

// linkedInode identifies one inode within one source package.
type linkedInode struct {
	pkg   string
	inode uint64
}

// applySlice applies one selected slice, skipping declarations that the
// architecture filters out and paths another selected package provides.
func (a *contentApplier) applySlice(slice *Slice, architecture string) error {
	if slice.Package == "" || slice.Name == "" {
		return errors.New("content selection requires a selected slice")
	}
	a.slice = slice
	for _, contentPath := range sortedKeys(slice.Contents) {
		info := slice.Contents[contentPath]
		if !architectureIncluded(info.Arch, architecture) {
			continue
		}
		if provider := a.preferred[contentPath]; provider != "" && provider != slice.Package {
			continue
		}
		if err := a.apply(contentPath, &info); err != nil {
			return err
		}
	}
	return nil
}
func (a *contentApplier) apply(contentPath string, info *PathInfo) error {
	if info.Kind == PathGenerate {
		return fmt.Errorf("slice %s path %s requests %q, which Vapor does not support",
			a.sliceKey(), contentPath, info.Generate)
	}
	// A glob is matched against the declared pattern, where a trailing slash is
	// what distinguishes a directory match; exact declarations are stored in the
	// tree's clean form, and the root is implicit rather than declarable.
	if info.Kind == PathGlob {
		return a.glob(contentPath, info)
	}
	contentPath = strings.TrimSuffix(contentPath, "/")
	if contentPath == "" {
		if info.Kind != PathDir {
			return fmt.Errorf("slice %s declares root as %q", a.sliceKey(), info.Kind)
		}
		return nil
	}
	if err := a.operation(contentPath, info); err != nil {
		return err
	}
	a.record(contentPath, info)
	return nil
}
func (a *contentApplier) operation(contentPath string, info *PathInfo) error {
	switch info.Kind {
	case PathDir:
		return a.result.Tree.Dir(contentPath, a.dirAttrs(info))
	case PathText:
		return a.result.Tree.File(contentPath, []byte(info.Info), a.fileAttrs(info))
	case PathSymlink:
		return a.symlink(contentPath, info)
	case PathCopy:
		return a.copy(contentPath, info)
	default:
		return fmt.Errorf("slice %s path %s has unsupported kind %q", a.sliceKey(), contentPath, info.Kind)
	}
}
func (a *contentApplier) dirAttrs(info *PathInfo) vfs.Attrs {
	return vfs.Attrs{Mode: modeOrDefault(info.Mode, DefaultSynthesizedDirMode), Origin: a.origin("")}
}
func (a *contentApplier) fileAttrs(info *PathInfo) vfs.Attrs {
	return vfs.Attrs{Mode: modeOrDefault(info.Mode, DefaultSynthesizedFileMode), Origin: a.origin("")}
}
func (a *contentApplier) symlink(contentPath string, info *PathInfo) error {
	if info.Mode != 0 {
		return fmt.Errorf("slice %s path %s sets a mode on a symlink", a.sliceKey(), contentPath)
	}
	if err := a.result.Tree.Symlink(contentPath, info.Info, vfs.Attrs{Origin: a.origin("")}); err != nil {
		return err
	}
	// A declared link must stay inside the image; a dangling target is fine.
	_, err := a.result.Tree.Resolve(contentPath)
	return err
}
func (a *contentApplier) record(contentPath string, info *PathInfo) {
	if info.Until == UntilMutate {
		a.result.Temporary = append(a.result.Temporary, contentPath)
	} else {
		a.retained[contentPath] = true
	}
	if !info.Mutable {
		return
	}
	a.result.Mutable = append(a.result.Mutable, contentPath)
	if content, err := a.result.Tree.Read(contentPath); err == nil {
		a.result.Original[contentPath] = fmt.Sprintf("%x", sha256.Sum256(content))
	}
}

// temporaryPaths returns the temporary paths in sorted order, dropping any that
// another declaration retains permanently.
func (a *contentApplier) temporaryPaths() []string {
	seen := make(map[string]bool, len(a.result.Temporary))
	paths := make([]string, 0, len(a.result.Temporary))
	for _, contentPath := range a.result.Temporary {
		if a.retained[contentPath] || seen[contentPath] {
			continue
		}
		seen[contentPath] = true
		paths = append(paths, contentPath)
	}
	slices.Sort(paths)
	return paths
}
func (a *contentApplier) source(pkgName string) (*Source, error) {
	source, ok := a.sources[pkgName]
	if !ok || source == nil || source.Tree == nil {
		return nil, fmt.Errorf("slice %s has no verified content for package %q", a.sliceKey(), pkgName)
	}
	return source, nil
}
func (a *contentApplier) origin(sourcePath string) vfs.Origin {
	return vfs.Origin{Package: a.slice.Package, Slice: a.sliceKey(), Path: sourcePath}
}
func (a *contentApplier) sliceKey() string {
	return SliceKey{Package: a.slice.Package, Slice: a.slice.Name}.String()
}

// glob applies one glob declaration. Expansion walks the verified source in
// sorted order, so the same archive always produces the same selection, and a
// pattern that matches nothing fails instead of silently selecting nothing.
func (a *contentApplier) glob(contentPath string, info *PathInfo) error {
	source, err := a.source(a.slice.Package)
	if err != nil {
		return err
	}
	matches := source.matching(contentPath)
	if len(matches) == 0 {
		return fmt.Errorf("slice %s glob %s matches no content in package %q", a.sliceKey(), contentPath,
			source.Package)
	}
	for _, match := range matches {
		if err := a.copyEntry(match, match, info); err != nil {
			return err
		}
		a.record(match, info)
	}
	return nil
}

// matching returns the source paths selected by a pattern, in sorted order.
func (s *Source) matching(pattern string) []string {
	var matched []string
	for _, entry := range s.Tree.Entries() {
		// Directories are matched with the trailing slash upstream tarball paths
		// carry, so a pattern without one selects files only.
		candidate := entry.Path
		if entry.Kind == vfs.Dir {
			candidate += "/"
		}
		if globMatches(pattern, candidate) {
			matched = append(matched, entry.Path)
		}
	}
	return matched
}
