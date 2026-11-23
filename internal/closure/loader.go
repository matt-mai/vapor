package closure

import (
	"bytes"
	"debug/elf"
	"fmt"
	"path"
	"slices"

	"github.com/matt-mai/vapor/internal/vfs"
)

// chain is the RPATH chain one executable passes to an object, with the executable it
// started from. Two executables can reach the same object and each must be judged
// against its own chain, so the chain is remembered with its root rather than on its
// own.
type chain struct {
	root string
	dirs inherited
}

// inheritRpaths reports, for each object the loader can reach, the RPATH directories
// it inherits from the objects that load it.
//
// glibc uses a loader's DT_RPATH for that loader's own dependencies and for
// everything they pull in, so a library may find its sibling through the
// executable's RPATH. DT_RUNPATH is not inherited: it applies only to the object
// that carries it, and an object that carries one searches only its own. A library
// that no executable reaches is not loaded at all, so it inherits nothing; it is
// still checked, because a missing dependency there is a defect whether or not
// something loads it today.
//
// Traversal state and inherited state are separate: an object is expanded once, but
// the directories it passes on are computed from its own chain, so a chain of any
// length carries the executable's RPATH to its end. Walk order is kept per executable,
// because the directories one executable inherits do not apply in another's process:
// when two chains reach the same object, the first one is recorded and a differing
// one is checked on its own.
func inheritRpaths(tree *vfs.Tree, t target, objects map[string]*bytes.Reader) (map[string]chain, []error) {
	result := make(map[string]chain, len(objects))
	roots := loaderRoots(objects)
	failures := make([]error, 0, len(roots))
	for _, root := range roots {
		failures = append(failures, walkRoot(tree, t, root, objects, result)...)
	}
	return result, failures
}

// walkRoot expands one executable's dependencies and returns the chains that cannot
// reach an object's dependencies.
//
// Every executable is walked even when another chain already reached it: the
// directories a chain carries describe one process, so an object two executables load
// searches the chain of the executable that loaded it. Each step carries the chain its
// own root produced, and an object is expanded once per root, so a shared library's
// dependencies are resolved in every process that maps it.
func walkRoot(tree *vfs.Tree, t target, root string, objects map[string]*bytes.Reader,
	reachable map[string]chain) []error {
	var failures []error
	// claimed holds the objects this root expanded, so a chain that loops stops and
	// two executables that share a library each expand it in their own process.
	claimed := make(map[string]bool, len(objects))
	queue := []step{{path: root}}
	claimed[root] = true
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		loaded, next := loadedObjects(tree, t, current.path, current.from, objects)
		for _, resolved := range loaded {
			expand, err := reachObject(tree, t, root, current.path, resolved, next, reachable, objects)
			if err != nil {
				failures = append(failures, err)
			}
			if !expand || claimed[resolved] {
				continue
			}
			claimed[resolved] = true
			queue = append(queue, step{path: resolved, from: next})
		}
	}
	return failures
}

// step is one object to expand with the RPATH chain its root gives it.
type step struct {
	path string
	from inherited
}

// reachObject records the chain that reaches an object from this root, or checks it
// when this root already reached the object by another chain. It reports whether the
// object still has to be expanded by this root, which is exactly when the chain is the
// first this root produced for it.
func reachObject(tree *vfs.Tree, t target, root, from, resolved string, next inherited,
	reachable map[string]chain, objects map[string]*bytes.Reader,
) (bool, error) {
	recorded, reached := reachable[resolved]
	if !reached {
		reachable[resolved] = chain{root: root, dirs: next}
		return true, nil
	}
	if recorded.root == root {
		if slices.Equal(recorded.dirs, next) {
			return false, nil
		}
		return false, checkChain(tree, t, from, resolved, next, objects)
	}
	return true, checkChain(tree, t, from, resolved, next, objects)
}

// checkChain reports whether an object can load its dependencies from the chain that
// reached it from root.
func checkChain(tree *vfs.Tree, t target, from, p string, dirs inherited,
	objects map[string]*bytes.Reader) error {
	file, err := parse(objects[p])
	if err != nil {
		return nil // reported by the object's own check
	}
	search, err := searchDirs(file, t, path.Dir(p), dirs)
	if err != nil {
		return nil
	}
	needed, err := importedLibraries(file)
	if err != nil {
		return nil
	}
	for _, name := range needed {
		if _, ok := resolveNeeded(tree, name, search); !ok {
			return fmt.Errorf("%s: needs %s, which is not found by the search path reaching it from %s",
				p, name, from)
		}
	}
	return nil
}

// loaderRoots returns the objects the loader starts from: those with a program
// interpreter. A library nothing reaches is never loaded, so it inherits nothing.
func loaderRoots(objects map[string]*bytes.Reader) []string {
	var roots []string
	for _, p := range sortedPaths(objects) {
		file, err := parse(objects[p])
		if err != nil {
			continue
		}
		if interpreter, err := interpreterOf(file); err == nil && interpreter != "" {
			roots = append(roots, p)
		}
	}
	return roots
}

// loadedObjects returns the objects p loads and the RPATH chain it passes to them.
func loadedObjects(tree *vfs.Tree, t target, p string, from inherited,
	objects map[string]*bytes.Reader,
) ([]string, inherited) {
	file, err := parse(objects[p])
	if err != nil {
		return nil, from
	}
	dirs, err := searchDirs(file, t, path.Dir(p), from)
	if err != nil {
		return nil, from
	}
	own, err := rpathDirs(file, path.Dir(p))
	if err != nil {
		return nil, from
	}
	next := append(append(inherited(nil), from...), own...)
	needed, err := importedLibraries(file)
	if err != nil {
		return nil, next
	}
	search := dirs
	var loaded []string
	for _, name := range needed {
		if resolved, ok := resolveNeeded(tree, name, search); ok {
			loaded = append(loaded, resolved)
		}
	}
	return loaded, next
}

// rpathDirs returns the expanded DT_RPATH directories of an object, which are the
// ones it passes on to the objects it loads. An object that carries DT_RUNPATH
// passes on nothing: its RPATH is disabled, so children never see it.
func rpathDirs(file *elf.File, objectDir string) ([]string, error) {
	rpath, _, err := dynamicPaths(file, elf.DT_RPATH)
	if err != nil {
		return nil, err
	}
	if _, present, err := dynamicPaths(file, elf.DT_RUNPATH); err != nil || present {
		return nil, err
	}
	return expandDirs(rpath, objectDir), nil
}
