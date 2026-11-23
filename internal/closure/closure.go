// Package closure verifies that every dynamic ELF object in an image tree can
// find its program interpreter and shared libraries.
package closure

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"sort"

	"github.com/matt-mai/vapor/internal/vfs"
)

type target struct {
	class   elf.Class
	machine elf.Machine
	triplet string
}

var targets = map[string]target{
	"linux/amd64": {elf.ELFCLASS64, elf.EM_X86_64, "x86_64-linux-gnu"},
	"linux/arm64": {elf.ELFCLASS64, elf.EM_AARCH64, "aarch64-linux-gnu"},
}

// Check reports every dynamic object in tree that cannot reach its interpreter or
// a DT_NEEDED library. All failures are returned together, in path order.
func Check(tree *vfs.Tree, platform string) error {
	if tree == nil {
		return errors.New("closure requires an image tree")
	}
	t, ok := targets[platform]
	if !ok {
		return fmt.Errorf("closure: unsupported platform %q", platform)
	}
	objects, failures := elfObjects(tree)
	inheritedDirs, chainFailures := inheritRpaths(tree, t, objects)
	failures = append(failures, chainFailures...)
	for _, p := range sortedPaths(objects) {
		if !examined(tree, inheritedDirs, p) {
			continue
		}
		failures = append(failures, checkObject(tree, t, p, objects[p], inheritedDirs[p].dirs)...)
	}
	return errors.Join(failures...)
}

// elfObjects reads the ELF objects the loader can reach, keyed by path. A file too
// small to hold the magic is skipped before it is read, and a read failure is
// collected with the other failures rather than ending the check, so one unreadable
// file does not hide the rest.
//
// A file the loader neither runs nor maps is not an object, whatever its first
// bytes say. Distribution packages ship ELF test fixtures: Go's source tree alone
// carries objects for a dozen machines, and a foreign machine or a deliberately
// malformed header there is not an image defect. The loader starts from the files
// it can execute, so an object with an execute bit is always inspected, and
// everything else only if an executable asks for it by name as a dependency.
func elfObjects(tree *vfs.Tree) (map[string]*bytes.Reader, []error) {
	objects := make(map[string]*bytes.Reader)
	var failures []error
	var magic [len(elfMagic)]byte
	for _, entry := range tree.Entries() {
		if entry.Kind != vfs.File || entry.Size < int64(len(elfMagic)) {
			continue
		}
		reader, err := tree.OpenFile(entry.Path)
		if err == nil {
			_, err = reader.ReadAt(magic[:], 0)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: cannot be read for closure checking", entry.Path))
		} else if string(magic[:]) == elfMagic {
			objects[entry.Path] = reader
		}
	}
	return objects, failures
}

// examined reports whether an object is one the closure must hold for: something
// the loader can execute, or something an executable reached through its
// dependencies. Test fixtures and documentation copies are neither.
func examined(tree *vfs.Tree, inheritedDirs map[string]chain, p string) bool {
	if _, reached := inheritedDirs[p]; reached {
		return true
	}
	entry, ok := tree.Lookup(p)
	return ok && entry.Mode&0o111 != 0
}

// elfMagic is the four-byte prefix every ELF object starts with.
const elfMagic = "\x7fELF"

// sortedPaths returns the keys of objects in sorted order, so a check reports the
// same failures in the same order every time.
func sortedPaths(objects map[string]*bytes.Reader) []string {
	paths := make([]string, 0, len(objects))
	for p := range objects {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
