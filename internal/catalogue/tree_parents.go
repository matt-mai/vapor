package catalogue

import (
	"fmt"
	"sort"
)

// addParentDirectories inserts a directory entry for every missing ancestor of
// the declared paths. Paths are processed in sorted order, so the ancestors of
// one deep path are also prefixes of the next; the walk for each path stops at
// the first ancestor already present, which keeps deep trees cheap.
func addParentDirectories(entries map[string]Entry) error {
	paths := make([]string, 0, len(entries))
	for name := range entries {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		if err := addParentsOf(name, entries); err != nil {
			return err
		}
	}
	return nil
}
func addParentsOf(name string, entries map[string]Entry) error {
	// Slice off components from the end instead of calling path.Dir, which
	// rescans the whole path on every step.
	for end := len(name) - 1; end > 0; end-- {
		if name[end] != '/' {
			continue
		}
		parent := name[:end]
		if _, exists := entries[parent]; exists {
			// Everything above an existing ancestor is present too.
			return nil
		}
		if len(entries) >= MaxTreeEntries {
			return fmt.Errorf("catalogue tree has more than %d entries", MaxTreeEntries)
		}
		entries[parent] = Entry{Path: parent, Kind: KindDir}
	}
	return nil
}

// maxLinkSteps bounds symlink expansion across one tree validation.
const maxLinkSteps = MaxTreeEntries * 8
