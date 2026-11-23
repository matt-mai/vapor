package catalogue

import (
	"errors"

	"github.com/matt-mai/vapor/internal/schema/lock"
)

// LockedTree rebuilds the tree and checks its digest against the lock.
func LockedTree(record *lock.Catalogue) (Tree, error) {
	if len(record.Manifest) == 0 {
		return Tree{}, errors.New("manifest is empty")
	}
	entries := make([]Entry, len(record.Manifest))
	for i := range record.Manifest {
		entry := &record.Manifest[i]
		entries[i] = Entry{
			Path: entry.Path, Kind: EntryKind(entry.Kind), Executable: entry.Executable,
			SHA256: entry.SHA256, Size: entry.Size, Target: entry.Target,
		}
	}
	tree, err := NewTree(entries)
	if err != nil {
		return Tree{}, err
	}
	digest, err := tree.Digest()
	if err != nil {
		return Tree{}, err
	}
	if digest != record.Tree {
		return Tree{}, errors.New("manifest does not match tree digest")
	}
	return tree, nil
}
