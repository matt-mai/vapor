// Package catalogue snapshots catalogue trees and computes their canonical identity.
package catalogue

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
)

const (
	// MaxTreeEntries bounds a catalogue snapshot before entries are exposed.
	MaxTreeEntries = 100_000
	// MaxTreeFileSize bounds one regular catalogue file.
	MaxTreeFileSize int64 = 64 << 20
	// MaxTreeContentSize bounds all regular file bytes in one snapshot.
	MaxTreeContentSize int64 = 256 << 20
	// MaxTreePathSize bounds catalogue-relative entry paths.
	MaxTreePathSize = 4096
	// MaxTreeTargetSize bounds symlink target strings.
	MaxTreeTargetSize = 4096

	treeDomain = "vapor.lock.catalogue-tree.v1"
)

// EntryKind is one canonical catalogue entry kind.
type EntryKind string

// Catalogue entry kinds.
const (
	KindDir     EntryKind = "dir"
	KindFile    EntryKind = "file"
	KindSymlink EntryKind = "symlink"
)

// Entry is one canonical catalogue tree entry.
type Entry struct {
	Path       string
	Kind       EntryKind
	Executable bool
	SHA256     string
	Size       int64
	Target     string
}

// Tree is a validated, path-sorted catalogue tree.
type Tree struct {
	entries []Entry
}

// NewTree validates entries, adds omitted parent directories, sorts by path and
// checks symlink confinement and cycles.
func NewTree(entries []Entry) (Tree, error) {
	if len(entries) > MaxTreeEntries {
		return Tree{}, fmt.Errorf("catalogue tree has more than %d entries", MaxTreeEntries)
	}
	byPath, err := indexEntries(entries)
	if err != nil {
		return Tree{}, err
	}
	if err := addParentDirectories(byPath); err != nil {
		return Tree{}, err
	}
	result := sortedEntries(byPath)
	if err := validateParents(byPath, result); err != nil {
		return Tree{}, err
	}
	if err := validateLinks(byPath); err != nil {
		return Tree{}, err
	}
	return Tree{entries: result}, nil
}
func indexEntries(entries []Entry) (map[string]Entry, error) {
	byPath := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		if err := validateEntry(&entry); err != nil {
			return nil, err
		}
		if _, exists := byPath[entry.Path]; exists {
			return nil, fmt.Errorf("catalogue tree contains duplicate path %q", entry.Path)
		}
		byPath[entry.Path] = entry
	}
	return byPath, nil
}
func sortedEntries(byPath map[string]Entry) []Entry {
	result := make([]Entry, 0, len(byPath))
	for _, entry := range byPath {
		result = append(result, entry)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result
}
func validateParents(byPath map[string]Entry, result []Entry) error {
	for _, entry := range result {
		parent := path.Dir(entry.Path)
		if parent != "." && byPath[parent].Kind != KindDir {
			return fmt.Errorf("catalogue tree path %q has non-directory parent", entry.Path)
		}
	}
	return nil
}

// Entries returns a copy of the validated tree entries.
func (tree Tree) Entries() []Entry {
	return append([]Entry(nil), tree.entries...)
}

// CanonicalJSON returns the canonical catalogue-tree payload.
func (tree Tree) CanonicalJSON() ([]byte, error) {
	entries := make([]any, len(tree.entries))
	for i, entry := range tree.entries {
		switch entry.Kind {
		case KindDir:
			entries[i] = struct {
				Kind string `json:"kind"`
				Path string `json:"path"`
			}{string(entry.Kind), entry.Path}
		case KindFile:
			entries[i] = struct {
				Executable bool   `json:"executable"`
				Kind       string `json:"kind"`
				Path       string `json:"path"`
				SHA256     string `json:"sha256"`
				Size       int64  `json:"size"`
			}{entry.Executable, string(entry.Kind), entry.Path, entry.SHA256, entry.Size}
		case KindSymlink:
			entries[i] = struct {
				Kind   string `json:"kind"`
				Path   string `json:"path"`
				Target string `json:"target"`
			}{string(entry.Kind), entry.Path, entry.Target}
		default:
			return nil, fmt.Errorf("catalogue tree entry %q has unsupported kind", entry.Path)
		}
	}
	payload := struct {
		Entries []any `json:"entries"`
	}{entries}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode catalogue tree: %w", err)
	}
	return encoded, nil
}

// Digest returns the domain-separated SHA256 identity of CanonicalJSON.
func (tree Tree) Digest() (string, error) {
	encoded, err := tree.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(treeDomain+"\x00"), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
