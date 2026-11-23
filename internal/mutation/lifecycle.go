package mutation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// Selection is the content a mutation run works on: the tree the selection
// produced, the paths only mutation may rewrite, and the paths that survive
// mutation only until it finishes.
type Selection struct {
	// Tree is the selected content. ApplyContent produced it.
	Tree *vfs.Tree
	// Mutable lists the paths a script may rewrite.
	Mutable []string
	// Temporary lists the paths that every declaration marked `until: mutate`.
	// They stay readable through every script and are removed afterwards.
	Temporary []string
}

// Validate rejects a selection that cannot be mutated, so a caller learns about a
// missing tree or an undeclared path before a worker starts.
func (s Selection) Validate() error {
	if s.Tree == nil {
		return errors.New("mutation requires an image tree")
	}
	for _, name := range s.Mutable {
		if _, ok := s.Tree.Lookup(cleanPath(name)); !ok {
			return fmt.Errorf("mutation mutable path %q is not in the image", name)
		}
	}
	for _, name := range s.Temporary {
		if _, ok := s.Tree.Lookup(cleanPath(name)); !ok {
			return fmt.Errorf("mutation temporary path %q is not in the image", name)
		}
	}
	return nil
}

// LifecycleResult reports what a mutation run did to the temporary content.
type LifecycleResult struct {
	// Removed lists the paths the run deleted, in removal order.
	Removed []string
	// EmptyDirectories lists the temporary directories that became empty and were
	// removed after their children.
	EmptyDirectories []string
}

// RunScripts runs requests in the given order against the selection, then removes
// the temporary content. Scripts run in dependency order, which the caller
// supplies; this stage never reorders them.
//
// The run is all-or-nothing: a failure at any point, including a removal failure,
// leaves the selection's tree exactly as it was, so a retry starts from the same
// content.
func RunScripts(ctx context.Context, selection Selection, requests []Request, limits SandboxLimits) (
	*Result, *LifecycleResult, error,
) {
	if err := selection.Validate(); err != nil {
		return nil, nil, err
	}
	staged := selection.Tree.Clone()
	result, err := Mutate(ctx, staged, selection.Mutable, requests, limits)
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := removeTemporary(staged, selection.Temporary)
	if err != nil {
		return nil, nil, err
	}
	if err := selection.Tree.Replace(staged); err != nil {
		return nil, nil, err
	}
	return result, lifecycle, nil
}

// removeTemporary deletes the temporary content, files before directories and
// directories deepest first, so a parent is only tried after its children are
// gone. A directory that is still non-empty is kept: another declaration owns its
// content, and an empty-directory cleanup must never delete that.
func removeTemporary(tree *vfs.Tree, temporary []string) (*LifecycleResult, error) {
	result := &LifecycleResult{}
	files, dirs := splitTemporary(tree, temporary)
	for _, name := range files {
		if err := tree.Remove(name); err != nil {
			return nil, fmt.Errorf("mutation cannot remove temporary path %q: %w", name, err)
		}
		result.Removed = append(result.Removed, name)
	}
	for _, name := range dirs {
		empty, err := isEmptyDirectory(tree, name)
		if err != nil {
			return nil, err
		}
		if !empty {
			continue
		}
		if err := tree.Remove(name); err != nil {
			return nil, fmt.Errorf("mutation cannot remove temporary directory %q: %w", name, err)
		}
		result.EmptyDirectories = append(result.EmptyDirectories, name)
	}
	return result, nil
}

// splitTemporary separates the temporary paths into files and directories, with
// directories ordered deepest first so children are removed before parents.
func splitTemporary(tree *vfs.Tree, temporary []string) (files, dirs []string) {
	for _, name := range temporary {
		name = cleanPath(name)
		entry, ok := tree.Lookup(name)
		if !ok {
			continue
		}
		// An implicit parent is not a declaration, so no slice asked for it to go.
		if entry.Implicit {
			continue
		}
		if entry.Kind == vfs.Dir {
			dirs = append(dirs, name)
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	sort.Slice(dirs, func(left, right int) bool {
		if len(dirs[left]) != len(dirs[right]) {
			return len(dirs[left]) > len(dirs[right])
		}
		return dirs[left] > dirs[right]
	})
	return files, dirs
}

// cleanPath drops the trailing slash a directory declaration carries, so a caller
// may pass either form.
func cleanPath(name string) string {
	return strings.TrimSuffix(name, "/")
}

// isEmptyDirectory reports whether a directory has no children left. A path that
// is no longer a directory is not empty in the sense that matters here: something
// replaced it, so it is not cleanup's to remove.
func isEmptyDirectory(tree *vfs.Tree, name string) (bool, error) {
	entry, ok := tree.Lookup(name)
	if !ok {
		return false, nil
	}
	if entry.Kind != vfs.Dir {
		return false, fmt.Errorf("mutation temporary path %q is no longer a directory", name)
	}
	children, err := tree.Children(name)
	if err != nil {
		return false, err
	}
	return len(children) == 0, nil
}
