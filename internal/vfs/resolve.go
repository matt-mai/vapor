package vfs

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Resolve follows every symlink in p and returns the resulting path. Resolution
// never leaves the tree, so an absolute target is root-relative and a relative
// target is resolved against the link's parent. Missing components are kept
// literally, which lets a caller resolve a path it is about to create; a
// component that exists as a regular file is an error once anything follows it.
func (t *Tree) Resolve(p string) (string, error) {
	if err := validatePath(p, true); err != nil {
		return "", err
	}
	return t.resolve(p)
}

// ResolveUnclean follows p like Resolve but accepts a path that is not clean, so a
// caller holding one from outside the image — a loader search directory, for
// example — gets the meaning the filesystem would give it. Cleaning such a path
// first would change that meaning: "/opt/link/../lib" reaches "/real/lib" when
// "/opt/link" is a symlink, not "/opt/lib".
//
// The result is always clean, and a path that climbs above the root is refused
// rather than clamped.
func (t *Tree) ResolveUnclean(p string) (string, error) {
	if err := validateUncleanPath(p); err != nil {
		return "", err
	}
	return t.resolve(p)
}

func (t *Tree) resolve(p string) (string, error) {
	r := &resolver{tree: t, active: make(map[string]bool), budget: 8*len(t.entries) + 64}
	stack, err := r.walk(nil, strings.Split(strings.TrimPrefix(p, "/"), "/"), p)
	if err != nil {
		return "", err
	}
	return joinPath(stack), nil
}

// validateUncleanPath is validatePath without the cleanliness requirement. The
// resolver handles "." and ".." itself, so only the properties it cannot recover
// from are checked here.
func validateUncleanPath(value string) error {
	if value == "" || !path.IsAbs(value) || strings.Contains(value, "\\") ||
		strings.ContainsFunc(value, unicode.IsControl) || !utf8.ValidString(value) {
		return fmt.Errorf("vfs path %q is not an absolute POSIX path", value)
	}
	return nil
}

// resolver expands links component by component. budget bounds total work so a
// pathological target cannot expand exponentially; active detects cycles.
type resolver struct {
	tree   *Tree
	active map[string]bool
	budget int
}

func (r *resolver) walk(stack, parts []string, origin string) ([]string, error) {
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		r.budget--
		if r.budget < 0 {
			return nil, fmt.Errorf("vfs path %q exceeds the symlink expansion limit", origin)
		}
		next, err := r.step(stack, part, origin)
		if err != nil {
			return nil, err
		}
		stack = next
	}
	return stack, nil
}

// step consumes one component, expanding it when it names a symlink.
func (r *resolver) step(stack []string, part, origin string) ([]string, error) {
	if part == ".." {
		if len(stack) == 0 {
			return nil, fmt.Errorf("vfs path %q escapes the image root", origin)
		}
		return stack[:len(stack)-1], nil
	}
	if err := r.requireDirectory(stack, origin); err != nil {
		return nil, err
	}
	next := append(append([]string{}, stack...), part)
	candidate := joinPath(next)
	entry, exists := r.tree.entries[candidate]
	if !exists || entry.node.kind != Symlink {
		return next, nil
	}
	return r.expand(stack, candidate, entry.node.target)
}

// expand resolves one link's target. An absolute target restarts at the root.
func (r *resolver) expand(stack []string, link, target string) ([]string, error) {
	if r.active[link] {
		return nil, fmt.Errorf("vfs symlink cycle at %q", link)
	}
	r.active[link] = true
	defer delete(r.active, link)
	if path.IsAbs(target) {
		stack = nil
	}
	return r.walk(stack, strings.Split(target, "/"), link)
}

func (r *resolver) requireDirectory(stack []string, origin string) error {
	if len(stack) == 0 {
		return nil
	}
	entry, exists := r.tree.entries[joinPath(stack)]
	if exists && entry.node.kind != Dir {
		return fmt.Errorf("vfs path %q passes through non-directory %q", origin, joinPath(stack))
	}
	return nil
}

func joinPath(stack []string) string {
	if len(stack) == 0 {
		return "/"
	}
	return "/" + strings.Join(stack, "/")
}

// resolveParent validates that every ancestor of p is a directory and that no
// ancestor is a symlink, so a declared path is stored where it was declared.
func (t *Tree) resolveParent(p string) error {
	parent := path.Dir(p)
	if parent == "/" {
		return nil
	}
	resolved, err := t.Resolve(parent)
	if err != nil {
		return fmt.Errorf("vfs path %q: %w", p, err)
	}
	if resolved != parent {
		return fmt.Errorf("vfs path %q has a symlink ancestor resolving to %q", p, resolved)
	}
	return nil
}

// validateTarget requires a clean POSIX link target. Relative targets may use
// ".."; confinement is enforced during resolution, not here.
func validateTarget(target string) error {
	if target == "" || !utf8.ValidString(target) || strings.ContainsRune(target, 0) ||
		strings.Contains(target, "\\") || strings.ContainsFunc(target, unicode.IsControl) ||
		path.Clean(target) != target {
		return errors.New("target must be a clean POSIX path without control characters or backslashes")
	}
	return nil
}
