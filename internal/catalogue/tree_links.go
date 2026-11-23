package catalogue

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

type linkResolver struct {
	entries  map[string]Entry
	resolved map[string][]string
	state    map[string]uint8
	steps    int
}

func validateLinks(entries map[string]Entry) error {
	resolver := &linkResolver{
		entries:  entries,
		resolved: make(map[string][]string),
		state:    make(map[string]uint8),
	}
	names := make([]string, 0, len(entries))
	for name, entry := range entries {
		if entry.Kind == KindSymlink {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		resolved, err := resolver.resolve(name)
		if err != nil {
			return err
		}
		if isAncestorOrSelf(joinComponents(resolved), name) {
			return fmt.Errorf("catalogue symlink %q resolves to its own ancestor", name)
		}
	}
	return nil
}

// resolve follows the target of name one component at a time so that a symlink
// met in the middle of a target is expanded before a later ".." is applied.
func (r *linkResolver) resolve(name string) ([]string, error) {
	switch r.state[name] {
	case 1:
		return nil, fmt.Errorf("catalogue symlink cycle at %q", name)
	case 2:
		return append([]string(nil), r.resolved[name]...), nil
	}
	r.state[name] = 1
	stack, err := r.walk(splitComponents(path.Dir(name)), r.entries[name].Target, name)
	if err != nil {
		return nil, err
	}
	r.state[name] = 2
	r.resolved[name] = append([]string(nil), stack...)
	return stack, nil
}
func (r *linkResolver) walk(stack []string, target, link string) ([]string, error) {
	parts := strings.Split(target, "/")
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, err := r.walkPart(stack, part, parts[i+1:], link)
		if err != nil {
			return nil, err
		}
		stack = next
	}
	return stack, nil
}
func (r *linkResolver) walkPart(stack []string, part string, rest []string, link string) ([]string, error) {
	r.steps++
	if r.steps > maxLinkSteps {
		return nil, errors.New("catalogue symlink expansion limit exceeded")
	}
	if part == ".." {
		if len(stack) == 0 {
			return nil, fmt.Errorf("catalogue symlink %q escapes the catalogue root", link)
		}
		return stack[:len(stack)-1], nil
	}
	candidate := joinComponents(append(append([]string(nil), stack...), part))
	entry, exists := r.entries[candidate]
	if exists && entry.Kind == KindSymlink {
		return r.resolve(candidate)
	}
	if exists && entry.Kind != KindDir && hasRemainingComponent(rest) {
		return nil, fmt.Errorf("catalogue symlink %q passes through non-directory %q", link, candidate)
	}
	return append(stack, part), nil
}
func splitComponents(value string) []string {
	if value == "" || value == "." {
		return nil
	}
	return strings.Split(value, "/")
}
func joinComponents(components []string) string {
	if len(components) == 0 {
		return "."
	}
	return strings.Join(components, "/")
}
func hasRemainingComponent(parts []string) bool {
	for _, part := range parts {
		if part != "" && part != "." {
			return true
		}
	}
	return false
}
func isAncestorOrSelf(candidate, name string) bool {
	return candidate == "." || candidate == name || strings.HasPrefix(name, candidate+"/")
}
