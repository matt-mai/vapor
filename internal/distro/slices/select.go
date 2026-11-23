package slices

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SelectSlices resolves selected slices and their essential closure for one
// architecture. wholePackages is the resolved whole-package set; selecting a
// slice from any of those packages is rejected. The result is dependency-first
// and contains each selected slice once.
func SelectSlices(packages map[string]*Package, requests []SliceKey, wholePackages []string,
	architecture string) ([]SliceKey, error) {
	if packages == nil {
		return nil, errors.New("slice selection requires packages")
	}
	roots := append([]SliceKey(nil), requests...)
	slices.SortFunc(roots, func(a, b SliceKey) int {
		return strings.Compare(a.String(), b.String())
	})
	whole := make(map[string]bool, len(wholePackages))
	for _, name := range wholePackages {
		whole[name] = true
	}
	selector := sliceSelector{
		packages:     packages,
		architecture: architecture,
		whole:        whole,
		state:        make(map[SliceKey]uint8),
		position:     make(map[SliceKey]int),
	}
	for _, root := range roots {
		if err := selector.visit(root); err != nil {
			return nil, err
		}
	}
	return selector.order, nil
}

type sliceSelector struct {
	packages     map[string]*Package
	architecture string
	whole        map[string]bool
	state        map[SliceKey]uint8
	stack        []SliceKey
	position     map[SliceKey]int
	order        []SliceKey
}

func (selector *sliceSelector) visit(key SliceKey) error {
	switch selector.state[key] {
	case 1:
		return fmt.Errorf("essential loop detected: %s",
			joinCycle(selector.stack[selector.position[key]:]))
	case 2:
		return nil
	}
	slice, err := selector.slice(key)
	if err != nil {
		return err
	}
	if selector.whole[key.Package] {
		return fmt.Errorf("package %q is requested both whole and sliced", key.Package)
	}
	selector.state[key] = 1
	selector.position[key] = len(selector.stack)
	selector.stack = append(selector.stack, key)
	for _, ref := range sortedEssentialKeys(slice) {
		info := slice.Essential[ref]
		if !architectureIncluded(info.Arch, selector.architecture) {
			continue
		}
		if !hasSlice(selector.packages, ref) {
			return fmt.Errorf("%s requires %s, but slice is missing", key, ref)
		}
		if err := selector.visit(ref); err != nil {
			return err
		}
	}
	selector.stack = selector.stack[:len(selector.stack)-1]
	delete(selector.position, key)
	selector.state[key] = 2
	selector.order = append(selector.order, key)
	return nil
}

func (selector *sliceSelector) slice(key SliceKey) (*Slice, error) {
	pkg, ok := selector.packages[key.Package]
	if !ok {
		return nil, fmt.Errorf("slices of package %q not found", key.Package)
	}
	slice, ok := pkg.Slices[key.Slice]
	if !ok {
		return nil, fmt.Errorf("slice %s not found", key)
	}
	return &slice, nil
}

func sortedEssentialKeys(slice *Slice) []SliceKey {
	keys := make([]SliceKey, 0, len(slice.Essential))
	for key := range slice.Essential {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b SliceKey) int {
		return strings.Compare(a.String(), b.String())
	})
	return keys
}

func architectureIncluded(arches []string, architecture string) bool {
	return len(arches) == 0 || architecture == "" || slices.Contains(arches, architecture)
}
