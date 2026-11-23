package slices

import (
	"fmt"
	"slices"
	"strings"
)

func validateEssentials(packages map[string]*Package) error {
	if err := validateEssentialReferences(packages); err != nil {
		return err
	}
	return validateEssentialCycles(packages)
}

func validateEssentialReferences(packages map[string]*Package) error {
	for _, key := range allSliceKeys(packages) {
		for _, ref := range essentialKeys(packages, key) {
			if !hasSlice(packages, ref) {
				return fmt.Errorf("%s requires %s, but slice is missing", key, ref)
			}
		}
	}
	return nil
}

func validateEssentialCycles(packages map[string]*Package) error {
	keys := allSliceKeys(packages)
	walker := &essentialWalker{
		packages: packages,
		state:    make(map[SliceKey]uint8),
		stack:    make([]SliceKey, 0, len(keys)),
		position: make(map[SliceKey]int),
	}
	for _, key := range keys {
		if walker.state[key] == 0 {
			if err := walker.visit(key); err != nil {
				return err
			}
		}
	}
	return nil
}

type essentialWalker struct {
	packages map[string]*Package
	state    map[SliceKey]uint8
	stack    []SliceKey
	position map[SliceKey]int
}

func (walker *essentialWalker) visit(key SliceKey) error {
	walker.state[key] = 1
	walker.position[key] = len(walker.stack)
	walker.stack = append(walker.stack, key)
	for _, ref := range essentialKeys(walker.packages, key) {
		switch walker.state[ref] {
		case 1:
			return fmt.Errorf("essential loop detected: %s", joinCycle(walker.stack[walker.position[ref]:]))
		case 0:
			if err := walker.visit(ref); err != nil {
				return err
			}
		}
	}
	walker.stack = walker.stack[:len(walker.stack)-1]
	delete(walker.position, key)
	walker.state[key] = 2
	return nil
}

type sliceRecord struct {
	key   SliceKey
	slice Slice
}

func allSlices(packages map[string]*Package) []sliceRecord {
	var records []sliceRecord
	for _, pkgName := range sortedKeys(packages) {
		pkg := packages[pkgName]
		for _, sliceName := range sortedKeys(pkg.Slices) {
			records = append(records, sliceRecord{
				key:   SliceKey{Package: pkgName, Slice: sliceName},
				slice: pkg.Slices[sliceName],
			})
		}
	}
	return records
}

func allSliceKeys(packages map[string]*Package) []SliceKey {
	records := allSlices(packages)
	keys := make([]SliceKey, len(records))
	for i, record := range records {
		keys[i] = record.key
	}
	return keys
}

func essentialKeys(packages map[string]*Package, key SliceKey) []SliceKey {
	pkg := packages[key.Package]
	if pkg == nil {
		return nil
	}
	slice, ok := pkg.Slices[key.Slice]
	if !ok {
		return nil
	}
	keys := make([]SliceKey, 0, len(slice.Essential))
	for ref := range slice.Essential {
		keys = append(keys, ref)
	}
	slices.SortFunc(keys, func(a, b SliceKey) int {
		return strings.Compare(a.String(), b.String())
	})
	return keys
}

func hasSlice(packages map[string]*Package, key SliceKey) bool {
	pkg := packages[key.Package]
	if pkg == nil {
		return false
	}
	_, ok := pkg.Slices[key.Slice]
	return ok
}

func joinCycle(stack []SliceKey) string {
	names := make([]string, 0, len(stack))
	for _, key := range stack {
		names = append(names, key.String())
	}
	return strings.Join(names, ", ")
}
