package locking

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/lock"
)

const (
	absent       = "<absent>"
	recordChange = "record"
)

// Change is one field-level difference between two lockfiles.
type Change struct {
	Section string
	Key     string
	Field   string
	Old     string
	New     string
}

// RefMove records a moved remote catalogue reference.
type RefMove struct {
	Catalogue string
	From      string
	To        string
}

// Comparison separates moved references from changes to selected content.
type Comparison struct {
	Refs    []RefMove
	Changes []Change
}

// Empty reports whether the locks are identical.
func (comparison Comparison) Empty() bool {
	return len(comparison.Refs) == 0 && len(comparison.Changes) == 0
}

// String renders a human-readable comparison.
func (comparison Comparison) String() string {
	lines := make([]string, 0, len(comparison.Refs)+len(comparison.Changes))
	for _, moved := range comparison.Refs {
		lines = append(lines, fmt.Sprintf("ref moved: catalogue %q commit %s -> %s",
			moved.Catalogue, moved.From, moved.To))
	}
	for _, change := range comparison.Changes {
		label := change.Section
		if change.Key != "" {
			label += " " + change.Key
		}
		if change.Field != "" {
			label += " " + change.Field
		}
		lines = append(lines, fmt.Sprintf("changed: %s: %s -> %s", label, change.Old, change.New))
	}
	if len(lines) == 0 {
		return "no drift"
	}
	return strings.Join(lines, "\n")
}

// Compare reports how current differs from previous.
func Compare(previous, current *lock.Lockfile) (Comparison, error) {
	if previous == nil || current == nil {
		return Comparison{}, fmt.Errorf("compare locks: both locks are required")
	}
	var comparison Comparison
	comparison.Changes = valueChanges("header", "", "version", previous.Version, current.Version)
	comparison.Changes = append(comparison.Changes,
		valueChanges("header", "", "spec", previous.SpecDigest, current.SpecDigest)...)
	comparison.Changes = append(comparison.Changes,
		valueChanges("header", "", "provider", previous.Provider, current.Provider)...)
	comparison.Changes = append(comparison.Changes,
		valueChanges("header", "", "platforms", previous.Platforms, current.Platforms)...)

	moved := map[string]bool{}
	for _, entry := range compareCatalogueRefs(previous.Catalogues, current.Catalogues) {
		comparison.Refs = append(comparison.Refs, entry)
		moved[entry.Catalogue] = true
	}
	comparison.Changes = append(comparison.Changes, compareLocalInputs(previous.LocalInputs, current.LocalInputs)...)
	comparison.Changes = append(comparison.Changes,
		compareCatalogues(previous.Catalogues, current.Catalogues, moved)...)
	comparison.Changes = append(comparison.Changes,
		compareRecords("repository", previous.Repositories, current.Repositories,
			func(record lock.Repository) string { return record.ID })...)
	comparison.Changes = append(comparison.Changes,
		compareRecords("package", previous.Packages, current.Packages,
			func(record lock.Package) string { return record.Platform + " " + record.Name })...)
	comparison.Changes = append(comparison.Changes,
		compareRecords("slice", previous.Slices, current.Slices,
			func(record lock.Slice) string { return record.Platform + " " + record.Package })...)
	comparison.Changes = append(comparison.Changes,
		compareRecords("artifact", previous.Artifacts, current.Artifacts,
			func(record lock.Artifact) string { return record.Name + " " + record.Platform })...)
	return comparison, nil
}

func compareCatalogueRefs(previous, current []lock.Catalogue) []RefMove {
	before := make(map[string]lock.Catalogue, len(previous))
	for i := range previous {
		entry := &previous[i]
		before[entry.Name] = *entry
	}
	var moves []RefMove
	for i := range current {
		entry := &current[i]
		old, ok := before[entry.Name]
		if !ok || old.Source.Commit == "" || entry.Source.Commit == "" || old.Source.Commit == entry.Source.Commit {
			continue
		}
		moves = append(moves, RefMove{Catalogue: entry.Name, From: old.Source.Commit, To: entry.Source.Commit})
	}
	sort.Slice(moves, func(i, j int) bool { return moves[i].Catalogue < moves[j].Catalogue })
	return moves
}

func compareCatalogues(previous, current []lock.Catalogue, moved map[string]bool) []Change {
	before := make(map[string]lock.Catalogue, len(previous))
	for i := range previous {
		entry := &previous[i]
		before[entry.Name] = *entry
	}
	names := make(map[string]bool, len(previous)+len(current))
	for i := range previous {
		names[previous[i].Name] = true
	}
	for i := range current {
		names[current[i].Name] = true
	}
	var changes []Change
	for _, name := range sortedKeys(names) {
		old, hadOld := before[name]
		next, hasNext := catalogueByName(current, name)
		if moved[name] {
			old, next = withoutRefEvidence(&old), withoutRefEvidence(&next)
		}
		switch {
		case !hadOld:
			changes = append(changes, recordChangeAt("catalogue", name, absent, formatValue(next)))
		case !hasNext:
			changes = append(changes, recordChangeAt("catalogue", name, formatValue(old), absent))
		default:
			changes = append(changes, valueChanges("catalogue", name, "", old, next)...)
		}
	}
	return changes
}

func withoutRefEvidence(entry *lock.Catalogue) lock.Catalogue {
	stripped := *entry
	stripped.Source.Commit = ""
	stripped.Tree = ""
	stripped.Archive = nil
	return stripped
}

func catalogueByName(catalogues []lock.Catalogue, name string) (lock.Catalogue, bool) {
	for i := range catalogues {
		if catalogues[i].Name == name {
			return catalogues[i], true
		}
	}
	return lock.Catalogue{}, false
}

func compareLocalInputs(previous, current []lock.LocalInput) []Change {
	return compareRecords("local-input", previous, current,
		func(record lock.LocalInput) string { return record.Role + " " + record.Path })
}

func compareRecords[T any](section string, previous, current []T, key func(T) string) []Change {
	before := make(map[string]T, len(previous))
	for _, record := range previous {
		before[key(record)] = record
	}
	after := make(map[string]T, len(current))
	afterKeys := make(map[string]bool, len(current))
	for _, record := range current {
		after[key(record)] = record
		afterKeys[key(record)] = true
	}
	keys := make(map[string]bool, len(before)+len(afterKeys))
	for name := range before {
		keys[name] = true
	}
	for name := range afterKeys {
		keys[name] = true
	}
	var changes []Change
	for _, name := range sortedKeys(keys) {
		old, hadOld := before[name]
		next, hasNext := after[name]
		switch {
		case !hadOld:
			changes = append(changes, recordChangeAt(section, name, absent, formatValue(next)))
		case !hasNext:
			changes = append(changes, recordChangeAt(section, name, formatValue(old), absent))
		default:
			changes = append(changes, valueChanges(section, name, "", old, next)...)
		}
	}
	return changes
}

func recordChangeAt(section, key, previous, current string) Change {
	return Change{Section: section, Key: key, Field: recordChange, Old: previous, New: current}
}

type absentValue struct{}

func valueChanges(section, key, field string, previous, current any) []Change {
	var changes []Change
	diffValue(&changes, section, key, field, normalizeValue(previous), normalizeValue(current))
	return changes
}

func normalizeValue(value any) any {
	if _, absent := value.(absentValue); absent {
		return value
	}
	data, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return value
	}
	return normalized
}

func diffValue(changes *[]Change, section, key, field string, previous, current any) {
	if _, missing := previous.(absentValue); missing {
		*changes = append(*changes, Change{Section: section, Key: key, Field: field, Old: absent, New: formatValue(current)})
		return
	}
	if _, missing := current.(absentValue); missing {
		*changes = append(*changes, Change{Section: section, Key: key, Field: field, Old: formatValue(previous), New: absent})
		return
	}
	if oldMap, ok := previous.(map[string]any); ok {
		if newMap, ok := current.(map[string]any); ok {
			diffMap(changes, section, key, field, oldMap, newMap)
			return
		}
	}
	if oldList, ok := previous.([]any); ok {
		if newList, ok := current.([]any); ok {
			diffList(changes, section, key, field, oldList, newList)
			return
		}
	}
	if !reflect.DeepEqual(previous, current) {
		*changes = append(*changes, wholeChange(section, key, field, previous, current))
	}
}

func diffMap(changes *[]Change, section, key, field string, previous, current map[string]any) {
	keys := make(map[string]bool, len(previous)+len(current))
	for name := range previous {
		keys[name] = true
	}
	for name := range current {
		keys[name] = true
	}
	for _, name := range sortedKeys(keys) {
		oldValue, hasOld := previous[name]
		newValue, hasNew := current[name]
		if !hasOld {
			oldValue = absentValue{}
		}
		if !hasNew {
			newValue = absentValue{}
		}
		child := name
		if field != "" {
			child = field + "." + name
		}
		diffValue(changes, section, key, child, oldValue, newValue)
	}
}

func diffList(changes *[]Change, section, key, field string, previous, current []any) {
	if len(previous) != len(current) {
		*changes = append(*changes, wholeChange(section, key, field, previous, current))
		return
	}
	for index := range previous {
		child := fmt.Sprintf("%s[%d]", field, index)
		diffValue(changes, section, key, child, previous[index], current[index])
	}
}

func wholeChange(section, key, field string, previous, current any) Change {
	return Change{Section: section, Key: key, Field: field, Old: formatValue(previous), New: formatValue(current)}
}

func formatValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	if string(data) == "null" {
		return "<none>"
	}
	return string(data)
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
