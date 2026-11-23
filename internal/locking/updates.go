package locking

import (
	"fmt"
	"sort"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// Update is one locked package whose repository now offers a newer version.
type Update struct {
	Platform string
	Kind     string
	Name     string
	From     string
	To       string
}

// String renders one update as "platform name from -> to".
func (update Update) String() string {
	return fmt.Sprintf("%s %s %s %s -> %s", update.Platform, update.Kind, update.Name, update.From, update.To)
}

// Updates reports the locked packages and slices that a fresh selection resolves to a
// newer version. It answers "is there anything to rebuild for", which is not the same
// question as Compare: metadata evidence churns every night and says nothing about
// whether the image would change.
func Updates(locked *lock.Lockfile, packages []lock.Package, slices []lock.Slice) ([]Update, error) {
	if locked == nil {
		return nil, fmt.Errorf("updates: a locked lockfile is required")
	}
	updates := make([]Update, 0, len(locked.Packages)+len(locked.Slices))
	updates = append(updates, packageUpdates(locked.Packages, packages)...)
	updates = append(updates, sliceUpdates(locked.Slices, slices)...)
	sort.Slice(updates, func(i, j int) bool {
		left, right := updates[i], updates[j]
		if left.Platform != right.Platform {
			return left.Platform < right.Platform
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Name < right.Name
	})
	return updates, nil
}

func packageUpdates(previous, current []lock.Package) []Update {
	before := make(map[string]lock.Package, len(previous))
	for i := range previous {
		before[previous[i].Platform+" "+previous[i].Name] = previous[i]
	}
	updates := make([]Update, 0, len(current))
	for i := range current {
		next := &current[i]
		old, ok := before[next.Platform+" "+next.Name]
		if !ok || !isNewer(old.Version, next.Version) {
			continue
		}
		updates = append(updates, Update{
			Platform: next.Platform, Kind: "package", Name: next.Name,
			From: old.Version, To: next.Version,
		})
	}
	return updates
}

func sliceUpdates(previous, current []lock.Slice) []Update {
	before := make(map[string]lock.Slice, len(previous))
	for i := range previous {
		before[previous[i].Platform+" "+previous[i].Package] = previous[i]
	}
	updates := make([]Update, 0, len(current))
	for i := range current {
		next := &current[i]
		old, ok := before[next.Platform+" "+next.Package]
		if !ok || !isNewer(old.Version, next.Version) {
			continue
		}
		updates = append(updates, Update{
			Platform: next.Platform, Kind: "slice", Name: next.Package,
			From: old.Version, To: next.Version,
		})
	}
	return updates
}

// isNewer reports whether candidate orders above current in Debian version order. A
// version that cannot be parsed does not count as newer: reporting it would rebuild an
// image for a string that may mean nothing.
func isNewer(current, candidate string) bool {
	old, err := deb.ParseVersion(current)
	if err != nil {
		return false
	}
	next, err := deb.ParseVersion(candidate)
	if err != nil {
		return false
	}
	return next.Compare(old) > 0
}
