package lock

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/spec"
)

func canonicalLockfile(lock *Lockfile) (*Lockfile, error) {
	if lock == nil {
		return nil, errors.New("lock must not be nil")
	}
	if err := checkLockText(reflect.ValueOf(lock)); err != nil {
		return nil, err
	}
	// Sorted collections need private backing arrays; semantic sequences only need [] normalization.
	canonical := *lock
	canonical.Platforms = nonNilSlice(lock.Platforms)
	canonical.LocalInputs = copyLockSlice(lock.LocalInputs)
	canonical.Catalogues = copyLockSlice(lock.Catalogues)
	canonical.Repositories = copyLockSlice(lock.Repositories)
	canonical.Packages = copyLockSlice(lock.Packages)
	canonical.Slices = copyLockSlice(lock.Slices)
	canonical.Artifacts = copyLockSlice(lock.Artifacts)
	canonicalLockRepositories(canonical.Repositories)
	for i := range canonical.Slices {
		canonical.Slices[i].Selected = nonNilSlice(canonical.Slices[i].Selected)
		canonical.Slices[i].Closure = nonNilSlice(canonical.Slices[i].Closure)
	}
	for i := range canonical.Artifacts {
		if canonical.Artifacts[i].Unpack == nil {
			return nil, fmt.Errorf("artifacts[%d]: unpack is required", i)
		}
	}
	sortLockRecords(&canonical)
	return &canonical, nil
}

func canonicalLockRepositories(repositories []Repository) {
	for i := range repositories {
		repository := &repositories[i]
		repository.Trust.Keys = copyLockSlice(repository.Trust.Keys)
		repository.Release.Signers = copyLockSlice(repository.Release.Signers)
		repository.Indexes = copyLockSlice(repository.Indexes)
		sort.SliceStable(repository.Trust.Keys, func(left, right int) bool {
			a, b := repository.Trust.Keys[left], repository.Trust.Keys[right]
			af, bf := strings.ToLower(a.Fingerprint), strings.ToLower(b.Fingerprint)
			if af != bf {
				return af < bf
			}
			return a.Path < b.Path
		})
		sort.SliceStable(repository.Release.Signers, func(left, right int) bool {
			return strings.ToLower(repository.Release.Signers[left]) < strings.ToLower(repository.Release.Signers[right])
		})
		sort.SliceStable(repository.Indexes, func(left, right int) bool {
			return repository.Indexes[left].Component < repository.Indexes[right].Component
		})
	}
}

func sortLockRecords(lock *Lockfile) {
	sort.SliceStable(lock.LocalInputs, func(left, right int) bool {
		a, b := lock.LocalInputs[left], lock.LocalInputs[right]
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Path < b.Path
	})
	sort.SliceStable(lock.Catalogues, func(left, right int) bool {
		return lock.Catalogues[left].Name < lock.Catalogues[right].Name
	})
	sort.SliceStable(lock.Repositories, func(left, right int) bool {
		return lock.Repositories[left].ID < lock.Repositories[right].ID
	})
	sort.SliceStable(lock.Packages, func(left, right int) bool {
		a, b := lock.Packages[left], lock.Packages[right]
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.Name < b.Name
	})
	sort.SliceStable(lock.Slices, func(left, right int) bool {
		a, b := lock.Slices[left], lock.Slices[right]
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.Package < b.Package
	})
	sort.SliceStable(lock.Artifacts, func(left, right int) bool {
		a, b := lock.Artifacts[left], lock.Artifacts[right]
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.Name < b.Name
	})
}

func checkLockText(value reflect.Value) error {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			return checkLockText(value.Elem())
		}
	case reflect.Struct:
		return checkLockStructText(value)
	case reflect.Slice:
		return checkLockSliceText(value)
	case reflect.String:
		return spec.CheckText(value.String(), "lock string")
	case reflect.Int, reflect.Int64, reflect.Bool:
	default:
		return fmt.Errorf("unsupported lock field type %s", value.Kind())
	}
	return nil
}

func checkLockStructText(value reflect.Value) error {
	for _, field := range value.Fields() {
		if err := checkLockText(field); err != nil {
			return err
		}
	}
	return nil
}

func checkLockSliceText(value reflect.Value) error {
	for i := 0; i < value.Len(); i++ {
		if err := checkLockText(value.Index(i)); err != nil {
			return err
		}
	}
	return nil
}

func copyLockSlice[T any](values []T) []T {
	result := make([]T, len(values))
	copy(result, values)
	return result
}

func nonNilSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
