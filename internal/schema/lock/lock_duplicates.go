package lock

import (
	"fmt"
	"strings"
)

func checkLockDuplicates(lock *Lockfile) error {
	if err := checkLockRecordDuplicates(lock); err != nil {
		return err
	}
	for i := range lock.Repositories {
		if err := checkLockRepositoryDuplicates(&lock.Repositories[i], fmt.Sprintf("repositories[%d]", i)); err != nil {
			return err
		}
	}
	for i := range lock.Slices {
		slice := &lock.Slices[i]
		if err := checkLockUnique(slice.Selected, fmt.Sprintf("slices[%d].selected", i),
			func(s string) string { return s }); err != nil {
			return err
		}
		if err := checkLockUnique(slice.Closure, fmt.Sprintf("slices[%d].closure", i),
			func(s string) string { return s }); err != nil {
			return err
		}
	}
	return nil
}

func checkLockRecordDuplicates(lock *Lockfile) error {
	if err := checkLockUnique(lock.LocalInputs, "local-inputs", func(r LocalInput) string {
		return r.Role + "\x00" +
			r.Path
	}); err != nil {
		return err
	}
	if err := checkLockUnique(lock.Catalogues, "catalogues", func(r Catalogue) string { return r.Name }); err != nil {
		return err
	}
	if err := checkLockUnique(lock.Repositories, "repositories", func(r Repository) string { return r.ID }); err != nil {
		return err
	}
	if err := checkLockUnique(lock.Repositories, "repositories", func(r Repository) string {
		return r.Name + "\x00" +
			r.Platform + "\x00" + r.Suite
	}); err != nil {
		return err
	}
	if err := checkLockUnique(lock.Packages, "packages", func(r Package) string {
		return r.Platform + "\x00" +
			r.Name
	}); err != nil {
		return err
	}
	if err := checkLockUnique(lock.Slices, "slices", func(r Slice) string {
		return r.Platform + "\x00" +
			r.Package
	}); err != nil {
		return err
	}
	return checkLockUnique(lock.Artifacts, "artifacts", func(r Artifact) string { return r.Platform + "\x00" + r.Name })
}

func checkLockRepositoryDuplicates(repository *Repository, location string) error {
	if err := checkLockUnique(repository.Trust.Keys, location+".trust.keys",
		func(key RepositoryKey) string { return strings.ToLower(key.Fingerprint) }); err != nil {
		return err
	}
	if err := checkLockUnique(repository.Release.Signers, location+".release.signers", strings.ToLower); err != nil {
		return err
	}
	return checkLockUnique(repository.Indexes, location+".indexes", func(index Index) string { return index.Component })
}

func checkLockUnique[T any](records []T, location string, key func(T) string) error {
	seen := make(map[string]bool, len(records))
	for i, record := range records {
		identity := key(record)
		if seen[identity] {
			return fmt.Errorf("%s[%d]: duplicate record", location, i)
		}
		seen[identity] = true
	}
	return nil
}
