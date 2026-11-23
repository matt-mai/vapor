package locking

import (
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// Blob is one cache entry a lockfile references.
type Blob struct {
	Digest string
	Size   int64
	// Label names the record in messages, as in `package "openssl"`.
	Label string
	// Read is false for repository evidence, which verification has already read and
	// the audit only counts, so nothing opens it twice.
	Read bool
}

// Blobs lists every cache entry a lockfile references. The audit and cache collection
// share this one enumeration: a blob kind added here is both checked and kept. Entries
// are not deduplicated, because a record that appears twice is counted twice.
func Blobs(lockfile *lock.Lockfile) ([]Blob, error) {
	if lockfile == nil {
		return nil, errors.New("lock must not be nil")
	}
	var blobs []Blob
	for i := range lockfile.Repositories {
		blobs = append(blobs, repositoryBlobs(&lockfile.Repositories[i])...)
	}
	for i := range lockfile.LocalInputs {
		input := &lockfile.LocalInputs[i]
		blobs = append(blobs, Blob{Digest: input.SHA256, Size: input.Size, Read: true,
			Label: fmt.Sprintf("local input %q", input.Path)})
	}
	for i := range lockfile.Catalogues {
		entries, err := catalogueBlobs(&lockfile.Catalogues[i])
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, entries...)
	}
	for i := range lockfile.Packages {
		pkg := &lockfile.Packages[i]
		blobs = append(blobs, Blob{Digest: pkg.Content.SHA256, Size: pkg.Content.Size, Read: true,
			Label: fmt.Sprintf("package %q", pkg.Name)})
	}
	for i := range lockfile.Slices {
		slice := &lockfile.Slices[i]
		blobs = append(blobs, Blob{Digest: slice.Content.SHA256, Size: slice.Content.Size, Read: true,
			Label: fmt.Sprintf("slice %q", slice.Package)})
	}
	for i := range lockfile.Artifacts {
		artifact := &lockfile.Artifacts[i]
		blobs = append(blobs, Blob{Digest: artifact.SHA256, Size: artifact.Size, Read: true,
			Label: fmt.Sprintf("artifact %q", artifact.Name)})
	}
	return blobs, nil
}

func repositoryBlobs(repository *lock.Repository) []Blob {
	blobs := make([]Blob, 0, len(repository.Trust.Keys)+len(repository.Indexes)+2)
	for _, key := range repository.Trust.Keys {
		blobs = append(blobs, Blob{Digest: key.SHA256, Size: key.Size,
			Label: fmt.Sprintf("repository %q key %q", repository.Name, key.Fingerprint)})
	}
	blobs = append(blobs, Blob{Digest: repository.Release.SHA256, Size: repository.Release.Size,
		Label: fmt.Sprintf("repository %q release", repository.Name)})
	if signature := repository.Release.Signature; signature != nil {
		blobs = append(blobs, Blob{Digest: signature.SHA256, Size: signature.Size,
			Label: fmt.Sprintf("repository %q release signature", repository.Name)})
	}
	for _, index := range repository.Indexes {
		blobs = append(blobs, Blob{Digest: index.SHA256, Size: index.Size,
			Label: fmt.Sprintf("repository %q index %q", repository.Name, index.Path)})
	}
	return blobs
}

// catalogueBlobs rebuilds the locked tree, which also proves the manifest still hashes
// to the recorded tree digest.
func catalogueBlobs(record *lock.Catalogue) ([]Blob, error) {
	tree, err := catalogue.LockedTree(record)
	if err != nil {
		return nil, fmt.Errorf("catalogue %q manifest: %w", record.Name, err)
	}
	entries := tree.Entries()
	blobs := make([]Blob, 0, len(entries)+1)
	for i := range entries {
		entry := &entries[i]
		if entry.Kind != catalogue.KindFile {
			continue
		}
		blobs = append(blobs, Blob{Digest: entry.SHA256, Size: entry.Size, Read: true,
			Label: fmt.Sprintf("catalogue %q file %q", record.Name, entry.Path)})
	}
	if record.Archive != nil {
		blobs = append(blobs, Blob{Digest: record.Archive.SHA256, Size: record.Archive.Size, Read: true,
			Label: fmt.Sprintf("catalogue %q archive", record.Name)})
	}
	return blobs, nil
}
