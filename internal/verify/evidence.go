// Package verify replays locked repository evidence from cached bytes.
package verify

import (
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// BlobStore provides verified cached bytes. *cache.Cache implements it.
type BlobStore interface {
	Open(digest string, size int64) (io.ReadCloser, error)
}

// maxIndexEvidenceSize leaves room for encoding overhead above the
// decompressed index bound.
const maxIndexEvidenceSize = deb.MaxIndexSize + (1 << 20)

// RepositoryPolicy selects the release matching rules for each locked repository,
// and the package names a repository was declared for. A nil policy matches the signed
// Suite without component prefixes and admits every name.
type RepositoryPolicy interface {
	ReleaseMatching(name string) deb.ReleaseIdentity
	PackageScope(name string) []string
}

// Repositories authenticates cached repository evidence and checks that the
// locked package selections match it. It does not read package archives, fetch,
// resolve or evaluate freshness.
func Repositories(lockfile *lock.Lockfile, blobs BlobStore) error {
	return RepositoriesWithPolicy(lockfile, blobs, nil)
}

// RepositoriesWithPolicy replays the release matching rules used at acquisition.
func RepositoriesWithPolicy(lockfile *lock.Lockfile, blobs BlobStore,
	policy RepositoryPolicy,
) error {
	if lockfile == nil {
		return errors.New("lock must not be nil")
	}
	if blobs == nil {
		return errors.New("blob store must not be nil")
	}
	selections := packageSelections(lockfile)
	if err := checkScope(lockfile, selections, policy); err != nil {
		return err
	}
	remaining := newSelections(selections)
	for i := range lockfile.Repositories {
		repository := &lockfile.Repositories[i]
		if err := verifyRepository(repository, blobs, policy, remaining); err != nil {
			return fmt.Errorf("repository %q: %w", repository.ID, err)
		}
	}
	return remaining.check(selections)
}

// checkScope holds every locked selection to the package names its repository was
// declared for. Selection applies the scope when it chooses a package, so this is what
// keeps a hand-edited lock, or a lock written by an older build, from spending a
// vendor's authority on a package the specification never granted it.
func checkScope(lockfile *lock.Lockfile, selections []packageSelection, policy RepositoryPolicy) error {
	if policy == nil {
		return nil
	}
	names := make(map[string]string, len(lockfile.Repositories))
	for i := range lockfile.Repositories {
		names[lockfile.Repositories[i].ID] = lockfile.Repositories[i].Name
	}
	for i := range selections {
		selection := &selections[i]
		name, known := names[selection.identity.repository]
		if !known {
			continue
		}
		scope := policy.PackageScope(name)
		if len(scope) == 0 || slices.Contains(scope, selection.identity.name) {
			continue
		}
		return fmt.Errorf("%s %q: repository %q was not declared for this package",
			selection.kind, selection.identity.name, name)
	}
	return nil
}

func verifyRepository(locked *lock.Repository, blobs BlobStore,
	policy RepositoryPolicy, remaining *selections,
) error {
	keys, err := RepositoryKeys(locked.Trust.Keys, blobs)
	if err != nil {
		return err
	}
	release, err := verifyRelease(&locked.Release, keys, blobs)
	if err != nil {
		return err
	}
	components := make([]string, len(locked.Indexes))
	for i, index := range locked.Indexes {
		components[i] = index.Component
	}
	identity := deb.ReleaseIdentity{Suite: locked.Suite, Architecture: locked.Architecture, Components: components}
	if policy != nil {
		matching := policy.ReleaseMatching(locked.Name)
		identity.MatchCodename, identity.PrefixedComponents = matching.MatchCodename, matching.PrefixedComponents
		identity.OwnIdentity = matching.OwnIdentity
	}
	if identityErr := deb.CheckReleaseIdentity(&release.Metadata, identity); identityErr != nil {
		return fmt.Errorf("release identity: %w", identityErr)
	}
	if !sameValidUntil(release.Metadata.ValidUntil, locked.Release.ValidUntil) {
		return errors.New("release valid-until does not match locked evidence")
	}
	for _, entry := range locked.Indexes {
		candidates, err := verifyIndexEntry(locked, &release.Metadata, blobs, entry)
		if err != nil {
			return err
		}
		remaining.match(locked.ID, candidates)
	}
	return nil
}

// RepositoryKeys loads the exact public fingerprints selected by a validated lock.
func RepositoryKeys(locked []lock.RepositoryKey, blobs BlobStore) ([]deb.PublicKey, error) {
	keys := make([]deb.PublicKey, 0, len(locked))
	for _, key := range locked {
		data, err := readEvidence(blobs, "key", key.SHA256, key.Size, deb.MaxKeySnapshotSize)
		if err != nil {
			return nil, err
		}
		loaded, err := deb.LoadTrustedKeys(data, []string{key.Fingerprint})
		if err != nil {
			return nil, fmt.Errorf("trusted key: %w", err)
		}
		keys = append(keys, loaded...)
	}
	return keys, nil
}

func verifyRelease(locked *lock.RepositoryRelease, keys []deb.PublicKey, blobs BlobStore) (*deb.VerifiedRelease, error) {
	raw, err := readEvidence(blobs, "release", locked.SHA256, locked.Size, deb.MaxReleaseSize)
	if err != nil {
		return nil, err
	}
	// Replay must land on the signer the lock recorded. Verifying every trusted
	// signature keeps that choice from depending on expiry: a lock whose signer
	// has since expired still replays, and a second valid signature cannot take
	// its place.
	recorded := make([]string, len(locked.Signers))
	for i, signer := range locked.Signers {
		recorded[i] = strings.ToUpper(signer)
	}
	var verified *deb.VerifiedRelease
	switch locked.Format {
	case deb.ReleaseFormatInRelease:
		verified, err = deb.VerifyInRelease(raw, keys, deb.VerifyOptions{Policy: deb.IgnoreExpiry, Accepted: recorded})
	case deb.ReleaseFormatDetached:
		verified, err = verifyDetachedRelease(raw, locked.Signature, keys, blobs, recorded)
	default:
		return nil, fmt.Errorf("unsupported release format %q", locked.Format)
	}
	if err != nil {
		return nil, fmt.Errorf("release signature: %w", err)
	}
	if verified.Format != locked.Format {
		return nil, errors.New("release format does not match locked evidence")
	}
	if !sameSigners(verified.Signers, locked.Signers) {
		return nil, errors.New("release signers do not match locked evidence")
	}
	return verified, nil
}

func verifyDetachedRelease(release []byte, signature *lock.Content, keys []deb.PublicKey,
	blobs BlobStore, recorded []string) (*deb.VerifiedRelease, error) {
	if signature == nil {
		return nil, errors.New("detached release signature is missing")
	}
	raw, err := readEvidence(blobs, "release signature", signature.SHA256, signature.Size, deb.MaxReleaseSignatureSize)
	if err != nil {
		return nil, err
	}
	return deb.VerifyDetachedRelease(release, raw, keys, deb.VerifyOptions{Policy: deb.IgnoreExpiry, Accepted: recorded})
}

func verifyIndexEntry(locked *lock.Repository, release *deb.Release, blobs BlobStore, entry lock.Index) ([]deb.Package, error) {
	format, ok := indexFormat(entry.Path, entry.Component, locked.Architecture)
	if !ok {
		return nil, fmt.Errorf("index path %q is not canonical", entry.Path)
	}
	signed, ok := release.Files[entry.Path]
	if !ok {
		return nil, fmt.Errorf("index %q is not referenced by release metadata", entry.Path)
	}
	if !strings.EqualFold(signed.SHA256, entry.SHA256) || signed.Size != entry.Size {
		return nil, fmt.Errorf("index %q does not match release metadata", entry.Path)
	}
	data, err := readEvidence(blobs, "index", entry.SHA256, entry.Size, maxIndexEvidenceSize)
	if err != nil {
		return nil, err
	}
	index := deb.Index{
		Component:    entry.Component,
		Architecture: locked.Architecture,
		Path:         entry.Path,
		Format:       format,
		SHA256:       entry.SHA256,
		Size:         entry.Size,
	}
	decompressed, err := deb.VerifyIndex(&index, data)
	if err != nil {
		return nil, fmt.Errorf("index %q: %w", entry.Path, err)
	}
	candidates, err := deb.ParsePackages(decompressed, &index, locked.Suite)
	if err != nil {
		return nil, fmt.Errorf("index %q: %w", entry.Path, err)
	}
	return candidates, nil
}

func indexFormat(indexPath, component, architecture string) (deb.IndexFormat, bool) {
	if !safeSegment(component) || !safeSegment(architecture) {
		return "", false
	}
	base := path.Join(component, "binary-"+architecture, "Packages")
	switch indexPath {
	case base:
		return deb.IndexFormatPlain, true
	case base + ".gz":
		return deb.IndexFormatGzip, true
	case base + ".xz":
		return deb.IndexFormatXZ, true
	default:
		return "", false
	}
}

func safeSegment(segment string) bool {
	return segment != "" && segment != "." && segment != ".." &&
		!strings.ContainsAny(segment, "/\\")
}

func sameSigners(signed, locked []string) bool {
	if len(signed) != len(locked) {
		return false
	}
	remaining := make(map[string]int, len(locked))
	for _, signer := range locked {
		remaining[strings.ToUpper(signer)]++
	}
	for _, signer := range signed {
		key := strings.ToUpper(signer)
		if remaining[key] == 0 {
			return false
		}
		remaining[key]--
	}
	return true
}

func sameValidUntil(signed string, locked *string) bool {
	if locked == nil {
		return signed == ""
	}
	return signed == *locked
}

type evidenceError struct {
	operation string
	kind      string
	cause     error
}

// Error keeps host paths and store-specific text out of caller-visible errors.
// The cause remains available through errors.Is and errors.As.
func (e *evidenceError) Error() string {
	return e.operation + " " + e.kind + " evidence failed"
}

func (e *evidenceError) Unwrap() error {
	return e.cause
}

func readEvidence(blobs BlobStore, kind, digest string, size, limit int64) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("%s evidence has invalid size %d", kind, size)
	}
	if size > limit {
		return nil, fmt.Errorf("%s evidence exceeds %d bytes", kind, limit)
	}
	reader, err := blobs.Open(digest, size)
	if err != nil {
		return nil, &evidenceError{operation: "open", kind: kind, cause: err}
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, size+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, &evidenceError{operation: "read", kind: kind, cause: readErr}
	}
	if closeErr != nil {
		return nil, &evidenceError{operation: "close", kind: kind, cause: closeErr}
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("%s evidence size does not match locked size", kind)
	}
	return data, nil
}
