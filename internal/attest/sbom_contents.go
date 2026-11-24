package attest

import (
	"crypto/sha1" // #nosec G505 -- SPDX 2.3 §8.4 requires one, and it is not used as a security claim.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// element is one locked contributor that still owns content in the finished tree. It
// says what the contributor is, not how a particular format names it.
type element struct {
	kind string
	// key is what a document orders and dedupes by: the contributor's own lock name.
	// reported is the name a payload shows, which differs for an artifact (the lock
	// names the download, the specification names the payload).
	key      string
	reported string
	version  string
	arch     string
	// locator is the package URL the element is published under. It is filled for a
	// vendored module, whose whole point is the package URL a scanner follows, and empty
	// for a locked record, which purlOf derives from the lock.
	locator string
	// archive is the package the element was cut from. It is the element itself for a
	// whole package, and the package a slice was cut from.
	archive string
	// slices is the dependency-first closure of a sliced package, which is what the
	// element covers. Empty for every other kind.
	slices []string
	// cpe is the declared CPE 2.3 name for a package whose own index files none under,
	// and for an artifact, which has no package URL a database can follow. Empty when the
	// specification names none.
	cpe string
	// upstream is the source package the archive was built from, which is the name
	// advisories are published under. Empty when the index names none.
	upstream string
	// vendor and release are the namespace and distribution the element is published
	// under, which are the distribution's unless the repository is the vendor's own.
	vendor   string
	release  string
	checksum string
	// identity is the domain-separated element identity, which is what a format names
	// the element by so the name changes when the element does.
	identity string
	files    []string
}

// content is what a finished tree holds: the contributors that still own something,
// the files with their final digests, and the files no locked record contributed. It
// is format-neutral, so a second format reads it instead of walking the tree again.
type content struct {
	elements []*element
	files    []file
	unowned  []string
}

// file is one tree file. The digests are of the bytes the image holds; SPDX 2.3 makes
// the SHA-1 mandatory, so both are computed in the one pass over the content.
type file struct {
	path     string
	sha1     string
	hash     string
	modified bool
}

// walk derives the document's content. Files are in tree order and elements are
// ordered by contributor, so the result never depends on map iteration.
func (input *SBOMInput) walk() (content, error) {
	locked := input.locked()
	collected := newContributors()
	found := content{files: make([]file, 0, 64), unowned: make([]string, 0)}
	vendored, err := input.vendoredByPath()
	if err != nil {
		return content{}, err
	}
	entries := input.Tree.Entries()
	for position := range entries {
		entry := &entries[position]
		if entry.Kind != vfs.File {
			continue
		}
		digests, err := input.digestsOf(entry.Path)
		if err != nil {
			return content{}, err
		}
		current := file{path: entry.Path, sha1: digests.sha1, hash: digests.sha256}
		current.modified = input.wasModified(entry.Path, current.hash)
		found.files = append(found.files, current)
		owners, err := locked.owners(entry)
		if err != nil {
			return content{}, err
		}
		// A vendored module is a contributor in its own right, and the payload that
		// carried it keeps the file too: the deb really does contain those bytes, and
		// the module really is a package a scanner must see. Both claims are true, so
		// both are published.
		owners = append(owners, vendored[entry.Path]...)
		if len(owners) == 0 {
			found.unowned = append(found.unowned, entry.Path)
		}
		if err := collected.add(entry.Path, owners); err != nil {
			return content{}, err
		}
	}
	found.elements = collected.sorted()
	return found, nil
}

// vendoredByPath describes every module the tree holds, keyed by the files it owns. The
// scan runs once per document, because reading every manifest per file would read the
// same bytes thousands of times.
func (input *SBOMInput) vendoredByPath() (map[string][]*element, error) {
	modules, err := discoverModules(input.Tree)
	if err != nil {
		return nil, err
	}
	byPath := map[string][]*element{}
	for _, current := range modules {
		described, err := moduleElement(current)
		if err != nil {
			return nil, err
		}
		for _, owned := range current.files {
			byPath[owned] = append(byPath[owned], described)
		}
	}
	return byPath, nil
}

// contributors collects the contributors a document describes. It is keyed by
// contributor rather than by identifier, so two contributors that a format would name
// the same way are reported instead of merged.
type contributors struct {
	elements map[string]*element
	// keys maps an identifier to its contributor, which is what a second format would
	// need to detect a clash in its own naming scheme.
	keys map[string]string
}

func newContributors() *contributors {
	return &contributors{elements: map[string]*element{}, keys: map[string]string{}}
}

func (collected *contributors) add(path string, owners []*element) error {
	for _, owner := range owners {
		key := owner.kind + "\x00" + owner.key
		identifier := owner.identity
		if other, taken := collected.keys[identifier]; taken && other != key {
			return fmt.Errorf("attest: %s and %s share the identifier %s", other, key, identifier)
		}
		collected.keys[identifier] = key
		found, ok := collected.elements[key]
		if !ok {
			found = owner
			collected.elements[key] = found
		}
		found.files = append(found.files, path)
	}
	return nil
}

func (collected *contributors) sorted() []*element {
	elements := make([]*element, 0, len(collected.elements))
	for _, found := range collected.elements {
		elements = append(elements, found)
	}
	sort.Slice(elements, func(left, right int) bool {
		return elements[left].kind+"\x00"+elements[left].key <
			elements[right].kind+"\x00"+elements[right].key
	})
	return elements
}

// fileDigests are the lowercase digests of one file's final bytes, which is what the
// image contains rather than what a package archive delivered.
type fileDigests struct {
	sha1   string
	sha256 string
}

func (input *SBOMInput) digestsOf(path string) (fileDigests, error) {
	reader, err := input.Tree.OpenFile(path)
	if err != nil {
		return fileDigests{}, fmt.Errorf("attest: read %s: %w", path, err)
	}
	// #nosec G401 -- SPDX 2.3 §8.4 requires a SHA-1 per file; it is a format field, not
	// a security claim, and the SHA-256 beside it is the digest to check.
	sha1Digest := sha1.New()
	sha256Digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(sha1Digest, sha256Digest), reader); err != nil {
		return fileDigests{}, fmt.Errorf("attest: read %s: %w", path, err)
	}
	return fileDigests{
		sha1:   hex.EncodeToString(sha1Digest.Sum(nil)),
		sha256: hex.EncodeToString(sha256Digest.Sum(nil)),
	}, nil
}

// wasModified reports a file a slice script rewrote. The digest is the content the
// image holds, so without the note a reader would read the mismatch as corruption.
func (input *SBOMInput) wasModified(path, hash string) bool {
	original, mutable := input.Original[path]
	return mutable && original != hash
}

// locked indexes this platform's records, so a document can never attribute another
// platform's payload to this image.
type locked struct {
	packages  map[string]lock.Package
	slices    map[string]lock.Slice
	artifacts map[string]lock.Artifact
	// repositories by ID, so a record's identity is read from the repository that
	// serves it and not from the distribution the image is built for.
	repositories map[string]*lock.Repository
	// distro and release are the distribution the image is built for, which names a
	// record from a repository that publishes under the distribution's own identity.
	distro  string
	release string
}

func (input *SBOMInput) locked() locked {
	index := locked{
		packages:  map[string]lock.Package{},
		slices:    map[string]lock.Slice{},
		artifacts: map[string]lock.Artifact{},
		distro:    input.Distro, release: input.Release,
	}
	for position := range input.Packages {
		record := &input.Packages[position]
		if record.Platform == input.Platform {
			index.packages[record.Name] = *record
		}
	}
	for position := range input.Slices {
		record := &input.Slices[position]
		if record.Platform == input.Platform {
			index.slices[record.Package] = *record
		}
	}
	for position := range input.Artifacts {
		record := &input.Artifacts[position]
		if record.Platform == input.Platform {
			index.artifacts[record.Name] = *record
		}
	}
	index.repositories = make(map[string]*lock.Repository, len(input.Repositories))
	for position := range input.Repositories {
		record := &input.Repositories[position]
		if record.Platform == input.Platform {
			index.repositories[record.ID] = record
		}
	}
	return index
}

// lockedElement refuses a record the document cannot vouch for. An element's version
// and its archive digest are the claim the document publishes about it, so a lock that
// holds neither is reported rather than repeated as if it had been checked. The digest
// comes back normalised, because only bare lowercase hex is a valid SPDX checksum.
func lockedElement(kind, name, version, digest string) (string, error) {
	switch {
	case name == "":
		return "", fmt.Errorf("attest: locked %s has no name", kind)
	case version == "":
		return "", fmt.Errorf("attest: locked %s %q has no version", kind, name)
	}
	hash, err := hexDigest(digest)
	if err != nil {
		return "", fmt.Errorf("attest: locked %s %q: %w", kind, name, err)
	}
	return hash, nil
}

// owners returns one element per distinct origin of a path. A path can have several
// contributors, for example a declared entry that replaced a package file, and every
// contributor stays visible.
func (index locked) owners(entry *vfs.Entry) ([]*element, error) {
	owners := make([]*element, 0, len(entry.Origins))
	seen := map[string]*element{}
	for _, origin := range entry.Origins {
		owner, err := index.owner(entry.Path, origin)
		if errors.Is(err, errUnowned) {
			continue
		}
		if err != nil {
			return nil, err
		}
		key := owner.kind + "\x00" + owner.key
		if _, taken := seen[key]; taken {
			continue
		}
		seen[key] = owner
		owners = append(owners, owner)
	}
	return owners, nil
}

// errUnowned reports a path the tree records without a locked contributor, such as a
// declared filesystem path or synthesized state. The document owns those itself.
var errUnowned = errors.New("attest: path has no locked contributor")

func (index locked) owner(path string, origin vfs.Origin) (*element, error) {
	if origin.Package == "" {
		return nil, errUnowned
	}
	if origin.Slice != "" {
		return index.sliceElement(path, origin)
	}
	record, whole := index.packages[origin.Package]
	artifact, packed := index.artifacts[origin.Package]
	switch {
	case whole && packed:
		return nil, fmt.Errorf("attest: %s: %q is both a package and an artifact", path, origin.Package)
	case whole:
		return index.packageElement(&record)
	case packed:
		return artifactElement(&artifact)
	}
	return nil, fmt.Errorf("attest: %s: contributor %q is not in the lock", path, origin.Package)
}

// sliceElement describes the sliced content of one package. Every file a package's
// slices contribute belongs to that one element, because an advisory is filed under the
// package: one element per slice would make a scanner report the same finding once per
// slice. The tree names a slice as "<package>_<slice>", so the slice named by a file is
// checked against the locked closure rather than trusted on its own.
func (index locked) sliceElement(path string, origin vfs.Origin) (*element, error) {
	record, ok := index.slices[origin.Package]
	if !ok {
		return nil, fmt.Errorf("attest: %s: no locked slice for %q", path, origin.Package)
	}
	slice := strings.TrimPrefix(origin.Slice, origin.Package+"_")
	if slice == origin.Slice {
		return nil, fmt.Errorf("attest: %s: %q does not name a slice of %q",
			path, origin.Slice, origin.Package)
	}
	if !slices.Contains(record.Closure, slice) {
		return nil, fmt.Errorf("attest: %s: slice %q is not in the locked closure of %q",
			path, slice, origin.Package)
	}
	hash, err := lockedElement(kindSlice, record.Package, record.Version, record.Content.SHA256)
	if err != nil {
		return nil, err
	}
	definition, err := hexDigest(record.DefinitionDigest)
	if err != nil {
		return nil, fmt.Errorf("attest: locked slice %q: %w", origin.Package, err)
	}
	identity, err := SlicesIdentity(record.Platform, record.Package, record.Version,
		record.Architecture, definition, hash, record.Content.Size, record.Closure)
	if err != nil {
		return nil, err
	}
	vendor, release := index.vendorOf(record.Repository)
	return &element{
		kind:     kindSlice,
		key:      record.Package,
		reported: record.Package,
		version:  record.Version,
		arch:     record.Architecture,
		archive:  record.Package,
		upstream: record.Source,
		vendor:   vendor,
		release:  release,
		cpe:      record.CPE,
		slices:   record.Closure,
		identity: identity,
	}, nil
}

// vendorOf returns the namespace and release a record is published under. A repository
// that authenticates its own release identity publishes packages the base distribution
// never built, so the vendor names them and the suite is the vendor's release. Naming
// the base distribution instead would hand a scanner a package it believes that
// distribution ships, and the distribution's advisories for the name describe its own
// build of it rather than this one.
func (index locked) vendorOf(repository string) (string, string) {
	return vendorNamespace(index.repositories[repository], index.distro, index.release)
}

// packageElement describes one whole package payload.
func (index locked) packageElement(record *lock.Package) (*element, error) {
	checksum, err := lockedElement(kindPackage, record.Name, record.Version,
		record.Content.SHA256)
	if err != nil {
		return nil, err
	}
	identity, err := PackageIdentity(record.Platform, record.Name, record.Version,
		record.Architecture, checksum, record.Content.Size)
	if err != nil {
		return nil, err
	}
	vendor, release := index.vendorOf(record.Repository)
	return &element{
		kind:     kindPackage,
		key:      record.Name,
		reported: record.Name,
		version:  record.Version,
		arch:     record.Architecture,
		archive:  record.Name,
		upstream: record.Source,
		vendor:   vendor,
		release:  release,
		cpe:      record.CPE,
		checksum: checksum,
		identity: identity,
	}, nil
}

// artifactElement describes one artifact payload. The published identity is the
// specification's, not the lock's download name, so that is the name the document states.
func artifactElement(record *lock.Artifact) (*element, error) {
	checksum, err := lockedElement(kindArtifact, record.SBOM.Name, record.SBOM.Version,
		record.SHA256)
	if err != nil {
		return nil, err
	}
	identity, err := ArtifactIdentity(record.Platform, record.Name,
		ArtifactVersion{Name: record.SBOM.Name, Version: record.SBOM.Version,
			CPE: record.SBOM.CPE},
		checksum, record.Size)
	if err != nil {
		return nil, err
	}
	return &element{
		kind:     kindArtifact,
		key:      record.Name,
		reported: record.SBOM.Name,
		version:  record.SBOM.Version,
		checksum: checksum,
		cpe:      record.SBOM.CPE,
		identity: identity,
	}, nil
}
