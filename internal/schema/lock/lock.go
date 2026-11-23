// Package lock is the version-1 resolved image lockfile.
package lock

import "github.com/matt-mai/vapor/internal/schema/contents"

// Lockfile is the version-1 immutable resolution record described in
// docs/developer/lock-schema.md. It does not itself authenticate evidence.
type Lockfile struct {
	Version      int          `yaml:"version" json:"version"`
	SpecDigest   string       `yaml:"spec" json:"spec"`
	Provider     Provider     `yaml:"provider" json:"provider"`
	Platforms    []string     `yaml:"platforms" json:"platforms"`
	LocalInputs  []LocalInput `yaml:"local-inputs" json:"local-inputs"`
	Catalogues   []Catalogue  `yaml:"catalogues" json:"catalogues"`
	Repositories []Repository `yaml:"repositories" json:"repositories"`
	Packages     []Package    `yaml:"packages" json:"packages"`
	Slices       []Slice      `yaml:"slices" json:"slices"`
	Artifacts    []Artifact   `yaml:"artifacts" json:"artifacts"`
}

// Provider records the distribution identity the lock was resolved for.
type Provider struct {
	Distro  string `yaml:"distro" json:"distro"`
	Release string `yaml:"release" json:"release"`
}

// LocalInput is a snapshotted trust-key, CA or VEX file.
type LocalInput struct {
	Role   string `yaml:"role" json:"role"`
	Path   string `yaml:"path" json:"path"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	Size   int64  `yaml:"size" json:"size"`
}

// Catalogue records a declared catalogue source and its resolved content.
type Catalogue struct {
	Name     string           `yaml:"name" json:"name"`
	Source   CatalogueSource  `yaml:"source" json:"source"`
	Tree     string           `yaml:"tree" json:"tree"`
	Manifest []CatalogueEntry `yaml:"manifest,omitempty" json:"manifest,omitempty"`
	Archive  *Archive         `yaml:"archive,omitempty" json:"archive,omitempty"`
}

// CatalogueEntry is one canonical entry in a catalogue tree manifest.
type CatalogueEntry struct {
	Path       string `yaml:"path" json:"path"`
	Kind       string `yaml:"kind" json:"kind"`
	Executable bool   `yaml:"executable,omitempty" json:"executable,omitempty"`
	SHA256     string `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	Size       int64  `yaml:"size,omitempty" json:"size,omitempty"`
	Target     string `yaml:"target,omitempty" json:"target,omitempty"`
}

// CatalogueSource distinguishes a remote selector from a local directory.
type CatalogueSource struct {
	Type     string             `yaml:"type" json:"type"`
	URL      string             `yaml:"url,omitempty" json:"url,omitempty"`
	Selector *CatalogueSelector `yaml:"selector,omitempty" json:"selector,omitempty"`
	Commit   string             `yaml:"commit,omitempty" json:"commit,omitempty"`
	Path     string             `yaml:"path,omitempty" json:"path,omitempty"`
}

// CatalogueSelector preserves the declared remote selector.
type CatalogueSelector struct {
	Branch *string `yaml:"branch,omitempty" json:"branch,omitempty"`
	Tag    *string `yaml:"tag,omitempty" json:"tag,omitempty"`
	Commit *string `yaml:"commit,omitempty" json:"commit,omitempty"`
}

// Archive is the exact acquired archive bytes of a remote catalogue.
type Archive struct {
	SHA256 string `yaml:"sha256" json:"sha256"`
	Size   int64  `yaml:"size" json:"size"`
}

// Repository records one consumed suite and its authentication evidence.
type Repository struct {
	ID           string            `yaml:"id" json:"id"`
	Name         string            `yaml:"name" json:"name"`
	Platform     string            `yaml:"platform" json:"platform"`
	Architecture string            `yaml:"architecture" json:"architecture"`
	URL          string            `yaml:"url" json:"url"`
	Suite        string            `yaml:"suite" json:"suite"`
	Trust        RepositoryTrust   `yaml:"trust" json:"trust"`
	Release      RepositoryRelease `yaml:"release" json:"release"`
	Indexes      []Index           `yaml:"indexes" json:"indexes"`
}

// RepositoryTrust lists anchors that were trusted for this suite.
type RepositoryTrust struct {
	Keys []RepositoryKey `yaml:"keys" json:"keys"`
}

// RepositoryKey is one full fingerprint and its public key bytes.
type RepositoryKey struct {
	Fingerprint string `yaml:"fingerprint" json:"fingerprint"`
	Path        string `yaml:"path,omitempty" json:"path,omitempty"`
	SHA256      string `yaml:"sha256" json:"sha256"`
	Size        int64  `yaml:"size" json:"size"`
}

// RepositoryRelease is the exact signed metadata evidence for a suite.
type RepositoryRelease struct {
	Format     string   `yaml:"format" json:"format"`
	Path       string   `yaml:"path" json:"path"`
	SHA256     string   `yaml:"sha256" json:"sha256"`
	Size       int64    `yaml:"size" json:"size"`
	ValidUntil *string  `yaml:"valid-until,omitempty" json:"valid-until,omitempty"`
	Signers    []string `yaml:"signers" json:"signers"`
	Signature  *Content `yaml:"signature,omitempty" json:"signature,omitempty"`
}

// Index identifies one consumed compressed package index.
type Index struct {
	Component string `yaml:"component" json:"component"`
	Path      string `yaml:"path" json:"path"`
	SHA256    string `yaml:"sha256" json:"sha256"`
	Size      int64  `yaml:"size" json:"size"`
}

// Content identifies repository-relative bytes and their exact size.
type Content struct {
	Path   string `yaml:"path" json:"path"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	Size   int64  `yaml:"size" json:"size"`
}

// Package is one resolved whole package payload on a platform.
type Package struct {
	Platform     string `yaml:"platform" json:"platform"`
	Name         string `yaml:"name" json:"name"`
	Version      string `yaml:"version" json:"version"`
	Architecture string `yaml:"architecture" json:"architecture"`
	// Source is the source package the archive was built from, absent when the index
	// names none. Vulnerability data and package URLs are keyed on it, so a scanner
	// reads a library under the package that publishes its fixes.
	Source     string  `yaml:"source,omitempty" json:"source,omitempty"`
	Repository string  `yaml:"repository" json:"repository"`
	Content    Content `yaml:"content" json:"content"`
}

// Slice is one resolved sliced-package payload and definition closure.
type Slice struct {
	Platform         string   `yaml:"platform" json:"platform"`
	Package          string   `yaml:"package" json:"package"`
	Version          string   `yaml:"version" json:"version"`
	Architecture     string   `yaml:"architecture" json:"architecture"`
	Source           string   `yaml:"source,omitempty" json:"source,omitempty"`
	Catalogue        string   `yaml:"catalogue" json:"catalogue"`
	Archive          string   `yaml:"archive" json:"archive"`
	Repository       string   `yaml:"repository" json:"repository"`
	Content          Content  `yaml:"content" json:"content"`
	Selected         []string `yaml:"selected" json:"selected"`
	Closure          []string `yaml:"closure" json:"closure"`
	DefinitionDigest string   `yaml:"definition-digest" json:"definition-digest"`
}

// Artifact is one resolved artifact payload on a platform. A payload from the local
// filesystem records the declared path instead of a URL.
type Artifact struct {
	Name     string `yaml:"name" json:"name"`
	Platform string `yaml:"platform" json:"platform"`
	URL      string `yaml:"url,omitempty" json:"url,omitempty"`
	Path     string `yaml:"path,omitempty" json:"path,omitempty"`
	SHA256   string `yaml:"sha256" json:"sha256"`
	Size     int64  `yaml:"size" json:"size"`
	Dest     string `yaml:"dest" json:"dest"`
	// Unpack is the placement of the payload: an archive, one file, or a package.
	Unpack *contents.Placement       `yaml:"unpack" json:"unpack"`
	UID    int                       `yaml:"uid" json:"uid"`
	GID    int                       `yaml:"gid" json:"gid"`
	Mode   *string                   `yaml:"mode,omitempty" json:"mode,omitempty"`
	SBOM   contents.ArtifactIdentity `yaml:"sbom" json:"sbom"`
}

// Source returns the payload identity the record names.
func (a *Artifact) Source() string {
	if a.Path != "" {
		return a.Path
	}
	return a.URL
}
