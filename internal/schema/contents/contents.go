package contents

import (
	"encoding/json"
	"errors"

	"gopkg.in/yaml.v3"
)

// SliceEngine bounds mutation steps without disabling required v3 semantics.
type SliceEngine struct {
	MaxSteps *int `yaml:"max-steps" json:"max-steps"`
}

// Contents declares image inputs; loading a spec does not acquire them.
type Contents struct {
	Packages     []PackageRequest  `yaml:"packages" json:"packages"`
	Slices       []SliceRequest    `yaml:"slices" json:"slices"`
	Catalogues   []CatalogueSource `yaml:"catalogues" json:"catalogues"`
	Repositories []Repository      `yaml:"repositories" json:"repositories"`
	Artifacts    []Artifact        `yaml:"artifacts" json:"artifacts"`
	SlicesEngine SliceEngine       `yaml:"slices-engine" json:"slices-engine"`
}

// PackageRequest selects a whole package with an optional version constraint.
// CPE is the advisory database's name for the package when its own index files none.
type PackageRequest struct {
	Name    string  `yaml:"name" json:"name"`
	Version *string `yaml:"version" json:"version"`
	CPE     string  `yaml:"cpe,omitempty" json:"cpe,omitzero"`
}

// SliceRequest selects a slice; Catalogue may be omitted with one source.
type SliceRequest struct {
	Package   string  `yaml:"package" json:"package"`
	Slice     string  `yaml:"slice" json:"slice"`
	Version   *string `yaml:"version" json:"version"`
	Catalogue *string `yaml:"catalogue" json:"catalogue"`
	CPE       string  `yaml:"cpe,omitempty" json:"cpe,omitzero"`
}

// CatalogueSource selects an exclusive local directory or remote Git reference.
type CatalogueSource struct {
	Name     string            `yaml:"name" json:"name"`
	URL      *string           `yaml:"url" json:"url"`
	Tag      *string           `yaml:"tag" json:"tag"`
	Branch   *string           `yaml:"branch" json:"branch"`
	Commit   *string           `yaml:"commit" json:"commit"`
	Path     *string           `yaml:"path" json:"path"`
	Archives map[string]string `yaml:"archives" json:"archives"`
}

// Endpoint assigns a repository mirror to explicit target platforms.
type Endpoint struct {
	Platforms []string `yaml:"platforms" json:"platforms"`
	URL       string   `yaml:"url" json:"url"`
}

// SuiteMatchCodename selects the signed Codename instead of the provider default.
const SuiteMatchCodename = "codename"

// RepositoryIdentityOwn lets a repository authenticate its own release identity
// instead of the distribution's. A vendor publishing a moving suite next to a
// fixed codename of its own is not describing the base release, so the provider's
// suite and codename rules cannot judge it.
const RepositoryIdentityOwn = "own"

// Repository declares authenticated package sources and their acquisition policy.
type Repository struct {
	Name       string     `yaml:"name" json:"name"`
	Platforms  []string   `yaml:"platforms" json:"platforms"`
	Endpoints  []Endpoint `yaml:"endpoints" json:"endpoints"`
	Suites     []string   `yaml:"suites" json:"suites"`
	SuiteMatch *string    `yaml:"suite-match,omitempty" json:"suite-match,omitzero"`
	Components []string   `yaml:"components" json:"components"`
	Trust      Trust      `yaml:"trust" json:"trust"`
	ByHash     *string    `yaml:"by-hash" json:"by-hash"`
	Freshness  Freshness  `yaml:"freshness" json:"freshness"`
	// Identity is empty for a repository of the base release and "own" for one
	// that authenticates its own release metadata.
	Identity *string `yaml:"identity,omitempty" json:"identity,omitzero"`
	// Packages names the packages this repository may supply. A vendor archive
	// only offers packages it was declared for, so adding it cannot replace an
	// unrelated base package. Empty means the whole archive is part of the image.
	Packages []string `yaml:"packages,omitempty" json:"packages,omitempty"`
}

// Trust replaces default trust for an explicit repository; it never merges keys.
type Trust struct {
	Keys []TrustKey `yaml:"keys" json:"keys"`
}

// TrustKey references public key material and independently trusted full fingerprints.
type TrustKey struct {
	Path         string   `yaml:"path" json:"path"`
	Fingerprints []string `yaml:"fingerprints" json:"fingerprints"`
}

// Freshness controls expiry checks on authenticated repository metadata.
type Freshness struct {
	ValidUntil *string `yaml:"valid-until" json:"valid-until"`
}

// Placement is how an artifact's payload is placed.
type Placement string

// Placement of an artifact payload. A package payload is a DEB whose content,
// identity and relationships come from the package itself, so dest, uid, gid and
// mode do not apply to it.
const (
	ArtifactUnpackArchive    Placement = "true"
	ArtifactUnpackStandalone Placement = "false"
	ArtifactUnpackPackage    Placement = "package"
)

// UnmarshalYAML accepts the boolean form of an archive or standalone placement, so
// `unpack: true` stays a plain boolean while `unpack: package` names the third one.
func (p *Placement) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!!bool":
		var value bool
		if err := node.Decode(&value); err != nil {
			return err
		}
		return p.fromBool(value)
	case "!!str":
		if node.Value != string(ArtifactUnpackPackage) {
			return errors.New("artifact unpack must be a boolean or package")
		}
		*p = ArtifactUnpackPackage
		return nil
	}
	return errors.New("artifact unpack must be a boolean or package")
}

// MarshalYAML writes a boolean placement as a boolean, so a lock stays readable.
func (p Placement) MarshalYAML() (any, error) {
	return p.canonical(), nil
}

// UnmarshalJSON accepts the shapes MarshalJSON writes, so a canonical spec snapshot
// and a canonical lock decode back to the same placement.
func (p *Placement) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("artifact unpack must be a boolean or package")
	}
	switch typed := value.(type) {
	case bool:
		return p.fromBool(typed)
	case string:
		if typed != string(ArtifactUnpackPackage) {
			return errors.New("artifact unpack must be a boolean or package")
		}
		*p = ArtifactUnpackPackage
		return nil
	}
	return errors.New("artifact unpack must be a boolean or package")
}

// MarshalJSON writes the same shape as MarshalYAML, so the canonical lock and the
// canonical JSON agree on how a placement is spelled.
func (p Placement) MarshalJSON() ([]byte, error) {
	value, err := json.Marshal(p.canonical())
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (p *Placement) fromBool(value bool) error {
	if value {
		*p = ArtifactUnpackArchive
		return nil
	}
	*p = ArtifactUnpackStandalone
	return nil
}

func (p Placement) canonical() any {
	switch p {
	case ArtifactUnpackArchive:
		return true
	case ArtifactUnpackStandalone:
		return false
	}
	return string(p)
}

// Artifact groups platform payloads sharing a destination and installation policy.
type Artifact struct {
	Name      string           `yaml:"name" json:"name"`
	Platforms []string         `yaml:"platforms" json:"platforms"`
	Sources   []ArtifactSource `yaml:"sources" json:"sources"`
	// Unpack is the placement of the payload: true extracts an archive, false
	// places one file, and "package" installs a DEB as a package.
	Unpack *Placement       `yaml:"unpack" json:"unpack"`
	Dest   string           `yaml:"dest" json:"dest"`
	UID    int              `yaml:"uid" json:"uid"`
	GID    int              `yaml:"gid" json:"gid"`
	Mode   *string          `yaml:"mode" json:"mode"`
	SBOM   ArtifactIdentity `yaml:"sbom" json:"sbom"`
}

// ArtifactSource identifies immutable payload bytes for explicit platforms. It is
// declared by URL or by a path relative to the specification directory, never both.
type ArtifactSource struct {
	Platforms []string `yaml:"platforms" json:"platforms"`
	URL       string   `yaml:"url" json:"url"`
	Path      string   `yaml:"path" json:"path"`
	SHA256    string   `yaml:"sha256" json:"sha256"`
}

// ArtifactIdentity supplies the required upstream name/version for later SBOMs, and the
// CPE a vulnerability database files an advisory under when the payload is not a package
// a purl can name.
type ArtifactIdentity struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
	CPE     string `yaml:"cpe,omitempty" json:"cpe,omitempty"`
}
