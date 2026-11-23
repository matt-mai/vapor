package attest

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/lock"
)

// SLSA provenance v1, as an in-toto statement. The build type is Vapor's own, so the
// parameters are documented where the payload is produced rather than borrowed from a
// hosted build platform.
const (
	buildTypeURI = "https://mattnet.de/vapor/build/v1"
	builderURI   = "https://mattnet.de/vapor"
)

// Toolchain is the tool that ran the build. It is passed in rather than read from the
// running binary, so the same inputs always produce the same bytes.
type Toolchain struct {
	Name    string
	Version string
}

// ProvenanceInput is what a provenance statement records: the image it describes, the
// lock whose content it replayed, and the tool that did the replay.
type ProvenanceInput struct {
	Name     string
	Platform string
	// Subject is the digest of the platform manifest this statement is attached to.
	Subject   string
	Lock      *lock.Lockfile
	Toolchain Toolchain
}

// Provenance returns the canonical bytes of one platform's SLSA v1 predicate. It is the
// claim itself, so a statement wrapping it and a file holding it carry the same bytes.
//
// Every locked input of that platform becomes a resolved dependency, including the
// lock itself, so a reader can tell that nothing was fetched outside it. Nothing here
// depends on the clock or the host, and nothing depends on SBOM generation.
func Provenance(input *ProvenanceInput) ([]byte, error) {
	document, err := input.statement()
	if err != nil {
		return nil, err
	}
	return Encode(document.Predicate)
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     predicate `json:"predicate"`
}

type subject struct {
	Name   string `json:"name"`
	Digest digest `json:"digest"`
}

type digest struct {
	SHA256 string `json:"sha256"`
}

type predicate struct {
	BuildDefinition buildDefinition `json:"buildDefinition"`
	RunDetails      runDetails      `json:"runDetails"`
}

type buildDefinition struct {
	BuildType            string       `json:"buildType"`
	ExternalParameters   parameters   `json:"externalParameters"`
	ResolvedDependencies []dependency `json:"resolvedDependencies"`
}

// parameters are the inputs under the control of whoever ran the build. The
// specification's identity is here rather than a copy of its text, which is what makes
// two builds comparable.
type parameters struct {
	Spec string `json:"spec"`
}

type dependency struct {
	Name   string `json:"name"`
	Digest digest `json:"digest"`
}

type runDetails struct {
	Builder builder `json:"builder"`
}

type builder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version"`
}

func (input *ProvenanceInput) statement() (statement, error) {
	if err := input.validate(); err != nil {
		return statement{}, err
	}
	dependencies, err := input.dependencies()
	if err != nil {
		return statement{}, err
	}
	return statement{
		Type: statementTypeV1,
		Subject: []subject{{
			Name:   input.Name + " " + input.Platform,
			Digest: digest{SHA256: strings.TrimPrefix(input.Subject, "sha256:")},
		}},
		PredicateType: PredicateTypeSLSA,
		Predicate: predicate{
			BuildDefinition: buildDefinition{
				BuildType:            buildTypeURI,
				ExternalParameters:   parameters{Spec: input.Lock.SpecDigest},
				ResolvedDependencies: dependencies,
			},
			// No timestamps: SLSA does not require them, and a build did not start at
			// the epoch. The builder version is the toolchain identity.
			RunDetails: runDetails{Builder: builder{
				ID:      builderURI,
				Version: map[string]string{input.Toolchain.Name: input.Toolchain.Version},
			}},
		},
	}, nil
}

func (input *ProvenanceInput) validate() error {
	switch {
	case input.Name == "":
		return errors.New("attest: provenance requires an image name")
	case !safeSegment(input.Name):
		return fmt.Errorf("attest: image name %q is not usable in a statement", input.Name)
	case input.Platform == "":
		return errors.New("attest: provenance requires a platform")
	case !safeSegment(input.Platform):
		return fmt.Errorf("attest: platform %q is not usable in a statement", input.Platform)
	case !strings.HasPrefix(input.Subject, "sha256:"):
		return errors.New("attest: provenance requires the subject manifest digest")
	case input.Lock == nil:
		return errors.New("attest: provenance requires the lock")
	case input.Toolchain.Name == "" || input.Toolchain.Version == "":
		return errors.New("attest: provenance requires the toolchain name and version")
	}
	if slices.Contains(input.Lock.Platforms, input.Platform) {
		return nil
	}
	return fmt.Errorf("attest: provenance platform %q is not in the lock", input.Platform)
}

// dependencies lists every locked input of this platform once. The lock itself is
// first, because everything else is only trustworthy through it.
func (input *ProvenanceInput) dependencies() ([]dependency, error) {
	collected := newDependencies()
	lockBytes, err := input.Lock.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("attest: encode lock for provenance: %w", err)
	}
	if err := collected.add("lock", Digest(lockBytes)); err != nil {
		return nil, err
	}
	for _, source := range input.sources() {
		for _, record := range source.records {
			if record.platform != "" && record.platform != input.Platform {
				continue
			}
			if err := collected.add(source.prefix+record.name, record.identity); err != nil {
				return nil, err
			}
		}
	}
	return collected.sorted(), nil
}

// lockedSource is one family of locked inputs and how a statement names them.
type lockedSource struct {
	prefix  string
	records []lockedRecord
}

type lockedRecord struct {
	name     string
	identity string
	// platform is empty when the input belongs to every platform, as a catalogue and a
	// trust key do.
	platform string
}

// sources lists the lock's input families in a fixed order. A record is named by what
// it is rather than by where it was fetched, so moving a mirror does not change the
// statement.
func (input *ProvenanceInput) sources() []lockedSource {
	lockfile := input.Lock
	catalogues := make([]lockedRecord, 0, len(lockfile.Catalogues))
	for position := range lockfile.Catalogues {
		catalogue := &lockfile.Catalogues[position]
		identity := catalogue.Tree
		if catalogue.Archive != nil {
			identity = catalogue.Archive.SHA256
		}
		catalogues = append(catalogues, lockedRecord{name: catalogue.Name, identity: identity})
	}
	local := make([]lockedRecord, 0, len(lockfile.LocalInputs))
	for position := range lockfile.LocalInputs {
		snapshot := &lockfile.LocalInputs[position]
		local = append(local, lockedRecord{
			name: snapshot.Role + "/" + snapshot.Path, identity: snapshot.SHA256,
		})
	}
	repositories := make([]lockedRecord, 0, len(lockfile.Repositories))
	for position := range lockfile.Repositories {
		repository := &lockfile.Repositories[position]
		repositories = append(repositories, lockedRecord{
			name: repository.ID, identity: repository.Release.SHA256, platform: repository.Platform,
		})
	}
	packages := make([]lockedRecord, 0, len(lockfile.Packages))
	for position := range lockfile.Packages {
		record := &lockfile.Packages[position]
		packages = append(packages, lockedRecord{
			name: record.Name, identity: record.Content.SHA256, platform: record.Platform,
		})
	}
	sliced := make([]lockedRecord, 0, len(lockfile.Slices))
	for position := range lockfile.Slices {
		record := &lockfile.Slices[position]
		sliced = append(sliced, lockedRecord{
			name: record.Package, identity: record.Content.SHA256, platform: record.Platform,
		})
	}
	artifacts := make([]lockedRecord, 0, len(lockfile.Artifacts))
	for position := range lockfile.Artifacts {
		record := &lockfile.Artifacts[position]
		artifacts = append(artifacts, lockedRecord{
			name: record.Name, identity: record.SHA256, platform: record.Platform,
		})
	}
	return []lockedSource{
		{prefix: "catalogue/", records: catalogues},
		{prefix: "input/", records: local},
		{prefix: "repository/", records: repositories},
		{prefix: "package/", records: packages},
		{prefix: "slice/", records: sliced},
		{prefix: "artifact/", records: artifacts},
	}
}

// dependencies collects resolved dependencies by name. Two inputs with the same name
// would make the statement ambiguous, so that is reported rather than merged.
type dependencies struct {
	items map[string]dependency
}

func newDependencies() *dependencies {
	return &dependencies{items: map[string]dependency{}}
}

func (collected *dependencies) add(name, identity string) error {
	hash, err := hexDigest(identity)
	if err != nil {
		return fmt.Errorf("attest: %s: %w", name, err)
	}
	if _, seen := collected.items[name]; seen {
		return fmt.Errorf("attest: %s appears twice among the locked inputs", name)
	}
	collected.items[name] = dependency{Name: name, Digest: digest{SHA256: hash}}
	return nil
}

func (collected *dependencies) sorted() []dependency {
	items := make([]dependency, 0, len(collected.items))
	for _, item := range collected.items {
		items = append(items, item)
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Name < items[right].Name })
	return items
}

// hexDigest accepts a lock digest with or without its algorithm prefix and returns the
// bare lowercase hex a statement carries.
func hexDigest(value string) (string, error) {
	hash := strings.TrimPrefix(value, "sha256:")
	if len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%q is not a SHA256 digest", value)
	}
	return hash, nil
}
