// Package locking assembles, audits and compares verified lock evidence.
package locking

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

// Provider supplies the canonical distribution and release identity.
type Provider interface {
	Distro() string
	Release() string
}

// BlobStore provides verified cached bytes.
type BlobStore interface {
	Open(digest string, size int64) (io.ReadCloser, error)
}

// Evidence contains records produced by resolution, acquisition and local
// snapshots. Assemble does not derive or rewrite their content.
type Evidence struct {
	LocalInputs  []lock.LocalInput
	Catalogues   []lock.Catalogue
	Repositories []lock.Repository
	Packages     []lock.Package
	Slices       []lock.Slice
	Artifacts    []lock.Artifact
	// Warnings are clock-derived diagnostics from the resolved inputs. They are
	// reported to the user and never reach a lock or an image.
	Warnings []string
}

// Stats reports actual audited outputs.
type Stats struct {
	Packages      int
	VerifiedBytes int64
}

// AssembleWithDefaults also accepts a provider-owned repository that may appear
// in the evidence without a spec declaration.
func AssembleWithDefaults(specification *spec.Spec, provider Provider, evidence *Evidence,
	defaults *lock.DefaultRepository) (*lock.Lockfile, error) {
	if specification == nil {
		return nil, errors.New("spec must not be nil")
	}
	if provider == nil {
		return nil, errors.New("provider must not be nil")
	}
	if evidence == nil {
		return nil, errors.New("evidence must not be nil")
	}
	release := provider.Release()
	digest, err := specification.SpecDigestForRelease(release)
	if err != nil {
		return nil, fmt.Errorf("assemble lock: %w", err)
	}
	canonical, err := spec.CopySpec(specification)
	if err != nil {
		return nil, fmt.Errorf("assemble lock: %w", err)
	}
	canonical.Release = release
	spec.ApplyDefaults(canonical)
	if err := spec.ValidateSpec(canonical); err != nil {
		return nil, fmt.Errorf("assemble lock: %w", err)
	}
	assembled := &lock.Lockfile{
		Version:      1,
		SpecDigest:   digest,
		Provider:     lock.Provider{Distro: provider.Distro(), Release: release},
		Platforms:    slices.Clone(canonical.Platforms),
		LocalInputs:  slices.Clone(evidence.LocalInputs),
		Catalogues:   slices.Clone(evidence.Catalogues),
		Repositories: slices.Clone(evidence.Repositories),
		Packages:     slices.Clone(evidence.Packages),
		Slices:       slices.Clone(evidence.Slices),
		Artifacts:    slices.Clone(evidence.Artifacts),
	}
	if err := lock.VerifyLockfileForProvider(specification, assembled, release, defaults); err != nil {
		return nil, fmt.Errorf("assemble lock: %w", err)
	}
	return assembled, nil
}
