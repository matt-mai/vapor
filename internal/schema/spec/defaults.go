package spec

import (
	"slices"

	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/schema/policy"
)

// ApplyDefaults fills optional platform, repository, artifact and catalogue
// fields with their documented defaults.
func ApplyDefaults(spec *Spec) {
	filesystem.ApplyDefaults(&spec.Filesystem)
	policy.ApplyDefaults(&spec.Hardening, &spec.Contents.SlicesEngine)
	if spec.Platforms == nil {
		spec.Platforms = []string{"linux/amd64"}
	}
	attestation.ApplyDefaults(&spec.SBOM, &spec.VEX)
	applyRepositoryDefaults(spec)
	applyArtifactDefaults(spec)
	applyCatalogueDefaults(spec)
}

func applyRepositoryDefaults(spec *Spec) {
	for i := range spec.Contents.Repositories {
		repository := &spec.Contents.Repositories[i]
		if repository.Platforms == nil {
			repository.Platforms = slices.Clone(spec.Platforms)
		}
		if repository.ByHash == nil {
			repository.ByHash = new("prefer")
		}
		if repository.Freshness.ValidUntil == nil {
			repository.Freshness.ValidUntil = new("if-present")
		}
	}
}

func applyArtifactDefaults(spec *Spec) {
	for i := range spec.Contents.Artifacts {
		artifact := &spec.Contents.Artifacts[i]
		if artifact.Platforms == nil {
			artifact.Platforms = slices.Clone(spec.Platforms)
		}
		if artifact.Unpack != nil && *artifact.Unpack == contents.ArtifactUnpackStandalone && artifact.Mode == nil {
			artifact.Mode = new("0644")
		}
	}
}

func applyCatalogueDefaults(spec *Spec) {
	if len(spec.Contents.Catalogues) != 1 {
		return
	}
	for i := range spec.Contents.Slices {
		if spec.Contents.Slices[i].Catalogue == nil {
			spec.Contents.Slices[i].Catalogue = new(spec.Contents.Catalogues[0].Name)
		}
	}
}
