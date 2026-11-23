package lock

import (
	"errors"
	"fmt"
	"math"
	"path"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func verifyLockArtifacts(spec *schemaSpec.Spec, lock *Lockfile) error {
	declared := declaredArtifacts(spec)
	artifacts := make(map[lockPackageKey]*Artifact)
	for i := range lock.Artifacts {
		artifact := &lock.Artifacts[i]
		specArtifact, ok := declared[artifact.Name]
		if !ok {
			return fmt.Errorf("lock artifacts[%d]: unknown artifact", i)
		}
		if err := verifyLockArtifact(artifact, specArtifact, spec, i); err != nil {
			return err
		}
		key := lockPackageKey{platform: artifact.Platform, name: artifact.Name}
		if _, duplicate := artifacts[key]; duplicate {
			return fmt.Errorf("lock artifacts[%d]: duplicate name and platform", i)
		}
		artifacts[key] = artifact
	}
	return verifyArtifactRequests(spec, artifacts)
}

func declaredArtifacts(spec *schemaSpec.Spec) map[string]*contents.Artifact {
	declared := make(map[string]*contents.Artifact)
	for i := range spec.Contents.Artifacts {
		declared[spec.Contents.Artifacts[i].Name] = &spec.Contents.Artifacts[i]
	}
	return declared
}

func verifyLockArtifact(artifact *Artifact, specArtifact *contents.Artifact, spec *schemaSpec.Spec, i int) error {
	if !slices.Contains(spec.Platforms, artifact.Platform) || !slices.Contains(specArtifact.Platforms, artifact.Platform) {
		return fmt.Errorf("lock artifacts[%d]: platform is outside the artifact scope", i)
	}
	source, ok := artifactSource(specArtifact, artifact.Platform)
	if !ok {
		return fmt.Errorf("lock artifacts[%d]: no spec source for platform", i)
	}
	if err := verifyArtifactSource(artifact, source, i); err != nil {
		return err
	}
	return verifyArtifactMetadata(artifact, specArtifact, i)
}

func verifyArtifactSource(artifact *Artifact, source contents.ArtifactSource, i int) error {
	if artifact.URL != source.URL || artifact.Path != source.Path || artifact.SHA256 != source.SHA256 {
		return fmt.Errorf("lock artifacts[%d]: source identity does not match the spec", i)
	}
	if (artifact.URL == "") == (artifact.Path == "") {
		return fmt.Errorf("lock artifacts[%d]: source requires either a url or a path", i)
	}
	if err := validateArtifactOrigin(artifact); err != nil {
		return fmt.Errorf("lock artifacts[%d]: %w", i, err)
	}
	if err := checkLockHash("artifact", artifact.SHA256); err != nil {
		return fmt.Errorf("lock artifacts[%d]: %w", i, err)
	}
	if err := checkLockSize("artifact", artifact.Size); err != nil {
		return fmt.Errorf("lock artifacts[%d]: %w", i, err)
	}
	return nil
}

func verifyArtifactMetadata(artifact *Artifact, specArtifact *contents.Artifact, i int) error {
	if artifact.Dest != specArtifact.Dest || artifact.UID != specArtifact.UID || artifact.GID != specArtifact.GID ||
		artifact.SBOM != specArtifact.SBOM {
		return fmt.Errorf("lock artifacts[%d]: placement metadata does not match the spec", i)
	}
	if err := validateLockArtifactDest(artifact.Dest, artifact.Unpack); err != nil {
		return fmt.Errorf("lock artifacts[%d]: %w", i, err)
	}
	if artifact.UID < 0 || artifact.GID < 0 || uint64(artifact.UID) > math.MaxUint32 || uint64(artifact.GID) > math.MaxUint32 {
		return fmt.Errorf("lock artifacts[%d]: uid/gid must be uint32-range integers", i)
	}
	if artifact.Unpack == nil || specArtifact.Unpack == nil || *artifact.Unpack != *specArtifact.Unpack {
		return fmt.Errorf("lock artifacts[%d]: unpack does not match the spec", i)
	}
	if err := verifyLockArtifactPlacement(artifact, i); err != nil {
		return err
	}
	if err := verifyLockArtifactMode(artifact, specArtifact, i); err != nil {
		return err
	}
	if strings.TrimSpace(artifact.SBOM.Name) == "" || strings.TrimSpace(artifact.SBOM.Version) == "" {
		return fmt.Errorf("lock artifacts[%d]: sbom identity must be nonempty", i)
	}
	if err := contents.ValidateCPE(artifact.SBOM.CPE); err != nil {
		return fmt.Errorf("lock artifacts[%d]: %w", i, err)
	}
	return nil
}

// verifyLockArtifactPlacement checks what a placement forbids. A package brings its
// own content, owner and modes, so the lock must not carry any of them.
func verifyLockArtifactPlacement(artifact *Artifact, i int) error {
	if *artifact.Unpack != contents.ArtifactUnpackPackage {
		return nil
	}
	if artifact.UID != 0 || artifact.GID != 0 {
		return fmt.Errorf("lock artifacts[%d]: a package artifact must not declare ownership", i)
	}
	return nil
}

func verifyArtifactRequests(spec *schemaSpec.Spec, artifacts map[lockPackageKey]*Artifact) error {
	for i := range spec.Contents.Artifacts {
		specArtifact := &spec.Contents.Artifacts[i]
		for _, platform := range specArtifact.Platforms {
			if _, ok := artifacts[lockPackageKey{platform: platform, name: specArtifact.Name}]; !ok {
				return fmt.Errorf("lock artifacts: missing payload for %q on %s", specArtifact.Name, platform)
			}
		}
	}
	return nil
}

func artifactSource(artifact *contents.Artifact, platform string) (contents.ArtifactSource, bool) {
	for _, source := range artifact.Sources {
		if slices.Contains(source.Platforms, platform) {
			return source, true
		}
	}
	return contents.ArtifactSource{}, false
}

func verifyLockArtifactMode(artifact *Artifact, specArtifact *contents.Artifact, i int) error {
	if *artifact.Unpack != contents.ArtifactUnpackStandalone {
		if artifact.Mode != nil {
			return fmt.Errorf("lock artifacts[%d]: unpacked artifact must not override mode", i)
		}
		return nil
	}
	if artifact.Mode == nil || specArtifact.Mode == nil || *artifact.Mode != *specArtifact.Mode {
		return fmt.Errorf("lock artifacts[%d]: mode does not match the spec", i)
	}
	if err := base.RequirePattern("artifact mode", *artifact.Mode, `^(0[0-7]{3}|0[1-7][0-7]{3})$`); err != nil {
		return fmt.Errorf("lock artifacts[%d]: %w", i, err)
	}
	return nil
}

// validateArtifactOrigin checks the one origin a record names: a path is already
// snapshotted, so its relative form is what replay can compare with the specification.
func validateArtifactOrigin(artifact *Artifact) error {
	if artifact.Path != "" {
		return base.ValidateLocalPath(artifact.Path)
	}
	return base.ValidateInputURL(artifact.URL, false)
}

func validateLockArtifactDest(dest string, unpack *contents.Placement) error {
	if unpack != nil && *unpack == contents.ArtifactUnpackPackage {
		if dest != "" {
			return errors.New("package artifact must not declare a destination")
		}
		return nil
	}
	if !path.IsAbs(dest) || path.Clean(dest) != dest || strings.Contains(dest, "\\") ||
		(unpack != nil && *unpack == contents.ArtifactUnpackStandalone && dest == "/") {
		return errors.New("artifact dest must be a clean absolute POSIX path")
	}
	return nil
}
