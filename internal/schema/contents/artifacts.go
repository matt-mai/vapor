// Package contents defines image inputs, repository and catalogue declarations.
package contents

import (
	"errors"
	"fmt"
	"math"
	"path"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// ValidateCPE checks an absent or well-formed CPE 2.3 name. The 13 colon-separated
// fields are checked rather than each attribute, because a scanner parses the string and
// a field count is what tells whole from truncated. An empty value is allowed: a payload
// whose advisories are filed under a purl needs none.
func ValidateCPE(value string) error {
	return validateCPENamed(value, "artifact sbom cpe")
}

// ValidateDeclaredCPE checks the CPE a package or slice request declares, which is the
// advisory database's name for a package its own index files none under.
func ValidateDeclaredCPE(value string) error {
	return validateCPENamed(value, "cpe")
}

func validateCPENamed(value, field string) error {
	if value == "" {
		return nil
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("%s must be a CPE 2.3 name without whitespace", field)
	}
	fields := SplitCPE(value)
	if len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
		return fmt.Errorf("%s must be a CPE 2.3 name such as "+
			"cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*", field)
	}
	if part := fields[2]; part != "a" && part != "o" && part != "h" {
		return fmt.Errorf("%s part must be a, o or h", field)
	}
	if fields[3] == "" || fields[4] == "" || fields[3] == "*" || fields[4] == "*" {
		return fmt.Errorf("%s must name a product, which wildcards cannot", field)
	}
	return nil
}

func validateArtifacts(artifacts []Artifact, platforms []string) error {
	seen := make(map[string]bool)
	identities := make(map[string]string)
	for i := range artifacts {
		artifact := &artifacts[i]
		if seen[artifact.Name] {
			return errors.New("duplicate artifact name")
		}
		seen[artifact.Name] = true
		if err := validateArtifact(artifact, platforms); err != nil {
			return fmt.Errorf("contents.artifacts[%d]: %w", i, err)
		}
		if err := agreeOnArtifactIdentity(identities, artifact); err != nil {
			return fmt.Errorf("contents.artifacts[%d]: %w", i, err)
		}
	}
	return nil
}

// agreeOnArtifactIdentity refuses two artifacts that share one platform and one purl but
// declare different CPEs. A claim names a product by its purl, and the CPE is the
// advisory-database name published beside it, so one purl with two names would put a
// claim under whichever name came first.
func agreeOnArtifactIdentity(identities map[string]string, artifact *Artifact) error {
	for _, platform := range artifact.Platforms {
		key := platform + "\x00" + artifact.SBOM.Name + "@" + artifact.SBOM.Version
		if first, seen := identities[key]; seen && first != artifact.SBOM.CPE {
			return fmt.Errorf("artifacts %q declare different CPEs for one identity", artifact.Name)
		}
		identities[key] = artifact.SBOM.CPE
	}
	return nil
}

func validateArtifact(artifact *Artifact, platforms []string) error {
	if err := base.ValidateInputName(artifact.Name); err != nil {
		return err
	}
	if err := base.ValidateScope(artifact.Platforms, platforms); err != nil {
		return err
	}
	if err := validateArtifactUnpack(artifact); err != nil {
		return err
	}
	if artifact.UID < 0 || artifact.GID < 0 || uint64(artifact.UID) > math.MaxUint32 || uint64(artifact.GID) > math.MaxUint32 {
		return errors.New("artifact uid/gid must be uint32-range integers")
	}
	if err := validateArtifactMode(artifact); err != nil {
		return err
	}
	if strings.TrimSpace(artifact.SBOM.Name) == "" || strings.TrimSpace(artifact.SBOM.Version) == "" {
		return errors.New("artifact sbom requires nonempty name and version")
	}
	if err := ValidateCPE(artifact.SBOM.CPE); err != nil {
		return err
	}
	return validateArtifactSources(artifact.Sources, artifact.Platforms)
}

// validateArtifactUnpack checks the placement of the payload and the fields it
// governs. A package payload brings its own content and identity, so it declares no
// destination and no ownership: the DEB decides where its files belong and the
// package database records them.
func validateArtifactUnpack(artifact *Artifact) error {
	if artifact.Unpack == nil {
		return errors.New("artifact unpack must be explicitly true, false or package")
	}
	switch *artifact.Unpack {
	case ArtifactUnpackArchive, ArtifactUnpackStandalone:
		if !path.IsAbs(artifact.Dest) || path.Clean(artifact.Dest) != artifact.Dest ||
			strings.Contains(artifact.Dest, "\\") || (*artifact.Unpack == ArtifactUnpackStandalone && artifact.Dest == "/") {
			return errors.New("artifact dest must be a clean absolute POSIX path, not root for a standalone file")
		}
		return nil
	case ArtifactUnpackPackage:
		if artifact.Dest != "" || artifact.UID != 0 || artifact.GID != 0 || artifact.Mode != nil {
			return errors.New("package artifacts take content, ownership and mode from the package; " +
				"drop dest, uid, gid and mode")
		}
		return nil
	default:
		return errors.New("artifact unpack must be true, false or package")
	}
}

func validateArtifactMode(artifact *Artifact) error {
	switch *artifact.Unpack {
	case ArtifactUnpackArchive, ArtifactUnpackPackage:
		if artifact.Mode != nil {
			return errors.New("unpacked artifacts preserve archive modes; mode overrides require unpack false")
		}
		return nil
	}
	if artifact.Mode == nil {
		return errors.New("standalone artifact requires a defaulted mode")
	}
	return base.RequirePattern("artifact mode", *artifact.Mode, `^(0[0-7]{3}|0[1-7][0-7]{3})$`)
}

func validateArtifactSources(sources []ArtifactSource, platforms []string) error {
	seen := make(map[string]bool)
	for i, source := range sources {
		if err := validateArtifactSource(&source); err != nil {
			return fmt.Errorf("artifact source[%d]: %w", i, err)
		}
		if err := base.RequirePattern("artifact SHA256", source.SHA256, `^[0-9a-f]{64}$`); err != nil {
			return err
		}
		if err := base.ClaimPlatforms(source.Platforms, platforms, seen); err != nil {
			return fmt.Errorf("artifact source[%d]: %w", i, err)
		}
	}
	if len(seen) != len(platforms) {
		return errors.New("artifact sources must cover every intended platform")
	}
	return nil
}

// validateArtifactSource accepts one origin: a URL, or a path the snapshot step can
// copy into the cache before any build reads it.
func validateArtifactSource(source *ArtifactSource) error {
	switch {
	case source.URL != "" && source.Path != "":
		return errors.New("artifact source requires either url or path, not both")
	case source.URL != "":
		return base.ValidateInputURL(source.URL, false)
	case source.Path != "":
		return base.ValidateLocalPath(source.Path)
	default:
		return errors.New("artifact source requires a url or a path")
	}
}
