package spec

import (
	"errors"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/container"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/schema/policy"
)

// ValidateSpec checks a decoded spec for cross-field consistency.
func ValidateSpec(spec *Spec) error {
	if spec.Version != 1 {
		return errors.New("version must be 1")
	}
	if err := requirePattern("name", spec.Name, `^[a-z0-9][a-z0-9_.-]{0,127}$`); err != nil {
		return err
	}
	if err := validateImage(spec.Image); err != nil {
		return err
	}
	if err := validateMetadata(spec.Tags, spec.Annotations); err != nil {
		return err
	}
	if err := requirePattern("distro", spec.Distro, `^[a-z][a-z0-9-]*$`); err != nil {
		return err
	}
	if err := validateRelease(spec.Release); err != nil {
		return err
	}
	if err := validatePlatforms(spec.Platforms); err != nil {
		return err
	}
	if err := container.Validate(&spec.Container); err != nil {
		return err
	}
	if err := contents.Validate(&spec.Contents, spec.Platforms); err != nil {
		return err
	}
	if err := policy.Validate(spec.Contents.SlicesEngine); err != nil {
		return err
	}
	if err := filesystem.Validate(&spec.Filesystem); err != nil {
		return err
	}
	return attestation.Validate(spec.VEX)
}

func validateImage(image string) error {
	repository, err := name.NewRepository(image, name.StrictValidation)
	if err != nil {
		return &inputError{message: "image must be a fully qualified repository without tag or digest", cause: err}
	}
	registry, err := url.Parse("//" + repository.RegistryStr())
	if err != nil {
		return &inputError{message: "image registry must be a valid authority", cause: err}
	}
	if registry.Hostname() == "" {
		return errors.New("image registry must include a hostname")
	}
	if strings.HasSuffix(repository.RegistryStr(), ":") {
		return errors.New("image registry port must not be empty")
	}
	// The library checks allowed characters, but not empty/invalid path components.
	for component := range strings.SplitSeq(repository.RepositoryStr(), "/") {
		if err := requirePattern("image repository component", component, `^[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*$`); err != nil {
			return err
		}
	}
	return nil
}

func validatePlatforms(platforms []string) error { return base.ValidatePlatforms(platforms) }

func requirePattern(field, value, pattern string) error {
	return base.RequirePattern(field, value, pattern)
}

// movingReleases are suite names, not immutable release identities.
var movingReleases = map[string]bool{"latest": true, "stable": true, "testing": true, "unstable": true, "sid": true}

func validateRelease(release string) error {
	if err := requirePattern("release", release, `^[0-9]+(\.[0-9]+)*$|^[a-z][a-z0-9-]*$`); err != nil {
		return err
	}
	if movingReleases[release] {
		return errors.New("release has invalid syntax")
	}
	return nil
}
