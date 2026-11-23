package deb

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// FreshnessPolicy declares how missing Valid-Until metadata is treated.
type FreshnessPolicy string

const (
	// FreshnessIfPresent enforces Valid-Until when supplied and allows its absence.
	FreshnessIfPresent FreshnessPolicy = "if-present"
	// FreshnessRequire rejects metadata without Valid-Until.
	FreshnessRequire FreshnessPolicy = "require"
)

// ReleaseIdentity is the repository identity authenticated metadata must match.
type ReleaseIdentity struct {
	Suite        string
	Architecture string
	Components   []string
	// MatchCodename compares the signed Codename with Suite instead of the
	// signed Suite. Debian signs a moving Suite (stable) next to a fixed
	// Codename (trixie), so only the codename identifies the release.
	MatchCodename bool
	// PrefixedComponents accepts a signed "<prefix>/<component>" entry as the
	// requested component. Debian's security archive lists updates/main.
	PrefixedComponents bool
	// OwnIdentity accepts whatever release name the metadata states, because the
	// repository is not the base distribution and only its keys authenticate it.
	// The architecture and components are still checked.
	OwnIdentity bool
}

// CheckReleaseIdentity binds authenticated metadata to the expected suite,
// native architecture and requested components.
func CheckReleaseIdentity(release *Release, expected ReleaseIdentity) error {
	if expected.Suite == "" {
		return errors.New("expected release suite is empty")
	}
	if expected.Architecture == "" {
		return errors.New("expected release architecture is empty")
	}
	if err := checkReleaseSuite(release, expected); err != nil {
		return err
	}
	if !slices.Contains(release.Architectures, expected.Architecture) {
		return fmt.Errorf("release metadata does not list architecture %q", expected.Architecture)
	}
	for _, component := range expected.Components {
		if !listsComponent(release, component, expected.PrefixedComponents) {
			return fmt.Errorf("release metadata does not list component %q", component)
		}
	}
	return nil
}

func checkReleaseSuite(release *Release, expected ReleaseIdentity) error {
	if expected.OwnIdentity {
		return nil
	}
	if expected.MatchCodename {
		if release.Codename == "" {
			return errors.New("release metadata has no codename")
		}
		if release.Codename != expected.Suite {
			return fmt.Errorf("release codename %q does not match %q", release.Codename, expected.Suite)
		}
		return nil
	}
	if release.Suite == "" {
		return errors.New("release metadata has no suite")
	}
	if release.Suite != expected.Suite {
		return fmt.Errorf("release suite %q does not match %q", release.Suite, expected.Suite)
	}
	return nil
}

func listsComponent(release *Release, component string, prefixed bool) bool {
	if slices.Contains(release.Components, component) {
		return true
	}
	if !prefixed {
		return false
	}
	for _, signed := range release.Components {
		prefix, name, ok := strings.Cut(signed, "/")
		if ok && prefix != "" && !strings.Contains(name, "/") && name == component {
			return true
		}
	}
	return false
}

// CheckFreshness enforces the configured Valid-Until policy against the caller's
// clock. Expiry is exclusive: metadata is invalid at the Valid-Until instant.
func CheckFreshness(release *Release, policy FreshnessPolicy, now time.Time) error {
	switch policy {
	case FreshnessIfPresent:
		if release.ValidUntil == "" {
			return nil
		}
	case FreshnessRequire:
		if release.ValidUntil == "" {
			return errors.New("release valid-until is required")
		}
	default:
		return fmt.Errorf("unsupported freshness policy %q", policy)
	}
	validUntil, err := parseReleaseTime(release.ValidUntil)
	if err != nil {
		return errors.New("release valid-until is not a valid date")
	}
	if !now.Before(validUntil) {
		return errors.New("release metadata has expired")
	}
	return nil
}

func parseReleaseTime(value string) (time.Time, error) {
	if strings.HasSuffix(value, " UTC") {
		return time.Parse(time.RFC1123, value)
	}
	return time.Parse(time.RFC1123Z, value)
}
