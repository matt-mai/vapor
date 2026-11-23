package filesystem

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// Validate checks filesystem paths, accounts, timezone and CA bundle declarations.
func Validate(filesystem *Filesystem) error {
	if err := validateFilesystemPaths(filesystem.Paths); err != nil {
		return err
	}
	if err := validateAccounts(filesystem.Accounts); err != nil {
		return err
	}
	if filesystem.Timezone != nil {
		if err := base.RequirePattern("filesystem timezone", *filesystem.Timezone,
			`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`); err != nil {
			return err
		}
	}
	if filesystem.CA != nil {
		if err := validateCABundle(*filesystem.CA); err != nil {
			return err
		}
	}
	return validateOSRelease(filesystem.OSRelease)
}

func validateCABundle(bundle CABundle) error {
	if bundle.Mode != "append" && bundle.Mode != "replace" {
		return errors.New("filesystem.ca.mode must explicitly select append or replace")
	}
	if len(bundle.Sources) == 0 {
		return errors.New("filesystem.ca.sources must not be empty")
	}
	seen := make(map[string]bool)
	for i, source := range bundle.Sources {
		if err := base.ValidateLocalPath(source); err != nil {
			return fmt.Errorf("filesystem.ca.sources[%d]: %w", i, err)
		}
		if seen[source] {
			return errors.New("duplicate CA source path")
		}
		seen[source] = true
	}
	return nil
}

func validateOSRelease(overrides map[string]string) error {
	for key, value := range overrides {
		switch key {
		case "NAME", "PRETTY_NAME", "VERSION", "HOME_URL", "DOCUMENTATION_URL", "SUPPORT_URL", "BUG_REPORT_URL", "LOGO":
		default:
			return errors.New("filesystem.os-release key is not a supported descriptive field; identity overrides are forbidden")
		}
		if strings.ContainsFunc(value, func(r rune) bool {
			return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
		}) {
			return errors.New("filesystem.os-release values must be single-line strings without control characters")
		}
	}
	return nil
}
