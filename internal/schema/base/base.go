// Package base holds schema validation primitives shared by the typed schema
// packages.
package base

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

type inputError struct {
	message string
	cause   error
}

func (e *inputError) Error() string { return e.message }
func (e *inputError) Unwrap() error { return e.cause }

// ValidateInputName checks a user-supplied input name.
func ValidateInputName(name string) error {
	return RequirePattern("input name", name, `^[a-z0-9][a-z0-9_.-]{0,127}$`)
}

// ValidateInputURL checks an HTTP(S) input URL.
func ValidateInputURL(value string, httpsOnly bool) error {
	u, err := url.Parse(value)
	if err != nil {
		return &inputError{message: "input URL is malformed", cause: err}
	}
	if (u.Scheme != schemeHTTPS && (httpsOnly || u.Scheme != schemeHTTP)) || !usableHost(u) ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsRune(value, '#') {
		return errors.New("input URL requires an allowed HTTP(S) scheme and hostname, without credentials, query or fragment")
	}
	return nil
}

// ValidateRedirectURL checks a redirect target. A server signs its own asset URL,
// so a redirect may carry a query where a declared input may not. The query is also
// why a target with one must be HTTPS: a signature sent in clear text is a signature
// published, and the digest check that follows protects the bytes, not the proof.
func ValidateRedirectURL(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return &inputError{message: "redirect target is malformed", cause: err}
	}
	if (u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) || !usableHost(u) ||
		u.User != nil || strings.ContainsRune(value, '#') {
		return errors.New("redirect target is not a credential-free HTTP(S) URL")
	}
	if (u.RawQuery != "" || u.ForceQuery) && u.Scheme != schemeHTTPS {
		return errors.New("redirect target with a query must be an HTTPS URL")
	}
	return nil
}

const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// usableHost rejects the host forms url.Parse accepts but a fetch cannot use.
func usableHost(u *url.URL) bool {
	return u.Hostname() != "" && u.Opaque == "" && !strings.HasSuffix(u.Host, ":")
}

// ValidateLocalPath checks a clean, relative, slash-separated path.
func ValidateLocalPath(value string) error {
	if value == "" || strings.TrimSpace(value) != value || path.Clean(value) != value ||
		path.IsAbs(value) || strings.ContainsRune(value, '\\') ||
		(len(value) >= 2 && value[1] == ':') || strings.ContainsFunc(value, unicode.IsControl) {
		return errors.New("local path must be nonempty, clean, relative and slash-separated (relative to the spec directory)")
	}
	return nil
}

// ValidateScope checks a duplicate-free platform subset.
func ValidateScope(scope, targets []string) error {
	if len(scope) == 0 {
		return errors.New("platform scope must not be empty")
	}
	seen := make(map[string]bool)
	for _, platform := range scope {
		if !slices.Contains(targets, platform) || seen[platform] {
			return errors.New("platform scope must be a duplicate-free subset of its target platforms")
		}
		seen[platform] = true
	}
	return nil
}

// ClaimPlatforms checks a payload scope and records its platforms as claimed.
func ClaimPlatforms(scope, targets []string, seen map[string]bool) error {
	if err := ValidateScope(scope, targets); err != nil {
		return err
	}
	for _, platform := range scope {
		if seen[platform] {
			return errors.New("platform payload scopes must not overlap")
		}
		seen[platform] = true
	}
	return nil
}

// ValidateTokens checks nonempty, unique, non-traversing identifiers.
func ValidateTokens(field string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", field)
	}
	seen := make(map[string]bool)
	for _, value := range values {
		if err := RequirePattern(field, value, `^[A-Za-z0-9][A-Za-z0-9._/-]*$`); err != nil {
			return err
		}
		if seen[value] || strings.Contains(value, "..") || strings.Contains(value, "//") || strings.HasSuffix(value, "/") {
			return fmt.Errorf("%s must contain unique non-traversing tokens", field)
		}
		seen[value] = true
	}
	return nil
}

// ValidatePlatforms checks the supported platform set.
func ValidatePlatforms(platforms []string) error {
	if len(platforms) == 0 {
		return errors.New("platforms must not be empty")
	}
	seen := make(map[string]bool)
	for _, platform := range platforms {
		if platform != "linux/amd64" && platform != "linux/arm64" {
			return fmt.Errorf("unsupported platform %q", platform)
		}
		if seen[platform] {
			return fmt.Errorf("duplicate platform %q", platform)
		}
		seen[platform] = true
	}
	return nil
}

// RequirePattern checks that value matches pattern.
func RequirePattern(field, value, pattern string) error {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return fmt.Errorf("validate %s pattern: %w", field, err)
	}
	if !matched {
		return fmt.Errorf("%s has invalid syntax", field)
	}
	return nil
}

// ValidatePackageVersion checks a package name and that an optional version
// expression is not empty. The expression's grammar belongs to the distribution,
// because only it knows what a version of that distribution looks like.
func ValidatePackageVersion(name string, version *string) error {
	if err := RequirePattern("package name", name, `^[a-z0-9][a-z0-9+.-]*$`); err != nil {
		return err
	}
	if version != nil && strings.TrimSpace(*version) == "" {
		return errors.New("package version expression must not be empty")
	}
	return nil
}
