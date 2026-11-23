package attest

import (
	"fmt"
	"net/url"
	"strings"
)

// A package URL is how a scanner ties a component to vulnerability data, so it is the
// one identity Vapor uses for a product both in SPDX and in VEX. It names archive
// content, never the mirror it was read from. The upstream qualifier is the source
// package the archive was built from: advisories are published per source package, so
// without it a scanner reads a library under a name no advisory mentions.
func packageURL(distro, release, name, version, arch, upstream string) string {
	locator := "pkg:deb/"
	if distro != "" {
		locator += purlEscape(distro) + "/"
	}
	locator += purlEscape(name) + "@" + purlEscape(version)
	locator += "?arch=" + purlEscape(arch)
	if distro != "" && release != "" {
		locator += "&distro=" + purlEscape(distro+"-"+release)
	}
	if upstream != "" && upstream != name {
		locator += "&upstream=" + purlEscape(upstream)
	}
	return locator
}

// artifactURL identifies an artifact by the upstream identity its specification
// declares. It is not a distribution package, so it carries no distro qualifier.
func artifactURL(name, version string) string {
	return "pkg:generic/" + purlEscape(name) + "@" + purlEscape(version)
}

// purlEscape percent-encodes everything outside the URL-safe set purl allows.
func purlEscape(value string) string {
	const digits = "0123456789ABCDEF"
	var escaped strings.Builder
	for index := 0; index < len(value); index++ {
		ch := value[index]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			escaped.WriteByte(ch)
		case ch == '.', ch == '-', ch == '_', ch == '~':
			escaped.WriteByte(ch)
		default:
			escaped.WriteByte('%')
			escaped.WriteByte(digits[ch>>4])
			escaped.WriteByte(digits[ch&0x0f])
		}
	}
	return escaped.String()
}

// product is a parsed package URL: what it names and the attributes it constrains.
type product struct {
	kind       string
	namespace  string
	name       string
	version    string
	qualifiers map[string]string
	// raw is the URL the product was read from, so rendering it back is lossless.
	raw string
}

// url returns the package URL this product is identified by.
func (found *product) url() string { return found.raw }

// parseProduct reads the subset of the purl grammar Vapor writes. An imported document
// may name a product more loosely than Vapor does, which the matching rules below
// decide case by case; anything this parser cannot read is refused, not guessed at.
func parseProduct(value string) (product, error) {
	rest, err := productPath(value)
	if err != nil {
		return product{}, err
	}
	path, query, _ := strings.Cut(rest, "?")
	found := product{raw: value, qualifiers: map[string]string{}}
	if err := found.splitPath(value, path); err != nil {
		return product{}, err
	}
	if err := found.readQualifiers(value, query); err != nil {
		return product{}, err
	}
	return found, nil
}

// productPath strips the scheme and refuses a subpath, which names something inside a
// package rather than the package itself.
func productPath(value string) (string, error) {
	rest, ok := strings.CutPrefix(value, "pkg:")
	if !ok {
		return "", fmt.Errorf("attest: %q is not a package URL", value)
	}
	rest, fragment, _ := strings.Cut(rest, "#")
	if fragment != "" {
		return "", fmt.Errorf("attest: %q carries a subpath", value)
	}
	return rest, nil
}

// splitPath reads the type, namespace, name and version of a package URL.
func (found *product) splitPath(value, path string) error {
	kind, rest, ok := strings.Cut(path, "/")
	if !ok || kind == "" || rest == "" {
		return fmt.Errorf("attest: %q has no type and name", value)
	}
	found.kind = kind
	namespace, escaped, _ := strings.Cut(rest, "/")
	if escaped == "" {
		escaped, namespace = namespace, ""
	}
	name, version, hasVersion := strings.Cut(escaped, "@")
	var err error
	if found.name, err = pathUnescape(value, "name", name); err != nil {
		return err
	}
	if found.namespace, err = pathUnescape(value, "namespace", namespace); err != nil {
		return err
	}
	if hasVersion {
		found.version, err = pathUnescape(value, "version", version)
	}
	return err
}

// readQualifiers reads the key=value pairs after the question mark.
func (found *product) readQualifiers(value, query string) error {
	for pair := range strings.SplitSeq(query, "&") {
		key, encoded, present := strings.Cut(pair, "=")
		if !present {
			continue
		}
		decoded, err := pathUnescape(value, "qualifier", encoded)
		if err != nil {
			return err
		}
		found.qualifiers[key] = decoded
	}
	return nil
}

func pathUnescape(value, part, encoded string) (string, error) {
	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		return "", fmt.Errorf("attest: %q has an unreadable %s: %w", value, part, err)
	}
	return decoded, nil
}

// covers reports whether this product names the same thing as another. Type, name and
// version must agree exactly. A qualifier the imported document states must match; one
// it omits constrains nothing, because a document written against a bare package URL
// says nothing about which architecture or distribution it meant.
func (found *product) covers(other *product) bool {
	if found.kind != other.kind || found.name != other.name || found.version != other.version {
		return false
	}
	if found.namespace != "" && found.namespace != other.namespace {
		return false
	}
	for key, value := range found.qualifiers {
		if other.qualifiers[key] != value {
			return false
		}
	}
	return true
}
