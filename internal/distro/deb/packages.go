package deb

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxPackageLineSize bounds one physical line. The longest line in the Ubuntu
// 26.04 amd64 universe index is about 20 KiB (a generated node-lodash version
// string); 1 MiB leaves room for similar generated fields without accepting
// unbounded lines.
const MaxPackageLineSize = 1 << 20

// MaxPackageFieldSize bounds an accumulated retained field value. The largest
// one observed in that index is about 20 KiB (node-lodash-packages Provides),
// so 1 MiB is roughly 50x headroom. Continuation lines are accumulated linearly
// rather than by repeated string concatenation.
const MaxPackageFieldSize = 1 << 20

// MaxPackageStanzaSize bounds the retained field values of one stanza. The
// largest observed retained stanza is about 23 KiB. Large fields such as
// Description are discarded, so they do not count.
const MaxPackageStanzaSize = 1 << 20

// MaxPackageFields bounds the distinct field names tracked for one stanza. The
// largest observed count is 34, so 256 bounds the per-stanza name map without
// constraining real packages.
const MaxPackageFields = 256

// PackageOrigin is the repository source of a candidate.
type PackageOrigin struct {
	Suite     string
	Component string
}

// Relations holds raw dependency relation expressions. Parse them with
// ParseDependencyList, ParseProvidesList and ParseConflictList; semantic
// resolution is deliberately separate from index decoding.
type Relations struct {
	PreDepends []string
	Depends    []string
	Provides   []string
	Conflicts  []string
	Breaks     []string
	Replaces   []string
}

// Package is one concrete candidate decoded from an authenticated index.
type Package struct {
	Name         string
	Version      string
	Architecture string
	// MultiArch is the declared Multi-Arch value, empty when the index says
	// nothing. Only "allowed" and "foreign" let an architecture-qualified
	// dependency be met by this candidate.
	MultiArch string
	// Source is the declared source package name, empty when the index names none.
	// A binary package is usually built from a package with another name, and
	// vulnerability data and package URLs are keyed on the source.
	Source    string
	Origin    PackageOrigin
	Filename  string
	SHA256    string
	Size      int64
	Relations Relations
}

// ParsePackages decodes a verified Packages index in file order. It does not
// sort candidates; callers preserve suite/component and stanza order for ties.
func ParsePackages(data []byte, index *Index, suite string) ([]Package, error) {
	if suite == "" || index.Component == "" || index.Architecture == "" {
		return nil, errors.New("package index origin is incomplete")
	}
	stanzas, err := readPackageStanzas(data)
	if err != nil {
		return nil, err
	}
	if len(stanzas) == 0 {
		return nil, nil
	}
	packages := make([]Package, 0, len(stanzas))
	for _, fields := range stanzas {
		pkg, err := packageFromFields(fields, index, suite)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

func packageFromFields(fields map[string]string, index *Index, suite string) (Package, error) {
	if err := requireFields(fields, "package", "version", "architecture", "filename", "size", "sha256"); err != nil {
		return Package{}, err
	}
	name, version, architecture, err := packageIdentity(fields, index)
	if err != nil {
		return Package{}, err
	}
	filename, sha256, size, err := packageArchive(fields, name)
	if err != nil {
		return Package{}, err
	}
	relations, err := packageRelations(fields)
	if err != nil {
		return Package{}, fmt.Errorf("package record %q has malformed relations", name)
	}
	multiArch, err := packageMultiArch(fields)
	if err != nil {
		return Package{}, err
	}
	source, err := packageSource(fields)
	if err != nil {
		return Package{}, err
	}
	return Package{
		Name:         name,
		Version:      version,
		Architecture: architecture,
		MultiArch:    multiArch,
		Source:       source,
		Origin:       PackageOrigin{Suite: suite, Component: index.Component},
		Filename:     filename,
		SHA256:       sha256,
		Size:         size,
		Relations:    relations,
	}, nil
}

// packageMultiArch reads the declared Multi-Arch value. An unrecognized value is
// refused rather than treated as absent: it decides whether an architecture-
// qualified dependency may be met, and guessing would select a package the release
// does not offer for it.
func packageMultiArch(fields map[string]string) (string, error) {
	switch value := strings.TrimSpace(fields["multi-arch"]); value {
	case "", "no", "same", "foreign", "allowed":
		return value, nil
	default:
		return "", fmt.Errorf("package record %q has unsupported multi-arch %q", fields["package"], value)
	}
}

func requireFields(fields map[string]string, names ...string) error {
	for _, name := range names {
		if fields[name] == "" {
			return fmt.Errorf("package record is missing %s", name)
		}
	}
	return nil
}

// packageSource reads the declared source package name. The field may carry the
// source version in parentheses, which describes a different thing than the source
// name and is dropped rather than confused with it.
func packageSource(fields map[string]string) (string, error) {
	source, _, _ := strings.Cut(strings.TrimSpace(fields["source"]), " (")
	if source == "" {
		return "", nil
	}
	if !validPackageName(source) {
		return "", fmt.Errorf("package record %q has an invalid source %q", fields["package"], source)
	}
	return source, nil
}

func packageIdentity(fields map[string]string, index *Index) (name, version, architecture string, err error) {
	name = fields["package"]
	if !validPackageName(name) {
		return "", "", "", fmt.Errorf("package record %q has an invalid name", name)
	}
	version = fields["version"]
	if !validPackageVersion(version) {
		return "", "", "", fmt.Errorf("package record %q has an invalid version", name)
	}
	architecture = fields["architecture"]
	if architecture != ArchitectureAll && architecture != index.Architecture {
		return "", "", "", fmt.Errorf("package record %q has architecture %q outside index architecture %q", name,
			architecture, index.Architecture)
	}
	return name, version, architecture, nil
}

func packageArchive(fields map[string]string, name string) (filename, sha256 string, size int64, err error) {
	filename = fields["filename"]
	if !safeRelativePath(filename) || !strings.HasSuffix(filename, ".deb") || strings.ContainsAny(filename, "?#") {
		return "", "", 0, fmt.Errorf("package record %q has an invalid filename", name)
	}
	if !isSHA256Hex(fields["sha256"]) {
		return "", "", 0, fmt.Errorf("package record %q has an invalid SHA256", name)
	}
	if !isDecimal(fields["size"]) {
		return "", "", 0, fmt.Errorf("package record %q has an invalid size", name)
	}
	size, err = strconv.ParseInt(fields["size"], 10, 64)
	if err != nil {
		return "", "", 0, fmt.Errorf("package record %q has an invalid size", name)
	}
	return filename, strings.ToLower(fields["sha256"]), size, nil
}

func packageRelations(fields map[string]string) (Relations, error) {
	var relations Relations
	fieldsToTargets := []struct {
		name   string
		target *[]string
	}{
		{"pre-depends", &relations.PreDepends},
		{"depends", &relations.Depends},
		{"provides", &relations.Provides},
		{"conflicts", &relations.Conflicts},
		{"breaks", &relations.Breaks},
		{"replaces", &relations.Replaces},
	}
	for _, field := range fieldsToTargets {
		expressions, err := splitRelations(fields[field.name])
		if err != nil {
			return Relations{}, fmt.Errorf("%s: %w", field.name, err)
		}
		*field.target = expressions
	}
	return relations, nil
}

func splitRelations(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	expressions := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("empty relation")
		}
		expressions = append(expressions, part)
	}
	return expressions, nil
}

func validFieldName(name string) bool {
	if name == "" || !isAlphanumeric(name[0]) {
		return false
	}
	for _, c := range []byte(name[1:]) {
		if !isAlphanumeric(c) && c != '-' {
			return false
		}
	}
	return true
}

func isAlphanumeric(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// ArchitectureAll is the architecture a package declares when its content fits every
// platform.
const ArchitectureAll = "all"

func validPackageName(name string) bool {
	if len(name) < 2 || ((name[0] < 'a' || name[0] > 'z') && (name[0] < '0' || name[0] > '9')) {
		return false
	}
	for _, c := range []byte(name) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func validPackageVersion(version string) bool {
	_, err := ParseVersion(version)
	return err == nil
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range []byte(value) {
		if !isHex(c) {
			return false
		}
	}
	return true
}
