package deb

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Control is the identity and relationships of one package, read from the control
// stanza of a local DEB. A repository index carries the same fields, so a package
// from a file obeys the same rules as a fetched one.
type Control struct {
	Name         string
	Version      string
	Architecture string
	MultiArch    string
	PreDepends   []RelationClause
	Depends      []RelationClause
	Provides     []Relation
}

// ParseControl reads the control stanza of a DEB. It accepts only the fields a
// resolved package needs, so an unrecognized field is refused rather than ignored:
// the stanza decides a package's identity and what it requires.
func ParseControl(data []byte) (Control, error) {
	fields, err := readControlFields(data)
	if err != nil {
		return Control{}, err
	}
	if missing := requireFields(fields, "package", "version", "architecture"); missing != nil {
		return Control{}, missing
	}
	name, version, architecture, err := controlIdentity(fields)
	if err != nil {
		return Control{}, err
	}
	relations, err := controlRelations(fields, name, architecture)
	if err != nil {
		return Control{}, err
	}
	multiArch, err := packageMultiArch(fields)
	if err != nil {
		return Control{}, err
	}
	return Control{
		Name: name, Version: version, Architecture: architecture, MultiArch: multiArch,
		PreDepends: relations.PreDepends, Depends: relations.Depends,
		Provides: relations.Provides,
	}, nil
}

// parsedRelations holds a control stanza's relations in decoded form.
type parsedRelations struct {
	PreDepends []RelationClause
	Depends    []RelationClause
	Provides   []Relation
}

// controlRelations decodes the relationship fields. A package installed from a file
// has no index to be checked against, so a malformed relation is refused here rather
// than silently dropping a requirement.
func controlRelations(fields map[string]string, name, architecture string) (parsedRelations, error) {
	native := architecture
	if native == ArchitectureAll {
		return parsedRelations{}, fmt.Errorf("local package %q has architecture all; name its native architecture", name)
	}
	relations, err := packageRelations(fields)
	if err != nil {
		return parsedRelations{}, fmt.Errorf("package record %q has malformed relations", name)
	}
	decoded := parsedRelations{}
	if decoded.PreDepends, err = decodeDependencies(strings.Join(relations.PreDepends, ", "), native); err != nil {
		return parsedRelations{}, fmt.Errorf("package %q has a malformed Pre-Depends", name)
	}
	if decoded.Depends, err = decodeDependencies(strings.Join(relations.Depends, ", "), native); err != nil {
		return parsedRelations{}, fmt.Errorf("package %q has a malformed Depends", name)
	}
	provides, err := ParseProvidesList(strings.Join(relations.Provides, ", "), native)
	if err != nil {
		return parsedRelations{}, fmt.Errorf("package %q has a malformed Provides", name)
	}
	for _, clause := range provides {
		decoded.Provides = append(decoded.Provides, clause...)
	}
	return decoded, nil
}

func decodeDependencies(value, native string) ([]RelationClause, error) {
	if value == "" {
		return nil, nil
	}
	return ParseDependencyList(value, native)
}

// readControlFields decodes the stanza's retained fields, rejecting text that is not
// valid UTF-8 or contains a NUL byte. A control stanza is a
// single paragraph, so a blank line or a second Package field is refused rather
// than treated as the start of another package.
func readControlFields(data []byte) (map[string]string, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("package control stanza is malformed")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), MaxPackageLineSize)
	stanza := newPackageStanza()
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if err := stanza.readLine(line); err != nil {
			return nil, err
		}
	}
	if err := packageScannerError(scanner); err != nil {
		return nil, err
	}
	if err := stanza.finish(); err != nil {
		return nil, err
	}
	if !stanza.hasFields() {
		return nil, errors.New("package control stanza is empty")
	}
	return stanza.fields, nil
}

// controlIdentity validates the fields that name the package. The architecture is
// not compared with a repository index here: a local package is installed for the
// platform the caller asks about.
func controlIdentity(fields map[string]string) (name, version, architecture string, err error) {
	name = strings.TrimSpace(fields["package"])
	if !validPackageName(name) {
		return "", "", "", fmt.Errorf("package record %q has an invalid name", name)
	}
	version = strings.TrimSpace(fields["version"])
	if !validPackageVersion(version) {
		return "", "", "", fmt.Errorf("package record %q has an invalid version", name)
	}
	architecture = strings.TrimSpace(fields["architecture"])
	if architecture != ArchitectureAll && !validArchitectureName(architecture) {
		return "", "", "", fmt.Errorf("package record %q has invalid architecture %q", name, architecture)
	}
	return name, version, architecture, nil
}

// ControlSatisfied reports the first dependency of a package that the selected
// packages do not meet, or nil when every one of them is met. Pre-Depends and
// Depends are both checked: a local package is installed, not configured, so a
// pre-dependency is not treated as already satisfied.
func ControlSatisfied(control *Control, native string, selected []Control) error {
	providers := providerIndex(selected)
	for _, clause := range append(control.PreDepends, control.Depends...) {
		if clauseSatisfied(clause, native, providers) {
			continue
		}
		return fmt.Errorf("local package %q depends on %q, which no selected package provides; add it to contents.packages",
			control.Name, clauseText(clause))
	}
	return nil
}

// providerIndex maps every name a selected package answers to that package's
// control stanza, so a virtual name is found the same way a real one is.
func providerIndex(selected []Control) map[string][]*Control {
	providers := make(map[string][]*Control, len(selected))
	for i := range selected {
		pkg := &selected[i]
		providers[pkg.Name] = append(providers[pkg.Name], pkg)
		for _, provided := range pkg.Provides {
			providers[provided.Name] = append(providers[provided.Name], pkg)
		}
	}
	return providers
}

func clauseSatisfied(clause RelationClause, native string, providers map[string][]*Control) bool {
	for i := range clause {
		relation := &clause[i]
		for _, candidate := range providers[relation.Name] {
			if relationSatisfied(relation, native, candidate) {
				return true
			}
		}
	}
	return false
}

// relationSatisfied judges one alternative: the qualifier must fit this image and
// an unconstrained relation needs no version check.
func relationSatisfied(relation *Relation, native string, candidate *Control) bool {
	if relation.Architecture != "" && relation.Architecture != "any" &&
		relation.Architecture != native && candidate.Architecture != ArchitectureAll {
		return false
	}
	if relation.Operator == "" {
		return true
	}
	version, err := ParseVersion(candidate.Version)
	if err != nil {
		return false
	}
	return compares(version.Compare(relation.Version), relation.Operator)
}

func compares(order int, operator RelationOperator) bool {
	switch operator {
	case RelationEqual:
		return order == 0
	case RelationLessOrEqual:
		return order <= 0
	case RelationGreaterOrEqual:
		return order >= 0
	case RelationLess:
		return order < 0
	case RelationGreater:
		return order > 0
	default:
		return false
	}
}

func clauseText(clause RelationClause) string {
	parts := make([]string, 0, len(clause))
	for _, relation := range clause {
		parts = append(parts, relation.String())
	}
	return strings.Join(parts, " | ")
}
