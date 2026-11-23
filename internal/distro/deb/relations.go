package deb

import (
	"errors"
	"strings"
)

// RelationOperator is a Debian version relation. The empty value means the
// relation is unversioned. Obsolete single-character operators are rejected.
type RelationOperator string

// Debian version relation operators.
const (
	RelationLess           RelationOperator = "<<"
	RelationLessOrEqual    RelationOperator = "<="
	RelationEqual          RelationOperator = "="
	RelationGreaterOrEqual RelationOperator = ">="
	RelationGreater        RelationOperator = ">>"
)

// Relation is one package relation. Architecture is empty for an unqualified
// relation, "any" for a multi-architecture relation, and otherwise the literal
// qualifier, which may name an architecture this image does not build for.
// Satisfying such a relation needs a foreign architecture; judging that belongs to
// resolution, because a qualifier only rules out the alternative carrying it.
// Operator is empty when Version is not constrained.
type Relation struct {
	Name         string
	Architecture string
	Operator     RelationOperator
	Version      Version
}

// String renders the relation the way a control field spells it.
func (r Relation) String() string {
	text := r.Name
	if r.Architecture != "" {
		text += ":" + r.Architecture
	}
	if r.Operator == "" {
		return text
	}
	return text + " (" + string(r.Operator) + " " + r.Version.String() + ")"
}

// RelationClause is one comma-separated position in a relation field. The
// alternatives of a dependency clause stay in declared order. Fields that do
// not accept alternatives produce one-element clauses.
type RelationClause []Relation

// ParseDependencyList parses a Pre-Depends or Depends value. Alternatives are
// kept in declared order. A foreign architecture qualifier is parsed and kept
// rather than refused: real Ubuntu packages offer it as one alternative next to
// a satisfiable cross-compiler, so returning an error here would reject a
// package that resolves fine.
func ParseDependencyList(value, nativeArchitecture string) ([]RelationClause, error) {
	return parseRelationList(value, nativeArchitecture, true, false)
}

// ParseProvidesList parses a Provides value. Alternatives are not accepted and
// a versioned provider must use the "=" operator.
func ParseProvidesList(value, nativeArchitecture string) ([]RelationClause, error) {
	return parseRelationList(value, nativeArchitecture, false, true)
}

// ParseConflictList parses a Conflicts, Breaks or Replaces value. Alternatives
// are not accepted.
func ParseConflictList(value, nativeArchitecture string) ([]RelationClause, error) {
	return parseRelationList(value, nativeArchitecture, false, false)
}

// The native architecture is required rather than defaulted: a caller that has not
// chosen a platform must not parse relations, even though the qualifier itself is
// judged during resolution.
func parseRelationList(value, nativeArchitecture string, alternatives, provides bool) ([]RelationClause, error) {
	if nativeArchitecture == "" {
		return nil, errors.New("native architecture is required")
	}
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	clauses := make([]RelationClause, 0, len(parts))
	for _, part := range parts {
		alternativesText := strings.Split(part, "|")
		if !alternatives && len(alternativesText) > 1 {
			return nil, errors.New("relation field does not accept alternatives")
		}
		clause := make(RelationClause, 0, len(alternativesText))
		for _, text := range alternativesText {
			relation, err := parseRelation(text, provides)
			if err != nil {
				return nil, err
			}
			clause = append(clause, relation)
		}
		clauses = append(clauses, clause)
	}
	return clauses, nil
}

func parseRelation(value string, provides bool) (Relation, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Relation{}, errors.New("empty relation")
	}
	value, constraint, versioned, err := splitRelationConstraint(value)
	if err != nil {
		return Relation{}, err
	}
	name, qualifier, qualified := splitRelationName(value)
	if !validPackageName(name) {
		return Relation{}, errors.New("relation has an invalid package name")
	}
	if qualified && qualifier == "" {
		return Relation{}, errors.New("relation has an invalid architecture qualifier")
	}
	architecture, err := relationArchitecture(qualifier)
	if err != nil {
		return Relation{}, err
	}
	relation := Relation{Name: name, Architecture: architecture}
	if versioned {
		relation.Operator, relation.Version, err = parseRelationVersion(constraint, provides)
		if err != nil {
			return Relation{}, err
		}
	}
	return relation, nil
}

func splitRelationConstraint(value string) (string, string, bool, error) {
	open := strings.IndexByte(value, '(')
	if open < 0 {
		return value, "", false, nil
	}
	if !strings.HasSuffix(value, ")") {
		return "", "", false, errors.New("relation has a malformed version constraint")
	}
	constraint := strings.TrimSpace(value[open+1 : len(value)-1])
	if strings.ContainsAny(constraint, "()") {
		return "", "", false, errors.New("relation has a malformed version constraint")
	}
	return strings.TrimSpace(value[:open]), constraint, true, nil
}

func splitRelationName(value string) (string, string, bool) {
	before, after, ok := strings.Cut(value, ":")
	if !ok {
		return value, "", false
	}
	return before, after, true
}

func parseRelationVersion(constraint string, provides bool) (RelationOperator, Version, error) {
	if constraint == "" {
		return "", Version{}, errors.New("relation has an empty version constraint")
	}
	operator, version, err := parseVersionConstraint(constraint)
	if err != nil {
		return "", Version{}, err
	}
	if provides && operator != RelationEqual {
		return "", Version{}, errors.New("versioned provides requires the = operator")
	}
	return operator, version, nil
}

func relationArchitecture(qualifier string) (string, error) {
	switch qualifier {
	case "", "any":
		return qualifier, nil
	case "native":
		return "", errors.New("native architecture qualifier is not supported in package relations")
	}
	if !validArchitectureName(qualifier) {
		return "", errors.New("relation has an invalid architecture qualifier")
	}
	if qualifier == ArchitectureAll {
		return "", errors.New("relation has an invalid architecture qualifier")
	}
	return qualifier, nil
}

func parseVersionConstraint(value string) (RelationOperator, Version, error) {
	operators := []struct {
		text     string
		operator RelationOperator
	}{
		{"<<", RelationLess},
		{"<=", RelationLessOrEqual},
		{">=", RelationGreaterOrEqual},
		{">>", RelationGreater},
		{"=", RelationEqual},
	}
	value = strings.TrimSpace(value)
	for _, candidate := range operators {
		if !strings.HasPrefix(value, candidate.text) {
			continue
		}
		text := strings.TrimSpace(value[len(candidate.text):])
		if text == "" {
			return "", Version{}, errors.New("version constraint has no version")
		}
		version, err := ParseVersion(text)
		if err != nil {
			return "", Version{}, errors.New("version constraint has an invalid version")
		}
		return candidate.operator, version, nil
	}
	return "", Version{}, errors.New("version constraint has an invalid operator")
}

func validArchitectureName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, c := range []byte(value) {
		if (c < 'a' || c > 'z') && !isDigit(c) && c != '-' {
			return false
		}
	}
	return true
}
