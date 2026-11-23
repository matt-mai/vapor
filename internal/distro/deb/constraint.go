package deb

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Constraint is a conjunction of version predicates over Debian versions. The
// zero value accepts every version, so callers that only have an optional
// constraint must use presence, not emptiness, to decide whether to filter.
type Constraint struct {
	predicates []Predicate
}

// Predicate is one "operator literal" term of a constraint.
type Predicate struct {
	Operator ConstraintOperator
	Literal  Version
	// dotted holds the numeric components of a dotted-numeric upstream and is
	// empty for any other upstream such as "2024a".
	dotted []string
}

// ConstraintOperator is one version predicate operator. Vapor uses Terraform's
// spelling, so ">" is strict and there is no ">>".
type ConstraintOperator string

// The operators a version constraint may use.
const (
	OperatorEqual          ConstraintOperator = "="
	OperatorNotEqual       ConstraintOperator = "!="
	OperatorGreater        ConstraintOperator = ">"
	OperatorGreaterOrEqual ConstraintOperator = ">="
	OperatorLess           ConstraintOperator = "<"
	OperatorLessOrEqual    ConstraintOperator = "<="
	OperatorPessimistic    ConstraintOperator = "~>"
)

// constraintOperators is ordered longest first so ">=" is not read as ">".
var constraintOperators = []ConstraintOperator{
	OperatorNotEqual, OperatorGreaterOrEqual, OperatorLessOrEqual,
	OperatorPessimistic, OperatorEqual, OperatorGreater, OperatorLess,
}

// ParseConstraint parses comma- or space-separated predicates that all must
// hold. Every predicate needs an operator, so a bare version is refused rather
// than guessed at.
func ParseConstraint(value string) (Constraint, error) {
	tokens := splitPredicates(value)
	if len(tokens) == 0 {
		return Constraint{}, errors.New("version expression is empty")
	}
	constraint := Constraint{predicates: make([]Predicate, 0, len(tokens))}
	for _, token := range tokens {
		predicate, err := parsePredicate(token)
		if err != nil {
			return Constraint{}, err
		}
		constraint.predicates = append(constraint.predicates, predicate)
	}
	return constraint, nil
}

// Allows reports whether every predicate accepts candidate.
func (c Constraint) Allows(candidate Version) bool {
	for i := range c.predicates {
		if !c.predicates[i].allows(candidate) {
			return false
		}
	}
	return true
}

// JoinExpressions combines two version expressions for the same package. Two
// requests narrow each other, so the result is a conjunction, not a conflict.
func JoinExpressions(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + ", " + next
}

// splitPredicates splits a constraint into "operator literal" tokens. Commas
// and whitespace both separate predicates.
func splitPredicates(value string) []string {
	var tokens []string
	for i := 0; i < len(value); {
		if isSeparator(value[i]) {
			i++
			continue
		}
		start := i
		for i < len(value) && !isSeparator(value[i]) && isOperatorByte(value[i]) {
			i++
		}
		operator := value[start:i]
		for i < len(value) && isSpace(value[i]) {
			i++
		}
		start = i
		for i < len(value) && !isSeparator(value[i]) {
			i++
		}
		tokens = append(tokens, strings.TrimSpace(operator+" "+value[start:i]))
	}
	return tokens
}

func isSeparator(c byte) bool {
	return c == ',' || isSpace(c)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func isOperatorByte(c byte) bool {
	return c == '!' || c == '<' || c == '>' || c == '=' || c == '~'
}

func parsePredicate(token string) (Predicate, error) {
	operator, literal := splitOperator(token)
	if operator == "" {
		return Predicate{}, fmt.Errorf(
			"version expression %q needs an operator: write \"= %s\" to match a range of builds, "+
				"or \"= %s-<debian revision>\" to match one build", token, token, token)
	}
	if literal == "" {
		return Predicate{}, fmt.Errorf("operator %q needs a version", operator)
	}
	if isOperatorByte(literal[0]) {
		return Predicate{}, fmt.Errorf(
			"version expression %q: unsupported operator; use one of = != > >= < <= ~>", token)
	}
	version, err := ParseVersion(literal)
	if err != nil {
		return Predicate{}, fmt.Errorf("version expression %q: %w", token, err)
	}
	predicate := Predicate{Operator: operator, Literal: version}
	if components, ok := splitDotted(version.Upstream); ok {
		predicate.dotted = components
	}
	if operator == OperatorPessimistic && len(predicate.dotted) == 0 {
		return Predicate{}, fmt.Errorf(
			"version expression %q: ~> needs a numeric upstream version such as 3.0 or 2024.1", token)
	}
	if operator == OperatorPessimistic && version.Revision != "" {
		return Predicate{}, fmt.Errorf(
			"version expression %q: ~> needs a version without a Debian revision", token)
	}
	return predicate, nil
}

func splitOperator(token string) (ConstraintOperator, string) {
	for _, operator := range constraintOperators {
		if rest, ok := strings.CutPrefix(token, string(operator)); ok {
			return operator, strings.TrimSpace(rest)
		}
	}
	return "", token
}

// splitDotted returns the numeric components of a dotted-numeric upstream such
// as "3.0.13" and reports false for anything else, including "2024a" and
// "13ubuntu10".
func splitDotted(upstream string) ([]string, bool) {
	components := strings.Split(upstream, ".")
	for _, component := range components {
		if component == "" {
			return nil, false
		}
		for i := 0; i < len(component); i++ {
			if !isDigit(component[i]) {
				return nil, false
			}
		}
	}
	return components, true
}

func (p *Predicate) allows(candidate Version) bool {
	switch p.Operator {
	case OperatorEqual:
		return p.matches(candidate)
	case OperatorNotEqual:
		return !p.matches(candidate)
	case OperatorPessimistic:
		upper, ok := pessimisticUpper(p.dotted)
		return ok && p.compare(candidate) >= 0 && p.below(candidate, upper)
	case OperatorGreater:
		return p.compare(candidate) > 0
	case OperatorGreaterOrEqual:
		return p.compare(candidate) >= 0
	case OperatorLess:
		return p.compare(candidate) < 0
	case OperatorLessOrEqual:
		return p.compare(candidate) <= 0
	default:
		return false
	}
}

// matches decides equality in three cases: a literal with a Debian revision
// names one build exactly, a dotted-numeric literal is a component prefix over
// builds, and any other literal is upstream equality ignoring the revision.
func (p *Predicate) matches(candidate Version) bool {
	if candidate.Epoch != p.Literal.Epoch {
		return false
	}
	if p.Literal.Revision != "" {
		return candidate.Compare(p.Literal) == 0
	}
	if len(p.dotted) > 0 {
		upper, ok := prefixUpper(p.dotted)
		if !ok {
			return compareVersionPart(candidate.Upstream, p.Literal.Upstream) == 0
		}
		return compareVersionPart(candidate.Upstream, p.Literal.Upstream) >= 0 &&
			compareVersionPart(candidate.Upstream, upper) < 0
	}
	return compareVersionPart(candidate.Upstream, p.Literal.Upstream) == 0
}

// compare orders candidate against the literal. A literal with a revision
// compares whole versions; otherwise only the upstream decides, so a Debian
// revision never changes the outcome.
func (p *Predicate) compare(candidate Version) int {
	if result := cmp.Compare(candidate.Epoch, p.Literal.Epoch); result != 0 {
		return result
	}
	if p.Literal.Revision != "" {
		return compareVersionPart(candidate.Revision, p.Literal.Revision)
	}
	return compareVersionPart(candidate.Upstream, p.Literal.Upstream)
}

func (p *Predicate) below(candidate Version, upstream string) bool {
	return candidate.Epoch == p.Literal.Epoch &&
		compareVersionPart(candidate.Upstream, upstream) < 0
}

// prefixUpper bounds a component prefix: "3.0.13" excludes everything from
// "3.0.14" on, so "3.0.13.5" is inside and "3.0.131" is not.
func prefixUpper(components []string) (string, bool) {
	upper := slices.Clone(components)
	incremented, ok := incrementComponent(upper[len(upper)-1])
	if !ok {
		return "", false
	}
	upper[len(upper)-1] = incremented
	return strings.Join(upper, "."), true
}

// pessimisticUpper bounds "~>": the second-to-last component is incremented and
// everything after it is dropped, so "~> 3.0.13" stops below 3.1.
func pessimisticUpper(components []string) (string, bool) {
	index := len(components) - 1
	if len(components) > 1 {
		index = len(components) - 2
	}
	incremented, ok := incrementComponent(components[index])
	if !ok {
		return "", false
	}
	upper := append(slices.Clone(components[:index]), incremented)
	return strings.Join(upper, "."), true
}

func incrementComponent(component string) (string, bool) {
	value, err := strconv.ParseUint(component, 10, 64)
	if err != nil || value == ^uint64(0) {
		return "", false
	}
	return strconv.FormatUint(value+1, 10), true
}
