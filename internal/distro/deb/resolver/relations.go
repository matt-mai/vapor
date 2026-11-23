package resolver

import (
	"fmt"
	"strings"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func versionSatisfies(relation *deb.Relation, version deb.Version) bool {
	if relation.Operator == "" {
		return true
	}
	compared := version.Compare(relation.Version)
	switch relation.Operator {
	case deb.RelationLess:
		return compared < 0
	case deb.RelationLessOrEqual:
		return compared <= 0
	case deb.RelationEqual:
		return compared == 0
	case deb.RelationGreaterOrEqual:
		return compared >= 0
	case deb.RelationGreater:
		return compared > 0
	}
	return false
}

func formatClause(clause deb.RelationClause) string {
	limit := min(len(clause), 8)
	parts := make([]string, 0, limit+1)
	for i := range limit {
		parts = append(parts, formatRelation(&clause[i]))
	}
	if len(clause) > limit {
		parts = append(parts, "...")
	}
	return strings.Join(parts, " | ")
}

func formatRelation(relation *deb.Relation) string {
	name := relation.Name
	if relation.Architecture != "" {
		name += ":" + relation.Architecture
	}
	if relation.Operator == "" {
		return truncate(name)
	}
	return truncate(fmt.Sprintf("%s (%s %s)", name, relation.Operator, relation.Version))
}

func formatCandidate(candidate *Candidate) string {
	return truncate(candidate.Name + " " + candidate.Version)
}

// truncate keeps failure messages bounded even for adversarially long metadata.
func truncate(value string) string {
	const maxValueLength = 128
	if len(value) <= maxValueLength {
		return value
	}
	return value[:maxValueLength-3] + "..."
}
