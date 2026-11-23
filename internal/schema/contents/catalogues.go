package contents

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/base"
)

func validateCatalogues(contents *Contents) error {
	seen := make(map[string]bool)
	for i, source := range contents.Catalogues {
		if seen[source.Name] {
			return errors.New("duplicate catalogue name")
		}
		seen[source.Name] = true
		if err := validateCatalogue(source); err != nil {
			return fmt.Errorf("contents.catalogues[%d]: %w", i, err)
		}
		for _, archive := range slices.Sorted(maps.Keys(source.Archives)) {
			if !slices.ContainsFunc(contents.Repositories, func(repo Repository) bool {
				return repo.Name == source.Archives[archive]
			}) {
				return errors.New("catalogue archive binding references an undefined repository")
			}
		}
	}
	return nil
}

func validateCatalogue(source CatalogueSource) error {
	if err := base.ValidateInputName(source.Name); err != nil {
		return err
	}
	selectors := catalogueSelectors(source)
	if source.Path != nil {
		return validateLocalCatalogue(source, selectors)
	}
	if source.URL == nil || selectors != 1 {
		return errors.New("remote catalogue requires URL and exactly one tag, branch or commit")
	}
	if err := base.ValidateInputURL(*source.URL, true); err != nil {
		return err
	}
	if source.Commit != nil {
		return base.RequirePattern("catalogue full commit", *source.Commit, `^([0-9a-f]{40}|[0-9a-f]{64})$`)
	}
	ref := source.Tag
	if ref == nil {
		ref = source.Branch
	}
	return ValidateGitRef(*ref)
}

func catalogueSelectors(source CatalogueSource) int {
	selectors := 0
	for _, selector := range []*string{source.Tag, source.Branch, source.Commit} {
		if selector != nil {
			selectors++
		}
	}
	return selectors
}

func validateLocalCatalogue(source CatalogueSource, selectors int) error {
	if source.URL != nil || selectors != 0 {
		return errors.New("local catalogue path is exclusive with URL and remote selectors")
	}
	return base.ValidateLocalPath(*source.Path)
}

// ValidateGitRef checks a literal Git reference name for a catalogue source.
func ValidateGitRef(value string) error {
	if value == "" || value == "@" || value == "HEAD" || strings.HasPrefix(value, "-") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "..") || strings.Contains(value, "//") || strings.Contains(value, "@{") {
		return errors.New("catalogue selector must be a literal Git ref name")
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) || strings.ContainsRune("~^:?*[\\", char) {
			return errors.New("catalogue selector contains forbidden Git ref characters")
		}
	}
	for component := range strings.SplitSeq(value, "/") {
		if strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".") || strings.HasSuffix(component, ".lock") {
			return errors.New("catalogue selector contains an invalid Git ref component")
		}
	}
	return nil
}
