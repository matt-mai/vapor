package lock

import (
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func verifyLockCatalogues(spec *schemaSpec.Spec, lock *Lockfile) (map[string]*Catalogue, error) {
	declared := declaredCatalogueSources(spec)
	catalogues := make(map[string]*Catalogue)
	for i := range lock.Catalogues {
		catalogue := &lock.Catalogues[i]
		source, ok := declared[catalogue.Name]
		if !ok {
			return nil, fmt.Errorf("lock catalogues[%d]: unknown catalogue", i)
		}
		if _, ok := catalogues[catalogue.Name]; ok {
			return nil, fmt.Errorf("lock catalogues[%d]: duplicate name", i)
		}
		if err := verifyCatalogue(catalogue, *source, i); err != nil {
			return nil, err
		}
		catalogues[catalogue.Name] = catalogue
	}
	if len(catalogues) != len(declared) {
		return nil, errors.New("lock catalogues do not cover every declared catalogue")
	}
	return catalogues, nil
}

func declaredCatalogueSources(spec *schemaSpec.Spec) map[string]*contents.CatalogueSource {
	declared := make(map[string]*contents.CatalogueSource)
	for i := range spec.Contents.Catalogues {
		declared[spec.Contents.Catalogues[i].Name] = &spec.Contents.Catalogues[i]
	}
	return declared
}

func verifyCatalogue(catalogue *Catalogue, source contents.CatalogueSource, i int) error {
	if err := checkLockDerived("lock catalogue tree", catalogue.Tree); err != nil {
		return fmt.Errorf("lock catalogues[%d]: %w", i, err)
	}
	if err := verifyLockCatalogueSource(catalogue.Source, source); err != nil {
		return fmt.Errorf("lock catalogues[%d]: %w", i, err)
	}
	return verifyLockCatalogueArchive(catalogue, source, i)
}

func verifyLockCatalogueArchive(catalogue *Catalogue, source contents.CatalogueSource, i int) error {
	if source.Path != nil {
		if catalogue.Archive != nil {
			return fmt.Errorf("lock catalogues[%d]: local catalogue must not have an archive", i)
		}
		return nil
	}
	if catalogue.Archive == nil {
		return fmt.Errorf("lock catalogues[%d]: remote catalogue requires an archive", i)
	}
	if err := checkLockHash("lock catalogue archive", catalogue.Archive.SHA256); err != nil {
		return fmt.Errorf("lock catalogues[%d]: %w", i, err)
	}
	if err := checkLockSize("lock catalogue archive", catalogue.Archive.Size); err != nil {
		return fmt.Errorf("lock catalogues[%d]: %w", i, err)
	}
	return nil
}

func verifyLockCatalogueSource(source CatalogueSource, spec contents.CatalogueSource) error {
	if spec.Path != nil {
		if source.Type != "local" || source.Path != *spec.Path || source.URL != "" ||
			source.Selector != nil || source.Commit != "" {
			return errors.New("local catalogue source does not match the declaration")
		}
		return base.ValidateLocalPath(source.Path)
	}
	if source.Type != "remote" || source.URL != *spec.URL || source.Path != "" {
		return errors.New("remote catalogue source does not match the declaration")
	}
	if err := base.ValidateInputURL(source.URL, true); err != nil {
		return err
	}
	if source.Selector == nil {
		return errors.New("remote catalogue source requires a selector")
	}
	if err := checkLockCatalogueSelector(*source.Selector, spec); err != nil {
		return err
	}
	if err := base.RequirePattern("lock catalogue commit", source.Commit, `^([0-9a-f]{40}|[0-9a-f]{64})$`); err != nil {
		return err
	}
	if spec.Commit != nil && source.Commit != *spec.Commit {
		return errors.New("resolved catalogue commit does not match the declared commit")
	}
	return nil
}

func checkLockCatalogueSelector(selector CatalogueSelector, spec contents.CatalogueSource) error {
	count := 0
	if selector.Branch != nil {
		count++
		if err := checkSelectorValue(selector.Branch, spec.Branch); err != nil {
			return err
		}
	}
	if selector.Tag != nil {
		count++
		if err := checkSelectorValue(selector.Tag, spec.Tag); err != nil {
			return err
		}
	}
	if selector.Commit != nil {
		count++
		if err := checkSelectorCommit(selector.Commit, spec.Commit); err != nil {
			return err
		}
	}
	if count != 1 {
		return errors.New("catalogue selector must contain exactly one of branch, tag or commit")
	}
	return nil
}

func checkSelectorValue(value, declared *string) error {
	if *value == "" || declared == nil || *value != *declared {
		return errors.New("catalogue selector does not match the declaration")
	}
	return nil
}

func checkSelectorCommit(value, declared *string) error {
	if declared == nil || *value != *declared {
		return errors.New("catalogue selector does not match the declaration")
	}
	return base.RequirePattern("catalogue selector commit", *value, `^([0-9a-f]{40}|[0-9a-f]{64})$`)
}
