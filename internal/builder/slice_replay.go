package builder

import (
	"errors"
	"fmt"
	"slices"

	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

type sliceReplay struct {
	ordered []slicespkg.Slice
	sources []sliceReplaySource
}

type sliceReplaySource struct {
	pkg    *slicespkg.Package
	record *lock.Slice
}

func (i *Input) replaySlices(catalogues []Catalogue, records []*lock.Slice, architecture string) (sliceReplay, error) {
	byCatalogue := make(map[string]map[string]*lock.Slice)
	for _, record := range records {
		if byCatalogue[record.Catalogue] == nil {
			byCatalogue[record.Catalogue] = make(map[string]*lock.Slice)
		}
		byCatalogue[record.Catalogue][record.Package] = record
	}
	roots := i.sliceRootsByCatalogue()
	var replay sliceReplay
	for _, source := range i.spec.Contents.Catalogues {
		index := slices.IndexFunc(catalogues, func(cat Catalogue) bool { return cat.Name == source.Name })
		if index < 0 {
			return sliceReplay{}, fmt.Errorf("catalogue %q is missing from the lock", source.Name)
		}
		packages := catalogues[index].Packages
		if err := replay.addCatalogue(packages, roots[source.Name], byCatalogue[source.Name], architecture); err != nil {
			return sliceReplay{}, fmt.Errorf("catalogue %q: %w", source.Name, err)
		}
		delete(byCatalogue, source.Name)
	}
	if len(byCatalogue) != 0 {
		return sliceReplay{}, errors.New("locked slice closure refers to an undeclared catalogue")
	}
	return replay, nil
}

func (i *Input) sliceRootsByCatalogue() map[string][]slicespkg.SliceKey {
	roots := make(map[string][]slicespkg.SliceKey)
	for _, request := range i.spec.Contents.Slices {
		if request.Catalogue != nil {
			name := *request.Catalogue
			roots[name] = append(roots[name], slicespkg.SliceKey{Package: request.Package, Slice: request.Slice})
		}
	}
	return roots
}

func (r *sliceReplay) addCatalogue(packages map[string]*slicespkg.Package, roots []slicespkg.SliceKey,
	records map[string]*lock.Slice, architecture string,
) error {
	order, err := slicespkg.SelectSlices(packages, roots, nil, architecture)
	if err != nil {
		return err
	}
	// Lock records hold one package's projection, not the cross-package schedule.
	grouped := make(map[string][]string)
	for _, key := range order {
		grouped[key.Package] = append(grouped[key.Package], key.Slice)
	}
	for _, key := range order {
		pkg := packages[key.Package]
		if closure, first := grouped[key.Package]; first {
			record := records[pkg.RealName]
			if err := checkSliceClosure(pkg, record, closure); err != nil {
				return err
			}
			r.sources = append(r.sources, sliceReplaySource{pkg: pkg, record: record})
			delete(grouped, key.Package)
			delete(records, pkg.RealName)
		}
		r.ordered = append(r.ordered, pkg.Slices[key.Slice])
	}
	if len(records) != 0 {
		return errors.New("locked slice closure contains an unselected package")
	}
	return nil
}

func checkSliceClosure(pkg *slicespkg.Package, record *lock.Slice, closure []string) error {
	if record == nil || !slices.Equal(record.Closure, closure) {
		return fmt.Errorf("slice package %q: locked slice closure does not match the catalogue selection", pkg.RealName)
	}
	digest, err := slicespkg.DefinitionDigest(pkg.Path, pkg.SHA256, pkg.Size, closure)
	if err != nil {
		return fmt.Errorf("slice package %q: %w", pkg.RealName, err)
	}
	if digest != record.DefinitionDigest {
		return fmt.Errorf("slice package %q: catalogue definition does not match its locked digest", pkg.RealName)
	}
	return nil
}
