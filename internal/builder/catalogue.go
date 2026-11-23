package builder

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/matt-mai/vapor/internal/catalogue"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// Catalogue is one locked catalogue, rebuilt offline from the manifest the lock
// recorded and the verified blobs it names. The tree is re-digested and must match
// the locked identity, so a tampered manifest cannot describe different content.
type Catalogue struct {
	Name     string
	Tree     catalogue.Tree
	Metadata *slicespkg.Catalogue
	Packages map[string]*slicespkg.Package
}

// Catalogues rebuilds and parses every catalogue a specification declares. It never
// resolves a selector and never runs Git: the recorded manifest is the tree, and
// every byte comes from the verified store.
func (i *Input) Catalogues(ctx context.Context) ([]Catalogue, error) {
	catalogues := make([]Catalogue, 0, len(i.lockfile.Catalogues))
	for index := range i.lockfile.Catalogues {
		record := &i.lockfile.Catalogues[index]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rebuilt, err := i.catalogue(ctx, record)
		if err != nil {
			return nil, fmt.Errorf("build catalogue %q: %w", record.Name, err)
		}
		catalogues = append(catalogues, rebuilt)
	}
	return catalogues, nil
}

func (i *Input) catalogue(ctx context.Context, record *lock.Catalogue) (Catalogue, error) {
	tree, err := catalogue.LockedTree(record)
	if err != nil {
		return Catalogue{}, fmt.Errorf("manifest: %w", err)
	}
	fsys, err := catalogue.FileSystem(tree, i.blobs)
	if err != nil {
		return Catalogue{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Catalogue{}, ctxErr
	}
	metadata, packages, err := parseCatalogue(fsys)
	if err != nil {
		return Catalogue{}, err
	}
	return Catalogue{Name: record.Name, Tree: tree, Metadata: metadata, Packages: packages}, nil
}

// parseCatalogue strictly decodes the catalogue metadata and its slice definitions.
func parseCatalogue(fsys fs.FS) (*slicespkg.Catalogue, map[string]*slicespkg.Package, error) {
	root, err := fs.ReadFile(fsys, "chisel.yaml")
	if err != nil {
		return nil, nil, errors.New("read catalogue metadata")
	}
	metadata, err := slicespkg.ParseCatalogue(root)
	if err != nil {
		return nil, nil, err
	}
	packages, err := slicespkg.ParsePackages(fsys, metadata)
	if err != nil {
		return nil, nil, err
	}
	return metadata, packages, nil
}
