package lockinput

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/snapshot"
)

type catalogueInput struct {
	name      string
	catalogue *slicespkg.Catalogue
	packages  map[string]*slicespkg.Package
	record    lock.Catalogue
	bindings  map[string]slicespkg.Binding
}

func loadCatalogues(ctx context.Context, request *Request, local map[string]snapshot.Catalogue,
	evidence *locking.Evidence) ([]*catalogueInput, error) {
	result := make([]*catalogueInput, 0, len(request.Spec.Contents.Catalogues))
	definitions := make([]slicespkg.NamedPackageDefinitions, 0, len(request.Spec.Contents.Catalogues))
	for i := range request.Spec.Contents.Catalogues {
		source := &request.Spec.Contents.Catalogues[i]
		input, err := loadCatalogue(ctx, request, source, local[source.Name])
		if err != nil {
			return nil, fmt.Errorf("catalogue %q: %w", source.Name, err)
		}
		evidence.Catalogues = append(evidence.Catalogues, input.record)
		for _, warning := range input.catalogue.Maintenance.Warnings(request.Now) {
			evidence.Warnings = append(evidence.Warnings, fmt.Sprintf("catalogue %q: %s", source.Name, warning))
		}
		result = append(result, input)
		definitions = append(definitions, slicespkg.NamedPackageDefinitions{Catalogue: source.Name, Packages: input.packages})
	}
	if len(request.Spec.Contents.Slices) != 0 {
		if len(result) == 0 {
			return nil, errors.New("sliced contents require a catalogue")
		}
		if _, err := slicespkg.MergePackageDefinitions(definitions); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func loadCatalogue(ctx context.Context, request *Request, source *contents.CatalogueSource,
	snapped snapshot.Catalogue) (*catalogueInput, error) {
	tree, record, err := catalogueSnapshot(ctx, request, source, snapped)
	if err != nil {
		return nil, err
	}
	parsed, packages, err := parseCatalogueTree(tree, request.Cache)
	if err != nil {
		return nil, err
	}
	input := &catalogueInput{
		name: source.Name, catalogue: parsed, packages: packages, record: record,
		bindings: make(map[string]slicespkg.Binding),
	}
	for _, platform := range request.Spec.Platforms {
		bindings, err := slicespkg.BindArchives(parsed, source, request.Spec.Contents.Repositories,
			request.Provider, platform)
		if err != nil {
			return nil, err
		}
		for i := range bindings {
			input.bindings[platform+"\x00"+bindings[i].Archive.Name] = bindings[i]
		}
	}
	return input, nil
}

func catalogueSnapshot(ctx context.Context, request *Request, source *contents.CatalogueSource,
	snapped snapshot.Catalogue) (catalogue.Tree, lock.Catalogue, error) {
	if source.Path != nil {
		return snapped.Tree, lock.Catalogue{
			Name:     source.Name,
			Source:   lock.CatalogueSource{Type: "local", Path: *source.Path},
			Tree:     snapped.Digest,
			Manifest: catalogueManifest(snapped.Tree),
		}, nil
	}
	resolved, err := catalogue.ResolveRemote(ctx, request.Git, catalogue.RemoteSource{
		URL: *source.URL, Branch: source.Branch, Tag: source.Tag, Commit: source.Commit,
	}, request.Cache)
	if err != nil {
		return catalogue.Tree{}, lock.Catalogue{}, err
	}
	tree := resolved.Tree
	treeDigest, err := tree.Digest()
	if err != nil {
		return catalogue.Tree{}, lock.Catalogue{}, err
	}
	return tree, lock.Catalogue{
		Name: source.Name,
		Source: lock.CatalogueSource{
			Type: "remote", URL: *source.URL,
			Selector: &lock.CatalogueSelector{Branch: source.Branch, Tag: source.Tag, Commit: source.Commit},
			Commit:   resolved.Commit,
		},
		Tree:     treeDigest,
		Manifest: catalogueManifest(tree),
		Archive:  &lock.Archive{SHA256: resolved.ArchiveSHA256, Size: resolved.ArchiveSize},
	}, nil
}

func catalogueManifest(tree catalogue.Tree) []lock.CatalogueEntry {
	entries := tree.Entries()
	manifest := make([]lock.CatalogueEntry, len(entries))
	for i := range entries {
		entry := &entries[i]
		manifest[i] = lock.CatalogueEntry{
			Path: entry.Path, Kind: string(entry.Kind), Executable: entry.Executable,
			SHA256: entry.SHA256, Size: entry.Size, Target: entry.Target,
		}
	}
	return manifest
}

func parseCatalogueTree(tree catalogue.Tree, store *cache.Cache) (*slicespkg.Catalogue,
	map[string]*slicespkg.Package, error) {
	fsys, err := treeFS(tree, store)
	if err != nil {
		return nil, nil, err
	}
	root, err := fs.ReadFile(fsys, "chisel.yaml")
	if err != nil {
		return nil, nil, errors.New("read catalogue metadata")
	}
	parsed, err := slicespkg.ParseCatalogue(root)
	if err != nil {
		return nil, nil, err
	}
	packages, err := slicespkg.ParsePackages(fsys, parsed)
	if err != nil {
		return nil, nil, err
	}
	return parsed, packages, nil
}

func treeFS(tree catalogue.Tree, store *cache.Cache) (fs.FS, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entries := tree.Entries()
	for i := range entries {
		entry := &entries[i]
		if err := writeTreeEntry(writer, entry, store); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
}

func writeTreeEntry(writer *zip.Writer, entry *catalogue.Entry, store *cache.Cache) error {
	if entry.Kind == catalogue.KindDir {
		_, err := writer.Create(entry.Path + "/")
		return err
	}
	file, err := writer.Create(entry.Path)
	if err != nil {
		return err
	}
	if entry.Kind == catalogue.KindSymlink {
		_, err = io.WriteString(file, entry.Target)
		return err
	}
	data, err := readTreeBlob(store, entry.SHA256, entry.Size)
	if err != nil {
		return fmt.Errorf("catalogue entry %q: %w", entry.Path, err)
	}
	_, err = file.Write(data)
	return err
}

func readTreeBlob(store *cache.Cache, digest string, size int64) ([]byte, error) {
	reader, err := store.Open(digest, size)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, errors.New("cached input has the wrong size")
	}
	return data, nil
}
