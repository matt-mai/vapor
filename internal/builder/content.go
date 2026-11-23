package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/matt-mai/vapor/internal/artifact"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/mutation"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Content is one platform's image filesystem before mutation, synthesis and
// hardening. It is not an image yet: nothing here has run a script or written
// generated state.
type Content struct {
	Tree     *vfs.Tree
	Packages []synthesis.PackageState
	// Mutable, Temporary and Original are the slice declarations the mutation stage
	// works from.
	Mutable   []string
	Temporary []string
	Original  map[string]string
	scripts   []mutation.Request
	budget    extractionBudget
}

// extractionBudget bounds what one platform's content may hold in total. The vfs
// limits bound a single archive, so without this an image made of many large
// packages could retain far more than one archive's worth while it is assembled.
type extractionBudget struct {
	entries int
	bytes   int64
}

// imageBudget is what one platform may hold in total: the entry and content bounds
// of the largest single archive the importer admits.
func imageBudget() extractionBudget {
	limits := vfs.DefaultLimits()
	return extractionBudget{entries: limits.MaxEntries, bytes: limits.MaxTotalSize}
}

// charge spends what an extracted tree contributes and refuses the first
// extraction that would not fit. An entry two archives share counts twice, which
// is the memory a not-yet-merged tree actually cost.
func (b *extractionBudget) charge(tree *vfs.Tree) error {
	for _, entry := range tree.Entries() {
		b.entries--
		b.bytes -= entry.Size
	}
	if b.entries < 0 {
		return fmt.Errorf("image content exceeds %d filesystem entries", imageBudget().entries)
	}
	if b.bytes < 0 {
		return fmt.Errorf("image content exceeds %d bytes", imageBudget().bytes)
	}
	return nil
}

// Content assembles one platform's filesystem from the verified cache: whole
// packages, sliced package content and artifacts, merged in that order. Every byte
// comes from a blob the lock names, so this stage cannot reach the network.
func (i *Input) Content(ctx context.Context, platform string) (*Content, error) {
	if err := i.checkPlatform(platform); err != nil {
		return nil, err
	}
	architecture, err := i.provider.Architecture(platform)
	if err != nil {
		return nil, err
	}
	content := &Content{Tree: vfs.New(), budget: imageBudget()}
	if err := i.wholePackages(ctx, platform, content); err != nil {
		return nil, err
	}
	if err := i.slicedPackages(ctx, platform, architecture, content); err != nil {
		return nil, err
	}
	if err := i.artifacts(ctx, platform, architecture, content); err != nil {
		return nil, err
	}
	// Every entry needs its control stanza. A payload whose stanza did not survive
	// decoding would otherwise be recorded as a package with no metadata, which is
	// worse than failing the stage that produced it.
	for _, pkg := range content.Packages {
		if len(pkg.Control) > 0 {
			continue
		}
		return nil, fmt.Errorf("package %q has no control stanza in its payload", pkg.Name)
	}
	content.finalizeTemporary()
	return content, nil
}

// finalizeTemporary recomputes which temporary paths may be removed, now that every
// input has merged. A whole package or an artifact can ship the same bytes a slice
// declares `until: mutate`; that entry has a permanent contributor, so removing it
// after mutation would delete another input's file. Only the slice's origin says
// the path is temporary, so one permanent origin is enough to keep it.
func (c *Content) finalizeTemporary() {
	kept := make([]string, 0, len(c.Temporary))
	for _, name := range c.Temporary {
		if entry, ok := c.Tree.Lookup(name); ok && slices.ContainsFunc(entry.Origins, func(origin vfs.Origin) bool {
			return origin.Slice == ""
		}) {
			continue
		}
		kept = append(kept, name)
	}
	c.Temporary = kept
}

func (i *Input) checkPlatform(platform string) error {
	if slices.Contains(i.spec.Platforms, platform) {
		return nil
	}
	return fmt.Errorf("platform %q is not declared by the specification", platform)
}

// wholePackages extracts every whole package the lock resolved for this platform.
func (i *Input) wholePackages(ctx context.Context, platform string, content *Content) error {
	for index := range i.lockfile.Packages {
		record := &i.lockfile.Packages[index]
		if record.Platform != platform {
			continue
		}
		i.extract(record.Name+" "+record.Version, record.Content.Size)
		data, err := i.read(ctx, record.Content.SHA256, record.Content.Size)
		if err != nil {
			return fmt.Errorf("package %q: %w", record.Name, err)
		}
		origin := vfs.Origin{Package: record.Name, Path: record.Content.Path}
		extracted, err := deb.Extract(data, origin)
		if err != nil {
			return fmt.Errorf("package %q: %w", record.Name, err)
		}
		if err := content.budget.charge(extracted.Tree); err != nil {
			return fmt.Errorf("package %q: %w", record.Name, err)
		}
		if err := content.Tree.Merge(extracted.Tree); err != nil {
			return fmt.Errorf("package %q: %w", record.Name, err)
		}
		control, _ := extracted.Control.Member("control")
		content.Packages = append(content.Packages, synthesis.PackageState{
			Name: record.Name, Version: record.Version, Architecture: record.Architecture,
			Status: synthesis.StatusInstalled, Control: control,
		})
	}
	return nil
}

// slicedPackages checks the replayed closure against the lock before applying content.
func (i *Input) slicedPackages(ctx context.Context, platform, architecture string,
	content *Content,
) error {
	records := i.platformSlices(platform)
	if len(records) == 0 && len(i.spec.Contents.Slices) == 0 {
		return nil
	}
	catalogues, err := i.Catalogues(ctx)
	if err != nil {
		return err
	}
	definitions := make([]slicespkg.NamedPackageDefinitions, 0, len(catalogues))
	for index := range catalogues {
		catalogue := &catalogues[index]
		definitions = append(definitions, slicespkg.NamedPackageDefinitions{
			Catalogue: catalogue.Name, Packages: catalogue.Packages,
		})
	}
	packages, err := slicespkg.MergePackageDefinitions(definitions)
	if err != nil {
		return err
	}
	replay, err := i.replaySlices(catalogues, records, architecture)
	if err != nil {
		return err
	}
	sources := make(map[string]*slicespkg.Source, len(records))
	for _, source := range replay.sources {
		if sourceErr := i.sliceSource(ctx, source, sources, content); sourceErr != nil {
			return sourceErr
		}
	}
	applied, err := slicespkg.ApplyContent(replay.ordered, sources, architecture, packages)
	if err != nil {
		return err
	}
	if err := content.Tree.Merge(applied.Tree); err != nil {
		return err
	}
	content.Mutable = append(content.Mutable, applied.Mutable...)
	content.Temporary = append(content.Temporary, applied.Temporary...)
	content.Original = applied.Original
	content.scripts = i.scriptRequests(replay.ordered)
	return nil
}

func (i *Input) platformSlices(platform string) []*lock.Slice {
	records := make([]*lock.Slice, 0, len(i.lockfile.Slices))
	for index := range i.lockfile.Slices {
		if i.lockfile.Slices[index].Platform == platform {
			records = append(records, &i.lockfile.Slices[index])
		}
	}
	return records
}

// sliceSource extracts one locked slice package once and records it as a content
// source. Several slices of one package share the extracted tree.
func (i *Input) sliceSource(ctx context.Context, source sliceReplaySource, sources map[string]*slicespkg.Source,
	content *Content,
) error {
	pkg, record := source.pkg, source.record
	if pkg.Archive != "" && pkg.Archive != record.Archive {
		return fmt.Errorf("slice package %q: locked archive %q is not the archive the catalogue pins %q",
			record.Package, record.Archive, pkg.Archive)
	}
	i.extract(record.Package+" "+record.Version, record.Content.Size)
	data, err := i.read(ctx, record.Content.SHA256, record.Content.Size)
	if err != nil {
		return fmt.Errorf("slice package %q: %w", record.Package, err)
	}
	origin := vfs.Origin{Package: record.Package, Path: record.Content.Path}
	extracted, err := deb.Extract(data, origin)
	if err != nil {
		return fmt.Errorf("slice package %q: %w", record.Package, err)
	}
	if err := content.budget.charge(extracted.Tree); err != nil {
		return fmt.Errorf("slice package %q: %w", record.Package, err)
	}
	sources[pkg.Name] = &slicespkg.Source{Package: pkg.Name, Tree: extracted.Tree}
	control, _ := extracted.Control.Member("control")
	content.Packages = append(content.Packages, synthesis.PackageState{
		Name: record.Package, Version: record.Version, Architecture: record.Architecture,
		Status: synthesis.StatusUnpacked, Control: control,
	})
	return nil
}

// artifacts places every artifact the lock resolved for this platform.
func (i *Input) artifacts(ctx context.Context, platform, architecture string, content *Content) error {
	for index := range i.lockfile.Artifacts {
		record := &i.lockfile.Artifacts[index]
		if record.Platform != platform {
			continue
		}
		i.extract(record.Name, record.Size)
		data, err := i.read(ctx, record.SHA256, record.Size)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", record.Name, err)
		}
		if err := i.placeArtifact(record, data, architecture, content); err != nil {
			return err
		}
	}
	return nil
}

// placeArtifact places one payload: a package artifact installs itself, every other
// placement is a tree the artifact package produces.
func (i *Input) placeArtifact(record *lock.Artifact, data []byte, architecture string, content *Content) error {
	if record.Unpack != nil && *record.Unpack == contents.ArtifactUnpackPackage {
		return i.localPackage(record, data, architecture, content)
	}
	tree, err := artifact.Place(record, data)
	if err != nil {
		return err
	}
	if err := content.budget.charge(tree); err != nil {
		return fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	if err := content.Tree.Merge(tree); err != nil {
		return fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	return nil
}

// localPackage installs a DEB artifact as a package: its payload joins the image and
// its control stanza becomes the package record, so the lock's package list, the
// dpkg database and the SPDX inventory describe it exactly as a fetched package.
//
// Ownership is recorded under the artifact's declared name, because that is the record
// the document reads the contributor back from; the package the payload describes is
// its own identity, which the SPDX element states as the package's name.
func (i *Input) localPackage(record *lock.Artifact, data []byte, architecture string, content *Content) error {
	origin := vfs.Origin{Package: record.Name, Path: record.Source()}
	extracted, err := deb.Extract(data, origin)
	if err != nil {
		return fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	if err := content.budget.charge(extracted.Tree); err != nil {
		return fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	if err := content.Tree.Merge(extracted.Tree); err != nil {
		return fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	control, _ := extracted.Control.Member("control")
	content.Packages = append(content.Packages, synthesis.PackageState{
		Name: record.SBOM.Name, Version: record.SBOM.Version, Architecture: architecture,
		Status: synthesis.StatusInstalled, Control: control,
	})
	return nil
}

// read loads one verified blob, bounded by its recorded size so a store that returns
// more cannot hand the parser unbounded input.
func (i *Input) read(ctx context.Context, digest string, size int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := i.blobs.Open(digest, size)
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
