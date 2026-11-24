package builder

import (
	"context"
	"fmt"

	"github.com/matt-mai/vapor/internal/closure"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/hardening"
	"github.com/matt-mai/vapor/internal/mutation"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Assemble runs one platform end to end: sliced mutations, temporary cleanup, then
// declared entries, synthesized state, the link check, hardening and the ELF closure
// check. The result is the tree the layer is serialized from.
func (i *Input) Assemble(ctx context.Context, content *Content, platform string) (*vfs.Tree, error) {
	i.working("mutate")
	tree, err := mutate(ctx, content)
	if err != nil {
		return nil, err
	}
	if err := applyPaths(tree, i.spec.Filesystem.Paths); err != nil {
		return nil, err
	}
	i.working("synthesize state")
	if err := i.synthesize(ctx, tree, content, platform); err != nil {
		return nil, err
	}
	i.working("hardening")
	if err := hardening.Apply(tree, i.spec.Hardening); err != nil {
		return nil, fmt.Errorf("hardening: %w", err)
	}
	// Both dpkg records follow hardening, so the status database and the file
	// lists describe the same surviving ownership set. Deriving the status before
	// hardening left a record for a package whose last file hardening removed.
	i.working("package database")
	if err := i.packageDatabase(tree, content); err != nil {
		return nil, err
	}
	if err := i.packageFileLists(tree, content); err != nil {
		return nil, err
	}
	if err := tree.ConfineLinks(); err != nil {
		return nil, fmt.Errorf("symlinks: %w", err)
	}
	i.working("ELF closure")
	if err := closure.Check(tree, platform); err != nil {
		return nil, fmt.Errorf("ELF closure: %w", err)
	}
	// The command check runs last: hardening is what removes the shells and package
	// tools a declared command may name.
	if err := checkCommand(tree, &i.spec.Container); err != nil {
		return nil, err
	}
	return tree, nil
}

func mutate(ctx context.Context, content *Content) (*vfs.Tree, error) {
	if len(content.scripts) == 0 && len(content.Temporary) == 0 {
		return content.Tree.Clone(), nil
	}
	selection := mutation.Selection{Mutable: content.Mutable, Temporary: content.Temporary}
	selection.Tree = content.Tree.Clone()
	if _, _, err := mutation.RunScripts(ctx, selection, content.scripts,
		mutation.DefaultSandboxLimits()); err != nil {
		return nil, fmt.Errorf("mutation: %w", err)
	}
	// RunScripts commits into the tree it was given, so the committed result is the
	// staged clone rather than a new tree.
	return selection.Tree, nil
}

func (i *Input) scriptRequests(ordered []slicespkg.Slice) []mutation.Request {
	var requests []mutation.Request
	for index := range ordered {
		slice := &ordered[index]
		if slice.Mutate != "" {
			name := slicespkg.SliceKey{Package: slice.Package, Slice: slice.Name}.String()
			requests = append(requests, mutation.Request{
				Name: name, Script: []byte(slice.Mutate), MaxSteps: i.maxSteps(),
			})
		}
	}
	return requests
}

func (i *Input) maxSteps() int {
	if i.spec.Contents.SlicesEngine.MaxSteps == nil {
		return 0
	}
	return *i.spec.Contents.SlicesEngine.MaxSteps
}

// synthesize writes the state no package supplies: accounts, timezone, release
// identity, the trust bundle and the package database.
func (i *Input) synthesize(ctx context.Context, tree *vfs.Tree, content *Content, platform string) error {
	declared := &i.spec.Filesystem
	if err := synthesis.Accounts(tree, &declared.Accounts); err != nil {
		return fmt.Errorf("accounts: %w", err)
	}
	if err := synthesis.SandboxAccount(tree, content.Packages); err != nil {
		return fmt.Errorf("apt sandbox account: %w", err)
	}
	if err := synthesis.BaseAccounts(tree); err != nil {
		return fmt.Errorf("base accounts: %w", err)
	}
	if err := synthesis.Timezone(tree, declared.Timezone); err != nil {
		return fmt.Errorf("timezone: %w", err)
	}
	if err := synthesis.Release(tree, i.provider.ReleaseIdentity(), declared.OSRelease); err != nil {
		return fmt.Errorf("release identity: %w", err)
	}
	if err := synthesis.CA(tree, i.provider.CABundlePath(), declared.CA, i.caSources()); err != nil {
		return fmt.Errorf("CA bundle: %w", err)
	}
	return i.aptSources(ctx, tree, platform)
}

// packageDatabase writes the dpkg records collected during assembly: a whole
// package is installed, a sliced one is unpacked.
func (i *Input) packageDatabase(tree *vfs.Tree, content *Content) error {
	if err := synthesis.PackageDatabase(tree, content.Packages); err != nil {
		return fmt.Errorf("package database: %w", err)
	}
	return nil
}

// packageFileLists writes one file list per package, naming the files it
// contributed. It runs after hardening so a list only names paths the image still
// has: a stripped package would otherwise report every removed file as missing. The
// database is written at the same point for the same reason.
func (i *Input) packageFileLists(tree *vfs.Tree, content *Content) error {
	if err := synthesis.FileLists(tree, content.Packages); err != nil {
		return fmt.Errorf("package file lists: %w", err)
	}
	return nil
}

// caSources reads the declared CA inputs from the verified cache. The lock records
// them as local inputs, so a build reads exactly the bytes the lock snapshotted.
func (i *Input) caSources() map[string][]byte {
	sources := make(map[string][]byte)
	for index := range i.lockfile.LocalInputs {
		input := &i.lockfile.LocalInputs[index]
		if input.Role != "ca" {
			continue
		}
		data, err := i.read(context.Background(), input.SHA256, input.Size)
		if err != nil {
			continue
		}
		sources[input.Path] = data
	}
	return sources
}
