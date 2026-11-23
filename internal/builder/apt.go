package builder

import (
	"context"
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/policy"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/verify"
	"github.com/matt-mai/vapor/internal/vfs"
)

// aptSources writes the locked package sources for an image that installs packages
// at runtime. An immutable image gains nothing from them, and a stale source list is
// what makes apt usable after the image was built, so they are opt-in.
func (i *Input) aptSources(ctx context.Context, tree *vfs.Tree, platform string) error {
	if !policy.PackageSources(i.spec.Hardening) {
		return nil
	}
	repositories, err := i.repositorySources(ctx, platform)
	if err != nil {
		return err
	}
	return synthesis.APTSources(tree, repositories)
}

// repositorySources describes the locked repositories that serve this platform.
func (i *Input) repositorySources(ctx context.Context, platform string) ([]synthesis.APTRepository, error) {
	var repositories []synthesis.APTRepository
	for index := range i.lockfile.Repositories {
		record := &i.lockfile.Repositories[index]
		if record.Platform != platform || len(record.Indexes) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		keys, err := verify.RepositoryKeys(record.Trust.Keys, i.blobs)
		if err != nil {
			return nil, fmt.Errorf("package sources for repository %q: %w", record.Name, err)
		}
		keyring, err := deb.PublicKeyring(keys)
		if err != nil {
			return nil, fmt.Errorf("package sources for repository %q: %w", record.Name, err)
		}
		components := make([]string, len(record.Indexes))
		for n := range record.Indexes {
			components[n] = record.Indexes[n].Component
		}
		repositories = append(repositories, synthesis.APTRepository{
			URL: record.URL, Suite: record.Suite, Components: components, Keyring: keyring,
		})
	}
	return repositories, nil
}
