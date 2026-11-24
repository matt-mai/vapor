package lockinput

import (
	"context"
	"time"

	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/snapshot"
)

// ResolveSelection resolves whole packages and slices against the current repository
// metadata without downloading a single payload. It is Collect minus the three
// acquisition steps, so a caller can ask what a fresh lock would select and compare it
// with a lock it already has.
func ResolveSelection(ctx context.Context, request *Request) (*locking.Evidence, error) {
	if err := validateRequest(ctx, request); err != nil {
		return nil, err
	}
	if request.Now.IsZero() {
		request.Now = time.Now()
	}
	snapped, err := snapshot.Snapshot(request.SpecDir, request.Spec, request.Cache)
	if err != nil {
		return nil, err
	}
	request.Inputs = snapped.Inputs
	evidence := &locking.Evidence{LocalInputs: snapped.Inputs}
	local := make(map[string]snapshot.Catalogue, len(snapped.Catalogues))
	for _, item := range snapped.Catalogues {
		local[item.Name] = item
	}
	catalogues, err := loadCatalogues(ctx, request, local, evidence)
	if err != nil {
		return nil, err
	}
	repositories, archives, err := acquireRepositories(ctx, request, catalogues)
	if err != nil {
		return nil, err
	}
	if evidence.Packages, err = resolveWholePackages(request.Spec, archives); err != nil {
		return nil, err
	}
	selections, err := selectAllSlices(request, catalogues, archives)
	if err != nil {
		return nil, err
	}
	if evidence.Slices, err = lockSlices(selections, archives, specCPEs(request.Spec)); err != nil {
		return nil, err
	}
	evidence.Repositories = referencedRepositories(repositories, evidence)
	return evidence, nil
}
