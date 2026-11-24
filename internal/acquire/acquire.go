// Package acquire fetches resolved package and artifact payloads into the cache.
//
// Acquisition consumes fixed resolution results. It never selects versions,
// archives or platforms and never inspects image contents.
package acquire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"

	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

// MaxPackageSize bounds one resolved package archive before verification.
const MaxPackageSize int64 = 2 << 30

// MaxArtifactSize bounds one artifact payload before verification.
const MaxArtifactSize int64 = 2 << 30

// Fetcher retrieves one absolute input URL. The caller must close the reader.
type Fetcher interface {
	Fetch(ctx context.Context, url string) (io.ReadCloser, error)
}

// Local opens one payload declared by a path relative to the specification
// directory. Local payloads never pass through a URL fetcher.
type Local interface {
	Open(declaredPath string) (io.ReadCloser, error)
}

// Store publishes verified bytes by SHA256 and exact size.
type Store interface {
	Store(r io.Reader, digest string, size int64) error
}

// Package is one resolved package archive to acquire.
type Package struct {
	Platform     string
	Name         string
	Version      string
	Architecture string
	URL          string
	SHA256       string
	Size         int64
}

// PackageRecord is a verified package archive published to the cache.
type PackageRecord struct {
	Platform     string
	Name         string
	Version      string
	Architecture string
	URL          string
	SHA256       string
	Size         int64
}

// Acquired names one archive this package verified and published to the cache.
type Acquired struct {
	Name    string
	Version string
	Size    int64
}

// Packages verifies and caches every resolved package archive, calling progress as
// each one is published. progress may be nil, and a byte offset is what the archive
// declares rather than what was read, so a caller can total a known set of downloads
// without waiting for the last one.
func Packages(ctx context.Context, fetcher Fetcher, store Store, packages []Package,
	progress func(Acquired, int64),
) ([]PackageRecord, error) {
	if ctx == nil || fetcher == nil || store == nil {
		return nil, errors.New("package acquisition requires context, fetcher and store")
	}
	records := make([]PackageRecord, 0, len(packages))
	seen := make(map[string]bool, len(packages))
	for i := range packages {
		pkg := &packages[i]
		if err := validatePackage(pkg); err != nil {
			return nil, err
		}
		key := pkg.Platform + "\x00" + pkg.Name
		if seen[key] {
			return nil, fmt.Errorf("package %q is resolved twice on %s", pkg.Name, pkg.Platform)
		}
		seen[key] = true
		record, err := acquirePackage(ctx, fetcher, store, pkg)
		if err != nil {
			return nil, fmt.Errorf("package %q on %s: %w", pkg.Name, pkg.Platform, err)
		}
		records = append(records, record)
		// The size comes from the resolved record, not from the bytes read, so a
		// caller that totals all the downloads gets the same number either way.
		if progress != nil {
			progress(Acquired{Name: pkg.Name, Version: pkg.Version, Size: pkg.Size}, pkg.Size)
		}
	}
	sortPackages(records)
	return records, nil
}

func acquirePackage(ctx context.Context, fetcher Fetcher, store Store, pkg *Package) (PackageRecord, error) {
	reader, err := fetch(ctx, fetcher, pkg.URL)
	if err != nil {
		return PackageRecord{}, err
	}
	storeErr := store.Store(reader, pkg.SHA256, pkg.Size)
	closeErr := reader.Close()
	if storeErr != nil {
		return PackageRecord{}, storeFailure(storeErr)
	}
	if closeErr != nil {
		return PackageRecord{}, &fetchError{cause: closeErr}
	}
	return PackageRecord{
		Platform:     pkg.Platform,
		Name:         pkg.Name,
		Version:      pkg.Version,
		Architecture: pkg.Architecture,
		URL:          pkg.URL,
		SHA256:       pkg.SHA256,
		Size:         pkg.Size,
	}, nil
}

func sortPackages(records []PackageRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Platform != records[j].Platform {
			return records[i].Platform < records[j].Platform
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Version < records[j].Version
	})
}

func validatePackage(pkg *Package) error {
	if pkg.Platform == "" || pkg.Name == "" || pkg.Version == "" || pkg.Architecture == "" {
		return fmt.Errorf("package %q on %q has incomplete resolution", pkg.Name, pkg.Platform)
	}
	if err := base.ValidateInputURL(pkg.URL, false); err != nil {
		return fmt.Errorf("package %q on %s: %w", pkg.Name, pkg.Platform, err)
	}
	if err := base.RequirePattern("package SHA256", pkg.SHA256, `^[0-9a-f]{64}$`); err != nil {
		return fmt.Errorf("package %q on %s: %w", pkg.Name, pkg.Platform, err)
	}
	if pkg.Size <= 0 || pkg.Size > MaxPackageSize {
		return fmt.Errorf("package %q on %s has invalid size %d", pkg.Name, pkg.Platform, pkg.Size)
	}
	return nil
}

// Artifact is one resolved artifact payload for one platform.
type Artifact struct {
	Platform string
	Name     string
	URL      string
	Path     string
	SHA256   string
	Dest     string
	Unpack   contents.Placement
	UID      int
	GID      int
	Mode     *string
	SBOM     contents.ArtifactIdentity
}

// ArtifactRecord is a verified artifact payload published to the cache.
type ArtifactRecord struct {
	Platform string
	Name     string
	URL      string
	Path     string
	SHA256   string
	Size     int64
	Dest     string
	Unpack   contents.Placement
	UID      int
	GID      int
	Mode     *string
	SBOM     contents.ArtifactIdentity
}

// Artifacts expands and caches every artifact payload for its intended platforms.
// local is only used by sources declared with a path, so a URL-only call passes nil.
func Artifacts(ctx context.Context, fetcher Fetcher, local Local, store Store, artifacts []contents.Artifact,
	platforms []string, progress func(Acquired, int64),
) ([]ArtifactRecord, error) {
	if ctx == nil || fetcher == nil || store == nil {
		return nil, errors.New("artifact acquisition requires context, fetcher and store")
	}
	names := make(map[string]bool, len(artifacts))
	for i := range artifacts {
		if names[artifacts[i].Name] {
			return nil, fmt.Errorf("artifact %q is declared twice", artifacts[i].Name)
		}
		names[artifacts[i].Name] = true
	}
	var records []ArtifactRecord
	seen := make(map[string]bool)
	for i := range artifacts {
		expanded, err := expandArtifact(&artifacts[i], platforms)
		if err != nil {
			return nil, fmt.Errorf("artifact %q: %w", artifacts[i].Name, err)
		}
		expandedRecords, err := acquireExpanded(ctx, fetcher, local, store, expanded, seen, progress)
		if err != nil {
			return nil, err
		}
		records = append(records, expandedRecords...)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Platform < records[j].Platform
	})
	return records, nil
}

func acquireExpanded(ctx context.Context, fetcher Fetcher, local Local, store Store, artifacts []Artifact,
	seen map[string]bool, progress func(Acquired, int64),
) ([]ArtifactRecord, error) {
	records := make([]ArtifactRecord, 0, len(artifacts))
	for i := range artifacts {
		artifact := &artifacts[i]
		key := artifact.Platform + "\x00" + artifact.Name
		if seen[key] {
			return nil, fmt.Errorf("artifact %q is resolved twice on %s", artifact.Name, artifact.Platform)
		}
		seen[key] = true
		size, err := acquireArtifact(ctx, fetcher, local, store, artifact)
		if err != nil {
			return nil, fmt.Errorf("artifact %q on %s: %w", artifact.Name, artifact.Platform, err)
		}
		records = append(records, ArtifactRecord{
			Platform: artifact.Platform,
			Name:     artifact.Name,
			URL:      artifact.URL,
			Path:     artifact.Path,
			SHA256:   artifact.SHA256,
			Size:     size,
			Dest:     artifact.Dest,
			Unpack:   artifact.Unpack,
			UID:      artifact.UID,
			GID:      artifact.GID,
			Mode:     artifact.Mode,
			SBOM:     artifact.SBOM,
		})
		// An artifact's size is only known once it was read, so the total advances by
		// what this payload turned out to weigh.
		if progress != nil {
			progress(Acquired{Name: artifact.Name, Version: artifact.SBOM.Version, Size: size}, size)
		}
	}
	return records, nil
}

func expandArtifact(artifact *contents.Artifact, platforms []string) ([]Artifact, error) {
	if artifact.Unpack == nil {
		return nil, errors.New("unpack must be resolved")
	}
	intended := artifact.Platforms
	if len(intended) == 0 {
		intended = platforms
	}
	if err := base.ValidateScope(intended, platforms); err != nil {
		return nil, err
	}
	if err := validateSources(artifact.Sources, intended); err != nil {
		return nil, err
	}
	result := make([]Artifact, 0, len(intended))
	for _, platform := range intended {
		source := artifactSource(artifact, platform)
		result = append(result, Artifact{
			Platform: platform,
			Name:     artifact.Name,
			URL:      source.URL,
			Path:     source.Path,
			SHA256:   source.SHA256,
			Dest:     artifact.Dest,
			Unpack:   *artifact.Unpack,
			UID:      artifact.UID,
			GID:      artifact.GID,
			Mode:     artifact.Mode,
			SBOM:     artifact.SBOM,
		})
	}
	return result, nil
}

func validateSources(sources []contents.ArtifactSource, intended []string) error {
	claimed := make(map[string]bool, len(intended))
	for i := range sources {
		source := &sources[i]
		if err := base.ValidateScope(source.Platforms, intended); err != nil {
			return fmt.Errorf("payload source %d: %w", i, err)
		}
		if err := base.ClaimPlatforms(source.Platforms, intended, claimed); err != nil {
			return fmt.Errorf("payload source %d: %w", i, err)
		}
		if err := validateSourceOrigin(source); err != nil {
			return fmt.Errorf("payload source %d: %w", i, err)
		}
		if err := base.RequirePattern("artifact SHA256", source.SHA256, `^[0-9a-f]{64}$`); err != nil {
			return fmt.Errorf("payload source %d: %w", i, err)
		}
	}
	if len(claimed) != len(intended) {
		return errors.New("payload sources must cover every intended platform")
	}
	return nil
}

// validateSourceOrigin keeps a payload to one origin, so a path never becomes a URL.
func validateSourceOrigin(source *contents.ArtifactSource) error {
	switch {
	case source.URL != "" && source.Path != "":
		return errors.New("artifact source requires either url or path, not both")
	case source.URL != "":
		return base.ValidateInputURL(source.URL, false)
	case source.Path != "":
		return base.ValidateLocalPath(source.Path)
	default:
		return errors.New("artifact source requires a url or a path")
	}
}

func artifactSource(artifact *contents.Artifact, platform string) contents.ArtifactSource {
	for i := range artifact.Sources {
		if contains(artifact.Sources[i].Platforms, platform) {
			return artifact.Sources[i]
		}
	}
	return contents.ArtifactSource{}
}

func acquireArtifact(ctx context.Context, fetcher Fetcher, local Local, store Store, artifact *Artifact) (int64, error) {
	reader, err := artifactPayload(ctx, fetcher, local, artifact)
	if err != nil {
		return 0, err
	}
	file, err := os.CreateTemp("", "vapor-artifact-*")
	if err != nil {
		_ = reader.Close()
		return 0, errors.New("create temporary download file")
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, MaxArtifactSize+1))
	closeErr := reader.Close()
	if copyErr != nil {
		return 0, &fetchError{cause: copyErr}
	}
	if closeErr != nil {
		return 0, &fetchError{cause: closeErr}
	}
	if written > MaxArtifactSize {
		return 0, fmt.Errorf("payload exceeds %d bytes", MaxArtifactSize)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != artifact.SHA256 {
		return 0, fmt.Errorf("payload digest %s does not match declared sha256", actual)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, errors.New("rewind downloaded payload")
	}
	if err := store.Store(file, artifact.SHA256, written); err != nil {
		return 0, storeFailure(err)
	}
	return written, nil
}

// artifactPayload opens the declared origin, so a path never becomes a URL.
func artifactPayload(ctx context.Context, fetcher Fetcher, local Local, artifact *Artifact) (io.ReadCloser, error) {
	if artifact.Path == "" {
		return fetch(ctx, fetcher, artifact.URL)
	}
	if local == nil {
		return nil, errors.New("local artifact requires a specification directory reader")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := local.Open(artifact.Path)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, errors.New("local reader returned no payload")
	}
	return reader, nil
}

func fetch(ctx context.Context, fetcher Fetcher, url string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := fetcher.Fetch(ctx, url)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, &fetchError{cause: err}
	}
	if reader == nil {
		return nil, errors.New("fetcher returned no payload")
	}
	return reader, nil
}

func contains(values []string, want string) bool {
	return slices.Contains(values, want)
}

// storeFailure reports a stalled payload read. The bytes come from the network and
// only pass through the cache writer, so a timeout here is a download that ran out of
// time; naming it a cache failure sends the reader looking in the wrong place.
func storeFailure(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &fetchError{cause: err}
	}
	return err
}

// fetchError keeps the cause out of the message, because a transport error quotes
// the request URL and a URL may carry credentials. The reasons below are composed by
// Vapor itself and name no request, so they are worth printing.
type fetchError struct{ cause error }

func (e *fetchError) Error() string {
	if reason := safeReason(e.cause); reason != "" {
		return "download failed: " + reason
	}
	return "download failed (details redacted)"
}

func (e *fetchError) Unwrap() error { return e.cause }

// safeReason names a failure whose text Vapor wrote, and nothing else.
func safeReason(cause error) string {
	if refusal, ok := errors.AsType[*redirectRefusal](cause); ok {
		return refusal.Error()
	}
	if status, ok := errors.AsType[*statusError](cause); ok {
		return fmt.Sprintf("HTTP %d", status.status)
	}
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, os.ErrDeadlineExceeded) {
		return "timed out"
	}
	return ""
}
