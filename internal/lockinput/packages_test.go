package lockinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

func TestSolveWholePlatformIncludesTransitiveDependencies(t *testing.T) {
	t.Parallel()
	set := &archiveSet{
		platform: deb.PlatformAMD64,
		archive:  slicespkg.Archive{Name: "ubuntu", Priority: 10},
		repos: []*repository{{
			record: lock.Repository{ID: "repository", Architecture: "amd64"},
			packages: []deb.Package{
				{Name: "aa", Version: "1", Architecture: "amd64", Origin: deb.PackageOrigin{Suite: "test", Component: "main"}, Filename: "aa.deb", Relations: deb.Relations{Depends: []string{"bb"}}},
				{Name: "bb", Version: "1", Architecture: "amd64", Origin: deb.PackageOrigin{Suite: "test", Component: "main"}, Filename: "bb.deb"},
			},
		}},
	}
	selected, err := solveWholePlatform(deb.PlatformAMD64, []string{"aa"}, nil, map[string]*archiveSet{"u": set})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Name != "aa" || selected[1].Name != "bb" {
		t.Fatalf("selected = %#v", selected)
	}
	if _, err := solveWholePlatform(deb.PlatformARM64, []string{"aa"}, nil, map[string]*archiveSet{"u": set}); err == nil {
		t.Fatal("missing platform accepted")
	}
}

func TestAcquireWholePackagesPublishesPayload(t *testing.T) {
	t.Parallel()
	data := []byte("whole package payload")
	sum := sha256.Sum256(data)
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	archives := map[string]*archiveSet{"u": {
		platform: deb.PlatformAMD64,
		binding:  slicespkg.Binding{URL: "https://example.invalid/ubuntu"},
		repos:    []*repository{{record: lock.Repository{ID: "repository"}}},
	}}
	packages := []lock.Package{{
		Platform: "linux/amd64", Name: "aa", Version: "1", Architecture: "amd64", Repository: "repository",
		Content: lock.Content{Path: "pool/aa.deb", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))},
	}}
	restricted := false
	request := &Request{
		Cache: store, Artifacts: staticFetcher(data),
		Repository: func(_ string, pro bool) (Fetcher, error) {
			restricted = pro
			return staticFetcher(data), nil
		},
	}
	if acquireErr := acquireWholePackages(t.Context(), request, packages, archives); acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if restricted {
		t.Fatal("public package used the restricted fetcher")
	}
	reader, err := store.Open(hex.EncodeToString(sum[:]), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("cached payload = %q, %v", got, err)
	}
	if err := acquireWholePackages(t.Context(), request, []lock.Package{{
		Platform: "linux/amd64", Name: "bb", Repository: "missing",
	}}, archives); err == nil {
		t.Fatal("missing repository binding accepted")
	}
	archives["u"].binding.Archive.Pro = "esm-apps"
	if acquireErr := acquireWholePackages(t.Context(), request, packages, archives); acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if !restricted {
		t.Fatal("Pro package used the public fetcher")
	}
}

type staticFetcher []byte

func (f staticFetcher) Fetch(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f)), nil
}

// A negative priority keeps an archive out of the default candidate set: it may
// serve a slice pinned to it, but it must not supply whole packages.
func TestSolveWholePlatformIgnoresNegativePriorityArchives(t *testing.T) {
	t.Parallel()
	// The vendor archive offers the same package at a higher version, so it wins
	// whenever it is in the candidate set.
	origin := deb.PackageOrigin{Suite: "test", Component: "main"}
	pinned := &archiveSet{
		platform: deb.PlatformAMD64,
		archive:  slicespkg.Archive{Name: "vendor", Priority: -10},
		repos: []*repository{{
			record: lock.Repository{ID: "vendor-repository", Architecture: "amd64"},
			packages: []deb.Package{{Name: "aa", Version: "9", Architecture: "amd64",
				Origin: origin, Filename: "vendor-aa.deb"}},
		}},
	}
	stable := &archiveSet{
		platform: deb.PlatformAMD64,
		archive:  slicespkg.Archive{Name: "stable", Priority: 0},
		repos: []*repository{{
			record: lock.Repository{ID: "stable-repository", Architecture: "amd64"},
			packages: []deb.Package{{Name: "aa", Version: "1", Architecture: "amd64",
				Origin: origin, Filename: "stable-aa.deb"}},
		}},
	}
	selected, err := solveWholePlatform(deb.PlatformAMD64, []string{"aa"}, nil,
		map[string]*archiveSet{"vendor": pinned, "stable": stable})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Version != "1" {
		t.Fatalf("selected = %#v, want the stable version", selected)
	}
}
