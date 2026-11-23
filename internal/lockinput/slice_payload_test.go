package lockinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func TestSelectedProSliceUsesAuthenticatedFetcher(t *testing.T) {
	t.Parallel()
	data := []byte("pro package payload")
	sum := sha256.Sum256(data)
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	archives := map[string]*archiveSet{archiveKey("catalogue", "esm-apps", deb.PlatformAMD64): {
		platform: deb.PlatformAMD64,
		archive:  slicespkg.Archive{Name: "esm-apps", Priority: 10, Pro: "esm-apps"},
		binding: slicespkg.Binding{
			URL: "https://esm.invalid/apps/ubuntu", Platform: deb.PlatformAMD64,
			Archive: slicespkg.Archive{Name: "esm-apps", Priority: 10, Pro: "esm-apps"},
		},
		repos: []*repository{{
			record: lock.Repository{ID: "repository", Suite: "resolute-apps-security"},
			packages: []deb.Package{{
				Name: "base-files", Version: "26.04", Architecture: "amd64", Filename: "pool/base-files.deb",
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
				Origin: deb.PackageOrigin{Suite: "resolute-apps-security", Component: "main"},
			}},
		}},
	}}
	selections := []sliceSelection{{
		platform: deb.PlatformAMD64, catalogue: "catalogue",
		selection: slicespkg.PackageSelection{
			RealName: "base-files", Version: "26.04", Archive: "esm-apps", Suite: "resolute-apps-security", Component: "main",
		},
	}}
	payloads, err := slicePayloads(selections, archives)
	if err != nil {
		t.Fatal(err)
	}
	restricted := false
	request := &Request{Cache: store, Artifacts: staticFetcher(data), Repository: func(_ string, pro bool) (Fetcher, error) {
		restricted = pro
		return staticFetcher(data), nil
	}}
	if acquireErr := acquireGroups(t.Context(), request, payloads); acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if !restricted {
		t.Fatal("Pro slice payload used the public fetcher")
	}
	reader, err := store.Open(hex.EncodeToString(sum[:]), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
}

func TestResolveSlicedPackagesFetchesWinningComponent(t *testing.T) {
	t.Parallel()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input, archives, winner := competingSliceComponents()
	request := &Request{
		Cache: store, Provider: ubuntu.New("26.04"),
		Spec: &spec.Spec{
			Platforms: []string{deb.PlatformAMD64},
			Contents: contents.Contents{Slices: []contents.SliceRequest{
				{Catalogue: &input.name, Package: "base-files", Slice: "data"},
			}},
		},
		Repository: func(string, bool) (Fetcher, error) { return componentPayloadFetcher(winner.Filename), nil },
	}
	records, err := resolveSlicedPackages(t.Context(), request, []*catalogueInput{input}, archives)
	if err != nil {
		t.Fatal(err)
	}
	want := lock.Content{Path: winner.Filename, SHA256: winner.SHA256, Size: winner.Size}
	if len(records) != 1 || records[0].Content != want {
		t.Fatalf("slice records = %+v, want content %+v", records, want)
	}
	reader, err := store.Open(winner.SHA256, winner.Size)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
}

func competingSliceComponents() (*catalogueInput, map[string]*archiveSet, deb.Package) {
	archive := slicespkg.Archive{Name: "ubuntu", Priority: 10, Suites: []string{"test"}, Components: []string{"main", "universe"}}
	input := &catalogueInput{
		name:      "local",
		catalogue: &slicespkg.Catalogue{Archives: map[string]slicespkg.Archive{"ubuntu": archive}},
		packages: map[string]*slicespkg.Package{"base-files": {
			Name: "base-files", RealName: "base-files", Archive: "ubuntu", Path: "slices/base-files.yaml",
			SHA256: strings.Repeat("a", 64), Size: 1,
			Slices: map[string]slicespkg.Slice{"data": {Package: "base-files", Name: "data"}},
		}},
	}
	winner := sliceComponentPackage("main")
	archives := map[string]*archiveSet{archiveKey(input.name, archive.Name, deb.PlatformAMD64): {
		platform: deb.PlatformAMD64, archive: archive,
		binding: slicespkg.Binding{URL: "https://example.invalid/ubuntu"},
		repos: []*repository{{
			record:   lock.Repository{ID: "repository", Suite: "test"},
			packages: []deb.Package{sliceComponentPackage("universe"), winner},
		}},
	}}
	return input, archives, winner
}

func sliceComponentPackage(component string) deb.Package {
	return deb.Package{
		Name: "base-files", Version: "26.04", Architecture: "amd64",
		Origin:   deb.PackageOrigin{Suite: "test", Component: component},
		Filename: "pool/" + component + "/base-files.deb",
		SHA256:   fmt.Sprintf("%x", sha256.Sum256([]byte(component))), Size: int64(len(component)),
	}
}

type componentPayloadFetcher string

func (f componentPayloadFetcher) Fetch(_ context.Context, path string) (io.ReadCloser, error) {
	if path != string(f) {
		return nil, fmt.Errorf("unexpected payload path %q, want %q", path, f)
	}
	return io.NopCloser(strings.NewReader("main")), nil
}
