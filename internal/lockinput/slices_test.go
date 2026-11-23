package lockinput

import (
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func TestSelectSlicedPackagesUsesNativeArchitecture(t *testing.T) {
	t.Parallel()
	aa := &slicespkg.Package{
		RealName: "aa", Name: "aa", Archive: "ubuntu", Path: "slices/aa.yaml",
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 1,
		Slices: map[string]slicespkg.Slice{
			"base": {
				Package: "aa", Name: "base",
				Essential: map[slicespkg.SliceKey]slicespkg.EssentialInfo{
					{Package: "bb", Slice: "base"}: {Arch: []string{"amd64"}},
				},
			},
		},
	}
	bb := &slicespkg.Package{
		RealName: "bb", Name: "bb", Archive: "ubuntu", Path: "slices/bb.yaml",
		SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Size: 1,
		Slices: map[string]slicespkg.Slice{"base": {Package: "bb", Name: "base"}},
	}
	input := &catalogueInput{
		name: "cat",
		catalogue: &slicespkg.Catalogue{Archives: map[string]slicespkg.Archive{
			"ubuntu": {Name: "ubuntu", Version: "26.04", Suites: []string{"test"}, Components: []string{"main"}, Priority: 10},
		}},
		packages: map[string]*slicespkg.Package{"aa": aa, "bb": bb},
	}
	archives := map[string]*archiveSet{archiveKey("cat", "ubuntu", deb.PlatformAMD64): {
		platform: deb.PlatformAMD64,
		archive:  slicespkg.Archive{Name: "ubuntu", Priority: 10},
		binding:  slicespkg.Binding{URL: "https://example.invalid/ubuntu"},
		repos: []*repository{{
			record: lock.Repository{ID: "repo", Suite: "test"},
			packages: []deb.Package{
				{Name: "aa", Version: "1", Architecture: "amd64", Filename: "aa.deb", Origin: deb.PackageOrigin{Suite: "test", Component: "main"}},
				{Name: "bb", Version: "1", Architecture: "amd64", Filename: "bb.deb", Origin: deb.PackageOrigin{Suite: "test", Component: "main"}},
			},
		}},
	}}
	request := &Request{
		Spec: &spec.Spec{
			Platforms: []string{deb.PlatformAMD64},
			Contents:  contents.Contents{Slices: []contents.SliceRequest{{Package: "aa", Slice: "base"}}},
		},
		Provider: ubuntu.New("26.04"),
	}
	byPackage := map[string][]contents.SliceRequest{"aa": request.Spec.Contents.Slices}
	selected, err := selectSlicedPackages(request, input, deb.PlatformAMD64, byPackage, archives)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 {
		t.Fatalf("amd64 essential was filtered out: %#v", selected)
	}
	found := false
	for i := range selected {
		if selected[i].selection.Package == "bb" {
			found = true
		}
	}
	if !found {
		t.Fatalf("amd64 essential was filtered out: %#v", selected)
	}
}

func TestSliceRequestsPartitionByCatalogue(t *testing.T) {
	t.Parallel()
	a, b := "a", "b"
	request := &Request{Spec: &spec.Spec{Contents: contents.Contents{Slices: []contents.SliceRequest{
		{Package: "aa", Slice: "base", Catalogue: &a},
		{Package: "aa", Slice: "extra", Catalogue: &b},
	}}}}
	onlyA := sliceRequestsByPackage(request.Spec, "a")
	if len(onlyA["aa"]) != 1 || onlyA["aa"][0].Slice != "base" {
		t.Fatalf("catalogue a requests = %#v", onlyA)
	}
	onlyB := sliceRequestsByPackage(request.Spec, "b")
	if len(onlyB["aa"]) != 1 || onlyB["aa"][0].Slice != "extra" {
		t.Fatalf("catalogue b requests = %#v", onlyB)
	}
	if len(sliceRequestsByPackage(request.Spec, "missing")) != 0 {
		t.Fatal("unknown catalogue received requests")
	}
}

// A slice closure can reach a name the specification never listed, so the archive
// scope has to filter origins, not only whole-package candidates.
func TestSliceVersionsRespectRepositoryScope(t *testing.T) {
	t.Parallel()
	input := &catalogueInput{
		name: "cat",
		catalogue: &slicespkg.Catalogue{Archives: map[string]slicespkg.Archive{
			"ubuntu": {Name: "ubuntu", Priority: 10},
		}},
		packages: map[string]*slicespkg.Package{},
	}
	archives := map[string]*archiveSet{archiveKey("cat", "ubuntu", deb.PlatformAMD64): {
		platform: deb.PlatformAMD64,
		archive:  slicespkg.Archive{Name: "ubuntu", Priority: 10},
		repos: []*repository{{
			record: lock.Repository{ID: "vendor"},
			scope:  []string{"aa"},
			packages: []deb.Package{
				{Name: "aa", Version: "1", Origin: deb.PackageOrigin{Suite: "test", Component: "main"}},
				{Name: "bb", Version: "1", Origin: deb.PackageOrigin{Suite: "test", Component: "main"}},
			},
		}},
	}}
	versions := sliceVersions(input, deb.PlatformAMD64, archives)
	if len(versions["aa"]) != 1 {
		t.Fatalf("scoped name was filtered out: %#v", versions)
	}
	if len(versions["bb"]) != 0 {
		t.Fatalf("out-of-scope name was offered as an origin: %#v", versions["bb"])
	}
}
