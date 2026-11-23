package lockinput

import (
	"errors"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func TestSkipArchiveDefersUnselectedRestrictedSources(t *testing.T) {
	t.Parallel()
	negative := slicespkg.Binding{Archive: slicespkg.Archive{Name: "esm", Pro: "esm-apps", Priority: -1}}
	if !skipArchive(&Request{Spec: &spec.Spec{}}, &negative, "unused", nil) {
		t.Fatal("unselected negative Pro archive would be acquired")
	}
	if skipArchive(&Request{Spec: &spec.Spec{}}, &negative, "used", map[string]bool{"used": true}) {
		t.Fatal("selected negative Pro archive was skipped")
	}
	withoutPackages := &spec.Spec{Contents: contents.Contents{Slices: []contents.SliceRequest{{Package: "aa", Slice: "data"}}}}
	positive := slicespkg.Binding{Archive: slicespkg.Archive{Name: "esm", Pro: "esm-apps", Priority: 10}}
	if !skipArchive(&Request{Spec: withoutPackages}, &positive, "unused", nil) {
		t.Fatal("unselected positive Pro archive would be acquired for a slice-only spec")
	}
	withPackages := &spec.Spec{Contents: contents.Contents{Packages: []contents.PackageRequest{{Name: "aa"}}}}
	if skipArchive(&Request{Spec: withPackages}, &positive, "unused", nil) {
		t.Fatal("Pro archive was skipped while resolving whole packages")
	}
	public := slicespkg.Binding{Archive: slicespkg.Archive{Name: "ubuntu", Priority: -1}}
	if skipArchive(&Request{Spec: &spec.Spec{}}, &public, "unused", nil) {
		t.Fatal("public archive was skipped")
	}
}

func TestSpecRepositoriesWorkWithoutCatalogue(t *testing.T) {
	t.Parallel()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{
		Spec: &spec.Spec{
			Platforms: []string{"linux/amd64"},
			Contents: contents.Contents{Packages: []contents.PackageRequest{{Name: "aa"}},
				Repositories: []contents.Repository{{
					Name: "ubuntu", Platforms: []string{"linux/amd64"}, Suites: []string{"resolute"},
					Components: []string{"main"},
					Endpoints: []contents.Endpoint{{
						Platforms: []string{"linux/amd64"}, URL: "https://archive.ubuntu.com/ubuntu",
					}},
				}}},
		},
		Provider: ubuntu.New("26.04"),
		Cache:    store,
	}
	states := make(map[string]*repository)
	archives := make(map[string]*archiveSet)
	if err := addSpecRepositories(request, states, archives); err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || len(archives) != 1 {
		t.Fatalf("states=%d archives=%d", len(states), len(archives))
	}
	for _, set := range archives {
		if len(set.repos) != 1 || set.repos[0].record.URL != "https://archive.ubuntu.com/ubuntu" {
			t.Fatalf("archive set = %#v", set)
		}
	}
}

func TestReferencedRepositoriesKeepsOnlyUsedSuites(t *testing.T) {
	t.Parallel()
	repositories := []lock.Repository{
		{ID: "sha256:aaa", Suite: "resolute"},
		{ID: "sha256:bbb", Suite: "resolute-security"},
		{ID: "sha256:ccc", Suite: "resolute-updates"},
	}
	evidence := &locking.Evidence{
		Packages: []lock.Package{{Repository: "sha256:aaa"}},
		Slices:   []lock.Slice{{Repository: "sha256:ccc"}},
	}
	kept := referencedRepositories(repositories, evidence)
	if len(kept) != 2 || kept[0].ID != "sha256:aaa" || kept[1].ID != "sha256:ccc" {
		t.Fatalf("kept = %#v, want only the referenced suites in order", kept)
	}
	if kept := referencedRepositories(repositories, &locking.Evidence{}); len(kept) != 0 {
		t.Fatalf("kept = %#v, want nothing when no package or slice came from them", kept)
	}
}

func TestAcquireRepositoriesRejectsConflictingCatalogueComponents(t *testing.T) {
	t.Parallel()
	request, catalogues := implicitCatalogueBindings(t)
	for _, reversed := range []bool{false, true} {
		if reversed {
			catalogues[0], catalogues[1] = catalogues[1], catalogues[0]
		}
		_, _, err := acquireRepositories(t.Context(), request, catalogues)
		if err == nil || !strings.Contains(err.Error(), `disagree on components`) ||
			!strings.Contains(err.Error(), `"first"`) || !strings.Contains(err.Error(), `"second"`) {
			t.Fatalf("reversed=%t: got %v, want a conflict naming both catalogues", reversed, err)
		}
	}
}

func implicitCatalogueBindings(t *testing.T) (*Request, []*catalogueInput) {
	t.Helper()
	const platform = "linux/amd64"
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{
		Spec: &spec.Spec{Platforms: []string{platform}}, Provider: ubuntu.New("26.04"), Cache: store,
		Repository: func(string, bool) (Fetcher, error) {
			unexpectedErr := errors.New("a conflicting binding reached repository acquisition")
			t.Error(unexpectedErr)
			return nil, unexpectedErr
		},
	}
	inputs := make([]*catalogueInput, 0, 2)
	for _, name := range []string{"first", "second"} {
		archive := slicespkg.Archive{
			Name: "ubuntu", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"},
		}
		if name == "second" {
			archive.Components = append(archive.Components, "universe")
		}
		catalogue := &slicespkg.Catalogue{Archives: map[string]slicespkg.Archive{"ubuntu": archive}}
		bindings, err := slicespkg.BindArchives(catalogue, &contents.CatalogueSource{Name: name}, nil, request.Provider, platform)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, &catalogueInput{
			name: name, catalogue: catalogue, bindings: map[string]slicespkg.Binding{platform + "\x00ubuntu": bindings[0]},
		})
	}
	return request, inputs
}

func TestBuildCatalogueStatesSkipsUnboundArchives(t *testing.T) {
	t.Parallel()
	request := &Request{Spec: &spec.Spec{Platforms: []string{"linux/amd64"}}, Provider: ubuntu.New("26.04")}
	input := &catalogueInput{
		name: "custom",
		catalogue: &slicespkg.Catalogue{Archives: map[string]slicespkg.Archive{
			"main": {Name: "main", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}},
			"esm":  {Name: "esm", Version: "26.04", Suites: []string{"resolute"}, Components: []string{"main"}, Pro: "esm-apps"},
		}},
		bindings: map[string]slicespkg.Binding{},
	}
	states := make(map[string]*repository)
	archives := make(map[string]*archiveSet)
	key := archiveKey("custom", "main", "linux/amd64")
	err := buildCatalogueStates(request, input, "linux/amd64", map[string]bool{key: true}, states, archives)
	if err == nil || !strings.Contains(err.Error(), `archive "main" is not bound`) {
		t.Fatalf("error = %v, want an explicit binding request for the used archive", err)
	}
	if err := buildCatalogueStates(request, input, "linux/amd64", map[string]bool{}, states, archives); err != nil {
		t.Fatal(err)
	}
	if len(archives) != 2 || len(states) != 0 {
		t.Fatalf("archives = %#v, states = %#v; an unbound archive must add nothing to acquire", archives, states)
	}
}
