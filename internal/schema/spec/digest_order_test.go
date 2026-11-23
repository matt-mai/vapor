package spec

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type digestListPath struct {
	name    string
	indices []int
}

func digestListPaths(value reflect.Value, prefix []int, name string) []digestListPath {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return digestListPaths(value.Elem(), prefix, name)
	}
	var result []digestListPath
	if value.Kind() == reflect.Slice && value.Len() >= 2 {
		result = append(result, digestListPath{name, slices.Clone(prefix)})
	}
	if value.Kind() == reflect.Struct {
		for i := 0; i < value.NumField(); i++ {
			indices := append(slices.Clone(prefix), i)
			result = append(result, digestListPaths(value.Field(i), indices, name+"."+value.Type().Field(i).Name)...)
		}
	}
	if value.Kind() == reflect.Slice {
		for i := 0; i < value.Len(); i++ {
			indices := append(slices.Clone(prefix), i)
			result = append(result, digestListPaths(value.Index(i), indices, name+"["+strconv.Itoa(i)+"]")...)
		}
	}
	return result
}

func orderingSpec(t *testing.T) *Spec {
	t.Helper()
	spec := digestVectorSpec(t)
	contents := &spec.Contents
	contents.Packages = append(contents.Packages, PackageRequest{Name: "curl"})
	contents.Slices = append(contents.Slices, SliceRequest{Package: "base-files", Slice: "copyright", Catalogue: new("custom")})
	repo := &contents.Repositories[0]
	repo.Endpoints = []Endpoint{
		{Platforms: []string{"linux/arm64"}, URL: "https://example.com/arm64"},
		{Platforms: []string{"linux/amd64"}, URL: "https://example.com/amd64"},
	}
	repo.Trust.Keys[0].Fingerprints = append(repo.Trust.Keys[0].Fingerprints, strings.Repeat("f", 40))
	repo.Trust.Keys = append(repo.Trust.Keys, TrustKey{Path: "keys/extra.asc", Fingerprints: []string{strings.Repeat("a", 40)}})
	otherRepo := *repo
	otherRepo.Name = "other"
	contents.Repositories = append(contents.Repositories, otherRepo)
	artifact := &contents.Artifacts[0]
	artifact.Sources = []ArtifactSource{
		{Platforms: []string{"linux/arm64"}, URL: "https://example.com/arm64", SHA256: strings.Repeat("a", 64)},
		{Platforms: []string{"linux/amd64"}, URL: "https://example.com/amd64", SHA256: strings.Repeat("b", 64)},
	}
	otherArtifact := *artifact
	otherArtifact.Name, otherArtifact.Dest = "other", "/app/other"
	contents.Artifacts = append(contents.Artifacts, otherArtifact)
	spec.Filesystem.Accounts.Users = append(spec.Filesystem.Accounts.Users, UserAccount{Name: "other", UID: new(65533), GID: new(65532)})
	spec.Filesystem.Accounts.Groups = append(spec.Filesystem.Accounts.Groups, GroupAccount{Name: "other", GID: new(65533)})
	return spec
}

func TestSpecDigest_AllListOrdersMatter(t *testing.T) {
	t.Parallel()
	base := orderingSpec(t)
	paths := digestListPaths(reflect.ValueOf(base), nil, "Spec")
	if len(paths) < 30 {
		t.Fatalf("ordering fixture lost list coverage: %d", len(paths))
	}
	want := requireDigest(t, base)
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			spec, err := copySpec(base)
			if err != nil {
				t.Fatal(err)
			}
			value := reflect.ValueOf(spec).Elem()
			for _, index := range path.indices {
				for value.Kind() == reflect.Pointer {
					value = value.Elem()
				}
				if value.Kind() == reflect.Struct {
					value = value.Field(index)
				} else {
					value = value.Index(index)
				}
			}
			reflect.Swapper(value.Interface())(0, 1)
			if requireDigest(t, spec) == want {
				t.Fatal("list reordering did not change digest")
			}
		})
	}
	// The multi-payload fixture uses singleton scopes, so check shared scopes too.
	for _, change := range []func(*Spec){
		func(s *Spec) { slices.Reverse(s.Contents.Repositories[0].Endpoints[0].Platforms) },
		func(s *Spec) { slices.Reverse(s.Contents.Artifacts[0].Sources[0].Platforms) },
	} {
		spec := digestVectorSpec(t)
		before := requireDigest(t, spec)
		change(spec)
		if requireDigest(t, spec) == before {
			t.Fatal("payload scope reordering did not change digest")
		}
	}
}
