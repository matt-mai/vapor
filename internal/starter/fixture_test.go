package starter

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func TestStarter_PinnedSyntheticSelection(t *testing.T) {
	t.Parallel()
	options := testOptions(t)
	if err := Generate(options); err != nil {
		t.Fatal(err)
	}
	spec, loadErr := schemaSpec.LoadSpec(filepath.Join(options.Dir, "image.yaml"))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(spec.Contents.Catalogues) != 1 || len(spec.Contents.Slices) != 1 {
		t.Fatal("starter must select one catalogue and one slice")
	}
	catalogue := spec.Contents.Catalogues[0]
	if catalogue.Name != "ubuntu" || catalogue.URL == nil || *catalogue.URL != "https://github.com/canonical/chisel-releases" || catalogue.Branch == nil || *catalogue.Branch != "ubuntu-26.04" {
		t.Fatal("starter source differs from qualified baseline")
	}
	selection := spec.Contents.Slices[0]
	fixtureDir := filepath.Join("..", "distro", "slices", "testdata", "chisel-v3")
	data, readErr := os.ReadFile(filepath.Join(fixtureDir, "expectations.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var expected struct {
		Selection string              `json:"starterSelection"`
		Closures  map[string][]string `json:"starterClosureByArch"`
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if selection.Package+"_"+selection.Slice != expected.Selection || selection.Catalogue == nil || *selection.Catalogue != catalogue.Name {
		t.Fatal("starter selection differs from fixture")
	}
	data, readErr = os.ReadFile(filepath.Join(fixtureDir, "catalogue", "slices", "base-files.yaml"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var definition struct {
		Package   string               `yaml:"package"`
		Essential map[string]yaml.Node `yaml:"essential"`
		Slices    map[string]struct {
			Essential map[string]yaml.Node `yaml:"essential"`
		} `yaml:"slices"`
	}
	if err := yaml.Unmarshal(data, &definition); err != nil {
		t.Fatal(err)
	}
	if definition.Package != selection.Package || !slices.Equal(slices.Sorted(maps.Keys(definition.Essential)), []string{"base-files_copyright"}) {
		t.Fatal("fixture package/copyright essentials changed; requalify starter")
	}
	release, ok := definition.Slices[selection.Slice]
	if !ok || !slices.Equal(slices.Sorted(maps.Keys(release.Essential)), []string{"base-files_etc", "base-files_lib"}) {
		t.Fatal("fixture release-info essentials changed; requalify starter")
	}
	closure := []string{"base-files_copyright", "base-files_etc", "base-files_lib", "base-files_release-info"}
	for _, suffix := range []string{"copyright", "etc", "lib"} {
		entry, ok := definition.Slices[suffix]
		if !ok || len(entry.Essential) != 0 {
			t.Fatal("fixture dependency changed; requalify starter")
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if !slices.Equal(expected.Closures[arch], closure) {
			t.Fatalf("fixture closure changed for %s", arch)
		}
	}
}
