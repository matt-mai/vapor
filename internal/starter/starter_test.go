package starter

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{Distro: "ubuntu", Release: "26.04", Name: "ubuntu-minimal", Dir: filepath.Join(t.TempDir(), "nested", "image")}
}

func TestGenerate_ValidSpecAndDeterministicBytes(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ubuntu-minimal", "42", "true"} {
		t.Run(name, func(t *testing.T) {
			var previous []byte
			for range 2 {
				options := testOptions(t)
				options.Name = name
				if err := Generate(options); err != nil {
					t.Fatal(err)
				}
				filename := filepath.Join(options.Dir, "image.yaml")
				spec, loadErr := schemaSpec.LoadSpec(filename)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if spec.Name != name || spec.Image != "ghcr.io/example/"+name || spec.Distro != "ubuntu" || spec.Release != "26.04" || spec.Container.User != "65532:65532" || !slices.Equal(spec.Platforms, []string{"linux/amd64"}) {
					t.Fatalf("incorrect starter: %+v", spec)
				}
				if _, err := spec.SpecDigest(); err != nil {
					t.Fatal(err)
				}
				if len(spec.Contents.Artifacts) != 0 || len(spec.Contents.Packages) != 0 {
					t.Fatal("unexpected extra inputs")
				}
				if !starterInputs(spec) {
					t.Fatalf("unexpected repository or catalogue declarations: %+v", spec.Contents)
				}
				data, err := os.ReadFile(filename)
				if err != nil || previous != nil && !bytes.Equal(previous, data) {
					t.Fatalf("read or determinism failure: %v", err)
				}
				previous = data
				entries, err := os.ReadDir(options.Dir)
				if err != nil || len(entries) != 1 || entries[0].Name() != "image.yaml" {
					t.Fatalf("unexpected output entries/temporary leak: %v, %v", entries, err)
				}
				info, err := os.Stat(filename)
				if err != nil || info.Mode().Perm()&0o077 != 0 {
					t.Fatalf("output must not grant group/other access: %v", err)
				}
			}
		})
	}
}

// starterInputs reports whether the generated spec declares exactly the public
// Ubuntu archive bound to the only catalogue, and nothing from a subscription
// archive. A starter image must lock without further editing, so it needs the
// binding that the real catalogue's unbound Pro archives would otherwise demand.
func starterInputs(spec *schemaSpec.Spec) bool {
	repositories := spec.Contents.Repositories
	if len(repositories) != 1 {
		return false
	}
	repository := repositories[0]
	if repository.Name != "ubuntu" || !slices.Equal(repository.Suites,
		[]string{"resolute", "resolute-security", "resolute-updates"}) {
		return false
	}
	if len(repository.Endpoints) != 1 ||
		repository.Endpoints[0].URL != "https://archive.ubuntu.com/ubuntu" {
		return false
	}
	catalogues := spec.Contents.Catalogues
	if len(catalogues) != 1 || len(catalogues[0].Archives) != 1 || catalogues[0].Archives["ubuntu"] != "ubuntu" {
		return false
	}
	for _, name := range spec.Contents.Catalogues[0].Archives {
		if strings.Contains(name, "esm") {
			return false
		}
	}
	return true
}

// A Debian starter names packages only: the reviewed archives are the provider's
// own, so the image locks without restating endpoints, keys or a catalogue.
func TestGenerate_DebianTemplate(t *testing.T) {
	t.Parallel()
	options := testOptions(t)
	options.Distro, options.Release, options.Name = "debian", "trixie", "debian-demo"
	if err := Generate(options); err != nil {
		t.Fatal(err)
	}
	spec, err := schemaSpec.LoadSpec(filepath.Join(options.Dir, "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Distro != "debian" || spec.Release != "trixie" {
		t.Fatalf("starter distro/release = %s/%s", spec.Distro, spec.Release)
	}
	if len(spec.Contents.Repositories) != 0 || len(spec.Contents.Catalogues) != 0 || len(spec.Contents.Slices) != 0 {
		t.Fatalf("a Debian starter must not declare repositories, catalogues or slices: %+v", spec.Contents)
	}
	names := make([]string, 0, len(spec.Contents.Packages))
	for _, pkg := range spec.Contents.Packages {
		names = append(names, pkg.Name)
	}
	if !slices.Equal(names, []string{"base-files", "ca-certificates"}) {
		t.Fatalf("starter packages are %v", names)
	}
}

func TestGenerate_CodenameRelease(t *testing.T) {
	t.Parallel()
	options := testOptions(t)
	options.Release = "resolute"
	if err := Generate(options); err != nil {
		t.Fatal(err)
	}
	spec, err := schemaSpec.LoadSpec(filepath.Join(options.Dir, "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Release != "26.04" {
		t.Fatalf("starter release = %q, want the canonical 26.04", spec.Release)
	}
}

func TestGenerate_ValidationBeforeIO(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*Options){
		"distro":            func(o *Options) { o.Distro = "alpine" },
		"release":           func(o *Options) { o.Release = "99.99" },
		"unknown codename":  func(o *Options) { o.Release = "ferocious" },
		"empty name":        func(o *Options) { o.Name = "" },
		"traversal name":    func(o *Options) { o.Name = "../outside" },
		"absolute name":     func(o *Options) { o.Name = "/outside" },
		"YAML injection":    func(o *Options) { o.Name = "app\nimage: bad" },
		"image component":   func(o *Options) { o.Name = "a..b" },
		"empty directory":   func(o *Options) { o.Dir = "" },
		"control directory": func(o *Options) { o.Dir += "\x1b[31m" },
	} {
		t.Run(name, func(t *testing.T) {
			options := testOptions(t)
			original := options.Dir
			change(&options)
			if err := Generate(options); err == nil {
				t.Fatal("invalid options accepted")
			}
			if _, err := os.Stat(filepath.Dir(original)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("validation touched output parents: %v", err)
			}
		})
	}
}

func TestGenerate_ConcurrentNoOverwrite(t *testing.T) {
	t.Parallel()
	options := testOptions(t)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Go(func() { results <- Generate(options) })
	}
	group.Wait()
	close(results)
	var successes, exists int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, fs.ErrExist):
			exists++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || exists != 1 {
		t.Fatalf("successes=%d, exists=%d", successes, exists)
	}
	if _, err := schemaSpec.LoadSpec(filepath.Join(options.Dir, "image.yaml")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(options.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file leak: %v, %v", entries, err)
	}
}

func TestGenerate_OutputParentIsFile(t *testing.T) {
	t.Parallel()
	options := testOptions(t)
	parent := filepath.Dir(options.Dir)
	if err := os.WriteFile(parent, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Generate(options); err == nil || !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("want contextual filesystem failure: %v", err)
	}
	data, err := os.ReadFile(parent)
	if err != nil || string(data) != "keep" {
		t.Fatalf("parent file changed: %v", err)
	}
}
