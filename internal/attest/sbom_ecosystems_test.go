package attest_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// The detector table reads six manifest shapes. Each is a different file format stating
// the same two facts, so each is pinned with the manifest a real image would hold.

// ecosystemFixture builds a tree holding one manifest at the path its ecosystem uses and
// returns the document that describes it.
func ecosystemFixture(t *testing.T, manifestPath string, manifest []byte,
	payloadPath string, payload []byte,
) map[string]any {
	t.Helper()
	tree := vfs.New()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tree.File(manifestPath, manifest, vfs.Attrs{Mode: 0o644,
		Origin: vfs.Origin{Path: "filesystem.paths"}}))
	if payloadPath != "" {
		must(tree.File(payloadPath, payload, vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Path: "filesystem.paths"}}))
	}
	return documents(t, &attest.SBOMInput{
		Name: "ecosystem-image", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ef", 32),
		Packages: []lock.Package{{Platform: "linux/amd64", Name: "base-files",
			Version: "1", Architecture: "amd64",
			Content: lock.Content{Path: "pool/base-files.deb",
				SHA256: strings.Repeat("cd", 32), Size: 1}}},
		Tree: tree,
	})
}

// TestSBOMReadsEveryEcosystemManifest pins the six manifest shapes Vapor reads.
func TestSBOMReadsEveryEcosystemManifest(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		content  string
		payload  string
		want     string
	}{
		{
			name:     "glob",
			manifest: "/usr/lib/node_modules/glob/package.json",
			content:  `{"name":"glob","version":"10.5.0"}`,
			payload:  "/usr/lib/node_modules/glob/index.js",
			want:     "pkg:npm/glob@10.5.0",
		},
		{
			name:     "@sigstore/core",
			manifest: "/usr/lib/node_modules/@sigstore/core/package.json",
			content:  `{"name":"@sigstore/core","version":"2.0.0"}`,
			payload:  "/usr/lib/node_modules/@sigstore/core/index.js",
			want:     "pkg:npm/%40sigstore/core@2.0.0",
		},
		{
			name:     "pip",
			manifest: "/usr/local/python/lib/python3.15/site-packages/pip-26.3.dist-info/METADATA",
			content:  "Metadata-Version: 2.1\nName: pip\nVersion: 26.3\n",
			payload:  "/usr/local/python/lib/python3.15/site-packages/pip/__init__.py",
			want:     "pkg:pypi/pip@26.3",
		},
		{
			name:     "Newtonsoft.Json",
			manifest: "/app/lib/Newtonsoft.Json.nuspec",
			content:  `<?xml version="1.0"?><package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>`,
			payload:  "/app/lib/Newtonsoft.Json.dll",
			want:     "pkg:nuget/Newtonsoft.Json@13.0.3",
		},
		{
			name:     "errors",
			manifest: "/app/vendor/modules.txt",
			content:  "# github.com/pkg/errors v0.9.1\n## explicit\ngithub.com/pkg/errors\n",
			payload:  "/app/vendor/github.com/pkg/errors/errors.go",
			want:     "pkg:golang/github.com/pkg/errors@0.9.1",
		},
		{
			name:     "slf4j-api",
			manifest: "/app/lib/META-INF/maven/org.slf4j/slf4j-api/pom.properties",
			content:  "groupId=org.slf4j\nartifactId=slf4j-api\nversion=2.0.9\n",
			payload:  "/app/lib/slf4j-api-2.0.9.jar",
			want:     "pkg:maven/org.slf4j/slf4j-api@2.0.9",
		},
		{
			name:     "rake",
			manifest: "/app/gems/rake-13.1.0/rake.gemspec",
			content:  "Gem::Specification.new do |s|\n  s.name = \"rake\"\n  s.version = \"13.1.0\"\nend\n",
			payload:  "/app/gems/rake-13.1.0/lib/rake.rb",
			want:     "pkg:gem/rake@13.1.0",
		},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			document := ecosystemFixture(t, current.manifest, []byte(current.content),
				current.payload, []byte("payload"))
			stated := packagesNamed(t, document, current.name)
			if len(stated) != 1 {
				t.Fatalf("document states %d packages, want 1", len(stated))
			}
			if got := locatorOf(t, stated[0]); got != current.want {
				t.Errorf("purl = %q, want %q", got, current.want)
			}
		})
	}
}

// TestSBOMIgnoresAGoMainModule refuses a go.mod that names a main module. It states no
// version, so it is the application itself rather than a dependency a scanner could match.
func TestSBOMIgnoresAGoMainModule(t *testing.T) {
	document := ecosystemFixture(t, "/app/go.mod", []byte("module example.com/app\n\ngo 1.22\n"),
		"", nil)
	for _, entry := range document["packages"].([]any) {
		if name := entry.(map[string]any)["name"]; name == "app" || name == "example.com/app" {
			t.Errorf("document claims the main module as a package: %v", name)
		}
	}
}

// TestSBOMIgnoresAManifestThatIsTooLarge refuses to read an oversized file as metadata.
func TestSBOMIgnoresAManifestThatIsTooLarge(t *testing.T) {
	tree := vfs.New()
	huge := append([]byte(`{"name":"glob","version":"1"}`), make([]byte, 2<<20)...)
	if err := tree.File("/app/package.json", huge, vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_, err := attest.SPDX(&attest.SBOMInput{
		Name: "large-image", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ac", 32), Tree: tree,
	})
	if err == nil {
		t.Fatal("a two megabyte manifest was read as metadata")
	}
	if !strings.Contains(err.Error(), "larger than a manifest") {
		t.Errorf("error = %v, want one naming the size limit", err)
	}
}
