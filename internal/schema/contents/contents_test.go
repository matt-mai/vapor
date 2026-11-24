package contents_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

const contentsFixture = minimalSpec + `platforms: [linux/amd64, linux/arm64]
contents:
  packages:
    - name: openssl
      version: "= 3.0-1"
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
      archives: {ubuntu: main}
  slices:
    - package: base-files
      slice: release-info
  repositories:
    - name: main
      suites: [resolute, resolute-updates]
      components: [main, universe]
      endpoints:
        - platforms: [linux/amd64]
          url: https://example.com/ubuntu
        - platforms: [linux/arm64]
          url: http://ports.example.com/ubuntu-ports
      trust:
        keys:
          - path: keys/repo.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
  artifacts:
    - name: server
      dest: /usr/bin/server
      unpack: false
      sources:
        - platforms: [linux/amd64]
          url: https://example.com/server-amd64
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        - platforms: [linux/arm64]
          url: https://example.com/server-arm64
          sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      sbom: {name: server, version: "1.0"}
`

func TestLoadSpec_PackageShorthand(t *testing.T) {
	t.Parallel()
	loaded, err := loadText(t, strings.Replace(contentsFixture, `    - name: openssl
      version: "= 3.0-1"`, `    - openssl
    - name: curl
      version: "= 8.5.0-2"`, 1))
	if err != nil {
		t.Fatal(err)
	}
	packages := loaded.Contents.Packages
	if len(packages) != 2 || packages[0].Name != "openssl" || packages[0].Version != nil {
		t.Fatalf("bare package = %#v, want the name and no pin", packages[0])
	}
	if packages[1].Name != "curl" || packages[1].Version == nil || *packages[1].Version != "= 8.5.0-2" {
		t.Fatalf("mapping package = %#v, want the name and the pin", packages[1])
	}
}

func TestLoadSpec_PackageShorthandStaysStrict(t *testing.T) {
	t.Parallel()
	const entry = `    - name: openssl
      version: "= 3.0-1"`
	tests := []struct{ replacement, message string }{
		{"    - 42", "expected a string"},
		{"    - name: openssl\n      future: 1", `unknown field "future"`},
		{"    - [openssl]", "expected a mapping"},
		{"    - null", "expected a string"},
		{"    - \"\"", "package name has invalid syntax"},
	}
	for _, tt := range tests {
		loaded, err := loadText(t, strings.Replace(contentsFixture, entry, tt.replacement, 1))
		if err == nil || loaded != nil || !strings.Contains(err.Error(), tt.message) {
			t.Errorf("%q: want nil spec and %q error, got %v", tt.replacement, tt.message, err)
		}
	}
}

func TestLoadSpec_ContentsAndDefaults(t *testing.T) {
	t.Parallel()
	loaded, err := loadText(t, contentsFixture)
	if err != nil {
		t.Fatal(err)
	}
	repo, artifact := loaded.Contents.Repositories[0], loaded.Contents.Artifacts[0]
	if *repo.ByHash != "prefer" || *repo.Freshness.ValidUntil != "if-present" || len(repo.Platforms) != 2 ||
		*artifact.Unpack != contents.ArtifactUnpackStandalone || *artifact.Mode != "0644" || len(artifact.Platforms) != 2 || *loaded.Contents.Slices[0].Catalogue != "custom" {
		t.Fatalf("wrong defaults: %#v %#v", repo, artifact)
	}
	loaded.Platforms[0] = "changed"
	if repo.Platforms[0] != "linux/amd64" || artifact.Platforms[0] != "linux/amd64" {
		t.Fatal("platform defaults share backing arrays")
	}
}

func TestLoadSpec_ContentsStrictYAML(t *testing.T) {
	t.Parallel()
	tests := []struct{ old, replacement string }{
		{"contents:\n", "contents: {future: value}\nignored:\n"},
		{"unpack: false", "unpack: null"},
		{"unpack: false", "unpack: \"false\""},
		{"unpack: false", "unpack: 0"},
		{"unpack: false", "unpack: false\n      uid: \"0\""},
		{"unpack: false", "unpack: false\n      uid: null"},
		{"branch: ubuntu-26.04", "branch: null"},
		{"branch: ubuntu-26.04", "branch: 42"},
		{"branch: ubuntu-26.04", "branch: ''"},
		{"branch: ubuntu-26.04", "branch: ubuntu-26.04\n      branch: other"},
		{"unpack: false", "unpack: false\n      mode: 0755"},
		{"unpack: false", "unpack: false\n      future: value"},
		{"url: https://example.com/server-amd64", "url: '${SECRET}'"},
		{"path: keys/repo.asc", "path: '${KEY}'"},
		{"archives: {ubuntu: main}", "archives: {\"bad\\0archive\": main}"},
		{"trust:\n", "trust: {future: value}\n      unused:\n"},
		{"fingerprints: [", "fingerprints: [null, "},
	}
	for i, tt := range tests {
		input := strings.Replace(contentsFixture, tt.old, tt.replacement, 1)
		if loaded, err := loadText(t, input); err == nil || loaded != nil {
			t.Fatalf("case %d accepted invalid input", i)
		}
	}
}

func TestLoadSpec_LocalCatalogueWithoutFilesystemAccess(t *testing.T) {
	t.Parallel()
	input := strings.Replace(contentsFixture, "url: https://example.com/catalogue\n      branch: ubuntu-26.04", "path: nonexistent/catalogue", 1)
	if _, err := loadText(t, input); err != nil {
		t.Fatal(err)
	}
}

func TestContents_Rejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*contents.Contents)
	}{
		{"duplicate package", func(c *contents.Contents) { c.Packages = append(c.Packages, c.Packages[0]) }},
		{"package name", func(c *contents.Contents) { c.Packages[0].Name = "pkg:arm64" }},
		{"bare version", func(c *contents.Contents) { c.Packages[0].Version = new("1.4.1") }},
		{"unknown operator", func(c *contents.Contents) { c.Packages[0].Version = new(">> 1") }},
		{"pessimistic non-numeric", func(c *contents.Contents) { c.Packages[0].Version = new("~> 2024a") }},
		{"pessimistic with revision", func(c *contents.Contents) { c.Packages[0].Version = new("~> 1.4.1-2") }},
		{"empty version", func(c *contents.Contents) { c.Packages[0].Version = new("") }},
		{"overlap", func(c *contents.Contents) { c.Packages[0].Name = "base-files" }},
		{"duplicate slice", func(c *contents.Contents) { c.Slices = append(c.Slices, c.Slices[0]) }},
		{"slice name", func(c *contents.Contents) { c.Slices[0].Slice = "bad_name" }},
		{"short slice", func(c *contents.Contents) { c.Slices[0].Slice = "a" }},
		{"numeric slice prefix", func(c *contents.Contents) { c.Slices[0].Slice = "1abc" }},
		{"trailing slice dash", func(c *contents.Contents) { c.Slices[0].Slice = "abc-" }},
		{"consecutive slice dashes", func(c *contents.Contents) { c.Slices[0].Slice = "abc--def" }},
		{"slice package", func(c *contents.Contents) { c.Slices[0].Package = "../pkg" }},
		{"no catalogue", func(c *contents.Contents) { c.Catalogues = nil }},
		{"unknown catalogue", func(c *contents.Contents) { c.Slices[0].Catalogue = new("missing") }},
		{"conflicting pins", func(c *contents.Contents) {
			c.Slices[0].Version = new("1")
			c.Slices = append(c.Slices, contents.SliceRequest{Package: "base-files", Slice: "copyright", Version: new("2"), Catalogue: new("custom")})
		}},
		{"duplicate catalogue", func(c *contents.Contents) { c.Catalogues = append(c.Catalogues, c.Catalogues[0]) }},
		{"catalogue name", func(c *contents.Contents) { c.Catalogues[0].Name = "../cat" }},
		{"no selector", func(c *contents.Contents) { c.Catalogues[0].Branch = nil }},
		{"two selectors", func(c *contents.Contents) { c.Catalogues[0].Tag = new("v1") }},
		{"short commit", func(c *contents.Contents) { c.Catalogues[0].Branch = nil; c.Catalogues[0].Commit = new("abc123") }},
		{"empty URL", func(c *contents.Contents) { c.Catalogues[0].URL = new("") }},
		{"no URL", func(c *contents.Contents) { c.Catalogues[0].URL = nil }},
		{"local remote mix", func(c *contents.Contents) { c.Catalogues[0].Path = new("catalogue") }},
		{"archive reference", func(c *contents.Contents) { c.Catalogues[0].Archives["ubuntu"] = "missing" }},
		{"empty archive repository", func(c *contents.Contents) { c.Catalogues[0].Archives["CustomArchive"] = "" }},
		{"duplicate repository", func(c *contents.Contents) { c.Repositories = append(c.Repositories, c.Repositories[0]) }},
		{"repository name", func(c *contents.Contents) { c.Repositories[0].Name = "bad/name" }},
		{"invalid suite matching", func(c *contents.Contents) { c.Repositories[0].SuiteMatch = new("either") }},
		{"empty suite matching", func(c *contents.Contents) { c.Repositories[0].SuiteMatch = new("") }},
		{"repository scopes", func(c *contents.Contents) { c.Repositories[0].Platforms = []string{} }},
		{"repository scope duplicate", func(c *contents.Contents) { c.Repositories[0].Platforms = []string{"linux/amd64", "linux/amd64"} }},
		{"repository scope foreign", func(c *contents.Contents) { c.Repositories[0].Platforms = []string{"all"} }},
		{"missing endpoint", func(c *contents.Contents) { c.Repositories[0].Endpoints = c.Repositories[0].Endpoints[:1] }},
		{"overlapping endpoints", func(c *contents.Contents) { c.Repositories[0].Endpoints[1].Platforms = []string{"linux/amd64"} }},
		{"empty endpoint scope", func(c *contents.Contents) { c.Repositories[0].Endpoints[0].Platforms = nil }},
		{"unknown endpoint scope", func(c *contents.Contents) { c.Repositories[0].Endpoints[0].Platforms = []string{"linux/386"} }},
		{"bad endpoint URL", func(c *contents.Contents) { c.Repositories[0].Endpoints[0].URL = "file:///etc/passwd" }},
		{"missing suites", func(c *contents.Contents) { c.Repositories[0].Suites = nil }},
		{"duplicate suites", func(c *contents.Contents) { c.Repositories[0].Suites = []string{"resolute", "resolute"} }},
		{"suite traversal", func(c *contents.Contents) { c.Repositories[0].Suites = []string{"../suite"} }},
		{"component token", func(c *contents.Contents) { c.Repositories[0].Components = []string{""} }},
		{"by hash", func(c *contents.Contents) { c.Repositories[0].ByHash = new("sometimes") }},
		{"freshness", func(c *contents.Contents) { c.Repositories[0].Freshness.ValidUntil = new("ignore") }},
		{"missing key path", func(c *contents.Contents) { c.Repositories[0].Trust.Keys[0].Path = "" }},
		{"unclean key path", func(c *contents.Contents) { c.Repositories[0].Trust.Keys[0].Path = "keys/../key.asc" }},
		{"missing fingerprint", func(c *contents.Contents) { c.Repositories[0].Trust.Keys[0].Fingerprints = nil }},
		{"short fingerprint", func(c *contents.Contents) {
			c.Repositories[0].Trust.Keys[0].Fingerprints = []string{"0123456789ABCDEF"}
		}},
		{"duplicate key path", func(c *contents.Contents) {
			c.Repositories[0].Trust.Keys = append(c.Repositories[0].Trust.Keys, c.Repositories[0].Trust.Keys[0])
		}},
		{"duplicate fingerprint", func(c *contents.Contents) {
			c.Repositories[0].Trust.Keys[0].Fingerprints = []string{strings.Repeat("a", 40), strings.Repeat("A", 40)}
		}},
		{"repository identity", func(c *contents.Contents) { c.Repositories[0].Identity = new("vendor") }},
		{"repository identity without keys", func(c *contents.Contents) {
			c.Repositories[0].Identity = new("own")
			c.Repositories[0].Trust.Keys = nil
		}},
		{"repository packages without identity", func(c *contents.Contents) { c.Repositories[0].Packages = []string{"nginx"} }},
		{"repository package name", func(c *contents.Contents) {
			c.Repositories[0].Identity = new("own")
			c.Repositories[0].Packages = []string{"pkg:arm64"}
		}},
		{"duplicate repository package", func(c *contents.Contents) {
			c.Repositories[0].Identity = new("own")
			c.Repositories[0].Packages = []string{"nginx", "nginx"}
		}},
		{"artifact name", func(c *contents.Contents) { c.Artifacts[0].Name = "" }},
		{"duplicate artifact", func(c *contents.Contents) { c.Artifacts = append(c.Artifacts, c.Artifacts[0]) }},
		{"missing unpack", func(c *contents.Contents) { c.Artifacts[0].Unpack = nil }},
		{"relative destination", func(c *contents.Contents) { c.Artifacts[0].Dest = "bin/server" }},
		{"unclean destination", func(c *contents.Contents) { c.Artifacts[0].Dest = "/usr/../server" }},
		{"standalone root", func(c *contents.Contents) { c.Artifacts[0].Dest = "/" }},
		{"backslash destination", func(c *contents.Contents) { c.Artifacts[0].Dest = `/usr\server` }},
		{"negative uid", func(c *contents.Contents) { c.Artifacts[0].UID = -1 }},
		{"gid overflow", func(c *contents.Contents) { c.Artifacts[0].GID = 4294967296 }},
		{"invalid mode", func(c *contents.Contents) { c.Artifacts[0].Mode = new("9999") }},
		{"unpack mode override", func(c *contents.Contents) { c.Artifacts[0].Unpack = new(contents.ArtifactUnpackArchive) }},
		{"missing sbom name", func(c *contents.Contents) { c.Artifacts[0].SBOM.Name = " " }},
		{"missing sbom version", func(c *contents.Contents) { c.Artifacts[0].SBOM.Version = "" }},
		{"artifact empty scope", func(c *contents.Contents) { c.Artifacts[0].Platforms = []string{} }},
		{"missing source", func(c *contents.Contents) { c.Artifacts[0].Sources = nil }},
		{"source coverage gap", func(c *contents.Contents) { c.Artifacts[0].Sources = c.Artifacts[0].Sources[:1] }},
		{"source overlap", func(c *contents.Contents) { c.Artifacts[0].Sources[1].Platforms = []string{"linux/amd64"} }},
		{"source url", func(c *contents.Contents) { c.Artifacts[0].Sources[0].URL = "https://:5000/server" }},
		{"source path and url", func(c *contents.Contents) { c.Artifacts[0].Sources[0].Path = "files/server" }},
		{"source neither", func(c *contents.Contents) { c.Artifacts[0].Sources[0].URL = "" }},
		{"source absolute path", func(c *contents.Contents) {
			c.Artifacts[0].Sources[0].URL, c.Artifacts[0].Sources[0].Path = "", "/srv/server"
		}},
		{"source unclean path", func(c *contents.Contents) {
			c.Artifacts[0].Sources[0].URL, c.Artifacts[0].Sources[0].Path = "", "files/../server"
		}},
		{"source digest", func(c *contents.Contents) { c.Artifacts[0].Sources[0].SHA256 = "sha256:" + strings.Repeat("a", 64) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loaded, err := loadText(t, contentsFixture)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&loaded.Contents)
			if err := spec.ValidateSpec(loaded); err == nil {
				t.Fatal("invalid contents accepted")
			}
		})
	}
}

// Two slice requests for one package are one element in the attestation document, so
// they have to agree on the CPE that element publishes. An omission beside a declaration
// is the same disagreement as two different names, and it is refused while the
// specification is validated rather than after a lock exists.
func TestLoadSpec_SliceRequestsDisagreeOnCPE(t *testing.T) {
	t.Parallel()
	const otherCPE = "cpe:2.3:a:gnu:base-files:13ubuntu10:*:*:*:*:*:*:*"
	cases := map[string]struct {
		first, second string
		rejected      bool
	}{
		"omission beside a declaration": {
			first: "", second: "      cpe: " + otherCPE + "\n", rejected: true,
		},
		"declaration beside an omission": {
			first: "      cpe: " + otherCPE + "\n", second: "", rejected: true,
		},
		"two different names": {
			first:    "      cpe: " + otherCPE + "\n",
			second:   "      cpe: cpe:2.3:a:gnu:base-files:13ubuntu11:*:*:*:*:*:*:*\n",
			rejected: true,
		},
		"identical declarations": {
			first: "      cpe: " + otherCPE + "\n", second: "      cpe: " + otherCPE + "\n",
		},
		"neither declares one": {},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text := strings.Replace(contentsFixture, `    - package: base-files
      slice: release-info`, `    - package: base-files
      slice: release-info
`+testCase.first+`    - package: base-files
      slice: copyright
`+testCase.second, 1)
			_, err := loadText(t, text)
			if testCase.rejected && err == nil {
				t.Fatal("disagreeing slice requests were accepted")
			}
			if !testCase.rejected && err != nil {
				t.Fatalf("agreeing slice requests rejected: %v", err)
			}
		})
	}
}
