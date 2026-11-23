package contents_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func TestContents_ValidVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*contents.Contents)
	}{
		{"upstream archive key", func(c *contents.Contents) { c.Catalogues[0].Archives = map[string]string{"CustomArchive": "main"} }},
		{"encoded URL hash", func(c *contents.Contents) { c.Artifacts[0].Sources[0].URL = "https://example.com/server%23amd64" }},
		{"tag", func(c *contents.Contents) { c.Catalogues[0].Branch = nil; c.Catalogues[0].Tag = new("releases/v1") }},
		{"commit", func(c *contents.Contents) {
			c.Catalogues[0].Branch = nil
			c.Catalogues[0].Commit = new(strings.Repeat("a", 40))
		}},
		{"sha256 commit", func(c *contents.Contents) {
			c.Catalogues[0].Branch = nil
			c.Catalogues[0].Commit = new(strings.Repeat("b", 64))
		}},
		{"archive root", func(c *contents.Contents) {
			c.Artifacts[0].Unpack = new(contents.ArtifactUnpackArchive)
			c.Artifacts[0].Mode = nil
			c.Artifacts[0].Dest = "/"
		}},
		{"standalone mode and ids", func(c *contents.Contents) {
			c.Artifacts[0].Mode = new("0755")
			c.Artifacts[0].UID = 4294967295
			c.Artifacts[0].GID = 65532
		}},
		{"common payload", func(c *contents.Contents) {
			c.Artifacts[0].Sources = c.Artifacts[0].Sources[:1]
			c.Artifacts[0].Sources[0].Platforms = []string{"linux/amd64", "linux/arm64"}
		}},
		{"intentional subset", func(c *contents.Contents) {
			c.Artifacts[0].Platforms = []string{"linux/arm64"}
			c.Artifacts[0].Sources = c.Artifacts[0].Sources[1:]
		}},
		{"repository subset", func(c *contents.Contents) {
			c.Repositories[0].Platforms = []string{"linux/amd64"}
			c.Repositories[0].Endpoints = c.Repositories[0].Endpoints[:1]
		}},
		{"strict policies", func(c *contents.Contents) {
			c.Repositories[0].ByHash = new("require")
			c.Repositories[0].Freshness.ValidUntil = new("require")
		}},
		{"no by hash", func(c *contents.Contents) { c.Repositories[0].ByHash = new("disable") }},
		{"64 hex trust", func(c *contents.Contents) {
			c.Repositories[0].Trust.Keys[0].Fingerprints = []string{strings.Repeat("f", 64)}
		}},
		{"provider default trust", func(c *contents.Contents) { c.Repositories[0].Trust.Keys = nil }},
		{"vendor identity", func(c *contents.Contents) {
			c.Repositories[0].Identity = new("own")
			c.Repositories[0].Packages = []string{"nginx", "nginx-full"}
		}},
		{"matching package pins", func(c *contents.Contents) {
			c.Slices[0].Version = new("= 1")
			c.Slices = append(c.Slices, contents.SliceRequest{Package: "base-files", Slice: "copyright", Version: new("= 1"), Catalogue: new("custom")})
		}},
		{"narrowing package pins", func(c *contents.Contents) {
			c.Slices[0].Version = new(">= 1")
			c.Slices = append(c.Slices, contents.SliceRequest{Package: "base-files", Slice: "copyright", Version: new("< 2"), Catalogue: new("custom")})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loaded, err := loadText(t, contentsFixture)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&loaded.Contents)
			if err := spec.ValidateSpec(loaded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateGitRef_LiteralSelectors(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "@", "HEAD", "-option", "/a", "a/", "a..b", "a//b", "a@{1}", "a~1", "a^1", "a:b", "a?b", "a*b", "a[b", `a\b`, "a b", "a\nb", ".hidden", "a/.hidden", "a.", "a.lock"} {
		if err := contents.ValidateGitRef(value); err == nil {
			t.Fatalf("invalid ref accepted: %q", value)
		}
	}
	for _, value := range []string{"ubuntu-26.04", "v1.0.0", "release/stable"} {
		if err := contents.ValidateGitRef(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadSpec_InputURLsAreRedacted(t *testing.T) {
	t.Parallel()
	secret := "private_marker_19a"
	for i, value := range []string{
		"https://user:" + secret + "@example.com/server",
		"https://example.com/server?token=" + secret,
		"https://example.com/server#" + secret,
		"https://example.com/" + secret + "#",
		"https://example.com/" + secret + "\nbad",
	} {
		input := strings.Replace(contentsFixture, "https://example.com/server-amd64", "\""+strings.ReplaceAll(value, "\n", `\n`)+"\"", 1)
		loaded, err := loadText(t, input)
		if loaded != nil || err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("case %d: expected value-free URL failure: %v", i, err)
		}
	}
}

func TestApplyDefaults_ContentsAreIdempotent(t *testing.T) {
	t.Parallel()
	loaded, err := loadText(t, contentsFixture)
	if err != nil {
		t.Fatal(err)
	}
	before := *loaded.Contents.Artifacts[0].Mode
	repoPolicy := *loaded.Contents.Repositories[0].Freshness.ValidUntil
	spec.ApplyDefaults(loaded)
	if *loaded.Contents.Artifacts[0].Mode != before || *loaded.Contents.Repositories[0].Freshness.ValidUntil != repoPolicy {
		t.Fatal("defaults changed on second application")
	}
	raw, err := spec.DecodeSpec([]byte(contentsFixture))
	if err != nil {
		t.Fatal(err)
	}
	if raw.Contents.Repositories[0].ByHash != nil || raw.Contents.Artifacts[0].Mode != nil || raw.Contents.Artifacts[0].Platforms != nil {
		t.Fatal("decoding applied contents defaults")
	}
	if raw.Contents.Slices[0].Catalogue != nil {
		t.Fatal("decoding inferred a catalogue")
	}
}
