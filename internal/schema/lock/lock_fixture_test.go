package lock

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func validMultiPlatformLock(t *testing.T) (*spec.Spec, *Lockfile) {
	t.Helper()
	loaded, err := loadText(t, contentsFixture)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := loaded.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	inputHash := strings.Repeat("a", 64)
	fingerprint := "0123456789ABCDEF0123456789ABCDEF01234567"
	key := RepositoryKey{Fingerprint: fingerprint, Path: "keys/repo.asc", SHA256: inputHash, Size: 10}

	makeRepository := func(platform, architecture, suite, url, component, indexPath string) Repository {
		repository := Repository{
			Name:         "main",
			Platform:     platform,
			Architecture: architecture,
			URL:          url,
			Suite:        suite,
			Trust:        RepositoryTrust{Keys: []RepositoryKey{key}},
			Release: RepositoryRelease{
				Format:  "inrelease",
				Path:    "dists/" + suite + "/InRelease",
				SHA256:  strings.Repeat("d", 64),
				Size:    100,
				Signers: []string{fingerprint},
			},
			Indexes: []Index{{
				Component: component,
				Path:      indexPath,
				SHA256:    strings.Repeat("e", 64),
				Size:      200,
			}},
		}
		repository.ID = RepositoryID(repository.Name, repository.Platform, repository.Architecture, repository.URL, repository.Suite)
		return repository
	}

	amd64 := makeRepository("linux/amd64", "amd64", "resolute", "https://example.com/ubuntu", "main", "main/binary-amd64/Packages.xz")
	arm64 := makeRepository("linux/arm64", "arm64", "resolute-updates", "http://ports.example.com/ubuntu-ports", "universe", "universe/binary-arm64/Packages.xz")

	makePackage := func(platform, architecture, repository string, size int64) Package {
		return Package{
			Platform:     platform,
			Name:         "openssl",
			Version:      "3.0-1",
			Architecture: architecture,
			Repository:   repository,
			Content: Content{
				Path:   "pool/main/o/openssl/openssl_3.0-1_" + architecture + ".deb",
				SHA256: strings.Repeat("1", 64),
				Size:   size,
			},
		}
	}
	makeSlice := func(platform, repository string) Slice {
		return Slice{
			Platform:         platform,
			Package:          "base-files",
			Version:          "13ubuntu10",
			Architecture:     "all",
			Catalogue:        "custom",
			Archive:          "ubuntu",
			Repository:       repository,
			Content:          Content{Path: "pool/main/b/base-files/base-files_13ubuntu10_all.deb", SHA256: strings.Repeat("2", 64), Size: 300},
			Selected:         []string{"release-info"},
			Closure:          []string{"copyright", "etc", "lib", "release-info"},
			DefinitionDigest: "sha256:" + strings.Repeat("3", 64),
		}
	}
	makeArtifact := func(platform, url, sha string) Artifact {
		return Artifact{
			Name:     "server",
			Platform: platform,
			URL:      url,
			SHA256:   sha,
			Size:     400,
			Dest:     "/usr/bin/server",
			Unpack:   new(contents.ArtifactUnpackStandalone),
			UID:      0,
			GID:      0,
			Mode:     new("0644"),
			SBOM:     contents.ArtifactIdentity{Name: "server", Version: "1.0"},
		}
	}

	return loaded, &Lockfile{
		Version:    1,
		SpecDigest: digest,
		Provider:   Provider{Distro: "ubuntu", Release: "26.04"},
		Platforms:  []string{"linux/amd64", "linux/arm64"},
		LocalInputs: []LocalInput{{
			Role: "trust-key", Path: "keys/repo.asc", SHA256: inputHash, Size: 10,
		}},
		Catalogues: []Catalogue{{
			Name:   "custom",
			Source: CatalogueSource{Type: "remote", URL: "https://example.com/catalogue", Selector: &CatalogueSelector{Branch: new("ubuntu-26.04")}, Commit: strings.Repeat("4", 40)},
			Tree:   "sha256:" + strings.Repeat("b", 64),
			Archive: &Archive{
				SHA256: strings.Repeat("c", 64),
				Size:   512,
			},
		}},
		Repositories: []Repository{amd64, arm64},
		Packages: []Package{
			makePackage("linux/amd64", "amd64", amd64.ID, 1000),
			makePackage("linux/arm64", "arm64", arm64.ID, 1001),
		},
		Slices: []Slice{
			makeSlice("linux/amd64", amd64.ID),
			makeSlice("linux/arm64", arm64.ID),
		},
		Artifacts: []Artifact{
			makeArtifact("linux/amd64", "https://example.com/server-amd64", strings.Repeat("a", 64)),
			makeArtifact("linux/arm64", "https://example.com/server-arm64", strings.Repeat("b", 64)),
		},
	}
}

// bindingDefaults is the provider replay needs to compare slices with the archive
// they claim. The fixture catalogue binds its archive to the explicit repository, so
// that is what each slice has to record.
func bindingDefaults() *DefaultRepository {
	return &DefaultRepository{
		Name:    "ubuntu",
		Covered: map[string]bool{"custom": true},
		Bindings: map[string]ArchiveBinding{
			BindingKey("custom", "ubuntu", "linux/amd64"): {
				Repository: "main", Suites: []string{"resolute", "resolute-updates"},
				Components: []string{"main", "universe"},
			},
			BindingKey("custom", "ubuntu", "linux/arm64"): {
				Repository: "main", Suites: []string{"resolute", "resolute-updates"},
				Components: []string{"main", "universe"},
			},
		},
	}
}
