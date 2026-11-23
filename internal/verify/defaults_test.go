package verify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/verify"
)

type appsProvider struct {
	*ubuntu.Provider
	apps deb.KeySnapshot
}

func (p *appsProvider) ProTrust(service string) []deb.KeySnapshot {
	if service == "esm-apps" {
		return []deb.KeySnapshot{p.apps}
	}
	return p.Provider.ProTrust(service)
}

func TestProviderDefaults_ReplaysOnlyTheBoundService(t *testing.T) {
	entity, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: entity})
	provider := &appsProvider{
		Provider: ubuntu.New("26.04"),
		apps:     deb.KeySnapshot{Data: publicKey(t, entity), Fingerprints: []string{fingerprint(entity)}},
	}
	root := fmt.Sprintf(`format: v3
maintenance:
  standard: 2026-04-23
  expanded: 2031-05-29
  legacy: 2036-04-23
  end-of-life: 2038-04-27
archives:
  restricted:
    version: "26.04"
    suites: [resolute]
    components: [main]
    pro: esm-apps
    priority: 16
    public-keys: [test]
public-keys:
  test:
    id: "%016X"
    armor: |
      %s
`, entity.PrimaryKey.KeyId, strings.ReplaceAll(strings.TrimSuffix(rootKeyArmor(t, entity), "\n"), "\n", "\n      "))
	loaded := proSpec(t)
	repo := &signed.lock.Repositories[0]
	repo.Name = "mirror"
	repo.ID = lock.RepositoryID(repo.Name, repo.Platform, repo.Architecture, repo.URL, repo.Suite)
	repo.Trust.Keys[0].Path = ""
	evidence := proEvidence(t, signed, root)
	defaults, err := verify.ProviderDefaults(t.Context(), provider, loaded, evidence.Catalogues, evidence.Repositories, signed.cache)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := locking.AssembleWithDefaults(loaded, provider, evidence, defaults)
	if err != nil {
		t.Fatal(err)
	}
	inputs := &builder.Inputs{Spec: loaded, Lockfile: locked, Provider: provider, Blobs: signed.cache}
	if _, openErr := builder.Open(t.Context(), inputs); openErr != nil {
		t.Fatalf("build refused the locked Apps key: %v", openErr)
	}
	if evidenceErr := verify.Repositories(locked, signed.cache); evidenceErr != nil {
		t.Fatalf("offline evidence: %v", evidenceErr)
	}

	locked.Catalogues[0].Tree = "sha256:" + strings.Repeat("0", 64)
	if _, openErr := builder.Open(t.Context(), inputs); openErr == nil || !strings.Contains(openErr.Error(), "does not match tree digest") {
		t.Fatalf("build accepted a mismatched catalogue tree: %v", openErr)
	}
	locked.Catalogues[0].Tree = evidence.Catalogues[0].Tree

	infra := provider.ProTrust("esm-infra")[0]
	sum := sha256.Sum256(infra.Data)
	locked.Repositories[0].Trust.Keys = []lock.RepositoryKey{{
		Fingerprint: infra.Fingerprints[0], SHA256: hex.EncodeToString(sum[:]), Size: int64(len(infra.Data)),
	}}
	locked.Repositories[0].Release.Signers = infra.Fingerprints
	if _, openErr := builder.Open(t.Context(), inputs); openErr == nil || !strings.Contains(openErr.Error(), "trust does not match a provider key") {
		t.Fatalf("Apps binding with an Infra key: %v", openErr)
	}

	other := proEvidence(t, signed, strings.Replace(root, "pro: esm-apps", "pro: esm-infra", 1)).Catalogues[0]
	other.Name = "other"
	source := loaded.Contents.Catalogues[0]
	source.Name = other.Name
	loaded.Contents.Catalogues = append(loaded.Contents.Catalogues, source)
	catalogues := []lock.Catalogue{evidence.Catalogues[0], other}
	if _, conflictErr := verify.ProviderDefaults(t.Context(), provider, loaded, catalogues, evidence.Repositories, signed.cache); conflictErr == nil ||
		!strings.Contains(conflictErr.Error(), "conflicting catalogue trust") {
		t.Fatalf("conflicting catalogue trust: %v", conflictErr)
	}
	loaded.Contents.Catalogues = loaded.Contents.Catalogues[:1]

	loaded.Contents.Catalogues[0].Archives = nil
	defaults, err = verify.ProviderDefaults(t.Context(), provider, loaded, evidence.Catalogues, evidence.Repositories, signed.cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locking.AssembleWithDefaults(loaded, provider, evidence, defaults); err == nil ||
		!strings.Contains(err.Error(), "trust does not match a provider key") {
		t.Fatalf("standalone repository with an Apps key: %v", err)
	}
}

// A lock names the catalogue a slice came from, and two catalogues may declare the
// same archive name for different repositories. Every spec platform must carry a
// binding too, because the slice is checked on the platform it was locked for.
func TestProviderDefaults_KeysBindingsByCatalogueAndPlatform(t *testing.T) {
	entity, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: entity})
	root := blockRoot(t, entity)
	provider := ubuntu.New("26.04")
	loaded := multiCatalogueSpec(t)
	catalogues := []lock.Catalogue{
		catalogueRecord(t, signed, "first", root), catalogueRecord(t, signed, "second", root),
	}
	repositories := []lock.Repository{repositoryRecord(signed.lock.Repositories[0], "one", "https://one.example.com/ubuntu"),
		repositoryRecord(signed.lock.Repositories[0], "two", "https://two.example.com/ubuntu")}
	defaults, err := verify.ProviderDefaults(t.Context(), provider, loaded, catalogues, repositories, signed.cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range loaded.Platforms {
		for catalogue, repository := range map[string]string{"first": "one", "second": "two"} {
			binding, ok := defaults.Bindings[lock.BindingKey(catalogue, "ubuntu", platform)]
			if !ok || binding.Repository != repository {
				t.Fatalf("%s on %s = %+v, want repository %q", catalogue, platform, binding, repository)
			}
		}
	}
	if !defaults.Covered["first"] || !defaults.Covered["second"] {
		t.Fatalf("covered = %v", defaults.Covered)
	}
}

func blockRoot(t *testing.T, entity *openpgp.Entity) string {
	t.Helper()
	return fmt.Sprintf(`format: v3
maintenance:
  standard: 2026-04-23
  end-of-life: 2038-04-27
archives:
  ubuntu:
    version: "26.04"
    suites: [resolute]
    components: [main]
    priority: 10
    public-keys: [test]
public-keys:
  test:
    id: "%016X"
    armor: |
      %s
`, entity.PrimaryKey.KeyId, strings.ReplaceAll(strings.TrimSuffix(rootKeyArmor(t, entity), "\n"), "\n", "\n      "))
}

func multiCatalogueSpec(t *testing.T) *spec.Spec {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
name: two-catalogues
image: example.invalid/two-catalogues
distro: ubuntu
release: "26.04"
platforms: [linux/amd64, linux/arm64]
contents:
  catalogues:
    - name: first
      path: first
      archives: {ubuntu: one}
    - name: second
      path: second
      archives: {ubuntu: two}
  packages:
    - name: demo
  repositories:
    - name: one
      suites: [resolute]
      components: [main]
      endpoints:
        - platforms: [linux/amd64, linux/arm64]
          url: https://one.example.com/ubuntu
    - name: two
      suites: [resolute]
      components: [main]
      endpoints:
        - platforms: [linux/amd64, linux/arm64]
          url: https://two.example.com/ubuntu
`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func catalogueRecord(t *testing.T, signed *fixture, name, root string) lock.Catalogue {
	t.Helper()
	record := proEvidence(t, signed, root).Catalogues[0]
	record.Name = name
	record.Source.Path = name
	return record
}

func repositoryRecord(repository lock.Repository, name, url string) lock.Repository {
	repository.Name, repository.URL = name, url
	repository.ID = lock.RepositoryID(repository.Name, repository.Platform, repository.Architecture,
		repository.URL, repository.Suite)
	return repository
}

func rootKeyArmor(t *testing.T, entity *openpgp.Entity) string {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.PrimaryKey.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

func proSpec(t *testing.T) *spec.Spec {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
name: scoped-build
image: example.invalid/scoped-build
distro: ubuntu
release: "26.04"
contents:
  catalogues:
    - name: local
      path: catalogue
      archives: {restricted: mirror}
  packages:
    - name: demo
  repositories:
    - name: mirror
      suites: [resolute]
      components: [main]
      endpoints:
        - platforms: [linux/amd64]
          url: https://archive.ubuntu.com/ubuntu
`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func proEvidence(t *testing.T, signed *fixture, root string) *locking.Evidence {
	t.Helper()
	data := []byte(root)
	digest := storeBlob(t, signed.cache, data)
	tree, err := catalogue.NewTree([]catalogue.Entry{{
		Path: "chisel.yaml", Kind: catalogue.KindFile, SHA256: digest, Size: int64(len(data)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	treeDigest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &locking.Evidence{
		Catalogues: []lock.Catalogue{{
			Name: "local", Tree: treeDigest, Source: lock.CatalogueSource{Type: "local", Path: "catalogue"},
			Manifest: []lock.CatalogueEntry{{Path: "chisel.yaml", Kind: "file", SHA256: digest, Size: int64(len(data))}},
		}},
		Repositories: signed.lock.Repositories,
		Packages: []lock.Package{{
			Platform: "linux/amd64", Name: "demo", Version: "1.0-1", Architecture: "amd64",
			Repository: signed.lock.Repositories[0].ID,
			Content:    lock.Content{Path: "pool/main/d/demo/demo_1.0-1_amd64.deb", SHA256: strings.Repeat("a", 64), Size: 42},
		}},
	}
}
