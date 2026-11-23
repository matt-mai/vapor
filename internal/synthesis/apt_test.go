package synthesis_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

const mirror = "https://mirror.example.invalid/ubuntu"

func sourceKeyringPath(keyring []byte) string {
	return fmt.Sprintf("/etc/apt/keyrings/vapor-%x.gpg", sha256.Sum256(keyring))
}

func TestAPTSources_BindsEachSuiteToItsComponentsAndKeys(t *testing.T) {
	firstKey, secondKey := []byte("first keyring"), []byte("second keyring")
	repositories := []synthesis.APTRepository{
		{URL: mirror, Suite: "resolute", Components: []string{"main"}, Keyring: firstKey},
		{URL: mirror + "/", Suite: "resolute", Components: []string{"restricted", "main"}, Keyring: firstKey},
		{URL: mirror, Suite: "resolute-updates", Components: []string{"universe"}, Keyring: secondKey},
	}
	want := fmt.Sprintf(`Types: deb
URIs: %[1]s
Suites: resolute
Components: main restricted
Signed-By: %[2]s

Types: deb
URIs: %[1]s
Suites: resolute-updates
Components: universe
Signed-By: %[3]s
`, mirror, sourceKeyringPath(firstKey), sourceKeyringPath(secondKey))
	for range 2 {
		tree := vfs.New()
		if err := synthesis.APTSources(tree, repositories); err != nil {
			t.Fatal(err)
		}
		if content := readFile(t, tree, synthesis.APTSourcesPath); content != want {
			t.Fatalf("sources are %q", content)
		}
		if entry, ok := tree.Lookup(synthesis.APTSourcesPath); !ok || entry.Mode != 0o644 ||
			len(entry.Origins) != 1 || entry.Origins[0] != synthesis.APTSourcesOrigin {
			t.Fatalf("sources entry = %+v", entry)
		}
		for _, keyring := range [][]byte{firstKey, secondKey} {
			path := sourceKeyringPath(keyring)
			if content := readFile(t, tree, path); content != string(keyring) {
				t.Fatalf("keyring at %s has wrong bytes", path)
			}
			if entry, ok := tree.Lookup(path); !ok || entry.Mode != 0o644 ||
				len(entry.Origins) != 1 || entry.Origins[0] != synthesis.APTSourcesOrigin {
				t.Fatalf("keyring entry = %+v", entry)
			}
		}
	}
}

func TestAPTSources_OmitsConflictingSuite(t *testing.T) {
	tree := vfs.New()
	conflictingKey := []byte("conflicting keyring")
	goodKey := []byte("good keyring")
	repositories := []synthesis.APTRepository{
		{URL: mirror, Suite: "resolute", Components: []string{"main"}, Keyring: conflictingKey},
		{URL: mirror + "/", Suite: "resolute", Components: []string{"universe"}, Keyring: goodKey},
		{URL: mirror, Suite: "resolute-updates", Components: []string{"main"}, Keyring: goodKey},
	}
	if err := synthesis.APTSources(tree, repositories); err != nil {
		t.Fatal(err)
	}
	sources := readFile(t, tree, synthesis.APTSourcesPath)
	if strings.Count(sources, "Suites: ") != 1 || !strings.Contains(sources, "Suites: resolute-updates\n") {
		t.Fatalf("sources are %q", sources)
	}
	if _, ok := tree.Lookup(sourceKeyringPath(conflictingKey)); ok {
		t.Fatal("keyring for omitted source was written")
	}
}

func TestAPTSources_RefusesInvalidSources(t *testing.T) {
	cases := []struct {
		name, url, suite string
		components       []string
		keyring          []byte
	}{
		{"newline in URI", mirror + "\nTypes: deb", "s", []string{"main"}, []byte("key")},
		{"credentials in URI", "https://user:token@example.invalid", "s", []string{"main"}, []byte("key")},
		{"empty URI", "", "s", []string{"main"}, []byte("key")},
		{"space in suite", mirror, "s main", []string{"main"}, []byte("key")},
		{"empty suite", mirror, "", []string{"main"}, []byte("key")},
		{"space in component", mirror, "s", []string{"main universe"}, []byte("key")},
		{"tab in component", mirror, "s", []string{"main\tuniverse"}, []byte("key")},
		{"control in component", mirror, "s", []string{"main\x00"}, []byte("key")},
		{"no components", mirror, "s", nil, []byte("key")},
		{"no keyring", mirror, "s", []string{"main"}, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repositories := []synthesis.APTRepository{{
				URL: test.url, Suite: test.suite, Components: test.components, Keyring: test.keyring,
			}}
			tree := vfs.New()
			if err := synthesis.APTSources(tree, repositories); err == nil {
				t.Fatal("invalid repository was accepted")
			}
			if len(tree.Entries()) != 0 {
				t.Fatal("invalid repository wrote files")
			}
		})
	}
}

func TestAPTSources_RefusesNilTree(t *testing.T) {
	//nolint:staticcheck // A nil tree is refused, not silently replaced.
	if err := synthesis.APTSources(nil, nil); err == nil {
		t.Fatal("nil tree was accepted")
	}
}

func TestAPTSources_WritesNothingWithoutRepositories(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.APTSources(tree, nil); err != nil {
		t.Fatal(err)
	}
	if len(tree.Entries()) != 0 {
		t.Fatal("files were written without repositories")
	}
}

func TestAPTSources_KeepsDeclaredSourceLists(t *testing.T) {
	repositories := []synthesis.APTRepository{{URL: mirror, Suite: "s", Components: []string{"main"}, Keyring: []byte("key")}}
	for _, path := range []string{"/etc/apt/sources.list", "/etc/apt/sources.list.d/ubuntu.sources", synthesis.APTSourcesPath} {
		t.Run(path, func(t *testing.T) {
			tree := vfs.New()
			if err := tree.File(path, []byte("existing\n"), vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
			if err := synthesis.APTSources(tree, repositories); err != nil {
				t.Fatal(err)
			}
			if path != synthesis.APTSourcesPath {
				if _, ok := tree.Lookup(synthesis.APTSourcesPath); ok {
					t.Fatal("a second source list was written")
				}
			}
			if content := readFile(t, tree, path); content != "existing\n" {
				t.Fatalf("declared source list = %q", content)
			}
			if _, ok := tree.Lookup(sourceKeyringPath(repositories[0].Keyring)); ok {
				t.Fatal("a keyring was written without a generated source")
			}
		})
	}
}
