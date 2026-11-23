package synthesis

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/vfs"
)

// APTSourcesPath is the generated source list, separate from vendor lists.
const APTSourcesPath = "/etc/apt/sources.list.d/vapor.sources"

// APTSourcesOrigin attributes generated package sources and keyrings to the lock.
var APTSourcesOrigin = vfs.Origin{Path: "apt.sources"}

// APTRepository is one locked suite and its verified binary public keyring.
type APTRepository struct {
	URL        string
	Suite      string
	Components []string
	Keyring    []byte
}

// APTSources writes the locked suites and their own keyrings unless the image
// already carries a source list.
func APTSources(tree *vfs.Tree, repositories []APTRepository) error {
	if tree == nil {
		return errors.New("package sources synthesis requires an image tree")
	}
	if len(repositories) == 0 || hasDeclaredSources(tree) {
		return nil
	}
	stanzas, err := collectSources(repositories)
	if err != nil {
		return err
	}
	return writeSources(tree, stanzas)
}

func hasDeclaredSources(tree *vfs.Tree) bool {
	if _, ok := tree.Lookup(APTSourcesPath); ok {
		return true
	}
	if isSourceList(tree, "/etc/apt/sources.list") {
		return true
	}
	dir := path.Dir(APTSourcesPath)
	if entry, ok := tree.Lookup(dir); ok && entry.Kind == vfs.Symlink {
		return true
	}
	children, _ := tree.Children(dir)
	for _, name := range children {
		ext := path.Ext(name)
		if (ext == ".list" || ext == ".sources") && isSourceList(tree, name) {
			return true
		}
	}
	return false
}

func isSourceList(tree *vfs.Tree, name string) bool {
	entry, ok := tree.Lookup(name)
	return ok && (entry.Kind == vfs.Symlink || (entry.Kind == vfs.File && entry.Size != 0))
}

type sourceStanza struct {
	APTRepository
	conflicting bool
}

func collectSources(repositories []APTRepository) ([]sourceStanza, error) {
	type target struct{ url, suite string }
	seen := make(map[target]int, len(repositories))
	var stanzas []sourceStanza
	for index := range repositories {
		repo := &repositories[index]
		if err := validateRepository(repo); err != nil {
			return nil, err
		}
		id := target{strings.TrimSuffix(repo.URL, "/"), repo.Suite}
		n, found := seen[id]
		if !found {
			seen[id] = len(stanzas)
			stanzas = append(stanzas, sourceStanza{APTRepository: *repo})
			stanzas[len(stanzas)-1].Components = slices.Clone(repo.Components)
			continue
		}
		stanza := &stanzas[n]
		// APT requires identical Signed-By values for the same URI and suite.
		if !bytes.Equal(stanza.Keyring, repo.Keyring) {
			stanza.conflicting = true
		}
		for _, component := range repo.Components {
			if !slices.Contains(stanza.Components, component) {
				stanza.Components = append(stanza.Components, component)
			}
		}
	}
	return stanzas, nil
}

func writeSources(tree *vfs.Tree, stanzas []sourceStanza) error {
	attrs := vfs.Attrs{Mode: 0o644, Origin: APTSourcesOrigin}
	written := make(map[string]bool)
	var out strings.Builder
	for index := range stanzas {
		stanza := &stanzas[index]
		if stanza.conflicting {
			continue
		}
		keyring := fmt.Sprintf("/etc/apt/keyrings/vapor-%x.gpg", sha256.Sum256(stanza.Keyring))
		if !written[keyring] {
			if err := tree.File(keyring, stanza.Keyring, attrs); err != nil {
				return fmt.Errorf("write package keyring: %w", err)
			}
			written[keyring] = true
		}
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		fmt.Fprintf(&out, "Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n",
			stanza.URL, stanza.Suite, strings.Join(stanza.Components, " "), keyring)
	}
	if out.Len() == 0 {
		return nil
	}
	return tree.File(APTSourcesPath, []byte(out.String()), attrs)
}

func validateRepository(repository *APTRepository) error {
	if err := base.ValidateInputURL(repository.URL, false); err != nil {
		return fmt.Errorf("package sources: %w", err)
	}
	if err := validateSourceToken("url", repository.URL); err != nil {
		return err
	}
	if err := validateSourceToken("suite", repository.Suite); err != nil {
		return err
	}
	if len(repository.Components) == 0 {
		return errors.New("package sources: repository suite has no component")
	}
	if len(repository.Keyring) == 0 {
		return errors.New("package sources: repository suite has no keyring")
	}
	for _, component := range repository.Components {
		if err := validateSourceToken("component", component); err != nil {
			return err
		}
	}
	return nil
}

func validateSourceToken(field, value string) error {
	if value == "" {
		return fmt.Errorf("package sources: %s must not be empty", field)
	}
	if strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return fmt.Errorf("package sources: %s must be a single token", field)
	}
	return nil
}
