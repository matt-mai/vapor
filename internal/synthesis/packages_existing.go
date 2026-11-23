package synthesis

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// statusStanza is one record the image already carries, kept verbatim.
type statusStanza struct {
	name         string
	architecture string
	text         string
}

// existingStanzas reads the records the image already carries. A missing file is
// empty, but one that exists and cannot be read fails: treating it as empty would
// silently drop records the image depends on.
func existingStanzas(tree *vfs.Tree) ([]statusStanza, error) {
	content, err := tree.Read(StatusPath)
	if err != nil {
		if errors.Is(err, vfs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s cannot be read: %w", StatusPath, err)
	}
	return parseStatusStanzas(content)
}

// uncoveredStanzas drops records that a selected package already describes, so
// the file never holds two stanzas for one package.
func uncoveredStanzas(existing []statusStanza, records []statusRecord) []statusStanza {
	kept := make([]statusStanza, 0, len(existing))
	for _, stanza := range existing {
		covered := slices.ContainsFunc(records, func(record statusRecord) bool {
			return record.name == stanza.name && record.architecture == stanza.architecture
		})
		if !covered {
			kept = append(kept, stanza)
		}
	}
	return kept
}

// MaxStatusFileSize bounds an existing dpkg status file read during synthesis. The
// file arrives from selected packages and artifacts, so it is untrusted input like
// any other; the bound keeps a hostile one from being parsed in full.
const MaxStatusFileSize = 64 << 20

func parseStatusStanzas(content []byte) ([]statusStanza, error) {
	if len(content) > MaxStatusFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", StatusPath, MaxStatusFileSize)
	}
	var stanzas []statusStanza
	for block := range strings.SplitSeq(string(content), "\n\n") {
		block = strings.Trim(block, "\n")
		if block == "" {
			continue
		}
		stanza, err := parseStatusStanza(block)
		if err != nil {
			return nil, err
		}
		stanzas = append(stanzas, stanza)
	}
	return stanzas, nil
}
func parseStatusStanza(block string) (statusStanza, error) {
	stanza := statusStanza{text: block}
	for line := range strings.SplitSeq(block, "\n") {
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch field {
		case fieldPackage:
			stanza.name = strings.TrimSpace(value)
		case fieldArchitecture:
			stanza.architecture = strings.TrimSpace(value)
		}
	}
	if stanza.name == "" {
		return statusStanza{}, fmt.Errorf("%s has a record without a package name", StatusPath)
	}
	return stanza, nil
}
