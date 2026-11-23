package synthesis

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// Debian's ca-certificates package ships the individual roots and a list of the
// enabled ones; the bundle every TLS client reads is written by
// update-ca-certificates, which runs a maintainer script during configuration.
// Vapor never runs that script, so it builds the bundle from the verified payload
// instead: the same roots, in the order the package enables them.
//
// A release that ships no configuration list still ships the roots, so the list is
// only a filter: without it every root below the package's directory is enabled.
const (
	caConfigPath = "/etc/ca-certificates.conf"
	caRootsPath  = "/usr/share/ca-certificates"
)

// defaultCertificates returns the certificates the image enables. A payload
// without any roots has nothing to derive from, which is not an error: images that
// do not install ca-certificates simply have no public roots.
func defaultCertificates(tree *vfs.Tree) ([][]byte, error) {
	config, err := tree.Read(caConfigPath)
	if errors.Is(err, vfs.ErrNotExist) {
		return allCARoots(tree)
	}
	if err != nil {
		return nil, fmt.Errorf("CA roots %s cannot be read: %w", caConfigPath, err)
	}
	var certificates [][]byte
	for line := range strings.SplitSeq(string(config), "\n") {
		name, enabled, ok := caConfigEntry(line)
		if !ok || !enabled {
			continue
		}
		parsed, err := readCARoot(tree, name)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, parsed...)
	}
	return certificates, nil
}

// allCARoots returns every root the package carries, for a release that ships the
// roots without a list of the enabled ones.
func allCARoots(tree *vfs.Tree) ([][]byte, error) {
	entries, err := tree.Children(caRootsPath)
	if errors.Is(err, vfs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("CA roots %s cannot be read: %w", caRootsPath, err)
	}
	var certificates [][]byte
	for _, entry := range entries {
		if directory, isDirectory := strings.CutSuffix(entry, "/"); isDirectory {
			certificates, err = appendCARootDirectory(tree, certificates, directory)
		} else {
			certificates, err = appendCARoot(tree, certificates, strings.TrimPrefix(entry, caRootsPath+"/"))
		}
		if err != nil {
			return nil, err
		}
	}
	return certificates, nil
}

// appendCARootDirectory adds the roots of one hashed directory, which the package
// uses to separate a vendor's roots from the Mozilla bundle.
func appendCARootDirectory(tree *vfs.Tree, certificates [][]byte, directory string) ([][]byte, error) {
	entries, err := tree.Children(directory)
	if err != nil {
		return nil, fmt.Errorf("CA roots %s cannot be read: %w", directory, err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/") {
			continue
		}
		certificates, err = appendCARoot(tree, certificates, strings.TrimPrefix(entry, caRootsPath+"/"))
		if err != nil {
			return nil, err
		}
	}
	return certificates, nil
}

func appendCARoot(tree *vfs.Tree, certificates [][]byte, name string) ([][]byte, error) {
	parsed, err := readCARoot(tree, name)
	if err != nil {
		return nil, err
	}
	return append(certificates, parsed...), nil
}

// readCARoot parses one enabled root. update-ca-certificates warns about a listed
// root the package does not carry and keeps going; it is not trust material either
// way, so a missing file is skipped.
func readCARoot(tree *vfs.Tree, name string) ([][]byte, error) {
	content, err := tree.Read(path.Join(caRootsPath, name))
	if errors.Is(err, vfs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("CA root %q cannot be read: %w", name, err)
	}
	return parseCertificates(name, content)
}

// caConfigEntry reads one line of the configuration list. Entries name a file
// below /usr/share/ca-certificates, and a leading "!" disables one that would
// otherwise be enabled.
func caConfigEntry(line string) (name string, enabled, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false, false
	}
	enabled = true
	if stripped, disabled := strings.CutPrefix(line, "!"); disabled {
		line, enabled = stripped, false
	}
	if !validCARootName(line) {
		return "", false, false
	}
	return line, enabled, true
}

// validCARootName keeps a listed root inside the package's own directory, so a
// configuration file cannot reach outside the roots it is meant to name.
func validCARootName(name string) bool {
	return name != "" && !path.IsAbs(name) && path.Clean(name) == name &&
		name != ".." && !strings.HasPrefix(name, "../")
}
