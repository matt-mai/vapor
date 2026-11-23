// Package hardening applies the post-synthesis passes that remove tooling and
// privileged bits from a committed image tree.
package hardening

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/policy"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Pass names as they appear in failures.
const (
	stripDocs      = "strip-docs"
	stripShells    = "strip-shells"
	stripAptDpkg   = "strip-apt-dpkg"
	removeSUIDSGID = "remove-suid-sgid"
)

// declaredOrigin is the origin path of an applied filesystem.paths[] entry.
const declaredOrigin = "filesystem.paths"

// shellNames is the shell inventory, spelled in both binary directories.
var shellNames = []string{
	"ash", "bash", "csh", "dash", "fish", "ksh", "ksh93", "mksh", "pdksh",
	"posh", "rbash", "sash", "sh", "yash", "zsh",
}

// packageToolNames is the apt and dpkg executable inventory.
var packageToolNames = []string{
	"apt", "apt-cache", "apt-cdrom", "apt-config", "apt-get", "apt-key", "apt-mark",
	"dpkg", "dpkg-deb", "dpkg-divert", "dpkg-maintscript-helper", "dpkg-query",
	"dpkg-split", "dpkg-statoverride", "dpkg-trigger",
}

// documentationPrefixes are removed wholesale, except copyright notices.
var documentationPrefixes = []string{"/usr/share/man", "/usr/share/info", "/usr/share/doc"}

// copyrightPrefix is the documentation directory whose notices are protected.
const copyrightPrefix = "/usr/share/doc"

// Apply runs the enabled passes on tree and returns the first conflict in sorted
// path order. A failure leaves tree unchanged.
func Apply(tree *vfs.Tree, hardening policy.Hardening) error {
	if tree == nil {
		return errors.New("hardening requires an image tree")
	}
	if err := validateFlags(hardening); err != nil {
		return err
	}
	staged := tree.Clone()
	if err := run(staged, hardening); err != nil {
		return err
	}
	return tree.Replace(staged)
}

func validateFlags(hardening policy.Hardening) error {
	for _, flag := range []struct {
		name string
		set  *bool
	}{
		{stripDocs, hardening.StripDocs},
		{stripShells, hardening.StripShells},
		{stripAptDpkg, hardening.StripAptDpkg},
		{removeSUIDSGID, hardening.RemoveSUIDSGID},
	} {
		if flag.set == nil {
			return fmt.Errorf("hardening.%s: flag is not defaulted", flag.name)
		}
	}
	return nil
}

func run(tree *vfs.Tree, hardening policy.Hardening) error {
	candidates, err := collect(tree, hardening)
	if err != nil {
		return err
	}
	if err := checkConflicts(tree, candidates); err != nil {
		return err
	}
	for _, p := range deepestFirst(candidates) {
		if err := tree.Remove(p); err != nil {
			return fmt.Errorf("hardening: %w", err)
		}
	}
	if *hardening.RemoveSUIDSGID {
		return clearPrivilegedBits(tree)
	}
	return nil
}

// collect returns the paths the enabled deletion passes would remove, keyed by
// path so a merged /usr spelling cannot count twice.
func collect(tree *vfs.Tree, hardening policy.Hardening) (map[string]string, error) {
	candidates := make(map[string]string)
	if *hardening.StripShells {
		if err := addInventory(tree, candidates, shellNames, stripShells); err != nil {
			return nil, err
		}
	}
	if *hardening.StripAptDpkg {
		if err := addInventory(tree, candidates, packageToolNames, stripAptDpkg); err != nil {
			return nil, err
		}
	}
	if *hardening.StripDocs {
		addDocumentation(tree, candidates)
		if err := protectNoticeTargets(tree, candidates); err != nil {
			return nil, err
		}
	}
	dropNonEmptyDirectories(tree, candidates)
	return candidates, nil
}

// protectNoticeTargets keeps the content a protected notice links to. A notice is
// often a link into another documentation directory, and the link validator allows
// a missing target, so removing the target would leave the notice dangling without
// any error. A chain of links is followed one hop at a time so every link in it
// survives too.
//
// The documentation directory of a package is itself often a link, pointing at a
// directory shared by several packages. Removing that link removes the only path to
// the notice it holds, so a directory whose copyright a link leads to is kept as
// well, even though it looks like any other documentation directory.
func protectNoticeTargets(tree *vfs.Tree, candidates map[string]string) error {
	for _, entry := range tree.Entries() {
		if entry.Kind != vfs.Symlink || !isCopyright(entry.Path) {
			continue
		}
		if err := protectChain(tree, candidates, entry.Path, entry.Target); err != nil {
			return err
		}
	}
	return protectDirectoryLinks(tree, candidates)
}

// protectDirectoryLinks keeps the documentation links that are directories holding a
// notice. The pass above follows a notice's own links, so it never visits these: they
// are directories, not copyright notices themselves.
func protectDirectoryLinks(tree *vfs.Tree, candidates map[string]string) error {
	for _, entry := range tree.Entries() {
		if entry.Kind != vfs.Symlink || isCopyright(entry.Path) || !underDocumentation(entry.Path) {
			continue
		}
		if _, held := candidates[entry.Path]; !held {
			continue
		}
		keeps, err := holdsNotice(tree, entry.Path)
		if err != nil {
			return err
		}
		if keeps {
			delete(candidates, entry.Path)
		}
	}
	return nil
}

// holdsNotice reports whether the directory a documentation link points at holds a
// copyright notice, or a link that leads to one.
func holdsNotice(tree *vfs.Tree, link string) (bool, error) {
	// Bounded the same way protectChain is: confinement refuses a cycle, and this only
	// stops a pathological tree from being walked.
	for range len(tree.Entries()) {
		resolved, err := tree.Resolve(link)
		if err != nil {
			return false, fmt.Errorf("hardening.%s: %s: %w", stripDocs, link, err)
		}
		entry, exists := tree.Lookup(resolved)
		if !exists {
			return false, nil
		}
		switch entry.Kind {
		case vfs.Symlink:
			link = resolved
		case vfs.Dir:
			return treeHasCopyright(tree, resolved)
		default:
			return false, nil
		}
	}
	return false, fmt.Errorf("hardening.%s: %s links to too many targets", stripDocs, link)
}

// treeHasCopyright reports whether a documentation directory holds a notice, either
// directly or through one of the entries below it.
func treeHasCopyright(tree *vfs.Tree, dir string) (bool, error) {
	for _, entry := range tree.Entries() {
		if !strings.HasPrefix(entry.Path, dir+"/") {
			continue
		}
		if isCopyright(entry.Path) {
			return true, nil
		}
	}
	return false, nil
}

func protectChain(tree *vfs.Tree, candidates map[string]string, link, target string) error {
	// Bounded by the entry count: confinement already refuses a cycle, and this
	// only stops a pathological tree from being walked for each hop.
	for range len(tree.Entries()) {
		property := target
		if !path.IsAbs(property) {
			property = path.Join(path.Dir(link), property)
		}
		// The final component is kept rather than resolved: an intermediate hop is
		// itself a link, and it has to survive too.
		resolved, err := resolveAncestors(tree, property)
		if err != nil {
			return fmt.Errorf("hardening.%s: %s: %w", stripDocs, link, err)
		}
		entry, exists := tree.Lookup(resolved)
		if !exists {
			return nil
		}
		delete(candidates, resolved)
		if entry.Kind != vfs.Symlink {
			return nil
		}
		link, target = resolved, entry.Target
	}
	return fmt.Errorf("hardening.%s: %s links to too many targets", stripDocs, link)
}

// addDocumentation records every explicit entry under a documentation prefix,
// except the copyright notices that must survive.
func addDocumentation(tree *vfs.Tree, candidates map[string]string) {
	for _, entry := range tree.Entries() {
		if entry.Implicit || !underDocumentation(entry.Path) || isCopyright(entry.Path) {
			continue
		}
		candidates[entry.Path] = stripDocs
	}
}

// addInventory resolves each name's ancestors and records the entries that exist
// as a file or symlink. A directory at an inventory path is left alone.
func addInventory(tree *vfs.Tree, candidates map[string]string, names []string, pass string) error {
	for _, dir := range []string{"/usr/bin", "/bin"} {
		for _, name := range names {
			resolved, err := resolveAncestors(tree, dir+"/"+name)
			if err != nil {
				return fmt.Errorf("hardening.%s: %w", pass, err)
			}
			entry, ok := tree.Lookup(resolved)
			if !ok || entry.Implicit || entry.Kind == vfs.Dir {
				continue
			}
			candidates[resolved] = pass
		}
	}
	return nil
}

// resolveAncestors resolves the parent of p and keeps the final component, so a
// symlink at p is removed as a link rather than followed.
func resolveAncestors(tree *vfs.Tree, p string) (string, error) {
	parent, base := path.Split(p)
	resolved, err := tree.Resolve(path.Clean(parent))
	if err != nil {
		return "", err
	}
	return path.Join(resolved, base), nil
}

// dropNonEmptyDirectories removes a candidate directory that still holds a child
// which is not a candidate, deepest first, so a directory survives exactly when
// something inside it survives. Children are grouped by parent from Entries
// rather than read through Tree.Children, whose directory suffix is a display
// convention this decision must not depend on.
func dropNonEmptyDirectories(tree *vfs.Tree, candidates map[string]string) {
	children := make(map[string][]string)
	for _, entry := range tree.Entries() {
		parent := path.Dir(entry.Path)
		children[parent] = append(children[parent], entry.Path)
	}
	for _, p := range deepestFirst(candidates) {
		entry, ok := tree.Lookup(p)
		if !ok || entry.Kind != vfs.Dir {
			continue
		}
		// Deepest first, so a child directory that survives has already been
		// dropped from candidates and is seen here as a survivor.
		for _, child := range children[p] {
			if _, removed := candidates[child]; !removed {
				delete(candidates, p)
				break
			}
		}
	}
}

// checkConflicts fails when a declared or synthesized entry would be removed. A
// directory is only a candidate when everything below it is, so a declared entry
// below a removed directory is itself a candidate and fails here first.
func checkConflicts(tree *vfs.Tree, candidates map[string]string) error {
	for _, p := range sortedPaths(candidates) {
		entry, ok := tree.Lookup(p)
		if !ok {
			continue
		}
		origin, conflict := conflictOrigin(entry.Origins)
		if !conflict {
			continue
		}
		pass := candidates[p]
		if origin == declaredOrigin {
			return fmt.Errorf("hardening.%s: %s is declared in %s; disable %s or remove the declaration",
				pass, p, declaredOrigin, pass)
		}
		return fmt.Errorf("hardening.%s: %s was written by %s; disable %s or stop writing it",
			pass, p, origin, pass)
	}
	return nil
}

// conflictOrigin reports the origin that protects an entry. Only origins without
// a package or slice are Vapor's own: everything else is package or artifact
// content that hardening may remove.
func conflictOrigin(origins []vfs.Origin) (string, bool) {
	for _, origin := range origins {
		if origin.Package != "" || origin.Slice != "" {
			continue
		}
		if origin.Path == declaredOrigin || strings.HasPrefix(origin.Path, "filesystem.") {
			return origin.Path, true
		}
	}
	return "", false
}

// clearPrivilegedBits clears setuid and setgid on every entry that has a mode.
// The tree clears them per inode in one pass, so every name of a hard link
// changes together and a tree with many privileged files stays linear.
func clearPrivilegedBits(tree *vfs.Tree) error {
	if err := tree.ClearModeBits(fs.ModeSetuid | fs.ModeSetgid); err != nil {
		return fmt.Errorf("hardening.%s: %w", removeSUIDSGID, err)
	}
	return nil
}

func underDocumentation(p string) bool {
	for _, prefix := range documentationPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// isCopyright reports /usr/share/doc/<package>/copyright, the only protected
// documentation path.
func isCopyright(p string) bool {
	rest, ok := strings.CutPrefix(p, copyrightPrefix+"/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) == 2 && parts[1] == "copyright"
}

func sortedPaths(candidates map[string]string) []string {
	paths := make([]string, 0, len(candidates))
	for p := range candidates {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// deepestFirst orders paths so every child precedes its parent.
func deepestFirst(candidates map[string]string) []string {
	paths := sortedPaths(candidates)
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	return paths
}
