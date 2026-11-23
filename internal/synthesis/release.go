package synthesis

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/vfs"
)

// Release database locations. Ubuntu ships both and makes /etc a symlink to the
// /usr/lib file, so synthesis writes whichever the image already uses and keeps
// the two consistent when both are regular files.
const (
	OSReleasePath       = "/usr/lib/os-release"
	OSReleaseLegacyPath = "/etc/os-release"
)

// ReleaseOrigin attributes synthesized release state to the specification.
var ReleaseOrigin = vfs.Origin{Path: "filesystem.os-release"}

// identityFields are the os-release keys a provider may own, in serialization
// order. A specification cannot override them, and synthesis writes the provider's
// value whenever it supplies one.
var identityFields = []string{
	"ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME", "UBUNTU_CODENAME",
}

// descriptiveFields are the keys a specification may override.
var descriptiveFields = []string{
	"NAME", "PRETTY_NAME", "VERSION", "HOME_URL", "DOCUMENTATION_URL",
	"SUPPORT_URL", "BUG_REPORT_URL", "LOGO",
}

// Release applies os-release overrides and fills missing release state from the
// provider. Selected state is preserved except where the specification
// overrides a descriptive field or the provider owns an identity field.
func Release(tree *vfs.Tree, identity, overrides map[string]string) error {
	if tree == nil {
		return errors.New("release synthesis requires an image tree")
	}
	if err := validateOverrides(overrides); err != nil {
		return err
	}
	existing, err := readRelease(tree)
	if err != nil {
		return err
	}
	merged := mergeRelease(existing, identity, overrides)
	if err := checkIdentity(existing, identity); err != nil {
		return err
	}
	// Both release files are written, so the write is staged: a failure at the
	// second location must not leave the first one updated.
	staged := tree.Clone()
	if err := writeRelease(staged, merged); err != nil {
		return err
	}
	return tree.Replace(staged)
}

// validateOverrides rejects an override the schema should already have refused,
// so synthesis cannot be used as a way around the identity rule.
func validateOverrides(overrides map[string]string) error {
	for key, value := range overrides {
		if !slices.Contains(descriptiveFields, key) {
			return fmt.Errorf("release field %q is not a descriptive field", key)
		}
		if strings.ContainsFunc(value, func(r rune) bool {
			return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
		}) {
			return fmt.Errorf("release field %q must be a single line", key)
		}
	}
	return nil
}

// mergeRelease layers the selected state, the provider's fields and the overrides.
// An identity field takes the provider's value, so an image cannot claim a release
// it was not built from. A provider's descriptive field only fills a gap: the
// image's own release state is more specific than a distribution default.
func mergeRelease(existing, identity, overrides map[string]string) map[string]string {
	merged := make(map[string]string, len(existing)+len(identity)+len(overrides))
	maps.Copy(merged, existing)
	for field, value := range identity {
		if !slices.Contains(identityFields, field) {
			if merged[field] == "" {
				merged[field] = value
			}
			continue
		}
		if value != "" {
			merged[field] = value
		}
	}
	maps.Copy(merged, overrides)
	return merged
}

// checkIdentity fails when selected release state contradicts the provider. A
// package that ships a different distribution's os-release is a mistake worth
// reporting rather than silently overwriting.
//
// A provider value that is present but empty says the distribution has no such
// field, so a claim of one is refused rather than rewritten: Debian publishes no
// UBUNTU_CODENAME, and inventing one would be a lie about the image. A field the
// provider leaves out is not its business and stays as the package released it.
func checkIdentity(existing, identity map[string]string) error {
	for _, field := range identityFields {
		wanted, pinned := identity[field]
		if !pinned {
			continue
		}
		found := existing[field]
		if found == "" {
			continue
		}
		if wanted == "" {
			return fmt.Errorf("selected os-release declares %s %q, which the image release does not",
				field, found)
		}
		if found != wanted {
			return fmt.Errorf("selected os-release %s is %q but the image is %q", field, found, wanted)
		}
	}
	return nil
}

// readRelease loads the image's release state from every location that holds a
// regular file. Both are read because writeRelease updates both, so a second file
// with a different identity would otherwise be overwritten without ever being
// checked.
//
// A symlink is followed to the file it names, because that file is what a reader
// of the image sees: skipping the link would leave contradictory identity in place
// and a dangling one dangling. Two locations resolving to the same file are read
// once, so a link to the other release file is not a disagreement with itself.
//
// When both hold state the /usr/lib file wins, matching the order a reader of the
// image would see, but an identity field the two disagree on fails: they describe
// the same image, so a disagreement means one of them is wrong and would otherwise
// be overwritten without ever being read.
func readRelease(tree *vfs.Tree) (map[string]string, error) {
	targets, err := releaseTargets(tree)
	if err != nil {
		return nil, err
	}
	states := make(map[string]map[string]string, len(targets))
	for _, effective := range targets {
		if _, done := states[effective]; done {
			continue
		}
		parsed, err := readReleaseFile(tree, effective)
		if errors.Is(err, errNoReleaseFile) {
			continue
		}
		if err != nil {
			return nil, err
		}
		states[effective] = parsed
	}
	if err := checkLocationsAgree(states, targets); err != nil {
		return nil, err
	}
	merged := map[string]string{}
	for _, effective := range targets {
		maps.Copy(merged, states[effective])
	}
	return merged, nil
}

// errNoReleaseFile reports a release location that holds no regular file.
var errNoReleaseFile = errors.New("no release file")

// readReleaseFile parses one release file. A location holding no regular file is
// reported as errNoReleaseFile so the caller can skip it.
func readReleaseFile(tree *vfs.Tree, location string) (map[string]string, error) {
	entry, ok := tree.Lookup(location)
	if !ok || entry.Kind != vfs.File {
		return nil, errNoReleaseFile
	}
	content, err := tree.Read(location)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", location, err)
	}
	return parseRelease(location, content)
}

// releaseTargets resolves both release locations to the files they lead to, in the
// order a reader of the image sees them: the legacy path first, so the /usr/lib
// file wins when both hold state.
//
// A link is followed inside the image rather than skipped. Skipping it would leave
// a contradictory identity in place and a dangling one dangling, and the file it
// names is what a reader actually sees.
func releaseTargets(tree *vfs.Tree) ([]string, error) {
	targets := make([]string, 0, 2)
	for _, location := range []string{OSReleaseLegacyPath, OSReleasePath} {
		entry, ok := tree.Lookup(location)
		if !ok {
			continue
		}
		if entry.Kind != vfs.Symlink {
			targets = append(targets, location)
			continue
		}
		resolved, err := tree.Resolve(location)
		if err != nil {
			return nil, fmt.Errorf("%s cannot be resolved: %w", location, err)
		}
		// A link to nothing is refused rather than followed into a new file: the
		// image would then carry release identity at a path nothing declares, and a
		// reader of the standard location would still see a broken link.
		if target, ok := tree.Lookup(resolved); !ok || target.Kind != vfs.File {
			return nil, fmt.Errorf("%s is a symlink to %s, which is not a release file", location, resolved)
		}
		targets = append(targets, resolved)
	}
	return targets, nil
}

// checkLocationsAgree reports an identity field the two release files disagree on.
func checkLocationsAgree(states map[string]map[string]string, targets []string) error {
	if len(targets) < 2 || targets[0] == targets[1] {
		return nil
	}
	legacy, ok := states[targets[0]]
	if !ok {
		return nil
	}
	library, ok := states[targets[1]]
	if !ok {
		return nil
	}
	for _, field := range identityFields {
		if found, ok := legacy[field]; ok && found != library[field] {
			return fmt.Errorf("%s has %s %q but %s has %q",
				targets[0], field, found, targets[1], library[field])
		}
	}
	return nil
}

// writeRelease serializes the merged state in a stable key order and updates
// every release file the image has, so /etc and /usr/lib cannot drift apart.
func writeRelease(tree *vfs.Tree, merged map[string]string) error {
	if len(merged) == 0 {
		return nil
	}
	content := []byte(serializeRelease(merged))
	targets, err := releaseTargets(tree)
	if err != nil {
		return err
	}
	for _, effective := range targets {
		entry, ok := tree.Lookup(effective)
		if !ok {
			continue
		}
		// A release location holding something other than a file is refused rather
		// than skipped: silently leaving it would report success while the image
		// still describes a different release there.
		if entry.Kind != vfs.File {
			return fmt.Errorf("%s is not a regular file", effective)
		}
		if err := tree.ReplaceFile(effective, content); err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return tree.File(OSReleasePath, content, vfs.Attrs{Mode: 0o644, Origin: ReleaseOrigin})
	}
	return nil
}

// serializeRelease emits KEY="value" lines in a fixed order. Identity fields come
// first, then descriptive fields alphabetically, so the output does not depend on
// map iteration.
func serializeRelease(fields map[string]string) string {
	ordered := make([]string, 0, len(fields))
	for _, field := range identityFields {
		if _, ok := fields[field]; ok {
			ordered = append(ordered, field)
		}
	}
	rest := make([]string, 0, len(fields))
	for field := range fields {
		if !slices.Contains(identityFields, field) {
			rest = append(rest, field)
		}
	}
	slices.Sort(rest)
	ordered = append(ordered, rest...)
	var builder strings.Builder
	for _, field := range ordered {
		builder.WriteString(field)
		builder.WriteString(`="`)
		builder.WriteString(escapeRelease(fields[field]))
		builder.WriteString("\"\n")
	}
	return builder.String()
}

// escapeRelease escapes the characters that would otherwise end the quoted value.
func escapeRelease(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
	return replacer.Replace(value)
}
