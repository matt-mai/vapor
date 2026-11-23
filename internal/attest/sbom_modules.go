package attest

import (
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// A vendored module is a package a payload carries rather than the payload itself: the
// npm tree inside a Node.js deb, the wheel metadata beside a Python build. The lock
// names the payload and nothing inside it, so without this an image that ships 186
// libraries is described as holding one package and stays silent about the rest.
//
// Every ecosystem publishes the same two facts under its own manifest, so detection is
// one table rather than a walker per ecosystem.
type moduleEcosystem struct {
	// kind is the package URL type the ecosystem is published under.
	kind string
	// manifest reports whether a file name is this ecosystem's manifest.
	manifest func(name string) bool
	// parse reads the manifest's bytes. A manifest states one identity except for a Go
	// vendor list, which states one per vendored module.
	parse func(data []byte) ([]moduleName, error)
	// root is the directory a module's files live in, relative to the manifest's own
	// directory. Empty when they sit beside the manifest.
	root string
	// files overrides root when a manifest holds several modules whose content sits at
	// a path each of them names.
	files func(manifest string, stated moduleName, entries []vfs.Entry) []string
}

// moduleName is the identity one manifest states.
type moduleName struct {
	namespace string
	name      string
	version   string
}

// moduleEcosystems lists the manifest shapes Vapor reads. The order is fixed, so a tree
// holding several describes them the same way on every build.
var moduleEcosystems = []moduleEcosystem{
	{kind: "npm", manifest: func(name string) bool { return name == "package.json" },
		parse: parseNPM},
	// Installed distributions keep their metadata in <name>-<version>.dist-info and the
	// files themselves beside it.
	{kind: "pypi", manifest: func(name string) bool {
		return name == "METADATA" || name == "PKG-INFO"
	}, parse: parsePython, root: ".."},
	{kind: "nuget", manifest: func(name string) bool {
		return strings.EqualFold(path.Ext(name), ".nuspec")
	}, parse: parseNuGet, root: ".."},
	// A Go vendor list is the only file that states a module's version: go.mod names a
	// main module and no version, because the version comes from the dependency it was
	// required at.
	{kind: "golang", manifest: func(name string) bool { return name == "modules.txt" },
		parse: parseGoModulesTxt, files: golangFiles},
	{kind: "maven", manifest: func(name string) bool { return name == "pom.properties" },
		parse: parseMaven, root: ".."},
	{kind: "gem", manifest: func(name string) bool { return path.Ext(name) == ".gemspec" },
		parse: parseGemspec, root: ".."},
}

// errNotAModule reports a manifest that states no usable identity: a package.json for a
// project without a version, a gemspec that builds its version from a constant. Those are
// build inputs rather than installed modules, and claiming one would invent a package.
var errNotAModule = fmt.Errorf("attest: manifest states no module identity")

// moduleElement describes one vendored module. Its identity is derived from the module
// itself rather than from the payload that carried it, so the same module version in two
// images is one element and an advisory matches both.
func moduleElement(found *module) (*element, error) {
	identity, err := Identity(DomainModule, modulePayload{
		Kind:      found.kind,
		Namespace: found.namespace,
		Name:      found.name,
		Version:   found.version,
	})
	if err != nil {
		return nil, err
	}
	return &element{
		kind:     kindModule,
		key:      found.key(),
		reported: found.display(),
		version:  found.version,
		locator:  found.locator(),
		identity: identity,
	}, nil
}

// module is one vendored module found in the finished tree.
type module struct {
	kind      string
	namespace string
	name      string
	version   string
	// files are every path the module's directory holds.
	files []string
}

// display is the name the ecosystem itself uses: a scoped npm package states "at scope/name"
// while its package URL splits that into a namespace and a name, and a scanner matches on
// both the package URL and the name it reads.
func (found *module) display() string {
	if found.namespace == "" {
		return found.name
	}
	if strings.HasPrefix(found.namespace, "@") {
		return found.namespace + "/" + found.name
	}
	return found.name
}

// key is what two manifests stating the same identity share.
func (found *module) key() string {
	return found.kind + "\x00" + found.namespace + "\x00" + found.name + "\x00" + found.version
}

// locator is the package URL a scanner matches advisories against. A namespace keeps its
// slashes, because a Go module path and a Maven group ID are both written as segments; only
// the characters inside a segment are escaped.
func (found *module) locator() string {
	locator := "pkg:" + found.kind + "/"
	if found.namespace != "" {
		segments := strings.Split(found.namespace, "/")
		for index := range segments {
			segments[index] = purlEscape(segments[index])
		}
		locator += strings.Join(segments, "/") + "/"
	}
	// A Go module's own tag carries a leading v that a package URL does not.
	return locator + purlEscape(found.name) + "@" +
		purlEscape(strings.TrimPrefix(found.version, "v"))
}

// modulePayload is the identity of one vendored module. It is the module's own
// ecosystem, namespace, name and version, so the same module version in two images is one
// element and an advisory matches both. The platform is deliberately absent: a module is
// the same package wherever it was installed, and an advisory is filed once for it.
type modulePayload struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// discoverModules reads every manifest in the finished tree. The result is ordered by
// ecosystem and identity, so two builds of the same inputs describe them identically.
func discoverModules(tree *vfs.Tree) ([]*module, error) {
	entries := tree.Entries()
	seen := map[string]*module{}
	for position := range entries {
		entry := &entries[position]
		if entry.Kind != vfs.File {
			continue
		}
		if err := recordManifests(tree, entry, entries, seen); err != nil {
			return nil, err
		}
	}
	found := make([]*module, 0, len(seen))
	for _, current := range seen {
		found = append(found, current)
	}
	sort.Slice(found, func(left, right int) bool {
		return found[left].key() < found[right].key()
	})
	return found, nil
}

// recordManifests reads every manifest shape one file could be and records what it states.
func recordManifests(tree *vfs.Tree, entry *vfs.Entry, entries []vfs.Entry,
	seen map[string]*module,
) error {
	name := path.Base(entry.Path)
	for index := range moduleEcosystems {
		ecosystem := &moduleEcosystems[index]
		if !ecosystem.manifest(name) {
			continue
		}
		stated, err := readManifest(tree, entry, ecosystem)
		if err != nil {
			return err
		}
		for _, current := range stated {
			found := &module{kind: ecosystem.kind, namespace: current.namespace,
				name: current.name, version: current.version}
			files := rootOf(entry.Path, ecosystem, current, entries)
			if existing, taken := seen[found.key()]; taken {
				// The same module installed at two paths is one package; both file sets
				// belong to it, because both are in the image.
				existing.files = append(existing.files, files...)
				continue
			}
			found.files = files
			seen[found.key()] = found
		}
	}
	return nil
}

// rootOf lists the files of one module: the entries under the directory its manifest
// declares, or the manifest itself when the ecosystem keeps nothing else.
func rootOf(manifest string, ecosystem *moduleEcosystem, stated moduleName,
	entries []vfs.Entry,
) []string {
	if ecosystem.files != nil {
		return ecosystem.files(manifest, stated, entries)
	}
	root := path.Dir(manifest)
	if ecosystem.root != "" {
		root = path.Join(root, ecosystem.root)
	}
	prefix := root + "/"
	found := make([]string, 0)
	for position := range entries {
		if entries[position].Kind != vfs.File {
			continue
		}
		if strings.HasPrefix(entries[position].Path, prefix) {
			found = append(found, entries[position].Path)
		}
	}
	return found
}

// readManifest reads one manifest. A manifest that states no identity reports nil, which
// the caller skips: it is a build input, not an installed module.
func readManifest(tree *vfs.Tree, entry *vfs.Entry, ecosystem *moduleEcosystem) (
	[]moduleName, error,
) {
	if entry.Size > maxManifestSize {
		return nil, fmt.Errorf("attest: %s is larger than a manifest", entry.Path)
	}
	reader, err := tree.OpenFile(entry.Path)
	if err != nil {
		return nil, fmt.Errorf("attest: read %s: %w", entry.Path, err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("attest: read %s: %w", entry.Path, err)
	}
	stated, err := ecosystem.parse(data)
	if errors.Is(err, errNotAModule) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("attest: read %s: %w", entry.Path, err)
	}
	return stated, nil
}

// maxManifestSize bounds a file Vapor will read as a manifest. A manifest is metadata,
// so one larger than this is not the file its name claims.
const maxManifestSize = 1 << 20

// parseNPM reads the name and version a package.json states. A scoped name "at scope/name"
// keeps the scope as the package URL namespace with its leading at-sign, which the package
// URL specification requires and a scanner matches on.
func parseNPM(data []byte) ([]moduleName, error) {
	fields, err := jsonStrings(data)
	if err != nil {
		return nil, err
	}
	namespace, name, scoped := strings.Cut(fields["name"], "/")
	if !scoped || !strings.HasPrefix(namespace, "@") {
		namespace, name = "", fields["name"]
	}
	return one(identityOf(name, namespace, fields["version"]))
}

// parsePython reads the Name and Version of a distribution's metadata.
func parsePython(data []byte) ([]moduleName, error) {
	fields := headerFields(data)
	return one(identityOf(fields["Name"], "", fields["Version"]))
}

// parseNuGet reads a .nuspec's id and version, which share a name with dependency entries
// inside the same document, so only the metadata element's own tags are read.
func parseNuGet(data []byte) ([]moduleName, error) {
	return one(identityOf(tagText(data, "id"), "", tagText(data, "version")))
}

// parseMaven reads pom.properties.
func parseMaven(data []byte) ([]moduleName, error) {
	fields := equalsFields(data)
	return one(identityOf(fields["artifactId"], fields["groupId"], fields["version"]))
}

// parseGemspec reads the name and version a gemspec assigns.
func parseGemspec(data []byte) ([]moduleName, error) {
	return one(identityOf(gemspecValue(data, "name"), "", gemspecValue(data, "version")))
}

// one wraps a single identity so every parser has the same shape.
func one(stated moduleName, err error) ([]moduleName, error) {
	if err != nil {
		return nil, err
	}
	return []moduleName{stated}, nil
}

// identityOf refuses a manifest that states no usable identity.
func identityOf(name, namespace, version string) (moduleName, error) {
	if name == "" || version == "" {
		return moduleName{}, errNotAModule
	}
	return moduleName{namespace: namespace, name: name, version: version}, nil
}

// jsonStrings reads the top-level string fields of a JSON object without a decoder.
// package.json files in the wild carry comments and trailing commas, which a decoder
// rejects while a scanner accepts them. Only the outermost object's fields count: a
// nested "author": {"name": ...} states a person, not the module.
func jsonStrings(data []byte) (map[string]string, error) {
	fields := map[string]string{}
	start := skipSpace(data, 0)
	if start >= len(data) || data[start] != '{' {
		return fields, nil
	}
	for index := start + 1; index < len(data); {
		key, value, next, found, err := scanJSONField(data, index)
		if err != nil {
			return nil, err
		}
		if found {
			fields[key] = value
		}
		if next <= index {
			return fields, nil
		}
		index = next
	}
	return fields, nil
}

// scanJSONField reads one field of an object body starting at index. It returns the index
// to continue from, which is the closing brace's position once the body ends.
func scanJSONField(data []byte, index int) (string, string, int, bool, error) {
	switch data[index] {
	case '}':
		return "", "", len(data), false, nil
	case '{', '[':
		return "", "", skipValue(data, index), false, nil
	case '"':
		key, next, err := scanJSONString(data, index)
		if err != nil {
			return "", "", 0, false, err
		}
		value, after, found, err := scanJSONValue(data, next)
		if err != nil {
			return "", "", 0, false, err
		}
		if !found {
			return "", "", next, false, nil
		}
		return key, value, after, true, nil
	}
	return "", "", index + 1, false, nil
}

// skipValue returns the index after the value that starts at this position, counting
// braces and brackets so a nested object's fields are never read as the outer object's.
func skipValue(data []byte, start int) int {
	open := data[start]
	closing := byte('}')
	if open == '[' {
		closing = ']'
	}
	depth := 0
	for index := start; index < len(data); index++ {
		switch data[index] {
		case '"':
			_, next, err := scanJSONString(data, index)
			if err != nil {
				return len(data)
			}
			index = next - 1
		case open:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return index + 1
			}
		}
	}
	return len(data)
}

// scanJSONValue reads a key's quoted value after its colon, and reports whether the value
// after this key was a string at all.
func scanJSONValue(data []byte, start int) (string, int, bool, error) {
	start = skipSpace(data, start)
	if start >= len(data) || data[start] != ':' {
		return "", start, false, nil
	}
	start = skipSpace(data, start+1)
	if start >= len(data) || data[start] != '"' {
		return "", start, false, nil
	}
	value, next, err := scanJSONString(data, start)
	return value, next, err == nil, err
}

// skipSpace advances past the whitespace a JSON object may hold between tokens.
func skipSpace(data []byte, start int) int {
	for start < len(data) && isSpace(data[start]) {
		start++
	}
	return start
}

// scanJSONString reads one quoted string from its opening quote and returns the index
// after its closing quote.
func scanJSONString(data []byte, start int) (string, int, error) {
	var built strings.Builder
	for index := start + 1; index < len(data); index++ {
		switch data[index] {
		case '\\':
			if index+1 >= len(data) {
				return "", 0, fmt.Errorf("attest: unterminated escape in a manifest")
			}
			index++
			built.WriteByte(data[index])
		case '"':
			return built.String(), index + 1, nil
		default:
			built.WriteByte(data[index])
		}
	}
	return "", 0, fmt.Errorf("attest: unterminated string in a manifest")
}

// headerFields reads the first value of each key in a header block.
func headerFields(data []byte) map[string]string {
	fields := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if !found {
			continue
		}
		if _, taken := fields[key]; !taken {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

// equalsFields reads key=value lines, which is the shape pom.properties uses. A header
// block uses a colon, so the two readers stay separate rather than guessing at a line.
func equalsFields(data []byte) map[string]string {
	fields := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !found {
			continue
		}
		if _, taken := fields[key]; !taken {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

// tagText reads the text of the first element with this tag.
func tagText(data []byte, tag string) string {
	open, closing := "<"+tag+">", "</"+tag+">"
	text := string(data)
	start := strings.Index(text, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(text[start:], closing)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(text[start : start+end])
}

// gemspecAssignment matches the assignment shape a gemspec states its identity in.
var gemspecAssignment = regexp.MustCompile(`(?m)\.(name|version)\s*=\s*["']([^"']+)["']`)

// gemspecValue reads the value a gemspec assigns to one attribute.
func gemspecValue(data []byte, attribute string) string {
	for _, match := range gemspecAssignment.FindAllStringSubmatch(string(data), -1) {
		if match[1] == attribute {
			return match[2]
		}
	}
	return ""
}

// isSpace reports the whitespace a JSON object may hold between tokens.
func isSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// parseGoModulesTxt reads a Go vendor list, which is the one file that states a vendored
// module's version. A "# path version" line names a module and the "## explicit" comment
// after it says the main module requires it, so only those are modules the build holds on
// purpose; the rest are the transitive closure of one.
func parseGoModulesTxt(data []byte) ([]moduleName, error) {
	stated := make([]moduleName, 0)
	candidate, version := "", ""
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "## explicit"):
			if candidate != "" {
				stated = append(stated, goName(candidate, version))
			}
			candidate, version = "", ""
		case strings.HasPrefix(line, "# "):
			name, rest, _ := strings.Cut(line[2:], " ")
			if rest != "" {
				candidate, version = name, rest
			}
		}
	}
	if len(stated) == 0 {
		return nil, errNotAModule
	}
	return stated, nil
}

// goName splits a module path at its last slash, because a package URL names a Go module's
// path as the namespace and its final segment as the name.
func goName(modulePath, version string) moduleName {
	modulePath = strings.TrimSuffix(modulePath, "/")
	if !strings.Contains(modulePath, "/") {
		return moduleName{name: modulePath, version: version}
	}
	return moduleName{namespace: path.Dir(modulePath), name: path.Base(modulePath),
		version: version}
}

// golangFiles lists the files of one vendored Go module, which sit in a directory named by
// the module path rather than beside the vendor list.
func golangFiles(manifest string, stated moduleName, entries []vfs.Entry) []string {
	root := path.Join(path.Dir(manifest), stated.namespace, stated.name)
	prefix := root + "/"
	found := make([]string, 0)
	for position := range entries {
		if entries[position].Kind != vfs.File {
			continue
		}
		if strings.HasPrefix(entries[position].Path, prefix) {
			found = append(found, entries[position].Path)
		}
	}
	return found
}
