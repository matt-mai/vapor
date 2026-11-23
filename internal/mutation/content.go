package mutation

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"go.starlark.net/starlark"
)

// contentValue is the `content` object a mutation script receives. It exposes the
// upstream v3 API and nothing else: there is no host filesystem, no network and no
// way to reach a path the selection did not provide.
type contentValue struct {
	files   map[string]fileSlot
	request *ScriptRequest
	// dirs is every directory path, including the implicit parents of a file and
	// the selected directories that hold no file.
	dirs map[string]bool
	// links maps a selected symlink path to its target, so a read can follow it
	// inside the selected content.
	links map[string]string
	// writable is the set of paths a script may write: selected mutable regular
	// files. Everything else is read-only.
	writable map[string]bool
	// hardLinks marks paths that share an inode with another path, which upstream
	// refuses to mutate.
	hardLinks map[string]bool
	// state tracks the byte bounds the script has consumed.
	state *harnessState
	// limits are the caller's bounds, so the API charges the same ones the worker
	// enforces.
	limits *SandboxLimits
}

type fileSlot struct {
	id   uint32
	size int64
}

// newContentValue builds the API over a request's content set.
func newContentValue(request *ScriptRequest, state *harnessState, limits *SandboxLimits) *contentValue {
	index := request.FileIndex
	if request.readBody == nil {
		index = indexFiles(request.Files)
	}
	files := make(map[string]fileSlot, len(index))
	for id, file := range index {
		files[file.Name] = fileSlot{id: uint32(id), size: file.Size} //nolint:gosec // bounded before dispatch
	}
	dirs := map[string]bool{"/": true}
	for _, name := range request.Dirs {
		dirs[name] = true
	}
	for name := range files {
		addParents(dirs, name)
	}
	for name := range request.Links {
		addParents(dirs, name)
	}
	writable := make(map[string]bool, len(request.Mutable))
	for _, name := range request.Mutable {
		writable[name] = true
	}
	hardLinks := make(map[string]bool, len(request.HardLinks))
	for _, name := range request.HardLinks {
		hardLinks[name] = true
	}
	return &contentValue{
		files:     files,
		request:   request,
		dirs:      dirs,
		links:     request.Links,
		writable:  writable,
		hardLinks: hardLinks,
		state:     state,
		limits:    limits,
	}
}

func addParents(dirs map[string]bool, name string) {
	for parent := path.Dir(name); parent != "/" && parent != "."; parent = path.Dir(parent) {
		dirs[parent] = true
	}
}

// contentValue implements the Starlark value protocol. It is a plain object with
// three attributes, so it is immutable from the script's point of view.
func (*contentValue) String() string        { return "content{...}" }
func (*contentValue) Type() string          { return "content" }
func (*contentValue) Freeze()               {}
func (*contentValue) Truth() starlark.Bool  { return starlark.True }
func (*contentValue) Hash() (uint32, error) { return 0, errors.New("unhashable type: content") }

func (c *contentValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "read":
		return starlark.NewBuiltin("content.read", c.read), nil
	case "write":
		return starlark.NewBuiltin("content.write", c.write), nil
	case "list":
		return starlark.NewBuiltin("content.list", c.list), nil
	}
	// An absent attribute is reported to the script as a missing field, which is how
	// Starlark signals "no such operation" for a value with attributes.
	return nil, nil //nolint:nilnil // HasAttrs contract
}

func (*contentValue) AttrNames() []string { return []string{"list", "read", "write"} }

// read returns the selected content at path as a string.
func (c *contentValue) read(
	_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
	var name starlark.String
	if err := starlark.UnpackArgs("content.read", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	cleaned, err := c.selectedPath(name.GoString(), false)
	if err != nil {
		return nil, err
	}
	resolved, err := c.resolve(cleaned)
	if err != nil {
		return nil, err
	}
	file, ok := c.files[resolved]
	if !ok {
		return nil, &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content.read: %.1024q is not selected content", cleaned),
		}
	}
	if written, ok := c.state.writes[resolved]; ok {
		if chargeErr := c.state.chargeRead(int64(len(written))); chargeErr != nil {
			return nil, chargeErr
		}
		return starlark.String(written), nil
	}
	if chargeErr := c.state.chargeRead(file.size); chargeErr != nil {
		return nil, chargeErr
	}
	if c.request.readBody == nil {
		return starlark.String(c.request.Files[resolved]), nil
	}
	body, err := c.request.readBody(file.id, file.size)
	if err != nil {
		return nil, err
	}
	return starlark.String(body), nil
}

// resolve follows the symlinks a path names, one component at a time, inside the
// selected content. Resolving only the whole path would leave an ordinary
// directory alias unusable: /alias -> /real must make /alias/data resolve to
// /real/data. A link may only lead to selected content: the worker has no
// filesystem, so a target outside the selection does not exist for it.
//
// Each hop consumes one selected link, so a chain can never be longer than the
// link set and a cycle is detected by exhausting it. A target that climbs above
// the root is clamped there, which keeps resolution inside the selection.
func (c *contentValue) resolve(name string) (string, error) {
	pending := components(name)
	resolved := "/"
	for hops := 0; len(pending) > 0; {
		next := pending[0]
		pending = pending[1:]
		candidate := path.Join(resolved, next)
		target, ok := c.links[candidate]
		if !ok {
			resolved = candidate
			continue
		}
		hops++
		if hops > len(c.links) {
			return "", &ScriptError{
				Kind:    FailureCapability,
				Message: fmt.Sprintf("content: %.1024q is a symlink loop", name),
			}
		}
		if strings.HasPrefix(target, "/") {
			resolved = "/"
		}
		pending = append(components(target), pending...)
	}
	return resolved, nil
}

// components splits a clean absolute path into its names. The root has none.
func components(name string) []string {
	trimmed := strings.TrimPrefix(name, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// write replaces the content of an existing selected mutable regular file. The
// mode is preserved because the file already exists; upstream has no mode
// parameter and neither does this.
func (c *contentValue) write(
	_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
	var name starlark.String
	var data starlark.String
	if err := starlark.UnpackArgs("content.write", args, kwargs, "path", &name, "data", &data); err != nil {
		return nil, err
	}
	cleaned, err := c.selectedPath(name.GoString(), false)
	if err != nil {
		return nil, err
	}
	file, ok := c.files[cleaned]
	if !ok {
		return nil, &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content.write: %.1024q is not selected content", cleaned),
		}
	}
	if !c.writable[cleaned] {
		return nil, &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content.write: %.1024q is not a mutable regular file", cleaned),
		}
	}
	if c.hardLinks[cleaned] {
		return nil, &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content.write: %.1024q is a hard link and cannot be mutated", cleaned),
		}
	}
	previous := file.size
	if written, ok := c.state.writes[cleaned]; ok {
		previous = int64(len(written))
	}
	if err := c.state.chargeWrite(cleaned, data.GoString(), previous, c.limits); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// list returns the sorted immediate names under a selected directory, with
// directory names suffixed by a slash.
func (c *contentValue) list(
	_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
	var name starlark.String
	if err := starlark.UnpackArgs("content.list", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	cleaned, err := c.selectedPath(name.GoString(), true)
	if err != nil {
		return nil, err
	}
	if cleaned, err = c.resolve(cleaned); err != nil {
		return nil, err
	}
	if !c.dirs[cleaned] {
		return nil, &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content.list: %.1024q is not a selected directory", cleaned),
		}
	}
	names := c.children(cleaned)
	// A listing is charged for the bytes it returns, so a script cannot enumerate a
	// huge directory for free.
	var listed int64
	for _, name := range names {
		listed += int64(len(name))
	}
	if err := c.state.chargeRead(listed); err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(names))
	for i, child := range names {
		values[i] = starlark.String(child)
	}
	return starlark.NewList(values), nil
}

// children returns the sorted immediate names under dir. A directory is suffixed
// with a slash so a script can tell the two apart without a second call.
func (c *contentValue) children(dir string) []string {
	prefix := dir
	if prefix != "/" {
		prefix += "/"
	}
	seen := make(map[string]bool)
	for name := range c.files {
		c.recordChild(name, prefix, seen)
	}
	for name := range c.dirs {
		if name != "/" {
			c.recordChild(name, prefix, seen)
		}
	}
	for name := range c.links {
		c.recordChild(name, prefix, seen)
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// recordChild adds the immediate child of prefix that name belongs to, if any.
func (c *contentValue) recordChild(name, prefix string, seen map[string]bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" {
		return
	}
	if index := strings.IndexByte(rest, '/'); index >= 0 {
		seen[rest[:index]+"/"] = true
		return
	}
	if c.dirs[prefix+rest] {
		rest += "/"
	}
	seen[rest] = true
}

// selectedPath validates an API path argument. Image paths are absolute and clean,
// and a directory argument may carry one trailing slash.
func (c *contentValue) selectedPath(value string, allowTrailingSlash bool) (string, error) {
	if !strings.HasPrefix(value, "/") {
		return "", &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content path %.1024q is not absolute", value),
		}
	}
	trimmed := value
	if allowTrailingSlash && trimmed != "/" {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	cleaned := path.Clean(trimmed)
	if cleaned != trimmed {
		return "", &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content path %.1024q is not clean", value),
		}
	}
	if strings.ContainsAny(cleaned, "\\\x00") {
		return "", &ScriptError{
			Kind:    FailureCapability,
			Message: fmt.Sprintf("content path %.1024q contains an invalid character", value),
		}
	}
	return cleaned, nil
}
