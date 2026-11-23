package mutation_test

import (
	"context"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/mutation"
)

// contentFiles is the content set the API tests run against: two mutable files, one
// immutable file, a directory with a child, and a symlink.
func contentFiles() map[string][]byte {
	return map[string][]byte{
		"/etc/app.conf":        []byte("original"),
		"/usr/share/app/data":  []byte("payload"),
		"/usr/share/app/read":  []byte("read-only"),
		"/usr/share/app/sub/x": []byte("nested"),
	}
}

// contentMutable is the mutable subset: everything else is readable but immutable.
func contentMutable() []string {
	return []string{"/etc/app.conf", "/usr/share/app/data"}
}

func TestContentReadReturnsSelectedContent(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := runScript(t, `content.write("/etc/app.conf", content.read("/usr/share/app/data"))`,
		contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "payload" {
		t.Fatalf("read returned %q", got)
	}
}

func TestContentWriteReturnsOnlyChangedFiles(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := runScript(t, `content.write("/etc/app.conf", "changed")`, contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); len(result.Writes) != 1 || got != "changed" {
		t.Fatalf("write delta = %q", result.Writes)
	}
}

func TestContentWriteReturnsNone(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// Upstream's write returns None; a script that uses it as a value must see that.
	_, err := runScript(t, `x = content.write("/etc/app.conf", "changed")
if x != None:
    fail("write returned a value")
`, contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
}

func TestContentListIsSortedAndMarksDirectories(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := runScript(t, `names = content.list("/usr/share/app")
content.write("/etc/app.conf", ",".join(names))
`, contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "data,read,sub/" {
		t.Fatalf("list returned %q", got)
	}
}

func TestContentListOfRoot(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := runScript(t, `content.write("/etc/app.conf", ",".join(content.list("/")))`,
		contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "etc/,usr/" {
		t.Fatalf("list of root returned %q", got)
	}
}

// A selected directory that holds no file still exists for a script, and a
// selected link appears in a listing and resolves to its target.
func TestContentListIncludesEmptyDirectoriesAndLinks(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script: []byte(`names = content.list("/")
content.write("/etc/app.conf", ",".join(names) + "|" + content.read("/alias"))`),
		MaxSteps: 1000,
		Files:    map[string][]byte{"/etc/app.conf": []byte("initial")},
		Dirs:     []string{"/empty"},
		Links:    map[string]string{"/alias": "etc/app.conf"},
		Mutable:  []string{"/etc/app.conf"},
	}, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "alias,empty/,etc/|initial" {
		t.Fatalf("listing and link read returned %q", got)
	}
}

func TestContentListRejectsFiles(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	_, err := runScript(t, `content.list("/etc/app.conf")`, contentFiles(), contentMutable())
	requireKind(t, err, mutation.FailureCapability)
}

func TestContentRejectsUnselectedPaths(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	cases := map[string]string{
		"host file":      `content.read("/etc/shadow")`,
		"host directory": `content.list("/proc")`,
		"relative path":  `content.read("etc/app.conf")`,
		"unclean path":   `content.read("/etc/../etc/app.conf")`,
		"trailing slash": `content.read("/etc/app.conf/")`,
		"parent escape":  `content.read("/../../etc/shadow")`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := runScript(t, script, contentFiles(), contentMutable())
			requireKind(t, err, mutation.FailureCapability)
		})
	}
}

func TestContentRejectsImmutableAndCreatedWrites(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	cases := map[string]string{
		"immutable file":   `content.write("/usr/share/app/read", "x")`,
		"created file":     `content.write("/etc/new.conf", "x")`,
		"directory":        `content.write("/usr/share/app", "x")`,
		"host path":        `content.write("/etc/shadow", "x")`,
		"unselected file":  `content.write("/tmp/out", "x")`,
		"trailing slash":   `content.write("/etc/app.conf/", "x")`,
		"parent traversal": `content.write("/etc/../etc/app.conf", "x")`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := runScript(t, script, contentFiles(), contentMutable())
			requireKind(t, err, mutation.FailureCapability)
		})
	}
}

func TestContentRejectsHardlinkWrites(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// A write to one name of a hardlink would silently change the other, so the API
	// refuses it rather than reporting a change that did not happen.
	_, err := mutation.RunScript(t.Context(), &mutation.ScriptRequest{
		Script:    []byte(`content.write("/etc/app.conf", "x")`),
		MaxSteps:  1000,
		Files:     contentFiles(),
		Mutable:   contentMutable(),
		HardLinks: []string{"/etc/app.conf"},
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCapability)
}

func TestContentReadRejectsNonStringArguments(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	cases := map[string]string{
		"missing argument": `content.read()`,
		"wrong type":       `content.read(1)`,
		"unknown keyword":  `content.read(path = "/etc/app.conf", other = 1)`,
		"write missing":    `content.write("/etc/app.conf")`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := runScript(t, script, contentFiles(), contentMutable())
			requireKind(t, err, mutation.FailureCapability)
		})
	}
}

func TestContentUnknownAttributeIsNotCallable(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// There is no host, network or process API to reach: an unknown attribute is
	// simply absent, which Starlark reports as a failure to resolve.
	_, err := runScript(t, `content.exec("/bin/sh")`, contentFiles(), contentMutable())
	requireKind(t, err, mutation.FailureCapability)
}

func TestContentHasNoHostOrNetworkPrimitives(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// The predeclared environment is exactly `content` plus Starlark's own
	// builtins: no `open`, no `socket`, no `os`.
	for _, name := range []string{"open", "socket", "os", "subprocess", "eval"} {
		t.Run(name, func(t *testing.T) {
			_, err := runScript(t, name, contentFiles(), contentMutable())
			requireKind(t, err, mutation.FailureCapability)
		})
	}
}

func TestContentListChargesTheReadBound(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	limits := sandboxLimits()
	limits.MaxReadBytes = 4
	_, err := mutation.RunScript(t.Context(), &mutation.ScriptRequest{
		Script:   []byte(`content.list("/usr/share/app")`),
		MaxSteps: 1000,
		Files:    contentFiles(),
	}, limits)
	requireKind(t, err, mutation.FailureRead)
}

func TestContentStepsAreChargedPerScript(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// Two scripts that each fit the budget must both run: the budget is per
	// top-level script, not shared across the selection.
	limits := sandboxLimits()
	requests := []mutation.Request{
		{Name: "first", Script: []byte(`content.read("/etc/app.conf")`), MaxSteps: 200},
		{Name: "second", Script: []byte(`content.read("/etc/app.conf")`), MaxSteps: 200},
	}
	tree := imageTree(t)
	if _, err := mutation.Mutate(t.Context(), tree, mutablePaths(), requests, limits); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
}

func TestContentStepBudgetIncludesHelperCalls(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// Steps spent inside a helper count against the same budget, so a script cannot
	// hide work behind a function call.
	script := `def work():
    for i in range(10000):
        pass

work()
`
	_, err := runScript(t, script, contentFiles(), contentMutable())
	requireKind(t, err, mutation.FailureSteps)
}

func TestContentStepBudgetIsReported(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := runScript(t, `content.read("/etc/app.conf")`, contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if result.Steps == 0 {
		t.Fatal("script reported no steps")
	}
}

func TestContentPrintIsDiscarded(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// Scripts may print; it must not reach the build's output or the worker's reply.
	result, err := runScript(t, `print("noise")
content.write("/etc/app.conf", "done")
`, contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "done" {
		t.Fatalf("write after print returned %q", got)
	}
}

func TestContentTopLevelControlFlowIsAllowed(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// Upstream scripts use top-level control flow and reassignment, which Starlark
	// disables by default.
	script := `total = ""
for name in content.list("/usr/share/app"):
    total += name
content.write("/etc/app.conf", total)
`
	result, err := runScript(t, script, contentFiles(), contentMutable())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); !strings.Contains(got, "data") {
		t.Fatalf("control flow result = %q", got)
	}
}

// An ordinary directory alias must work component by component: resolving only the
// whole path would make /alias/data fail even though /alias -> /real is selected.
func TestContentReadsThroughDirectorySymlink(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	result, err := mutation.RunScript(t.Context(), &mutation.ScriptRequest{
		Script: []byte(`content.write("/etc/app.conf",
    content.read("/alias/data") + "|" + content.read("/alias/link") + "|" + ",".join(content.list("/alias")))`),
		MaxSteps: 1000,
		Files:    map[string][]byte{"/etc/app.conf": []byte("x"), "/real/data": []byte("payload")},
		Links:    map[string]string{"/alias": "real", "/real/link": "/real/data"},
		Mutable:  []string{"/etc/app.conf"},
	}, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "payload|payload|data,link" {
		t.Fatalf("read and list through a directory alias returned %q", got)
	}
}

func TestContentRejectsSymlinkCycles(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	_, err := mutation.RunScript(t.Context(), &mutation.ScriptRequest{
		Script:   []byte(`content.read("/a/x")`),
		MaxSteps: 1000,
		Links:    map[string]string{"/a": "b", "/b": "a"},
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCapability)
}
