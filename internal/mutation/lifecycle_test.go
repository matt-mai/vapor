package mutation_test

import (
	"bytes"
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/mutation"
	"github.com/matt-mai/vapor/internal/vfs"
)

// lifecycleTree builds a selection with mutable output, a temporary input file, a
// temporary directory with content, and a permanent file inside a temporary
// directory.
func lifecycleTree(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture", Slice: "fixture_runtime", Path: "slices/fixture.yaml"}
	build := []struct {
		name string
		run  func() error
	}{
		{"/tmp/", func() error { return tree.Dir("/tmp", vfs.Attrs{Mode: fs.ModeSticky | 0o777, Origin: origin}) }},
		{"/tmp/work/", func() error { return tree.Dir("/tmp/work", vfs.Attrs{Mode: 0o755, Origin: origin}) }},
		{"/etc/app.conf", func() error {
			return tree.File("/etc/app.conf", []byte("original"), vfs.Attrs{Mode: 0o644, Origin: origin})
		}},
		{"/tmp/input", func() error {
			return tree.File("/tmp/input", []byte("input\n"), vfs.Attrs{Mode: 0o644, Origin: origin})
		}},
		{"/tmp/work/scratch", func() error {
			return tree.File("/tmp/work/scratch", []byte("scratch\n"), vfs.Attrs{Mode: 0o644, Origin: origin})
		}},
		{"/tmp/work/keep", func() error {
			return tree.File("/tmp/work/keep", []byte("keep\n"), vfs.Attrs{Mode: 0o644, Origin: origin})
		}},
	}
	for _, step := range build {
		if err := step.run(); err != nil {
			t.Fatalf("build %q: %v", step.name, err)
		}
	}
	return tree
}

func lifecycleSelection(t *testing.T) mutation.Selection {
	t.Helper()
	return mutation.Selection{
		Tree:      lifecycleTree(t),
		Mutable:   []string{"/etc/app.conf"},
		Temporary: []string{"/tmp/input", "/tmp/work/scratch", "/tmp/work/"},
	}
}

func requireRemoved(t *testing.T, tree *vfs.Tree, paths ...string) {
	t.Helper()
	for _, name := range paths {
		if _, ok := tree.Lookup(strings.TrimSuffix(name, "/")); ok {
			t.Fatalf("%q survived", name)
		}
	}
}

func requireKept(t *testing.T, tree *vfs.Tree, paths ...string) {
	t.Helper()
	for _, name := range paths {
		if _, ok := tree.Lookup(strings.TrimSuffix(name, "/")); !ok {
			t.Fatalf("%q was removed", name)
		}
	}
}

func TestRunScriptsRemovesTemporaryContentAfterMutation(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	selection := lifecycleSelection(t)
	result, lifecycle, err := mutation.RunScripts(context.Background(), selection, []mutation.Request{
		mutationRequest("read-then-write", `content.write("/etc/app.conf", content.read("/tmp/input"))`),
	}, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScripts: %v", err)
	}
	if result.Scripts != 1 {
		t.Fatalf("scripts = %d", result.Scripts)
	}
	// The script read the temporary file, so removal happened after it ran.
	if got := readFile(t, selection.Tree, "/etc/app.conf"); got != "input\n" {
		t.Fatalf("script did not read temporary content: %q", got)
	}
	requireRemoved(t, selection.Tree, "/tmp/input", "/tmp/work/scratch")
	// "keep" was never temporary, so its directory is not empty and survives.
	requireKept(t, selection.Tree, "/tmp/work/keep", "/tmp/work/")
	if strings.Join(lifecycle.Removed, ",") != "/tmp/input,/tmp/work/scratch" {
		t.Fatalf("removed = %v", lifecycle.Removed)
	}
	if len(lifecycle.EmptyDirectories) != 0 {
		t.Fatalf("empty directories = %v", lifecycle.EmptyDirectories)
	}
}

func TestRunScriptsRemovesEmptyTemporaryDirectories(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	selection := lifecycleSelection(t)
	selection.Temporary = []string{"/tmp/input", "/tmp/work/scratch", "/tmp/work/keep", "/tmp/work/"}
	_, lifecycle, err := mutation.RunScripts(context.Background(), selection, nil, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScripts: %v", err)
	}
	requireRemoved(t, selection.Tree, "/tmp/input", "/tmp/work/scratch", "/tmp/work/keep", "/tmp/work/")
	if strings.Join(lifecycle.EmptyDirectories, ",") != "/tmp/work" {
		t.Fatalf("empty directories = %v", lifecycle.EmptyDirectories)
	}
}

func TestRunScriptsRemovesNestedTemporaryDirectoriesDeepestFirst(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture"}
	for _, name := range []string{"/a", "/a/b", "/a/b/c"} {
		if err := tree.Dir(name, vfs.Attrs{Mode: 0o755, Origin: origin}); err != nil {
			t.Fatalf("Dir(%q): %v", name, err)
		}
	}
	if err := tree.File("/a/b/c/leaf", []byte("x"), vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("File: %v", err)
	}
	selection := mutation.Selection{
		Tree:      tree,
		Temporary: []string{"/a/b/c/leaf", "/a/b/c/", "/a/b/", "/a/"},
	}
	_, lifecycle, err := mutation.RunScripts(context.Background(), selection, nil, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScripts: %v", err)
	}
	requireRemoved(t, tree, "/a/b/c/leaf", "/a/b/c", "/a/b", "/a")
	if strings.Join(lifecycle.EmptyDirectories, ",") != "/a/b/c,/a/b,/a" {
		t.Fatalf("empty directories = %v", lifecycle.EmptyDirectories)
	}
}

func TestRunScriptsKeepsSharedTemporaryPaths(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// A path another declaration keeps permanently is not in Temporary, so the
	// selection stage already decided it survives.
	selection := lifecycleSelection(t)
	selection.Temporary = []string{"/tmp/input"}
	_, _, err := mutation.RunScripts(context.Background(), selection, nil, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScripts: %v", err)
	}
	requireKept(t, selection.Tree, "/tmp/work/scratch", "/tmp/work/keep")
}

func TestRunScriptsFailureKeepsTemporaryContent(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	selection := lifecycleSelection(t)
	_, _, err := mutation.RunScripts(context.Background(), selection, []mutation.Request{
		mutationRequest("ok", `content.write("/etc/app.conf", "changed")`),
		mutationRequest("boom", "for i in range(10000):\n    pass\n"),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureSteps)
	// A failed run removes nothing: a retry needs the temporary content.
	requireKept(t, selection.Tree, "/tmp/input", "/tmp/work/scratch")
	if got := readFile(t, selection.Tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("committed tree changed after failure: %q", got)
	}
}

func TestRunScriptsIsDeterministic(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// The same selection and scripts must produce the same tree, so a manifest
	// hash over the result is stable.
	first := lifecycleSelection(t)
	second := lifecycleSelection(t)
	requests := []mutation.Request{
		mutationRequest("first", `content.write("/etc/app.conf", "abc")`),
		mutationRequest("second", `content.write("/etc/app.conf", content.read("/etc/app.conf") + "d")`),
	}
	if _, _, err := mutation.RunScripts(context.Background(), first, requests, sandboxLimits()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, _, err := mutation.RunScripts(context.Background(), second, requests, sandboxLimits()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := readFile(t, first.Tree, "/etc/app.conf"); got != "abcd" {
		t.Fatalf("first run result = %q", got)
	}
	requireSameTree(t, first.Tree, second.Tree)
}

func TestRunScriptsRejectsInvalidSelection(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	cases := map[string]mutation.Selection{
		"missing tree":         {},
		"undeclared mutable":   {Tree: lifecycleTree(t), Mutable: []string{"/etc/missing"}},
		"undeclared temporary": {Tree: lifecycleTree(t), Temporary: []string{"/tmp/missing"}},
	}
	for name, selection := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := mutation.RunScripts(context.Background(), selection, nil, sandboxLimits()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestRunScriptsEmptyRunOnlyCleansUp(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	selection := lifecycleSelection(t)
	result, lifecycle, err := mutation.RunScripts(context.Background(), selection, nil, sandboxLimits())
	if err != nil {
		t.Fatalf("RunScripts: %v", err)
	}
	if result.Scripts != 0 || result.Steps != 0 {
		t.Fatalf("result = %+v", result)
	}
	requireRemoved(t, selection.Tree, "/tmp/input", "/tmp/work/scratch")
	if len(lifecycle.Removed) != 2 {
		t.Fatalf("removed = %v", lifecycle.Removed)
	}
}

// requireSameTree asserts two trees have identical entries and content.
func requireSameTree(t *testing.T, left, right *vfs.Tree) {
	t.Helper()
	leftEntries := left.Entries()
	rightEntries := right.Entries()
	if len(leftEntries) != len(rightEntries) {
		t.Fatalf("entry counts differ: %d != %d", len(leftEntries), len(rightEntries))
	}
	for i, entry := range leftEntries {
		other := rightEntries[i]
		if entry.Path != other.Path || entry.Kind != other.Kind || entry.Mode != other.Mode ||
			entry.UID != other.UID || entry.GID != other.GID || entry.Target != other.Target {
			t.Fatalf("entry %d differs: %+v != %+v", i, entry, other)
		}
		if entry.Kind != vfs.File {
			continue
		}
		leftData, err := left.Read(entry.Path)
		if err != nil {
			t.Fatalf("Read(%q): %v", entry.Path, err)
		}
		rightData, err := right.Read(other.Path)
		if err != nil {
			t.Fatalf("Read(%q): %v", other.Path, err)
		}
		if !bytes.Equal(leftData, rightData) {
			t.Fatalf("%q content differs: %q != %q", entry.Path, leftData, rightData)
		}
	}
}
