package mutation_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/mutation"
	"github.com/matt-mai/vapor/internal/vfs"
)

// imageTree builds a small committed tree with two mutable files.
func imageTree(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	origin := vfs.Origin{Package: "fixture", Slice: "fixture_runtime", Path: "slices/fixture.yaml"}
	for _, name := range []string{"/etc/app.conf", "/usr/share/app/data"} {
		if err := tree.File(name, []byte("original"), vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
			t.Fatalf("File(%q): %v", name, err)
		}
	}
	return tree
}

// mutablePaths is what a slice declared `mutable` in the fixture selection.
func mutablePaths() []string {
	return []string{"/etc/app.conf", "/usr/share/app/data"}
}

func mutationRequest(name, script string) mutation.Request {
	return mutation.Request{Name: name, Script: []byte(script), MaxSteps: 1000}
}

// abortRequest kills the worker without a reply after the script runs, so a test can
// prove an abruptly killed worker commits nothing.
func abortRequest(name, script string) mutation.Request {
	request := mutationRequest(name, script)
	request.Abort = true
	return request
}

func readFile(t *testing.T, tree *vfs.Tree, path string) string {
	t.Helper()
	data, err := tree.Read(path)
	if err != nil {
		t.Fatalf("Read(%q): %v", path, err)
	}
	return string(data)
}

func TestMutateAppliesScriptsInOrder(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	result, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("first", `content.write("/etc/app.conf", "abc")`),
		mutationRequest("second", `content.write("/usr/share/app/data", "de")`),
	}, sandboxLimits())
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if result.Scripts != 2 || result.Steps == 0 {
		t.Fatalf("result = %+v", result)
	}
	if got := readFile(t, tree, "/etc/app.conf"); got != "abc" {
		t.Fatalf("first script not applied: %q", got)
	}
	if got := readFile(t, tree, "/usr/share/app/data"); got != "de" {
		t.Fatalf("second script not applied: %q", got)
	}
}

func TestMutateLaterScriptSeesEarlierWork(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	_, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("first", `content.write("/etc/app.conf", "hello")`),
		mutationRequest("second", `content.write("/usr/share/app/data", content.read("/etc/app.conf"))`),
	}, sandboxLimits())
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if got := readFile(t, tree, "/usr/share/app/data"); got != "hello" {
		t.Fatalf("second script did not see the first: %q", got)
	}
}

func TestMutateFailureLeavesTreeUnchanged(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	_, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("ok", `content.write("/etc/app.conf", "abc")`),
		mutationRequest("boom", "for i in range(10000):\n    pass\n"),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureSteps)
	if got := readFile(t, tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("committed tree changed after failure: %q", got)
	}
}

func TestMutateFailureNamesTheScript(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	_, err := mutation.Mutate(context.Background(), imageTree(t), mutablePaths(), []mutation.Request{
		mutationRequest("fixture/mutate", "for i in range(10000):\n    pass\n"),
	}, sandboxLimits())
	if err == nil || !strings.Contains(err.Error(), "fixture/mutate") {
		t.Fatalf("error does not name the script: %v", err)
	}
}

func TestMutateRejectsCreatedPaths(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	_, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("create", `content.write("/etc/new.conf", "data")`),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCapability)
	if _, ok := tree.Lookup("/etc/new.conf"); ok {
		t.Fatal("created path reached the committed tree")
	}
}

func TestMutateRejectsImmutableWrites(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	// The file is selected but not mutable, so it is readable and unwritable.
	_, err := mutation.Mutate(context.Background(), tree, []string{"/etc/app.conf"}, []mutation.Request{
		mutationRequest("immutable", `content.write("/usr/share/app/data", "x")`),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCapability)
	if got := readFile(t, tree, "/usr/share/app/data"); got != "original" {
		t.Fatalf("immutable content changed: %q", got)
	}
}

func TestMutateRejectsHardlinkWrites(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	origin := vfs.Origin{Package: "fixture", Slice: "fixture_runtime", Path: "slices/fixture.yaml"}
	if err := tree.Hardlink("/usr/share/app/alias", "/etc/app.conf", origin); err != nil {
		t.Fatalf("Hardlink: %v", err)
	}
	_, err := mutation.Mutate(context.Background(), tree, []string{"/etc/app.conf", "/usr/share/app/alias"}, []mutation.Request{
		mutationRequest("hardlink", `content.write("/etc/app.conf", "x")`),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCapability)
	if got := readFile(t, tree, "/usr/share/app/alias"); got != "original" {
		t.Fatalf("hardlink target changed: %q", got)
	}
}

func TestMutateEnforcesBuildGrowthBound(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	// Each script adds four bytes to an eight-byte file, so each stays under the
	// bound while together they exceed it.
	limits := sandboxLimits()
	limits.MaxVFSGrowthBytes = 6
	tree := imageTree(t)
	_, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("first", `content.write("/etc/app.conf", "0123456789ab")`),
		mutationRequest("second", `content.write("/usr/share/app/data", "0123456789ab")`),
	}, limits)
	requireKind(t, err, mutation.FailureVFSGrowth)
	if got := readFile(t, tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("growth failure committed content: %q", got)
	}
}

func TestMutateShrinkingContentIsFree(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	limits := sandboxLimits()
	limits.MaxVFSGrowthBytes = 1
	tree := imageTree(t)
	if _, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("shrink", `content.write("/etc/app.conf", "ab")`),
	}, limits); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if got := readFile(t, tree, "/etc/app.conf"); got != "ab" {
		t.Fatalf("shrink not applied: %q", got)
	}
}

func TestMutateRejectsOversizedMessage(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	limits := sandboxLimits()
	limits.MaxMessageBytes = 8
	_, err := mutation.Mutate(context.Background(), imageTree(t), mutablePaths(), []mutation.Request{
		mutationRequest("noop", `content.write("/etc/app.conf", "x")`),
	}, limits)
	requireKind(t, err, mutation.FailureMessage)
}

func TestMutateRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	if _, err := mutation.Mutate(context.Background(), nil, nil, nil, sandboxLimits()); err == nil {
		t.Fatal("expected an error for a nil tree")
	}
	bad := sandboxLimits()
	bad.MaxMessageBytes = 0
	if _, err := mutation.Mutate(context.Background(), imageTree(t), nil, nil, bad); err == nil {
		t.Fatal("expected an error for invalid limits")
	}
}

func TestMutateEmptyRunIsANoop(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	result, err := mutation.Mutate(context.Background(), tree, mutablePaths(), nil, sandboxLimits())
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if result.Scripts != 0 {
		t.Fatalf("result = %+v", result)
	}
	if got := readFile(t, tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("tree changed: %q", got)
	}
}

func TestMutateWorkerDeathLeavesTreeUnchanged(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	_, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		abortRequest("write-then-die", `content.write("/etc/app.conf", "abcd")`),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureWorkerDeath)
	if got := readFile(t, tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("worker death committed content: %q", got)
	}
}

func TestMutateCancellationLeavesTreeUnchanged(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := mutation.Mutate(ctx, tree, mutablePaths(), []mutation.Request{
		mutationRequest("blocked", "for i in range(100000000):\n    pass\n"),
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCancelled)
	if got := readFile(t, tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("cancellation committed content: %q", got)
	}
}

func TestMutatePreservesUnrelatedContent(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	tree := imageTree(t)
	before, readErr := tree.Read("/usr/share/app/data")
	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if _, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("one", `content.write("/etc/app.conf", "abc")`),
	}, sandboxLimits()); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	after, err := tree.Read("/usr/share/app/data")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("unrelated content changed: %q", after)
	}
}

func TestMutateSyntaxErrorIsACapabilityFailure(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	_, err := mutation.Mutate(context.Background(), imageTree(t), mutablePaths(), []mutation.Request{
		mutationRequest("broken", "this is not starlark("),
	}, sandboxLimits())
	var scriptErr *mutation.ScriptError
	if !errors.As(err, &scriptErr) {
		t.Fatalf("error is not a sandbox failure: %v", err)
	}
	if scriptErr.Kind != mutation.FailureCapability {
		t.Fatalf("failure kind = %s", scriptErr.Kind)
	}
}
