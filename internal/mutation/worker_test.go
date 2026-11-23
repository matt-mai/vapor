package mutation_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/mutation"
)

// TestMain turns the test binary into a sandbox worker when the parent re-executes
// it, so the worker path is exercised by the real process boundary rather than a
// stub.
func TestMain(m *testing.M) {
	if mutation.WorkerRequested() {
		os.Exit(mutation.RunWorker(os.Stdin, os.Stdout))
	}
	// Workers are killed asynchronously, so the leak check runs once the whole
	// binary has finished rather than around one test: with tests running in
	// parallel, a worker alive mid-run belongs to a test that is still going.
	os.Exit(checkNoWorkersLeaked(m.Run()))
}

// sandboxLimits returns limits small enough to trip quickly, so the adversarial
// cases stay fast while still exercising the real bounds.
func sandboxLimits() mutation.SandboxLimits {
	limits := mutation.DefaultSandboxLimits()
	limits.MaxScriptBytes = 4 << 10
	limits.MaxReadBytes = 64 << 10
	limits.MaxWriteBytes = 16 << 10
	limits.MaxScriptWrites = 32 << 10
	limits.MaxVFSGrowthBytes = 64 << 10
	limits.MaxMemoryBytes = 256 << 20 * raceMemoryFactor
	limits.MaxWallTime = 20 * time.Second
	limits.MaxCPUTime = 10 * time.Second
	return limits
}

func runScript(t *testing.T, script string, files map[string][]byte, mutable []string) (*mutation.ScriptResult, error) {
	t.Helper()
	return mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   []byte(script),
		MaxSteps: 1000,
		Files:    files,
		Mutable:  mutable,
	}, sandboxLimits())
}

func requireKind(t *testing.T, err error, want mutation.FailureKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", want)
	}
	var scriptErr *mutation.ScriptError
	if !errors.As(err, &scriptErr) {
		t.Fatalf("error is not a sandbox failure: %v", err)
	}
	if scriptErr.Kind != want {
		t.Fatalf("failure kind = %s, want %s (%v)", scriptErr.Kind, want, err)
	}
}

func TestRunScriptIsolatesTheWorker(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	result, err := runScript(t, `content.write("/tmp/out", "abcd")`, map[string][]byte{"/tmp/out": []byte("keep")}, []string{"/tmp/out"})
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	// The parent already refuses a result that reports host visibility, so reaching
	// this point with a result proves confinement held.
	if result.HostVisible {
		t.Fatal("worker could read a host path")
	}
	if string(result.Writes["/tmp/out"]) != "abcd" {
		t.Fatalf("write did not stage: %q", result.Writes["/tmp/out"])
	}
	if result.Steps == 0 {
		t.Fatal("worker reported no steps")
	}
}

func TestRunScriptRejectsOversizedScript(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	_, err := runScript(t, strings.Repeat("#", 8<<10), nil, nil)
	requireKind(t, err, mutation.FailureScriptSize)
}

func TestRunScriptEnforcesStepBudget(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	_, err := runScript(t, "for i in range(10000):\n    pass\n", nil, nil)
	requireKind(t, err, mutation.FailureSteps)
}

func TestRunScriptEnforcesReadAndWriteBounds(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	files := map[string][]byte{"/data": []byte(strings.Repeat("x", 70000))}
	// One read larger than the read bound.
	_, err := runScript(t, `content.read("/data")`, files, nil)
	requireKind(t, err, mutation.FailureRead)

	// One write larger than the write bound.
	_, err = runScript(t, `content.write("/data", "x" * 20000)`, map[string][]byte{"/data": []byte("payload")}, []string{"/data"})
	requireKind(t, err, mutation.FailureWrite)

	// Many writes that together exceed the script write bound.
	_, err = runScript(t, "for i in range(3):\n    content.write(\"/data\", \"x\" * 16000)\n",
		map[string][]byte{"/data": []byte("payload")}, []string{"/data"})
	requireKind(t, err, mutation.FailureWrite)
}

func TestRunScriptEnforcesContentGrowthBound(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	limits := sandboxLimits()
	limits.MaxVFSGrowthBytes = 8 << 10
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   []byte("for name in [\"/a\", \"/b\", \"/c\"]:\n    content.write(name, \"x\" * 4000)\n"),
		MaxSteps: 100,
		Files:    map[string][]byte{"/a": nil, "/b": nil, "/c": nil},
		Mutable:  []string{"/a", "/b", "/c"},
	}, limits)
	requireKind(t, err, mutation.FailureVFSGrowth)
}

func TestRunScriptRejectsUnselectedContent(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	_, err := runScript(t, `content.read("/etc/shadow")`, nil, nil)
	requireKind(t, err, mutation.FailureCapability)
}

func TestRunScriptDeniesHostAccess(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	// Reading a host path fails like any path outside the content set, and the
	// worker's own probe confirms it could not see one.
	_, err := runScript(t, `content.read("/etc/hostname")`, nil, nil)
	requireKind(t, err, mutation.FailureCapability)
}

func TestRunScriptEnforcesMemoryBound(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	if raceMemoryFactor > 1 {
		// The race detector's own allocations dwarf the bound this case needs, so
		// the uninstrumented run is the one that proves the kernel refuses it.
		t.Skip("race detector needs more heap than the memory bound")
	}
	// The same allocation is run under two bounds. The small bound must refuse it
	// and the large one must allow it: that is what shows the data limit is what
	// stops the script, rather than the runtime failing at a size of its own
	// choosing. A single bound cannot tell those apart.
	script := []byte(`bomb = "x" * 134217728`)
	small := sandboxLimits()
	small.MaxMemoryBytes = 256 << 20
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   script,
		MaxSteps: 100,
	}, small)
	requireKind(t, err, mutation.FailureMemory)

	large := sandboxLimits()
	large.MaxMemoryBytes = 1024 << 20
	if _, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   script,
		MaxSteps: 100,
	}, large); err != nil {
		t.Fatalf("allocation under a larger bound failed: %v", err)
	}
}

func TestRunScriptEnforcesWallClock(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	limits := sandboxLimits()
	// The CPU bound is a whole second because RLIMIT_CPU cannot express less, so
	// the wall clock has to be the tighter of the two to be what stops the worker.
	limits.MaxWallTime = 300 * time.Millisecond
	limits.MaxCPUTime = time.Second
	start := time.Now()
	// The worker hangs before evaluating, so the wall clock is what stops it rather
	// than the interpreter's step budget.
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   []byte(""),
		MaxSteps: 1000,
		Hang:     true,
	}, limits)
	requireKind(t, err, mutation.FailureWallTime)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("wall clock did not stop the worker in time: %v", elapsed)
	}
}

func TestRunScriptEnforcesCPUBound(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	limits := sandboxLimits()
	limits.MaxWallTime = 30 * time.Second
	// RLIMIT_CPU counts whole seconds and rounds up, so one second is the
	// smallest bound that is enforced as asked: the busy loop burns it well
	// before the wall clock could.
	limits.MaxCPUTime = time.Second
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   []byte("for i in range(100000000):\n    pass\n"),
		MaxSteps: 1 << 30,
	}, limits)
	requireKind(t, err, mutation.FailureCPUTime)
}

func TestRunScriptCancellationStopsTheWorker(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	_, err := mutation.RunScript(ctx, &mutation.ScriptRequest{
		Script:   []byte(""),
		MaxSteps: 1000,
		Hang:     true,
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureCancelled)
}

func TestRunScriptWorkerDeathIsReported(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   []byte(""),
		MaxSteps: 1000,
		Abort:    true,
	}, sandboxLimits())
	requireKind(t, err, mutation.FailureWorkerDeath)
}

func TestRunScriptRejectsInvalidRequests(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{Script: []byte("")}, sandboxLimits())
	if err == nil || !strings.Contains(err.Error(), "positive step budget") {
		t.Fatalf("error = %v", err)
	}
	bad := sandboxLimits()
	bad.MaxMemoryBytes = 0
	_, err = mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script: []byte(""), MaxSteps: 1,
	}, bad)
	if err == nil || !strings.Contains(err.Error(), "must all be positive") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunScriptAppliesParentLimits(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	// The worker must enforce the caller's bounds, not its own defaults: a read
	// that fits the default bound but not this one has to fail.
	limits := sandboxLimits()
	limits.MaxReadBytes = 1024
	_, err := mutation.RunScript(context.Background(), &mutation.ScriptRequest{
		Script:   []byte(`content.read("/data")`),
		MaxSteps: 100,
		Files:    map[string][]byte{"/data": []byte(strings.Repeat("x", 4096))},
	}, limits)
	requireKind(t, err, mutation.FailureRead)
}

func TestRunScriptStagesWritesWithoutTouchingTheCaller(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	files := map[string][]byte{"/data": []byte("original")}
	result, err := runScript(t, `content.write("/data", "abc")`, files, []string{"/data"})
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if string(files["/data"]) != "original" {
		t.Fatalf("caller map was mutated: %q", files["/data"])
	}
	if string(result.Writes["/data"]) != "abc" {
		t.Fatalf("staged write = %q", result.Writes["/data"])
	}
}

func TestRunScriptFailureReturnsNoResult(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	// A script that writes and then trips a bound must report the failure and no
	// staged content, so a caller cannot accidentally commit a partial script.
	result, err := runScript(t, "content.write(\"/data\", \"abcd\")\nfor i in range(10000):\n    pass\n",
		map[string][]byte{"/data": []byte("x")}, []string{"/data"})
	requireKind(t, err, mutation.FailureSteps)
	if result != nil {
		t.Fatalf("failed script returned a result: %+v", result)
	}
}
