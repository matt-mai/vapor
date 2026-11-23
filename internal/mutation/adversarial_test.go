package mutation_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/mutation"
	"github.com/matt-mai/vapor/internal/vfs"
)

// adversarialScript maps a published case to the Starlark that exercises it. Every
// case in mutation.AdversarialCases must appear here, so adding a case without an
// attack fails the suite.
func adversarialScript(name string) string {
	switch name {
	case "oversized script":
		return strings.Repeat("#", 8<<10)
	case "repeated read":
		// The read bound for this case is 32 bytes, so a few reads of an eight-byte
		// file exceed it without needing a large fixture.
		return `for i in range(8):
    content.read("/usr/share/app/data")
`
	case "oversized write":
		return `content.write("/etc/app.conf", "x" * 20000)
`
	case "write loop":
		return `for i in range(3):
    content.write("/etc/app.conf", "x" * 16000)
`
	case "cumulative growth":
		// Handled by the build-wide growth case below: one script cannot trip it.
		return ""
	case "oversized message":
		return ""
	case "string repetition":
		return `bomb = "x" * 536870912
`
	case "deep recursion":
		// Starlark forbids recursion outright, so the deepest reachable stack is
		// built from nested helper calls that each hold a large value.
		return `def level(n):
    hold = "x" * (1 << 20)
    return n

level(level(level(level(level(level(level(level(1))))))))
`
	case "blocking sleep":
		// Starlark cannot sleep, so the wall clock is proven as a backstop: a script
		// that spins is stopped by the parent's clock when the CPU bound is generous.
		return `for i in range(100000000):
    pass
`
	case "busy loop":
		// The step budget is generous here so the CPU bound, not the interpreter,
		// is what ends the process.
		return `for i in range(100000000):
    pass
`
	case "step exhaustion":
		return `for i in range(10000):
    pass
`
	case "host access":
		return `content.read("/etc/hostname")
`
	case "network access":
		// The worker has no socket and the language has no I/O primitive, so the
		// attack is only expressible as a host read, which the API refuses.
		return `content.read("/etc/resolv.conf")
`
	case "cancellation":
		return `for i in range(100000000):
    pass
`
	case "worker death":
		// An abruptly killed worker is driven by the parent, so the case is exercised
		// by TestWorkerDeathIsReported in worker_internal_test.go.
		return ""
	default:
		return ""
	}
}

// adversarialSteps is the interpreter budget a case runs with. Most cases keep the
// default so steps stay the first bound they meet; the wall-clock and CPU cases need
// a budget large enough that the interpreter is not what stops them.
func adversarialSteps(name string) int {
	switch name {
	case "blocking sleep", "busy loop", "cancellation":
		return 1 << 30
	}
	return 1000
}

// adversarialLimits tightens the bounds so every case trips quickly while still
// exercising the real kernel limits.
func adversarialLimits(name string) mutation.SandboxLimits {
	limits := sandboxLimits()
	limits.MaxMessageBytes = 32 << 10
	switch name {
	case "oversized message":
		limits.MaxMessageBytes = 8
	case "blocking sleep":
		// The worker hangs before evaluating, so it burns no CPU and the wall clock
		// is unambiguously what stops it.
		limits.MaxWallTime = 300 * time.Millisecond
		limits.MaxCPUTime = time.Second
	case "cancellation":
		limits.MaxWallTime = 300 * time.Millisecond
		limits.MaxCPUTime = time.Second
	case "busy loop":
		limits.MaxWallTime = 30 * time.Second
		limits.MaxCPUTime = time.Second
	case "repeated read":
		limits.MaxReadBytes = 32
	case "string repetition", "deep recursion":
		limits.MaxMemoryBytes = 128 << 20
	}
	return limits
}

func TestAdversarialCasesAreAllExercised(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	for _, testCase := range mutation.AdversarialCases() {
		if adversarialScript(testCase.Name) == "" && testCase.Name != "cumulative growth" &&
			testCase.Name != "oversized message" && testCase.Name != "worker death" {
			t.Fatalf("case %q has no attack script", testCase.Name)
		}
	}
}

// TestAdversarialCasesTripTheirBound runs every published case once and asserts
// two things at the same time: the failure kind and that the committed tree is
// unchanged. The cases run in parallel because two of them wait on a bound that
// cannot be expressed below a second. Leaked workers are checked by TestMain once
// the binary finishes, which is the only point where a survivor is unambiguous.
func TestAdversarialCasesTripTheirBound(t *testing.T) {
	t.Parallel()
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	for _, testCase := range mutation.AdversarialCases() {
		switch testCase.Name {
		case "cumulative growth", "oversized message":
			continue // need a staged tree, covered below
		case "worker death":
			continue // needs the parent to kill the worker, covered below
		}
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			skipMemoryCaseUnderRace(t, testCase)
			tree := adversarialTree(t)
			// The script writes first, so a failure that committed anything would
			// show up in the tree.
			// The worker hangs before evaluating when the case needs a worker that
			// never reaches the interpreter.
			script := `content.write("/etc/app.conf", "xxxx")` + "\n" + adversarialScript(testCase.Name)
			request := mutationRequest(testCase.Name, script)
			request.MaxSteps = adversarialSteps(testCase.Name)
			request.Hang = testCase.Name == "blocking sleep"
			_, err := mutation.Mutate(adversarialContext(t, testCase), tree, mutablePaths(), []mutation.Request{
				request,
			}, adversarialLimits(testCase.Name))
			requireKind(t, err, testCase.Expect)
			requireUnchanged(t, tree)
		})
	}
}

// adversarialContext cancels the run for the cancellation case and leaves every
// other case running normally.
func adversarialContext(t *testing.T, testCase mutation.AdversarialCase) context.Context {
	t.Helper()
	ctx := context.Background()
	if testCase.Name != "cancellation" {
		return ctx
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	t.Cleanup(cancel)
	return ctx
}

func TestAdversarialCumulativeGrowthFailsTheBuild(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	tree := adversarialTree(t)
	limits := sandboxLimits()
	limits.MaxVFSGrowthBytes = 6
	_, err := mutation.Mutate(context.Background(), tree, mutablePaths(), []mutation.Request{
		mutationRequest("first", `content.write("/etc/app.conf", "0123456789ab")`),
		mutationRequest("second", `content.write("/usr/share/app/data", "0123456789ab")`),
	}, limits)
	requireKind(t, err, mutation.FailureVFSGrowth)
	requireUnchanged(t, tree)
}

func bigFileTree(t *testing.T, size int) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	if err := tree.File("/etc/big", []byte(strings.Repeat("x", size)), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("File: %v", err)
	}
	return tree
}

// An oversized read should fail at the read budget, not during transfer or allocation.
func TestAdversarialReadBoundPrecedesAllocation(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	limits := sandboxLimits()
	limits.MaxReadBytes = 1 << 10
	tree := bigFileTree(t, 2<<20)
	_, err := mutation.Mutate(context.Background(), tree, []string{"/etc/big"}, []mutation.Request{
		mutationRequest("noop", `content.read("/etc/big")`),
	}, limits)
	requireKind(t, err, mutation.FailureRead)
}

func TestAdversarialReadsFileLargerThanMessageBound(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	limits := mutation.DefaultSandboxLimits()
	limits.MaxMessageBytes = 8 << 10
	tree := bigFileTree(t, 2<<20)
	result, err := mutation.Mutate(t.Context(), tree, nil, []mutation.Request{
		mutationRequest("read", `if content.read("/etc/big") != "x" * (2 << 20): fail("truncated file")`),
	}, limits)
	if err != nil {
		t.Fatalf("read larger than metadata bound failed: %v", err)
	}
	if result.Scripts != 1 {
		t.Fatalf("scripts = %d, want 1", result.Scripts)
	}
}

func TestAdversarialReadWithoutWriting(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	tree := bigFileTree(t, 1<<20)
	result, err := mutation.Mutate(context.Background(), tree, []string{"/etc/big"}, []mutation.Request{
		mutationRequest("noop", `content.read("/etc/big")`),
	}, mutation.DefaultSandboxLimits())
	if err != nil {
		t.Fatalf("read without a write failed: %v", err)
	}
	if result.Scripts != 1 {
		t.Fatalf("scripts = %d, want 1", result.Scripts)
	}
}

func TestAdversarialNoOpDoesNotReturnTheImage(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	// With no mutable paths the reply cap is smaller than this one input file.
	result, err := mutation.RunScript(t.Context(), &mutation.ScriptRequest{
		Script: []byte(`pass`), MaxSteps: 100,
		Files: map[string][]byte{"/etc/big": make([]byte, 1<<20)},
	}, sandboxLimits())
	if err != nil {
		t.Fatalf("read-only worker failed: %v", err)
	}
	if len(result.Writes) != 0 {
		t.Fatalf("read-only worker returned %d writes", len(result.Writes))
	}
}

// A script can build a string of any size and pass it to fail(), so the message
// that crosses the pipe and reaches the caller must be bounded. Without the
// truncation the parent collects the whole string: script-controlled output
// allocating outside the sandbox's memory limit.
func TestAdversarialOversizedDiagnosticIsTruncated(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	for name, script := range map[string]string{
		"assertion": `fail("x" * (8 * 1024 * 1024))`,
		"path":      `content.read("x" * (8 * 1024 * 1024))`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mutation.RunScript(t.Context(), &mutation.ScriptRequest{
				Script: []byte(script), MaxSteps: 100,
			}, sandboxLimits())
			requireKind(t, err, mutation.FailureCapability)
			if length := len(err.Error()); length > 8<<10 {
				t.Fatalf("reported message is %d bytes, want it bounded", length)
			}
		})
	}
}

func TestAdversarialReadAtTheLimit(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	limits := sandboxLimits()
	limits.MaxReadBytes = 8 << 20
	result, err := mutation.Mutate(t.Context(), bigFileTree(t, 8<<20), nil, []mutation.Request{
		mutationRequest("read", `if len(content.read("/etc/big")) != 8 << 20: fail("wrong size")`),
	}, limits)
	if err != nil {
		t.Fatalf("content at the read bound failed: %v", err)
	}
	if result.Scripts != 1 {
		t.Fatalf("scripts = %d, want 1", result.Scripts)
	}
}

func TestAdversarialOversizedMessageFailsTheBuild(t *testing.T) {
	if err := mutation.SandboxSupported(); err != nil {
		t.Skipf("sandbox unsupported on this platform: %v", err)
	}
	t.Parallel()
	limits := sandboxLimits()
	limits.MaxMessageBytes = 8
	_, err := mutation.Mutate(context.Background(), adversarialTree(t), mutablePaths(), []mutation.Request{
		mutationRequest("noop", `content.write("/etc/app.conf", "x")`),
	}, limits)
	requireKind(t, err, mutation.FailureMessage)
}

// checkNoWorkersLeaked runs after the last test and fails the binary if a worker
// survived, so a kill that was never collected cannot pass unnoticed. It waits
// briefly for the kernel to reap a worker whose death signal is still in flight.
func checkNoWorkersLeaked(code int) int {
	if code == 0 {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if workerCount() == 0 {
				return code
			}
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Fprintf(os.Stderr, "workers leaked: %d survived the run\n", workerCount())
		return 1
	}
	return code
}

// workerCount counts sandbox workers by their environment marker. Unreadable
// process entries are skipped: the tests may not own every process on the host.
func workerCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() || strings.Trim(entry.Name(), "0123456789") != "" {
			continue
		}
		environ, readErr := os.ReadFile("/proc/" + entry.Name() + "/environ")
		if readErr != nil {
			continue
		}
		if strings.Contains(string(environ), "VAPOR_SANDBOX_WORKER=1") {
			count++
		}
	}
	return count
}

// skipMemoryCaseUnderRace skips memory-bound cases when the race detector is on:
// ThreadSanitizer's own bookkeeping needs far more heap than the bound allows, so
// the worker dies for the detector's reasons rather than the script's.
func skipMemoryCaseUnderRace(t *testing.T, testCase mutation.AdversarialCase) {
	t.Helper()
	if raceMemoryFactor > 1 && testCase.Expect == mutation.FailureMemory {
		t.Skip("race detector needs more heap than the memory bound")
	}
}

func adversarialTree(t *testing.T) *vfs.Tree {
	t.Helper()
	return imageTree(t)
}

func requireUnchanged(t *testing.T, tree *vfs.Tree) {
	t.Helper()
	if got := readFile(t, tree, "/etc/app.conf"); got != "original" {
		t.Fatalf("committed content changed: %q", got)
	}
	if got := readFile(t, tree, "/usr/share/app/data"); got != "original" {
		t.Fatalf("committed content changed: %q", got)
	}
}
