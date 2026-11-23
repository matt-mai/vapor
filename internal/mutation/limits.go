package mutation

import (
	"errors"
	"fmt"
	"runtime"
	"time"
)

// SandboxLimits bounds one mutation script. Every field is required: a zero
// limit would silently accept unbounded work, so callers pass
// DefaultSandboxLimits or their own explicit values.
//
// These are internal safety bounds, not image-spec settings. A spec cannot raise
// them, and raising the step budget cannot relax any of them.
type SandboxLimits struct {
	// MaxScriptBytes bounds the source text of one top-level script.
	MaxScriptBytes int64
	// MaxReadBytes bounds the bytes a script reads, not the size of the staged image.
	MaxReadBytes int64
	// MaxWriteBytes bounds the data argument of one content write.
	MaxWriteBytes int64
	// MaxScriptWrites bounds all bytes one script writes.
	MaxScriptWrites int64
	// MaxVFSGrowthBytes bounds the bytes mutation may add across the whole build.
	MaxVFSGrowthBytes int64
	// MaxMessageBytes bounds the encoded script and image metadata.
	MaxMessageBytes int64
	// MaxMemoryBytes sets the worker's hard data-segment allocation limit.
	MaxMemoryBytes int64
	// MaxWallTime bounds one script including time spent blocked.
	MaxWallTime time.Duration
	// MaxCPUTime bounds the processor time of one script.
	MaxCPUTime time.Duration
}

// DefaultSandboxLimits returns the frozen mutation bounds.
func DefaultSandboxLimits() SandboxLimits {
	return SandboxLimits{
		MaxScriptBytes:    1 << 20,
		MaxReadBytes:      64 << 20,
		MaxWriteBytes:     16 << 20,
		MaxScriptWrites:   64 << 20,
		MaxVFSGrowthBytes: 256 << 20,
		MaxMessageBytes:   256 << 20,
		MaxMemoryBytes:    512 << 20,
		MaxWallTime:       60 * time.Second,
		MaxCPUTime:        30 * time.Second,
	}
}

// Validate rejects limits that cannot bound anything or that contradict each
// other, so a misconfigured sandbox fails before a script runs.
func (l SandboxLimits) Validate() error {
	if l.MaxScriptBytes <= 0 || l.MaxReadBytes <= 0 || l.MaxWriteBytes <= 0 ||
		l.MaxScriptWrites <= 0 || l.MaxVFSGrowthBytes <= 0 || l.MaxMessageBytes <= 0 ||
		l.MaxMemoryBytes <= 0 ||
		l.MaxWallTime <= 0 || l.MaxCPUTime <= 0 {
		return errors.New("mutation sandbox limits must all be positive")
	}
	if l.MaxWriteBytes > l.MaxScriptWrites {
		return errors.New("mutation sandbox write bound exceeds the script total")
	}
	// RLIMIT_CPU counts whole seconds and rounds up, so a bound finer than one
	// second would be enforced as a different value than the caller asked for: a
	// 100ms bound would allow a whole second. Refusing is honest; silently
	// loosening the bound is not.
	if l.MaxCPUTime%time.Second != 0 {
		return errors.New("mutation sandbox CPU bound must be a whole number of seconds")
	}
	// A CPU bound above the wall-clock bound is a contradiction only while the wall
	// clock can be set below it. A sub-second wall bound is the tighter limit on its
	// own, and the CPU bound cannot be expressed that small, so it is allowed.
	if l.MaxCPUTime > l.MaxWallTime && l.MaxWallTime >= time.Second {
		return errors.New("mutation sandbox CPU bound exceeds the wall-clock bound")
	}
	return nil
}

// CheckSandboxPlatform reports whether the named platform can enforce the
// mutation limits. It takes the platform name so callers and tests do not depend
// on the build host.
//
// Only Linux is supported: the worker's address-space and CPU limits are the
// memory and time boundary, and they are not enforceable elsewhere. An
// unsupported platform fails closed instead of running untrusted code with
// weaker guarantees.
func CheckSandboxPlatform(goos string) error {
	if goos == "linux" {
		return nil
	}
	return fmt.Errorf("mutation sandbox requires Linux resource limits; %q is not supported", goos)
}

// SandboxSupported reports whether the running platform can enforce the limits.
func SandboxSupported() error {
	return CheckSandboxPlatform(runtime.GOOS)
}

// FailureKind names the bound an adversarial script is expected to exceed.
type FailureKind string

// Sandbox failure kinds.
const (
	FailureScriptSize  FailureKind = "script-size"
	FailureRead        FailureKind = "read-bytes"
	FailureWrite       FailureKind = "write-bytes"
	FailureVFSGrowth   FailureKind = "vfs-growth"
	FailureMessage     FailureKind = "message-size"
	FailureMemory      FailureKind = "memory"
	FailureWallTime    FailureKind = "wall-time"
	FailureCPUTime     FailureKind = "cpu-time"
	FailureSteps       FailureKind = "steps"
	FailureCapability  FailureKind = "capability"
	FailureCancelled   FailureKind = "canceled"
	FailureWorkerDeath FailureKind = "worker-death"
)

// AdversarialCase is one published attack on the mutation sandbox and the
// failure it must produce. The contract is the expected kind, not the exact
// message, so wording can improve without weakening the guarantee.
type AdversarialCase struct {
	Name        string
	Description string
	Expect      FailureKind
}

// AdversarialCases returns the frozen adversarial suite. Every case must fail
// with its expected kind and leave the committed tree unchanged.
func AdversarialCases() []AdversarialCase {
	return []AdversarialCase{
		{"oversized script", "a script larger than the script bound is rejected before parsing", FailureScriptSize},
		{"repeated read", "reading the same large file in a loop exceeds the read bound", FailureRead},
		{"oversized write", "one content write larger than the write bound fails", FailureWrite},
		{"write loop", "many small writes exceed the cumulative script write bound", FailureWrite},
		{"cumulative growth", "scripts that each stay in budget exceed the build-wide growth bound", FailureVFSGrowth},
		{"oversized message", "an oversized script and file index are refused before encoding", FailureMessage},
		{"string repetition", "a single huge string allocation is refused by the worker memory bound", FailureMemory},
		{"deep recursion", "recursive helper calls exhaust the stack inside the memory bound", FailureMemory},
		{"blocking sleep", "a script that blocks exceeds the wall-clock bound", FailureWallTime},
		{"busy loop", "a script that spins exceeds the CPU bound", FailureCPUTime},
		{"step exhaustion", "a script exceeding the step budget fails on steps, not on time", FailureSteps},
		{"host access", "reading or writing a host path is denied by the content API", FailureCapability},
		{"network access", "opening a network connection is unavailable to the worker", FailureCapability},
		{"cancellation", "canceling a running script stops it and discards its staged changes", FailureCancelled},
		{"worker death", "an abruptly killed worker fails the build without committing", FailureWorkerDeath},
	}
}
