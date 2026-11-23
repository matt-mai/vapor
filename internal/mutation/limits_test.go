package mutation_test

import (
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/mutation"
)

func TestDefaultSandboxLimitsAreConsistent(t *testing.T) {
	t.Parallel()
	limits := mutation.DefaultSandboxLimits()
	if err := limits.Validate(); err != nil {
		t.Fatalf("default limits are invalid: %v", err)
	}
	if limits.MaxWriteBytes > limits.MaxScriptWrites {
		t.Fatal("one write may exceed the script total")
	}
	if limits.MaxScriptWrites > limits.MaxVFSGrowthBytes {
		t.Fatal("one script may exceed the build-wide growth bound")
	}
	if limits.MaxCPUTime > limits.MaxWallTime {
		t.Fatal("CPU bound exceeds the wall-clock bound")
	}
	if limits.MaxMemoryBytes >= 2<<30 {
		t.Fatalf("memory bound %d is not a real boundary", limits.MaxMemoryBytes)
	}
}

func TestSandboxLimitsRejectUnboundedValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*mutation.SandboxLimits)
		want   string
	}{
		{"zero script", func(l *mutation.SandboxLimits) { l.MaxScriptBytes = 0 }, "must all be positive"},
		{"negative read", func(l *mutation.SandboxLimits) { l.MaxReadBytes = -1 }, "must all be positive"},
		{"zero message", func(l *mutation.SandboxLimits) { l.MaxMessageBytes = 0 }, "must all be positive"},
		{"zero write", func(l *mutation.SandboxLimits) { l.MaxWriteBytes = 0 }, "must all be positive"},
		{"zero writes", func(l *mutation.SandboxLimits) { l.MaxScriptWrites = 0 }, "must all be positive"},
		{"zero growth", func(l *mutation.SandboxLimits) { l.MaxVFSGrowthBytes = 0 }, "must all be positive"},
		{"zero memory", func(l *mutation.SandboxLimits) { l.MaxMemoryBytes = 0 }, "must all be positive"},
		{"zero wall", func(l *mutation.SandboxLimits) { l.MaxWallTime = 0 }, "must all be positive"},
		{"zero cpu", func(l *mutation.SandboxLimits) { l.MaxCPUTime = 0 }, "must all be positive"},
		{"write above total", func(l *mutation.SandboxLimits) { l.MaxWriteBytes = l.MaxScriptWrites + 1 }, "exceeds the script total"},
		{"cpu above wall", func(l *mutation.SandboxLimits) { l.MaxCPUTime = l.MaxWallTime + time.Second }, "exceeds the wall-clock"},
		{"subsecond cpu", func(l *mutation.SandboxLimits) { l.MaxCPUTime = 100 * time.Millisecond }, "whole number of seconds"},
		{"fractional cpu", func(l *mutation.SandboxLimits) { l.MaxCPUTime = 1500 * time.Millisecond }, "whole number of seconds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := mutation.DefaultSandboxLimits()
			test.mutate(&limits)
			err := limits.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// A sub-second wall clock is the tighter limit on its own, so it is not a
// contradiction even though the CPU bound cannot be expressed that small.
func TestSandboxLimitsAcceptASubsecondWallClock(t *testing.T) {
	t.Parallel()
	limits := mutation.DefaultSandboxLimits()
	limits.MaxWallTime = 300 * time.Millisecond
	limits.MaxCPUTime = time.Second
	if err := limits.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestCheckSandboxPlatformFailsClosed(t *testing.T) {
	t.Parallel()
	if err := mutation.CheckSandboxPlatform("linux"); err != nil {
		t.Fatalf("linux rejected: %v", err)
	}
	for _, goos := range []string{"darwin", "windows", "freebsd", "plan9", ""} {
		err := mutation.CheckSandboxPlatform(goos)
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%q error = %v", goos, err)
		}
	}
}

func TestSandboxSupportedMatchesHost(t *testing.T) {
	t.Parallel()
	// The check must describe the running platform, not a compiled-in constant,
	// so a build on an unsupported host refuses to run mutation.
	err := mutation.SandboxSupported()
	if err == nil {
		if platformErr := mutation.CheckSandboxPlatform("linux"); platformErr != nil {
			t.Fatalf("supported host is not linux: %v", platformErr)
		}
		return
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error = %v", err)
	}
}

func TestAdversarialCasesAreComplete(t *testing.T) {
	t.Parallel()
	cases := mutation.AdversarialCases()
	if len(cases) < 10 {
		t.Fatalf("only %d adversarial cases", len(cases))
	}
	seen := make(map[string]bool, len(cases))
	kinds := make(map[mutation.FailureKind]bool)
	for _, testCase := range cases {
		if testCase.Name == "" || testCase.Description == "" || testCase.Expect == "" {
			t.Fatalf("incomplete case %+v", testCase)
		}
		if seen[testCase.Name] {
			t.Fatalf("duplicate case %q", testCase.Name)
		}
		seen[testCase.Name] = true
		kinds[testCase.Expect] = true
	}
	// Every bound in the contract must be attacked by at least one case.
	for _, kind := range []mutation.FailureKind{
		mutation.FailureScriptSize,
		mutation.FailureRead,
		mutation.FailureWrite,
		mutation.FailureVFSGrowth,
		mutation.FailureMemory,
		mutation.FailureWallTime,
		mutation.FailureCPUTime,
		mutation.FailureSteps,
		mutation.FailureCapability,
		mutation.FailureCancelled,
		mutation.FailureWorkerDeath,
	} {
		if !kinds[kind] {
			t.Fatalf("no adversarial case expects %q", kind)
		}
	}
}
