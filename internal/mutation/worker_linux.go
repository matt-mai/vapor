//go:build linux

package mutation

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// configureWorker confines the worker before it runs any script. The worker gets
// its own user, mount, PID and network namespaces, so it has no network, no
// privilege over the host, and no view of the host's mounts, and the process is
// killed if the parent dies.
//
// The mount namespace is what makes the chroot a boundary rather than a convention:
// chroot alone can be escaped by a process that still holds a descriptor or a mount
// from outside the new root, and a private mount namespace means there is nothing
// outside to reach. The PID namespace makes the worker PID 1 in its own tree, so
// nothing it spawns outlives it.
func configureWorker(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		// The worker is killed if the parent dies, so a crashed build cannot leave
		// a sandboxed process behind.
		Pdeathsig: syscall.SIGKILL,
	}
	return nil
}

// executeConfined runs one script inside the worker: it applies the process
// resource limits, confines itself to an empty root, then runs the script.
func executeConfined(request *ScriptRequest, limits *SandboxLimits) (*ScriptResult, *ScriptError) {
	if err := applyWorkerLimits(limits); err != nil {
		return nil, &ScriptError{Kind: FailureCapability, Message: err.Error()}
	}
	watchCPULimit()
	root := os.Getenv(workerRootEnv)
	if root == "" {
		return nil, &ScriptError{Kind: FailureWorkerDeath, Message: "worker has no sandbox root"}
	}
	if err := syscall.Chroot(root); err != nil {
		return nil, &ScriptError{Kind: FailureCapability, Message: "worker could not confine itself"}
	}
	if err := os.Chdir("/"); err != nil {
		return nil, &ScriptError{Kind: FailureCapability, Message: "worker could not enter its root"}
	}
	return runStarlark(request, limits)
}

// watchCPULimit exits with workerCPUExitCode when the CPU limit is reached. The
// kernel sends SIGXCPU, which a Go program does not treat as fatal, so without this
// the script would keep running until the parent's wall clock stopped it and the
// CPU bound would never be the reported reason.
func watchCPULimit() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGXCPU)
	go func() {
		<-signals
		os.Exit(workerCPUExitCode)
	}()
}

// applyBootstrapLimits applies the memory bound from the environment before the
// request is decoded. The CPU limit is not applied here: decoding is bounded work,
// and the CPU bound belongs to the script.
func applyBootstrapLimits() error {
	memory, err := bootstrapMemory()
	if err != nil {
		return err
	}
	return setDataLimit(memory)
}

// bootstrapMemory reads the memory bound the parent passed out of band.
func bootstrapMemory() (int64, error) {
	value := os.Getenv(workerMemoryEnv)
	if value == "" {
		return 0, errors.New("worker has no memory bound")
	}
	memory, err := strconv.ParseInt(value, 10, 64)
	if err != nil || memory <= 0 {
		return 0, errors.New("worker has an invalid memory bound")
	}
	return memory, nil
}

// applyWorkerLimits sets the CPU and data limits. They apply to the process that
// executes the script, so the kernel refuses an allocation or a time slice instead
// of a check noticing afterwards.
//
// The memory bound is RLIMIT_DATA rather than RLIMIT_AS: the Go runtime reserves
// large address-space arenas at startup that count against RLIMIT_AS, so an
// address-space bound near the intended heap size makes the runtime fail to start
// at all. RLIMIT_DATA bounds the heap the script can actually reach.
func applyWorkerLimits(limits *SandboxLimits) error {
	cpu := seconds(limits.MaxCPUTime)
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: cpu, Max: cpu}); err != nil {
		return errors.New("worker could not set its CPU limit")
	}
	return setDataLimit(limits.MaxMemoryBytes)
}

// setDataLimit applies the heap bound. It is called twice: once before decoding and
// once before the script runs, because the two phases allocate for different
// reasons and neither may exceed the bound.
func setDataLimit(memory int64) error {
	limit := uint64(memory) //nolint:gosec // positive, checked by the caller
	if err := syscall.Setrlimit(syscall.RLIMIT_DATA, &syscall.Rlimit{Cur: limit, Max: limit}); err != nil {
		return errors.New("worker could not set its memory limit")
	}
	return nil
}

// seconds converts a validated CPU bound to whole seconds. SandboxLimits.Validate
// refuses a bound that is not a whole number of seconds, so this cannot round a
// configured value into a different one.
func seconds(d time.Duration) uint64 {
	return uint64(d / time.Second) //nolint:gosec // positive and whole after validation
}
