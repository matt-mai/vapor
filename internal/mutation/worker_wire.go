package mutation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const workerEnvMark = "VAPOR_SANDBOX_WORKER"

const (
	// workerRootEnv names the empty directory the worker confines itself to.
	workerRootEnv = "VAPOR_SANDBOX_ROOT"
	// workerAbortEnv makes the worker exit without a reply. Only a test sets it.
	workerAbortEnv = "VAPOR_SANDBOX_ABORT"
	// workerHangEnv makes the worker block before evaluating. Only a test sets it.
	workerHangEnv = "VAPOR_SANDBOX_HANG"
	// workerMemoryEnv carries the memory bound out of band, because it has to be
	// applied before the request is decoded: decoding allocates, and the request
	// carries the content map the bound exists to refuse.
	workerMemoryEnv = "VAPOR_SANDBOX_MEMORY"
	// workerMessageEnv carries the message bound out of band, because the worker's
	// stdin reader has to be bounded before the request is decoded and the bound
	// cannot be read from the payload it is meant to bound.
	workerMessageEnv = "VAPOR_SANDBOX_MESSAGE"
	// maxDiagnosticBytes bounds one script-controlled diagnostic, such as the
	// message of a failed assertion. A script can build a string of any size and
	// pass it to fail(), so the message is truncated before it is serialized rather
	// than after it has crossed the pipe.
	maxDiagnosticBytes = 4 << 10
	// maxWireOverhead bounds the fixed JSON framing around a request payload: the
	// object keys and the limits block. Paths and content are measured separately.
	// It is a generous multiple of the real key text, because an under-estimate
	// would reject a valid request rather than admit an oversized one.
	maxWireOverhead = 4 << 10
	// runtimeFatalExitCode is the exit status of a Go runtime fatal error, which
	// for a worker means the address-space limit refused an allocation.
	runtimeFatalExitCode = 2
	// workerAbortExitCode is how a test worker exits when told to die without a
	// reply. It is outside the runtime and CPU codes so the parent's mapping is
	// unambiguous.
	workerAbortExitCode = 9
	// workerCPUExitCode is how a worker exits when its CPU limit is reached. The
	// worker reports it explicitly because the default signal disposition is not
	// reliable enough to distinguish from a crash.
	workerCPUExitCode = 3
)

func workerEnv(root string, limits SandboxLimits) []string {
	return []string{
		workerEnvMark + "=1",
		workerRootEnv + "=" + root,
		workerMemoryEnv + "=" + strconv.FormatInt(limits.MaxMemoryBytes, 10),
		// Leave headroom under RLIMIT_DATA for transient allocations and non-Go memory.
		"GOMEMLIMIT=" + strconv.FormatInt(limits.MaxMemoryBytes-limits.MaxMemoryBytes/4, 10),
		workerMessageEnv + "=" + strconv.FormatInt(limits.MaxMessageBytes, 10),
		"GORACE=atexit_sleep_ms=0",
	}
}

// ScriptRequest is one mutation script handed to a worker.
type ScriptRequest struct {
	// Script is the source text, already within the script bound.
	Script []byte `json:"script"`
	// MaxSteps is the interpreter step budget for this script.
	MaxSteps int `json:"max_steps"`
	// Files supplies in-memory inputs to RunScript. File bodies stay in the parent.
	Files map[string][]byte `json:"-"`
	// FileIndex maps wire IDs (slice offsets) to the visible regular files.
	FileIndex []fileMetadata `json:"file_index,omitempty"`
	readBody  func(uint32, int64) ([]byte, error)
	// Dirs lists the selected directories, including ones that hold no file. A
	// directory reconstructed from file parents alone would lose an empty one.
	Dirs []string `json:"dirs,omitempty"`
	// Links maps a selected symlink path to its target, so a script can list it and
	// read through it. Writes through a link stay refused.
	Links map[string]string `json:"links,omitempty"`
	// Mutable lists the paths a script may write: selected mutable regular files.
	Mutable []string `json:"mutable,omitempty"`
	// HardLinks lists paths that share an inode with another path. Upstream refuses
	// to mutate them, because the write would silently affect the other name.
	HardLinks []string `json:"hard_links,omitempty"`
	// Abort makes the worker die without replying, so the parent's handling of an
	// abruptly killed worker is testable. It is never set for a real build.
	Abort bool `json:"abort,omitempty"`
	// Hang makes the worker block before evaluating anything. Starlark has no
	// blocking primitive, so this is the only way to prove the wall clock and
	// cancellation stop a worker that never reaches the interpreter.
	Hang bool `json:"hang,omitempty"`
}

// workerPayload is what crosses to the worker. The limits travel with the request
// so the worker enforces exactly what the parent validated instead of its own
// defaults.
type workerPayload struct {
	Request ScriptRequest `json:"request"`
	Limits  workerLimits  `json:"limits"`
}

// workerLimits is the wire form of the byte and time bounds. Durations cross as
// nanoseconds so the worker cannot reinterpret a unit.
type workerLimits struct {
	MaxScriptBytes    int64 `json:"max_script_bytes"`
	MaxReadBytes      int64 `json:"max_read_bytes"`
	MaxWriteBytes     int64 `json:"max_write_bytes"`
	MaxScriptWrites   int64 `json:"max_script_writes"`
	MaxVFSGrowthBytes int64 `json:"max_vfs_growth_bytes"`
	MaxMemoryBytes    int64 `json:"max_memory_bytes"`
	MaxWallTime       int64 `json:"max_wall_time"`
	MaxCPUTime        int64 `json:"max_cpu_time"`
}

func encodeLimits(limits SandboxLimits) workerLimits {
	return workerLimits{
		MaxScriptBytes:    limits.MaxScriptBytes,
		MaxReadBytes:      limits.MaxReadBytes,
		MaxWriteBytes:     limits.MaxWriteBytes,
		MaxScriptWrites:   limits.MaxScriptWrites,
		MaxVFSGrowthBytes: limits.MaxVFSGrowthBytes,
		MaxMemoryBytes:    limits.MaxMemoryBytes,
		MaxWallTime:       int64(limits.MaxWallTime),
		MaxCPUTime:        int64(limits.MaxCPUTime),
	}
}

func (w workerLimits) decode() SandboxLimits {
	return SandboxLimits{
		MaxScriptBytes:    w.MaxScriptBytes,
		MaxReadBytes:      w.MaxReadBytes,
		MaxWriteBytes:     w.MaxWriteBytes,
		MaxScriptWrites:   w.MaxScriptWrites,
		MaxVFSGrowthBytes: w.MaxVFSGrowthBytes,
		MaxMemoryBytes:    w.MaxMemoryBytes,
		MaxWallTime:       time.Duration(w.MaxWallTime),
		MaxCPUTime:        time.Duration(w.MaxCPUTime),
	}
}

// ScriptResult is what a worker reports after running a script.
type ScriptResult struct {
	// Steps is the interpreter steps the script used.
	Steps uint64 `json:"steps"`
	// HostVisible reports whether the worker could read a host path. It must be
	// false: the worker runs in an empty root.
	HostVisible bool `json:"host_visible"`
	// Writes contains the final bytes of files whose content changed.
	Writes writeDelta `json:"writes,omitempty"`
}

type writeDelta map[string][]byte

func (w *writeDelta) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errors.New("worker writes must be an object")
	}
	writes := make(writeDelta)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return errors.New("worker write path is malformed")
		}
		if _, duplicate := writes[name]; duplicate {
			return errors.New("worker replied with a duplicate write path")
		}
		data, err := readWriteBody(decoder)
		if err != nil {
			return err
		}
		writes[name] = data
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("worker writes are malformed")
	}
	*w = writes
	return nil
}

func readWriteBody(decoder *json.Decoder) ([]byte, error) {
	token, err := decoder.Token()
	encoded, ok := token.(string)
	if err != nil || !ok {
		return nil, errors.New("worker write must contain a base64 string")
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// ScriptError is a script or sandbox failure reported by the worker.
type ScriptError struct {
	Kind    FailureKind `json:"kind"`
	Message string      `json:"message"`
}

func (e *ScriptError) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}
