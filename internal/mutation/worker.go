package mutation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"time"
)

// RunScript runs one script in a sandboxed worker process. The worker has no host
// filesystem and no network, an address-space and CPU limit, and is killed when
// ctx ends or the wall-clock bound expires.
//
// A failure of any kind returns an error and no result: the caller must treat the
// script as having changed nothing.
func RunScript(ctx context.Context, request *ScriptRequest, limits SandboxLimits) (*ScriptResult, error) {
	indexed := *request
	indexed.FileIndex = indexFiles(request.Files)
	return runScript(ctx, &indexed, &limits, func(name string) (*bytes.Reader, error) {
		return bytes.NewReader(request.Files[name]), nil
	})
}

func indexFiles(files map[string][]byte) []fileMetadata {
	index := make([]fileMetadata, 0, len(files))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		index = append(index, fileMetadata{Name: name, Size: int64(len(files[name]))})
	}
	return index
}

func runScript(ctx context.Context, request *ScriptRequest, limits *SandboxLimits, open openImageFile) (*ScriptResult, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if err := SandboxSupported(); err != nil {
		return nil, err
	}
	if int64(len(request.Script)) > limits.MaxScriptBytes {
		return nil, &ScriptError{Kind: FailureScriptSize, Message: "script exceeds the source bound"}
	}
	if err := indexDigests(ctx, request, limits.MaxWriteBytes, open); err != nil {
		return nil, err
	}
	if err := checkMessageBound(request, limits.MaxMessageBytes); err != nil {
		return nil, err
	}
	if request.MaxSteps <= 0 {
		return nil, errors.New("mutation script requires a positive step budget")
	}
	payload, err := json.Marshal(workerPayload{Request: *request, Limits: encodeLimits(*limits)})
	if err != nil {
		return nil, errors.New("mutation request could not be encoded")
	}
	return runWorker(ctx, payload, request, limits, open)
}

func runWorker(
	ctx context.Context, payload []byte, request *ScriptRequest, limits *SandboxLimits, open openImageFile,
) (*ScriptResult, error) {
	bound, err := replyBound(limits.MaxScriptWrites, request.Mutable)
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.New("mutation sandbox cannot locate its own binary")
	}
	root, err := os.MkdirTemp("", "vapor-sandbox-")
	if err != nil {
		return nil, errors.New("mutation sandbox cannot create a worker root")
	}
	defer func() {
		// The root is empty by construction; a leftover directory is not worth
		// failing a build over.
		_ = os.RemoveAll(root)
	}()

	runCtx, cancel := context.WithTimeout(ctx, limits.MaxWallTime)
	defer cancel()
	// The executable is this process's own binary, so the path is not attacker
	// controlled: the worker is the same code re-executed in a confined process.
	command := exec.CommandContext(runCtx, executable) //nolint:gosec // own binary
	command.Env = workerEnv(root, *limits)
	if request.Abort {
		command.Env = append(command.Env, workerAbortEnv+"=1")
	}
	if request.Hang {
		command.Env = append(command.Env, workerHangEnv+"=1")
	}
	command.Stdin = bytes.NewReader(payload)
	if setupErr := configureWorker(command); setupErr != nil {
		return nil, setupErr
	}
	var stdout bytes.Buffer
	// Both pipes are bounded while they are collected, not after: a script can
	// write to them, and an unbounded buffer would let it allocate outside the
	// sandbox's memory limit.
	reply := &boundedBuffer{buffer: &stdout, limit: bound}
	command.Stdout = reply
	// The worker's stderr is discarded rather than inherited: it carries the
	// runtime's own message, including source paths and possibly script content, and
	// the reply is the only channel a caller reads.
	command.Stderr = &boundedBuffer{buffer: &bytes.Buffer{}, limit: maxDiagnosticBytes}
	command.WaitDelay = time.Second

	pipe, err := newReadPipe()
	if err != nil {
		return nil, err
	}
	runErr, readErr := pipe.run(runCtx, command, request.FileIndex, open, limits.MaxReadBytes)
	if err := stopReason(ctx, runCtx); err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, readFailure(readErr, runErr)
	}
	return finishWorker(runErr, reply, request, limits)
}

func readFailure(readErr, runErr error) error {
	if exit, ok := errors.AsType[*exec.ExitError](runErr); readErr == errBodyPipeClosed && ok {
		switch exit.ExitCode() {
		case runtimeFatalExitCode, workerCPUExitCode:
			return workerExitError(runErr)
		}
	}
	return readErr
}

func finishWorker(
	runErr error, reply *boundedBuffer, request *ScriptRequest, limits *SandboxLimits,
) (*ScriptResult, error) {
	// A reply that had to be truncated is not a result, whatever it decodes to.
	if reply.truncated {
		return nil, &ScriptError{Kind: FailureWorkerDeath, Message: "worker reply exceeds the reply bound"}
	}
	// The worker reports structured failures even when it exits non-zero. A
	// successful result is usable only if the worker also exited normally.
	if decoded, err := readWorkerReply(reply.buffer.Bytes()); err == nil && (runErr == nil || decoded.Error != nil) {
		return acceptedReply(decoded, request, limits)
	}
	if runErr == nil {
		return nil, &ScriptError{Kind: FailureWorkerDeath, Message: "worker result is malformed"}
	}
	return nil, workerExitError(runErr)
}

// acceptedReply returns a decoded reply's result, or the failure it carries. A
// worker that can read a host path is not confined, whatever the script did:
// reporting success would hand the caller a result from a sandbox that did not
// hold, so it is a failure rather than a flag the caller may ignore.
func acceptedReply(reply workerReply, request *ScriptRequest, limits *SandboxLimits) (*ScriptResult, error) {
	if reply.Error != nil {
		return nil, reply.Error
	}
	if reply.Result.HostVisible {
		return nil, &ScriptError{Kind: FailureWorkerDeath,
			Message: "worker could read a host path, so confinement failed"}
	}
	if err := validateWrites(reply.Result.Writes, request, limits); err != nil {
		return nil, err
	}
	return reply.Result, nil
}

func validateWrites(writes map[string][]byte, request *ScriptRequest, limits *SandboxLimits) error {
	if len(writes) == 0 {
		return nil
	}
	mutable := writablePaths(request)
	remaining := limits.MaxScriptWrites
	files := make(map[string]bool, len(request.FileIndex))
	for _, file := range request.FileIndex {
		files[file.Name] = true
	}
	for name, data := range writes {
		if !files[name] || !mutable[name] {
			return &ScriptError{Kind: FailureCapability, Message: "worker wrote outside the mutable file set"}
		}
		size := int64(len(data))
		if size > limits.MaxWriteBytes || size > remaining {
			return &ScriptError{Kind: FailureWrite, Message: "worker reply exceeds the write bound"}
		}
		remaining -= size
	}
	return nil
}

func writablePaths(request *ScriptRequest) map[string]bool {
	mutable := make(map[string]bool, len(request.Mutable))
	for _, name := range request.Mutable {
		mutable[name] = true
	}
	for _, name := range request.HardLinks {
		delete(mutable, name)
	}
	return mutable
}

// boundedBuffer collects at most limit bytes and discards the rest. A worker can
// write to its own stdout and stderr, so the bound has to hold while the bytes
// arrive; checking the accumulated size afterwards would already have allocated
// them in the parent.
type boundedBuffer struct {
	buffer    *bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	room := b.limit - b.buffer.Len()
	if room < len(data) {
		b.truncated = true
		if room > 0 {
			b.buffer.Write(data[:room])
		}
		return written, nil
	}
	b.buffer.Write(data)
	return written, nil
}

// stopReason reports why the worker was stopped, distinguishing the caller giving
// up from the wall clock expiring: both kill the process, but only one is the
// script's fault.

func stopReason(ctx, runCtx context.Context) error {
	if err := canceled(ctx); err != nil {
		return err
	}
	if runCtx.Err() != nil {
		return &ScriptError{Kind: FailureWallTime, Message: "script exceeded the wall-clock bound"}
	}
	return nil
}

func canceled(ctx context.Context) error {
	if ctx.Err() != nil {
		return &ScriptError{Kind: FailureCancelled, Message: "script was canceled"}
	}
	return nil
}

// workerExitError turns a worker exit into the bound that ended it. The worker
// reports its own failures on stdout and exits 1, so any other exit without a
// reply means the process died rather than the script failing.
//
// The exit code is the signal, not the message: a Go runtime fatal error exits 2,
// and an allocation refused by the address-space limit is the only fatal error a
// worker can hit. A negative code means a signal ended the process, which is how
// the CPU limit is enforced.
func workerExitError(runErr error) error {
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		return errors.New("mutation worker could not be started")
	}
	switch code := exitErr.ExitCode(); {
	case code == workerCPUExitCode, code < 0:
		return &ScriptError{Kind: FailureCPUTime, Message: "worker was terminated by the CPU bound"}
	case code == runtimeFatalExitCode:
		// The runtime's own message is not forwarded: it carries source paths and
		// can quote script content, which belongs in neither a build error nor a log.
		return &ScriptError{Kind: FailureMemory, Message: "worker exceeded the memory bound"}
	default:
		return &ScriptError{Kind: FailureWorkerDeath, Message: "worker exited without a result"}
	}
}

// workerReply is the worker's single reply: either a result or a failure.
type workerReply struct {
	Result *ScriptResult `json:"result,omitempty"`
	Error  *ScriptError  `json:"error,omitempty"`
}

// readWorkerReply decodes the reply. An error means the reply itself is unusable,
// not that the script failed: a script failure is carried in workerReply.Error.
func readWorkerReply(data []byte) (workerReply, error) {
	var reply workerReply
	if len(data) == 0 {
		return reply, errors.New("worker produced no result")
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return reply, errors.New("worker result is malformed")
	}
	if (reply.Error == nil) == (reply.Result == nil) {
		return reply, errors.New("worker reply must contain either a result or an error")
	}
	return reply, nil
}

// RunWorker is the worker entry point. A process re-executed with the worker mark
// calls it instead of parsing arguments and exits with its return code.
func RunWorker(stdin io.Reader, stdout io.Writer) int {
	if os.Getenv(workerAbortEnv) == "1" {
		return workerAbortExitCode
	}
	if os.Getenv(workerHangEnv) == "1" {
		// Block until the parent's wall clock or cancellation kills the process.
		select {}
	}
	// Decoding the file index must also stay inside the kernel memory limit.
	if err := applyBootstrapLimits(); err != nil {
		writeWorkerReply(stdout, nil, &ScriptError{Kind: FailureCapability, Message: err.Error()})
		return 1
	}
	payload, err := readWorkerPayload(stdin)
	if err != nil {
		writeWorkerReply(stdout, nil, &ScriptError{Kind: FailureWorkerDeath, Message: err.Error()})
		return 1
	}
	ids := os.NewFile(readRequestFD, "image file requests")
	bodies := os.NewFile(readBodyFD, "image file bodies")
	defer func() {
		_ = ids.Close()
		_ = bodies.Close()
	}()
	payload.Request.readBody = func(id uint32, size int64) ([]byte, error) {
		return receiveBody(ids, bodies, id, size)
	}
	limits := payload.Limits.decode()
	result, scriptErr := executeConfined(&payload.Request, &limits)
	writeWorkerReply(stdout, result, scriptErr)
	if scriptErr != nil {
		return 1
	}
	return 0
}

// WorkerRequested reports whether this process was started as a sandbox worker.
func WorkerRequested() bool {
	return os.Getenv(workerEnvMark) == "1"
}

// readWorkerPayload decodes the request the parent sent. The reader is bounded by
// the message bound the parent itself enforced, so a payload the parent accepted
// can never be truncated here. The bound arrives in the environment because it has
// to be known before the payload is decoded.
func readWorkerPayload(stdin io.Reader) (workerPayload, error) {
	bound, err := bootstrapMessage()
	if err != nil {
		return workerPayload{}, err
	}
	var payload workerPayload
	decoder := json.NewDecoder(io.LimitReader(stdin, bound))
	if err := decoder.Decode(&payload); err != nil {
		return payload, errors.New("worker request is malformed")
	}
	return payload, nil
}

func writeWorkerReply(stdout io.Writer, result *ScriptResult, scriptErr *ScriptError) {
	if scriptErr != nil {
		scriptErr = &ScriptError{Kind: scriptErr.Kind, Message: truncateDiagnostic(scriptErr.Message)}
	}
	// The reply is best effort: a worker whose output pipe is gone has already
	// failed, and the parent reports that as a worker death.
	_ = json.NewEncoder(stdout).Encode(workerReply{Result: result, Error: scriptErr})
}

// checkMessageBound accounts for JSON escaping and framing before marshaling.
