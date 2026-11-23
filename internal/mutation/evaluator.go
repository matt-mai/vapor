package mutation

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"maps"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// scriptOptions are the upstream v3 language options: mutation scripts are written
// as top-level code with control flow and global reassignment, which Starlark
// disables by default. Recursion stays disabled, as it is upstream.
func scriptOptions() *syntax.FileOptions {
	return &syntax.FileOptions{
		TopLevelControl: true,
		GlobalReassign:  true,
	}
}

// runStarlark evaluates one mutation script against the request's content set and
// reports the staged result.
//
// The script gets exactly two names: `content`, the restricted API, and Starlark's
// `print`, which is discarded. There is no host filesystem, no network and no way to
// reach a path the selection did not provide, so a script cannot express those
// operations at all.
func runStarlark(request *ScriptRequest, limits *SandboxLimits) (*ScriptResult, *ScriptError) {
	state := &harnessState{writes: make(map[string][]byte), reads: limits.MaxReadBytes}

	exceeded := false
	thread := &starlark.Thread{
		Name:  "mutate",
		Print: func(*starlark.Thread, string) {},
	}
	// The interpreter counts steps itself, so a script that loops forever is stopped
	// by the budget rather than by the wall clock.
	thread.SetMaxExecutionSteps(uint64(request.MaxSteps)) //nolint:gosec // positive, checked by RunScript
	thread.OnMaxSteps = func(thread *starlark.Thread) {
		exceeded = true
		thread.Cancel("too many steps")
	}
	predeclared := starlark.StringDict{
		"content": newContentValue(request, state, limits),
	}
	_, err := starlark.ExecFileOptions(scriptOptions(), thread, "mutate", request.Script, predeclared)
	if exceeded {
		return nil, &ScriptError{Kind: FailureSteps, Message: "script exceeded the step budget"}
	}
	if err != nil {
		return nil, scriptError(err)
	}
	discardUnchanged(request, state.writes)
	return &ScriptResult{Steps: thread.ExecutionSteps(), HostVisible: hostVisible(), Writes: state.writes}, nil
}

func discardUnchanged(request *ScriptRequest, writes map[string][]byte) {
	if len(writes) == 0 {
		return
	}
	if request.readBody == nil {
		maps.DeleteFunc(writes, func(name string, data []byte) bool {
			return bytes.Equal(data, request.Files[name])
		})
		return
	}
	for _, file := range request.FileIndex {
		if data, ok := writes[file.Name]; ok && int64(len(data)) == file.Size && len(file.Digest) == sha256.Size {
			digest := sha256.Sum256(data)
			if bytes.Equal(digest[:], file.Digest) {
				delete(writes, file.Name)
			}
		}
	}
}

// truncateDiagnostic keeps the first line of a script-controlled message within
// the diagnostic bound. A script can build a string of any size and pass it to
// fail(), so the message is cut here rather than after it has been serialized.
func truncateDiagnostic(message string) string {
	if index := strings.IndexByte(message, '\n'); index >= 0 {
		message = message[:index]
	}
	if len(message) > maxDiagnosticBytes {
		message = message[:maxDiagnosticBytes]
	}
	return message
}

// scriptError maps an evaluation error to a failure kind. A bound the content API
// refused already carries its kind; anything else is the script's own fault and is
// reported as a capability failure so a build never claims a resource bound was hit
// when it was not.
func scriptError(err error) *ScriptError {
	if scriptErr, ok := errors.AsType[*ScriptError](err); ok {
		return scriptErr
	}
	return &ScriptError{Kind: FailureCapability, Message: truncateDiagnostic(err.Error())}
}
