package mutation

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// The worker runs in a child process, so its coverage never reaches the parent's
// profile. These tests call the evaluator directly, which covers the content API and
// the interpreter wiring without crossing a process boundary. The boundary itself is
// covered by the external tests.

func evaluatorRequest(script string) *ScriptRequest {
	return &ScriptRequest{
		Script:   []byte(script),
		MaxSteps: 1000,
		Files: map[string][]byte{
			"/etc/app.conf":        []byte("original"),
			"/usr/share/app/data":  []byte("payload"),
			"/usr/share/app/read":  []byte("read-only"),
			"/usr/share/app/sub/x": []byte("nested"),
		},
		Mutable: []string{"/etc/app.conf", "/usr/share/app/data"},
	}
}

func evaluatorLimits() *SandboxLimits {
	limits := DefaultSandboxLimits()
	limits.MaxScriptBytes = 4 << 10
	limits.MaxReadBytes = 64 << 10
	limits.MaxWriteBytes = 16 << 10
	limits.MaxScriptWrites = 32 << 10
	limits.MaxVFSGrowthBytes = 64 << 10
	return &limits
}

func requireEvaluatorKind(t *testing.T, err *ScriptError, want FailureKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", want)
	}
	if err.Kind != want {
		t.Fatalf("failure kind = %s, want %s (%s)", err.Kind, want, err.Message)
	}
}

func TestEvaluatorRunsScript(t *testing.T) {
	result, scriptErr := runStarlark(evaluatorRequest(`content.write("/etc/app.conf", "changed")`), evaluatorLimits())
	if scriptErr != nil {
		t.Fatalf("runStarlark: %v", scriptErr)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "changed" {
		t.Fatalf("write = %q", got)
	}
	if result.Steps == 0 {
		t.Fatal("no steps reported")
	}
	// The evaluator runs in this process, so the probe reports what the host can see.
	// Confinement is the worker's job and is asserted across the process boundary.
	if !result.HostVisible {
		t.Fatal("in-process probe did not see the host")
	}
}

func TestEvaluatorReadAndList(t *testing.T) {
	script := `content.write("/etc/app.conf", content.read("/usr/share/app/data") + ":" + ",".join(content.list("/usr/share/app")))`
	result, scriptErr := runStarlark(evaluatorRequest(script), evaluatorLimits())
	if scriptErr != nil {
		t.Fatalf("runStarlark: %v", scriptErr)
	}
	if got := string(result.Writes["/etc/app.conf"]); got != "payload:data,read,sub/" {
		t.Fatalf("result = %q", got)
	}
}

func TestEvaluatorListOfRootAndNested(t *testing.T) {
	cases := map[string]string{
		`content.list("/")`:                  "etc/,usr/",
		`content.list("/usr/share/app/sub")`: "x",
		`content.list("/usr/share/app/")`:    "data,read,sub/",
	}
	for script, want := range cases {
		t.Run(script, func(t *testing.T) {
			value, scriptErr := runStarlark(evaluatorRequest(`content.write("/etc/app.conf", ",".join(`+script+`))`), evaluatorLimits())
			if scriptErr != nil {
				t.Fatalf("runStarlark: %v", scriptErr)
			}
			if got := string(value.Writes["/etc/app.conf"]); got != want {
				t.Fatalf("list = %q, want %q", got, want)
			}
		})
	}
}

func TestEvaluatorStepBudget(t *testing.T) {
	_, scriptErr := runStarlark(evaluatorRequest("for i in range(10000):\n    pass\n"), evaluatorLimits())
	requireEvaluatorKind(t, scriptErr, FailureSteps)
}

func TestEvaluatorBounds(t *testing.T) {
	limits := evaluatorLimits()
	limits.MaxReadBytes = 4
	_, scriptErr := runStarlark(evaluatorRequest(`content.read("/usr/share/app/data")`), limits)
	requireEvaluatorKind(t, scriptErr, FailureRead)

	limits = evaluatorLimits()
	limits.MaxWriteBytes = 4
	_, scriptErr = runStarlark(evaluatorRequest(`content.write("/etc/app.conf", "0123456789")`), limits)
	requireEvaluatorKind(t, scriptErr, FailureWrite)

	limits = evaluatorLimits()
	limits.MaxScriptWrites = 4
	_, scriptErr = runStarlark(evaluatorRequest(`content.write("/etc/app.conf", "0123456789")`), limits)
	requireEvaluatorKind(t, scriptErr, FailureWrite)

	limits = evaluatorLimits()
	limits.MaxVFSGrowthBytes = 1
	_, scriptErr = runStarlark(evaluatorRequest(`content.write("/etc/app.conf", "0123456789")`), limits)
	requireEvaluatorKind(t, scriptErr, FailureVFSGrowth)
}

func TestEvaluatorCapabilityRefusals(t *testing.T) {
	cases := map[string]string{
		"unselected read":   `content.read("/etc/shadow")`,
		"relative read":     `content.read("etc/app.conf")`,
		"unclean read":      `content.read("/etc/../etc/app.conf")`,
		"immutable write":   `content.write("/usr/share/app/read", "x")`,
		"created write":     `content.write("/etc/new", "x")`,
		"directory write":   `content.write("/usr/share/app", "x")`,
		"file list":         `content.list("/etc/app.conf")`,
		"unselected list":   `content.list("/proc")`,
		"unknown attribute": `content.exec("/bin/sh")`,
		"undefined name":    `open("/etc/passwd")`,
		"syntax error":      `this is not starlark(`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			_, scriptErr := runStarlark(evaluatorRequest(script), evaluatorLimits())
			requireEvaluatorKind(t, scriptErr, FailureCapability)
		})
	}
}

func TestEvaluatorHardLinkWriteIsRefused(t *testing.T) {
	request := evaluatorRequest(`content.write("/etc/app.conf", "x")`)
	request.HardLinks = []string{"/etc/app.conf"}
	_, scriptErr := runStarlark(request, evaluatorLimits())
	requireEvaluatorKind(t, scriptErr, FailureCapability)
}

func TestEvaluatorWriteReturnsNone(t *testing.T) {
	_, scriptErr := runStarlark(evaluatorRequest(`x = content.write("/etc/app.conf", "v")
if x != None:
    fail("write returned a value")
`), evaluatorLimits())
	if scriptErr != nil {
		t.Fatalf("runStarlark: %v", scriptErr)
	}
}

func TestEvaluatorPrintIsDiscarded(t *testing.T) {
	// A script that prints must not fail and must not write anywhere.
	_, scriptErr := runStarlark(evaluatorRequest(`print("noise")`), evaluatorLimits())
	if scriptErr != nil {
		t.Fatalf("runStarlark: %v", scriptErr)
	}
}

func TestEvaluatorListChargesReturnedNames(t *testing.T) {
	limits := evaluatorLimits()
	limits.MaxReadBytes = 4
	_, scriptErr := runStarlark(evaluatorRequest(`content.list("/usr/share/app")`), limits)
	requireEvaluatorKind(t, scriptErr, FailureRead)
}

func TestScriptErrorKeepsKind(t *testing.T) {
	original := &ScriptError{Kind: FailureMemory, Message: "boom"}
	if got := scriptError(original); got != original {
		t.Fatalf("scriptError lost the original: %+v", got)
	}
	wrapped := errors.New("plain failure")
	got := scriptError(wrapped)
	if got.Kind != FailureCapability || got.Message != "plain failure" {
		t.Fatalf("scriptError = %+v", got)
	}
	multiline := scriptError(errors.New("first line\nsecond line"))
	if multiline.Message != "first line" {
		t.Fatalf("scriptError kept extra lines: %q", multiline.Message)
	}
}

func TestContentValueProtocol(t *testing.T) {
	value := newContentValue(evaluatorRequest(""), &harnessState{}, evaluatorLimits())
	if value.String() != "content{...}" || value.Type() != "content" {
		t.Fatalf("value = %s/%s", value.String(), value.Type())
	}
	if value.Truth() != true {
		t.Fatal("content is not truthy")
	}
	value.Freeze()
	if _, err := value.Hash(); err == nil {
		t.Fatal("content is hashable")
	}
	names := value.AttrNames()
	if strings.Join(names, ",") != "list,read,write" {
		t.Fatalf("AttrNames = %v", names)
	}
	for _, name := range names {
		if _, err := value.Attr(name); err != nil {
			t.Fatalf("Attr(%q): %v", name, err)
		}
	}
	if attr, err := value.Attr("missing"); attr != nil || err != nil {
		t.Fatalf("Attr(missing) = %v, %v", attr, err)
	}
}

func TestEvaluatorRevertedWriteRestoresGrowthBudget(t *testing.T) {
	request := evaluatorRequest(`content.write("/etc/app.conf", "0123456789")
if content.read("/alias") != "0123456789":
    fail("read did not see the staged write")
content.write("/etc/app.conf", "original")`)
	request.Links = map[string]string{"/alias": "/etc/app.conf"}
	limits := evaluatorLimits()
	limits.MaxVFSGrowthBytes = 2
	result, scriptErr := runStarlark(request, limits)
	if scriptErr != nil {
		t.Fatalf("runStarlark: %v", scriptErr)
	}
	if len(result.Writes) != 0 || string(request.Files["/etc/app.conf"]) != "original" {
		t.Fatal("reverted write appeared in the delta or changed the input")
	}

	limits.MaxReadBytes = 8
	_, scriptErr = runStarlark(request, limits)
	requireEvaluatorKind(t, scriptErr, FailureRead)

	limits.MaxReadBytes = 10
	limits.MaxScriptWrites = 17
	_, scriptErr = runStarlark(request, limits)
	requireEvaluatorKind(t, scriptErr, FailureWrite)

	limits.MaxScriptWrites = 27
	request.Script = append(request.Script, `
content.write("/usr/share/app/data", "123456789")`...)
	result, scriptErr = runStarlark(request, limits)
	if scriptErr != nil {
		t.Fatalf("revert did not free growth budget: %v", scriptErr)
	}
	if got := string(result.Writes["/usr/share/app/data"]); len(result.Writes) != 1 || got != "123456789" {
		t.Fatalf("write delta = %q", result.Writes)
	}
}

// A worker can write to its own pipes, so the collection buffer must stop at its
// limit instead of growing. The truncation is reported, because a truncated reply
// is a worker failure rather than a partial result.
func TestBoundedBufferStopsAtItsLimit(t *testing.T) {
	var collected bytes.Buffer
	buffer := &boundedBuffer{buffer: &collected, limit: 8}
	written, err := buffer.Write([]byte("0123456789"))
	if err != nil || written != 10 {
		t.Fatalf("Write = %d, %v; want 10, nil", written, err)
	}
	if collected.String() != "01234567" {
		t.Fatalf("collected %q, want the first eight bytes", collected.String())
	}
	if !buffer.truncated {
		t.Fatal("truncation was not reported")
	}
	if _, err := buffer.Write([]byte("more")); err != nil {
		t.Fatalf("Write after the limit: %v", err)
	}
	if collected.Len() != 8 {
		t.Fatalf("buffer grew past its limit: %q", collected.String())
	}
}

func TestBoundedBufferKeepsShortWrites(t *testing.T) {
	var collected bytes.Buffer
	buffer := &boundedBuffer{buffer: &collected, limit: 8}
	if _, err := buffer.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	if buffer.truncated || collected.String() != "short" {
		t.Fatalf("collected %q truncated=%v", collected.String(), buffer.truncated)
	}
}

// A script-controlled diagnostic is truncated before it is serialized, so a
// script cannot make the parent hold an arbitrarily large message.
func TestTruncateDiagnosticBoundsScriptMessages(t *testing.T) {
	if got := truncateDiagnostic("first line\nsecond line"); got != "first line" {
		t.Fatalf("truncateDiagnostic = %q, want the first line", got)
	}
	huge := strings.Repeat("x", 3*maxDiagnosticBytes)
	if got := len(truncateDiagnostic(huge)); got != maxDiagnosticBytes {
		t.Fatalf("truncateDiagnostic length = %d, want %d", got, maxDiagnosticBytes)
	}
}

// The message bound has to be known before the request is decoded, so it arrives
// in the environment like the memory bound. A worker that cannot read it must fail
// rather than fall back to a default the parent did not validate.
func TestBootstrapMessageReadsTheEnvironment(t *testing.T) {
	t.Setenv(workerMessageEnv, "")
	if _, err := bootstrapMessage(); err == nil {
		t.Fatal("a worker with no message bound was accepted")
	}
	t.Setenv(workerMessageEnv, "not a number")
	if _, err := bootstrapMessage(); err == nil {
		t.Fatal("an invalid message bound was accepted")
	}
	t.Setenv(workerMessageEnv, "0")
	if _, err := bootstrapMessage(); err == nil {
		t.Fatal("a zero message bound was accepted")
	}
	t.Setenv(workerMessageEnv, strconv.FormatInt(DefaultSandboxLimits().MaxMessageBytes, 10))
	bound, err := bootstrapMessage()
	if err != nil {
		t.Fatalf("a valid message bound was refused: %v", err)
	}
	if bound != DefaultSandboxLimits().MaxMessageBytes {
		t.Fatalf("bound = %d, want %d", bound, DefaultSandboxLimits().MaxMessageBytes)
	}
}

func TestReplyBoundFitsEncodedWrites(t *testing.T) {
	const count = 16 << 10
	writes := make(writeDelta, count+1)
	mutable := make([]string, 0, count+1)
	for i := range count {
		name := "/\"<\x01" + strconv.Itoa(i)
		writes[name] = []byte("x")
		mutable = append(mutable, name)
	}
	writes["/empty"] = []byte("")
	mutable = append(mutable, "/empty")
	bound, err := replyBound(count, mutable)
	if err != nil {
		t.Fatal(err)
	}
	var reply bytes.Buffer
	writeWorkerReply(&reply, &ScriptResult{Writes: writes}, nil)
	if reply.Len() == 0 || reply.Len() > bound {
		t.Fatalf("encoded length = %d, bound = %d", reply.Len(), bound)
	}
	larger, err := replyBound(2*count, mutable)
	if err != nil || larger <= bound {
		t.Fatalf("larger write budget: bound = %d, error = %v", larger, err)
	}
	if _, err := replyBound(math.MaxInt64, mutable); err == nil {
		t.Fatal("unrepresentable reply bound was accepted")
	}
}

func TestReadWorkerReplyRejectsMalformedWriteDeltas(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"result":{},"error":{"kind":"write-bytes"}}`,
		`{"result":{"writes":null}}`,
		`{"result":{"writes":{"/a":null}}}`,
		`{"result":{"writes":{"/a":[1]}}}`,
		`{"result":{"writes":{"/a":"not base64"}}}`,
		`{"result":{"writes":{"/a":"","\u002fa":""}}}`,
	} {
		if _, err := readWorkerReply([]byte(raw)); err == nil {
			t.Errorf("malformed reply accepted: %s", raw)
		}
	}
	reply, err := readWorkerReply([]byte(`{"result":{"writes":{"/a":""}}}`))
	if err != nil || reply.Result.Writes["/a"] == nil || len(reply.Result.Writes["/a"]) != 0 {
		t.Fatalf("empty write rejected: %+v, %v", reply, err)
	}
}

func TestAcceptReplyRejectsInvalidWrites(t *testing.T) {
	request := evaluatorRequest("")
	request.HardLinks = []string{"/etc/linked"}
	request.Mutable = append(request.Mutable, "/etc/linked", "/etc/missing")
	request.Files["/etc/linked"] = []byte("old")
	request.FileIndex = indexFiles(request.Files)
	limits := evaluatorLimits()
	limits.MaxWriteBytes, limits.MaxScriptWrites = 4, 6
	for _, test := range []struct {
		name   string
		writes map[string][]byte
		want   FailureKind
	}{
		{"new path", map[string][]byte{"/etc/missing": []byte("x")}, FailureCapability},
		{"immutable", map[string][]byte{"/usr/share/app/read": []byte("x")}, FailureCapability},
		{"hard link", map[string][]byte{"/etc/linked": []byte("x")}, FailureCapability},
		{"file budget", map[string][]byte{"/etc/app.conf": []byte("12345")}, FailureWrite},
		{"total budget", map[string][]byte{"/etc/app.conf": []byte("1234"), "/usr/share/app/data": []byte("1234")}, FailureWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := acceptedReply(workerReply{Result: &ScriptResult{Writes: test.writes}}, request, limits)
			var scriptErr *ScriptError
			if result != nil || !errors.As(err, &scriptErr) {
				t.Fatalf("invalid result accepted: %+v, %v", result, err)
			}
			requireEvaluatorKind(t, scriptErr, test.want)
		})
	}
}

func TestWorkerEnvSetsSoftMemoryTarget(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "1GiB")
	limits := evaluatorLimits()
	limits.MaxMemoryBytes = 512 << 20
	if env := strings.Join(workerEnv("/root", *limits), "\n"); !strings.Contains(env, "\nGOMEMLIMIT=402653184\n") {
		t.Fatal("worker did not get its own 384 MiB soft target")
	}
}

// The memory bound has to be applied before the request is decoded, because
// decoding allocates the content map. It therefore cannot travel inside the
// payload, so it arrives in the environment and is applied by the worker's first
// step. Only the parsing is covered here: applying a limit lowers this process's
// hard limit, which would break every later worker in the same test binary.
func TestBootstrapMemoryReadsTheEnvironment(t *testing.T) {
	t.Setenv(workerMemoryEnv, "")
	if _, err := bootstrapMemory(); err == nil {
		t.Fatal("a worker with no memory bound was accepted")
	}
	t.Setenv(workerMemoryEnv, "not a number")
	if _, err := bootstrapMemory(); err == nil {
		t.Fatal("an invalid memory bound was accepted")
	}
	t.Setenv(workerMemoryEnv, "0")
	if _, err := bootstrapMemory(); err == nil {
		t.Fatal("a zero memory bound was accepted")
	}
	t.Setenv(workerMemoryEnv, strconv.FormatInt(DefaultSandboxLimits().MaxMemoryBytes, 10))
	memory, err := bootstrapMemory()
	if err != nil {
		t.Fatalf("a valid memory bound was refused: %v", err)
	}
	if memory != DefaultSandboxLimits().MaxMemoryBytes {
		t.Fatalf("memory = %d, want %d", memory, DefaultSandboxLimits().MaxMemoryBytes)
	}
}

// The script is base64-encoded like every other []byte, so charging its raw size
// understates the request by a third: a script-only request could then be admitted
// at a size the worker's stdin reader truncates into a malformed payload.
func TestCheckMessageBoundChargesEncodedScript(t *testing.T) {
	limits := DefaultSandboxLimits()
	request := &ScriptRequest{Script: bytes.Repeat([]byte("#"), 30000), MaxSteps: 1000}
	encoded := int64(base64.StdEncoding.EncodedLen(len(request.Script))) + maxWireOverhead
	// A bound between the raw and encoded sizes admits the raw count and must
	// refuse the encoded one.
	limits.MaxMessageBytes = encoded - 1
	if err := checkMessageBound(request, limits.MaxMessageBytes); err == nil {
		t.Fatalf("a request of %d encoded bytes was admitted under a %d bound", encoded,
			limits.MaxMessageBytes)
	}
	limits.MaxMessageBytes = encoded
	if err := checkMessageBound(request, limits.MaxMessageBytes); err != nil {
		t.Fatalf("a request of exactly the bound was refused: %v", err)
	}
}
