package mutation

import (
	"encoding/base64"
	"errors"
	"math"
	"os"
	"strconv"
)

func checkMessageBound(request *ScriptRequest, bound int64) error {
	wire := int64(base64.StdEncoding.EncodedLen(len(request.Script))) + maxWireOverhead
	for _, file := range request.FileIndex {
		wire += escapedLength(file.Name) + 48
		if len(file.Digest) > 0 {
			wire += int64(base64.StdEncoding.EncodedLen(len(file.Digest))) + 16
		}
	}
	for _, name := range request.Dirs {
		wire += escapedLength(name) + 4
	}
	for name, target := range request.Links {
		wire += escapedLength(name) + escapedLength(target) + 6
	}
	for _, name := range request.Mutable {
		wire += escapedLength(name) + 4
	}
	for _, name := range request.HardLinks {
		wire += escapedLength(name) + 4
	}
	if wire > bound || uint64(len(request.FileIndex)) > math.MaxUint32 {
		return &ScriptError{Kind: FailureMessage, Message: "mutation request exceeds the message bound"}
	}
	return nil
}

func replyBound(maxWrites int64, mutable []string) (int, error) {
	bound := maxWireOverhead + 6*maxDiagnosticBytes
	if len(mutable) == 0 {
		return bound, nil
	}
	overflow := errors.New("mutation sandbox reply bound is too large")
	for _, name := range mutable {
		// Each entry adds JSON punctuation and may round its base64 up separately.
		const overhead = 10
		if remaining := math.MaxInt - bound - overhead; remaining < 0 || len(name) > remaining/6 {
			return 0, overflow
		}
		bound += 6*len(name) + overhead
	}
	if maxWrites > int64((math.MaxInt-bound)/4)*3 {
		return 0, overflow
	}
	return bound + base64.StdEncoding.EncodedLen(int(maxWrites)), nil //nolint:gosec // checked above
}

// bootstrapMessage reads the message bound the parent passed out of band. Only the
// parsing lives here: the bound is applied by the caller that reads the payload.
func bootstrapMessage() (int64, error) {
	value := os.Getenv(workerMessageEnv)
	if value == "" {
		return 0, errors.New("worker has no message bound")
	}
	bound, err := strconv.ParseInt(value, 10, 64)
	if err != nil || bound <= 0 {
		return 0, errors.New("worker has an invalid message bound")
	}
	return bound, nil
}

// escapedLength is the worst-case encoded length of a JSON string: every byte
// becomes a six-byte \u00XX escape.
func escapedLength(value string) int64 {
	return 6 * int64(len(value))
}
