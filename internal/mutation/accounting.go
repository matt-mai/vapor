package mutation

import "os"

// hostProbePath is a path that exists on the host and never inside a worker's
// empty root. Reading it is the capability probe: it must always fail.
const hostProbePath = "/etc/hostname"

// harnessState accounts for the bytes one script consumes. It is the single place
// the content API charges the read, write and growth bounds, so a script cannot
// consume more than its budget through any combination of calls.
type harnessState struct {
	writes map[string][]byte
	reads  int64
	wrote  int64
	growth int64
}

// chargeRead accounts for n bytes read from the content set.
func (s *harnessState) chargeRead(n int64) error {
	if n < 0 || n > s.reads {
		return &ScriptError{Kind: FailureRead, Message: "script exceeded the read bound"}
	}
	s.reads -= n
	return nil
}

func (s *harnessState) chargeWrite(path, data string, previousSize int64, limits *SandboxLimits) error {
	n := int64(len(data))
	if n > limits.MaxWriteBytes {
		return &ScriptError{Kind: FailureWrite, Message: "write exceeds the write bound"}
	}
	if n > limits.MaxScriptWrites-s.wrote {
		return &ScriptError{Kind: FailureWrite, Message: "script exceeded the write bound"}
	}
	growth := s.growth + (n - previousSize)
	if growth > limits.MaxVFSGrowthBytes {
		return &ScriptError{Kind: FailureVFSGrowth, Message: "script exceeded the content growth bound"}
	}
	s.wrote += n
	s.growth = growth
	s.writes[path] = []byte(data)
	return nil
}

// hostVisible reports whether the worker can read a host path. It is the
// capability probe: after confinement it must always be false.
func hostVisible() bool {
	_, err := os.ReadFile(hostProbePath)
	return err == nil
}
