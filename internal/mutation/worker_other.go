//go:build !linux

package mutation

import (
	"errors"
	"os/exec"
)

// configureWorker refuses to start a worker where the limits cannot be enforced.
func configureWorker(*exec.Cmd) error {
	return errors.New("mutation sandbox requires Linux resource limits")
}

// applyBootstrapLimits is unreachable: a worker cannot start on this platform.
func applyBootstrapLimits() error {
	return errors.New("mutation sandbox requires Linux resource limits")
}

// bootstrapMemory is unreachable: a worker cannot start on this platform.
func bootstrapMemory() (int64, error) {
	return 0, errors.New("mutation sandbox requires Linux resource limits")
}

// executeConfined is unreachable: a worker cannot start on this platform.
func executeConfined(*ScriptRequest, *SandboxLimits) (*ScriptResult, *ScriptError) {
	return nil, &ScriptError{Kind: FailureCapability, Message: "mutation sandbox requires Linux resource limits"}
}
