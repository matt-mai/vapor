package lock

import (
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/schema/base"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

type lockInputKey struct {
	role string
	path string
}

func verifyLockLocalInputs(spec *schemaSpec.Spec, lock *Lockfile) (map[lockInputKey]LocalInput, error) {
	expected := expectedLocalInputs(spec)
	inputs := make(map[lockInputKey]LocalInput)
	for i, input := range lock.LocalInputs {
		key, err := verifyLocalInput(input, i, expected)
		if err != nil {
			return nil, err
		}
		if _, ok := inputs[key]; ok {
			return nil, fmt.Errorf("lock local-inputs[%d]: duplicate role and path", i)
		}
		inputs[key] = input
	}
	if len(inputs) != len(expected) {
		return nil, errors.New("lock local inputs do not cover every declared key, CA and VEX input")
	}
	return inputs, nil
}

func expectedLocalInputs(spec *schemaSpec.Spec) map[lockInputKey]bool {
	expected := make(map[lockInputKey]bool)
	for i := range spec.Contents.Repositories {
		for _, key := range spec.Contents.Repositories[i].Trust.Keys {
			expected[lockInputKey{role: trustKeyRole, path: key.Path}] = true
		}
	}
	if spec.Filesystem.CA != nil {
		for _, source := range spec.Filesystem.CA.Sources {
			expected[lockInputKey{role: "ca", path: source}] = true
		}
	}
	for _, source := range spec.VEX.Inputs {
		expected[lockInputKey{role: "vex", path: source}] = true
	}
	return expected
}

func verifyLocalInput(input LocalInput, i int, expected map[lockInputKey]bool) (lockInputKey, error) {
	if input.Role != trustKeyRole && input.Role != "ca" && input.Role != "vex" {
		return lockInputKey{}, fmt.Errorf("lock local-inputs[%d]: unsupported role", i)
	}
	if err := base.ValidateLocalPath(input.Path); err != nil {
		return lockInputKey{}, fmt.Errorf("lock local-inputs[%d]: %w", i, err)
	}
	if err := checkLockHash("lock local input", input.SHA256); err != nil {
		return lockInputKey{}, fmt.Errorf("lock local-inputs[%d]: %w", i, err)
	}
	if err := checkLockSize("lock local input", input.Size); err != nil {
		return lockInputKey{}, fmt.Errorf("lock local-inputs[%d]: %w", i, err)
	}
	key := lockInputKey{role: input.Role, path: input.Path}
	if !expected[key] {
		return lockInputKey{}, fmt.Errorf("lock local-inputs[%d]: path does not match a declared spec input", i)
	}
	return key, nil
}
