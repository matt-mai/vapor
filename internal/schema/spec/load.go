package spec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"
)

// MaxSpecSize bounds encoded spec input before YAML node allocation.
const MaxSpecSize = 4 << 20

// LoadSpec reads a single strict YAML document, applies defaults and validates it.
// It returns no partial specification on failure and does not acquire image inputs.
func LoadSpec(path string) (*Spec, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read spec %q: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxSpecSize+1))
	if fileErr := errors.Join(readErr, file.Close()); fileErr != nil {
		return nil, fmt.Errorf("read spec %q: %w", path, fileErr)
	}
	spec, err := DecodeSpec(data)
	if err != nil {
		return nil, fmt.Errorf("load spec %q: %w", path, err)
	}
	ApplyDefaults(spec)
	if err := ValidateSpec(spec); err != nil {
		return nil, fmt.Errorf("load spec %q: validate spec: %w", path, err)
	}
	return spec, nil
}

// DecodeSpec strictly decodes a spec without applying defaults or semantic validation.
func DecodeSpec(data []byte) (*Spec, error) {
	if len(data) > MaxSpecSize {
		return nil, fmt.Errorf("spec document exceeds %d-byte limit", MaxSpecSize)
	}
	return DecodeDocument[Spec](data, "spec", nil)
}

// DecodeDocument strictly decodes one YAML mapping into T. The optional check
// runs on the validated mapping node before decoding; lock records use it to
// enforce required fields that YAML decoding cannot distinguish from values.
func DecodeDocument[T any](data []byte, kind string, check func(*yaml.Node) error) (*T, error) {
	if err := checkTypedDocument(data, reflect.TypeFor[T](), kind, check); err != nil {
		return nil, err
	}
	// Decode the same immutable bytes again because Node.Decode cannot enforce KnownFields.
	// This is a tradeoff between performance and correctness. We could avoid the second decode by
	// using a custom decoder that checks for unknown fields, but that would be more complex.
	// Given the small size of the record, the performance impact is negligible.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var record T
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode %s: %w", kind, yamlFailure(err))
	}
	return &record, nil
}

func checkTypedDocument(data []byte, expected reflect.Type, kind string, check func(*yaml.Node) error) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode %s document: %w", kind, yamlFailure(err))
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("decode trailing %s document: %w", kind, yamlFailure(err))
		}
		return fmt.Errorf("%s must contain exactly one YAML document", kind)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a YAML mapping", kind)
	}
	if err := checkNode(document.Content[0], expected, kind); err != nil {
		return err
	}
	if check != nil {
		return check(document.Content[0])
	}
	return nil
}

func yamlFailure(cause error) error {
	return &inputError{message: "invalid YAML syntax or field type (input values redacted)", cause: cause}
}
