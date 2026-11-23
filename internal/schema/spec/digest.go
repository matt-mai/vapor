package spec

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// SpecDigest hashes a defaulted, validated snapshot without changing spec or reading inputs.
func (spec *Spec) SpecDigest() (string, error) {
	canonical, err := CanonicalSpec(spec)
	if err != nil {
		return "", fmt.Errorf("spec digest: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(canonical)), nil
}

// SpecDigestForRelease hashes the spec after replacing its release with the
// provider's canonical release identity.
func (spec *Spec) SpecDigestForRelease(release string) (string, error) {
	canonical, err := CanonicalSpecForRelease(spec, release)
	if err != nil {
		return "", fmt.Errorf("spec digest: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(canonical)), nil
}

// CanonicalSpec returns the deterministic JSON encoding of spec for digesting.
func CanonicalSpec(spec *Spec) ([]byte, error) {
	return canonicalSpecBytes(spec, "")
}

// CanonicalSpecForRelease returns the deterministic encoding after replacing
// the release with a provider-canonical value.
func CanonicalSpecForRelease(spec *Spec, release string) ([]byte, error) {
	if release == "" {
		return nil, errors.New("canonical release must not be empty")
	}
	return canonicalSpecBytes(spec, release)
}

func canonicalSpecBytes(spec *Spec, release string) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("spec must not be nil")
	}
	if err := CheckDigestText(reflect.ValueOf(spec)); err != nil {
		return nil, err
	}
	snapshot, snapshotErr := CopySpec(spec)
	if snapshotErr != nil {
		return nil, snapshotErr
	}
	if release != "" {
		snapshot.Release = release
	}
	ApplyDefaults(snapshot)
	if err := ValidateSpec(snapshot); err != nil {
		return nil, fmt.Errorf("validate spec: %w", err)
	}
	value, err := CanonicalValue(reflect.ValueOf(snapshot))
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical spec: %w", err)
	}
	return encoded, nil
}

// CopySpec returns a deep copy of spec decoded into separate memory.
func CopySpec(spec *Spec) (*Spec, error) {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("snapshot spec: %w", err)
	}
	var snapshot Spec
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return nil, fmt.Errorf("decode spec snapshot: %w", err)
	}
	return &snapshot, nil
}

// CheckDigestText rejects string values that cannot be represented in a digest.
func CheckDigestText(value reflect.Value) error {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			return CheckDigestText(value.Elem())
		}
	case reflect.Struct:
		return checkDigestStructText(value)
	case reflect.Slice:
		return checkDigestSliceText(value)
	case reflect.Map:
		return checkDigestMapText(value)
	case reflect.String:
		return CheckText(value.String(), "spec string")
	case reflect.Int, reflect.Bool:
	default:
		return fmt.Errorf("unsupported schema kind %s", value.Kind())
	}
	return nil
}

func checkDigestStructText(value reflect.Value) error {
	for _, field := range value.Fields() {
		if err := CheckDigestText(field); err != nil {
			return err
		}
	}
	return nil
}

func checkDigestSliceText(value reflect.Value) error {
	for i := 0; i < value.Len(); i++ {
		if err := CheckDigestText(value.Index(i)); err != nil {
			return err
		}
	}
	return nil
}

func checkDigestMapText(value reflect.Value) error {
	for entry := value.MapRange(); entry.Next(); {
		if err := CheckDigestText(entry.Key()); err != nil {
			return err
		}
		if err := CheckDigestText(entry.Value()); err != nil {
			return err
		}
	}
	return nil
}

// CanonicalValue converts reflected values to canonical JSON-compatible forms.
func CanonicalValue(value reflect.Value) (any, error) {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			//nolint:nilnil // nil is the canonical value of a nil pointer.
			return nil, nil
		}
		return CanonicalValue(value.Elem())
	case reflect.Map:
		return canonicalMap(value)
	case reflect.Struct:
		return canonicalObject(value)
	case reflect.Slice:
		result := make([]any, value.Len())
		for i := range result {
			child, err := CanonicalValue(value.Index(i))
			if err != nil {
				return nil, err
			}
			result[i] = child
		}
		return result, nil
	case reflect.String, reflect.Int, reflect.Bool:
		return value.Interface(), nil
	default:
		return nil, fmt.Errorf("unsupported schema kind %s", value.Kind())
	}
}

func canonicalMap(value reflect.Value) (map[string]any, error) {
	result := make(map[string]any)
	for entry := value.MapRange(); entry.Next(); {
		child, err := CanonicalValue(entry.Value())
		if err != nil {
			return nil, err
		}
		result[entry.Key().String()] = child
	}
	return result, nil
}

func canonicalObject(value reflect.Value) (map[string]any, error) {
	result := make(map[string]any)
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		name, options, _ := strings.Cut(value.Type().Field(i).Tag.Get("json"), ",")
		if options == "omitzero" && field.IsZero() {
			continue
		}
		child, err := CanonicalValue(field)
		if err != nil {
			return nil, err
		}
		result[name] = child
	}
	return result, nil
}
