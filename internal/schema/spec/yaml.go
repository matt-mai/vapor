package spec

import (
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// YAML scalar tags this package checks against.
const (
	tagString = "!!str"
	tagBool   = "!!bool"
)

func checkNode(node *yaml.Node, expected reflect.Type, location string) error {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s: YAML anchors and aliases are not supported", location)
	}
	if expected.Kind() == reflect.Pointer {
		return checkNode(node, expected.Elem(), location)
	}
	if expected == reflect.TypeFor[contents.Placement]() {
		return checkPlacement(node, location)
	}
	switch expected.Kind() {
	case reflect.Struct, reflect.Map:
		if expected.Kind() == reflect.Struct && acceptsScalar(expected) && node.Kind == yaml.ScalarNode {
			return checkString(node, location)
		}
		return checkMappingNode(node, expected, location)
	case reflect.Slice:
		return checkSequenceNode(node, expected, location)
	case reflect.Int, reflect.Int64:
		return checkScalarNode(node, "!!int", location, "an integer")
	case reflect.Bool:
		return checkScalarNode(node, tagBool, location, "a boolean")
	case reflect.String:
		return checkString(node, location)
	default:
		return fmt.Errorf("%s: unsupported schema field type %s", location, expected)
	}
}

func checkMappingNode(node *yaml.Node, expected reflect.Type, location string) error {
	if node.Kind != yaml.MappingNode || node.Tag != "!!map" {
		return fmt.Errorf("%s: expected a mapping; custom YAML tags are not supported", location)
	}
	return checkMapping(node, expected, location)
}

func checkSequenceNode(node *yaml.Node, expected reflect.Type, location string) error {
	if node.Kind != yaml.SequenceNode || node.Tag != "!!seq" {
		return fmt.Errorf("%s: expected a sequence; custom YAML tags are not supported", location)
	}
	for i, child := range node.Content {
		if err := checkNode(child, expected.Elem(), fmt.Sprintf("%s[%d]", location, i)); err != nil {
			return err
		}
	}
	return nil
}

func checkScalarNode(node *yaml.Node, tag, location, description string) error {
	if node.Kind != yaml.ScalarNode || node.Tag != tag {
		return fmt.Errorf("%s: expected %s", location, description)
	}
	return nil
}

func checkMapping(node *yaml.Node, expected reflect.Type, location string) error {
	seen := make(map[string]bool)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if err := checkMappingKey(key, location, seen); err != nil {
			return err
		}
		fieldType, err := MappingValueType(expected, key.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", location, err)
		}
		childLocation := location + "." + key.Value
		if expected.Kind() == reflect.Map {
			childLocation = location + " entry"
		}
		if err := checkNode(value, fieldType, childLocation); err != nil {
			return err
		}
	}
	return nil
}

func checkMappingKey(key *yaml.Node, location string, seen map[string]bool) error {
	if key.Kind != yaml.ScalarNode || key.Tag != tagString || key.Anchor != "" {
		return fmt.Errorf("%s: mapping keys must be strings; YAML merges are not supported", location)
	}
	if err := checkString(key, location+" key"); err != nil {
		return err
	}
	if seen[key.Value] {
		return fmt.Errorf("%s: duplicate key", location)
	}
	seen[key.Value] = true
	return nil
}

// MappingValueType returns the declared type for key in a strict mapping.
func MappingValueType(expected reflect.Type, key string) (reflect.Type, error) {
	if expected.Kind() == reflect.Map {
		return expected.Elem(), nil
	}
	for field := range expected.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name == key {
			return field.Type, nil
		}
	}
	return nil, fmt.Errorf("unknown field %q", key)
}

// acceptsScalar reports whether a struct also decodes from a bare YAML string. Only
// the package request has a one-line form, and its own decoding keeps the mapping
// form strict, so this narrow list is all the generic check needs to know.
func acceptsScalar(expected reflect.Type) bool {
	return expected == reflect.TypeFor[contents.PackageRequest]()
}

// checkPlacement accepts one artifact placement: the boolean spellings an archive or
// standalone payload has always used, and the package keyword.
func checkPlacement(node *yaml.Node, location string) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s: expected a placement", location)
	}
	switch node.Tag {
	case tagBool:
		return nil
	case tagString:
		if node.Value == string(contents.ArtifactUnpackPackage) {
			return CheckText(node.Value, location)
		}
	}
	return fmt.Errorf("%s: expected a placement: true, false or package", location)
}

func checkString(node *yaml.Node, location string) error {
	if node.Kind != yaml.ScalarNode || node.Tag != tagString {
		return fmt.Errorf("%s: expected a string (quote string values)", location)
	}
	return CheckText(node.Value, location)
}

// CheckText rejects invalid UTF-8 and control characters in spec text.
func CheckText(value, location string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s: invalid UTF-8 is not allowed", location)
	}
	if strings.Contains(value, "${") {
		return fmt.Errorf("%s: interpolation is not supported", location)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s: NUL is not allowed in strings", location)
	}
	return nil
}
