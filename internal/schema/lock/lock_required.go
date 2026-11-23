package lock

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/matt-mai/vapor/internal/schema/spec"
)

// Presence is separate from zero-value validation; spec defaults do not apply to locks.
func checkLockRequiredFields(node *yaml.Node, expected reflect.Type, location string) error {
	if expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		return checkLockRequiredMapping(node, expected, location)
	case reflect.Slice:
		for i, child := range node.Content {
			if err := checkLockRequiredFields(child, expected.Elem(), fmt.Sprintf("%s[%d]", location, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkLockRequiredMapping(node *yaml.Node, expected reflect.Type, location string) error {
	present := make(map[string]bool, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		present[key] = true
		fieldType, err := spec.MappingValueType(expected, key)
		if err != nil {
			return err
		}
		if err := checkLockRequiredFields(node.Content[i+1], fieldType, location+"."+key); err != nil {
			return err
		}
	}
	for field := range expected.Fields() {
		name, options, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if !present[name] && options != "omitempty" {
			return fmt.Errorf("%s: required field %q is missing", location, name)
		}
	}
	return nil
}
