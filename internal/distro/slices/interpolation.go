package slices

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// rejectInterpolation walks decoded YAML and rejects ${...} outside literal
// text and mutate payloads, which are content rather than metadata.
func rejectInterpolation(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil // The strict decoder reports malformed YAML first.
	}
	return walkInterpolation(&document, nil, false)
}

func walkInterpolation(node *yaml.Node, path []string, inContents bool) error {
	switch node.Kind {
	case yaml.DocumentNode:
		return walkInterpolationChildren(node, path, inContents)
	case yaml.MappingNode:
		return walkInterpolationMapping(node, path, inContents)
	case yaml.SequenceNode:
		return walkInterpolationSequence(node, path, inContents)
	case yaml.ScalarNode:
		if strings.Contains(node.Value, "${") {
			return interpolationError(path)
		}
	}
	return nil
}

func walkInterpolationChildren(node *yaml.Node, path []string, inContents bool) error {
	for _, child := range node.Content {
		if err := walkInterpolation(child, path, inContents); err != nil {
			return err
		}
	}
	return nil
}

func walkInterpolationMapping(node *yaml.Node, path []string, inContents bool) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if strings.Contains(key.Value, "${") {
			return interpolationError(path)
		}
		if (inContents && key.Value == "text") || key.Value == "mutate" {
			continue
		}
		childPath := append(append([]string(nil), path...), key.Value)
		if err := walkInterpolation(value, childPath, inContents || key.Value == "contents"); err != nil {
			return err
		}
	}
	return nil
}

func walkInterpolationSequence(node *yaml.Node, path []string, inContents bool) error {
	for i, child := range node.Content {
		childPath := append(append([]string(nil), path...), fmt.Sprintf("[%d]", i))
		if err := walkInterpolation(child, childPath, inContents); err != nil {
			return err
		}
	}
	return nil
}

func interpolationError(path []string) error {
	location := strings.Join(path, ".")
	if location == "" {
		location = "catalogue metadata"
	}
	return fmt.Errorf("%s: interpolation is not supported", location)
}
