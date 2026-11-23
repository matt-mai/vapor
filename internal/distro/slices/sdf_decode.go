package slices

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

const nullTag = "!!null"

type rawPackage struct {
	Package      string              `yaml:"package"`
	Archive      string              `yaml:"archive"`
	Store        string              `yaml:"store"`
	DefaultTrack string              `yaml:"default-track"`
	Essential    rawEssentialMap     `yaml:"essential"`
	Slices       map[string]rawSlice `yaml:"slices"`
}

type rawSlice struct {
	Hint      string              `yaml:"hint"`
	Essential rawEssentialMap     `yaml:"essential"`
	Contents  map[string]*rawPath `yaml:"contents"`
	Mutate    string              `yaml:"mutate"`
}

type rawEssentialMap map[string]*rawEssential

func (m *rawEssentialMap) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == nullTag {
		*m = nil
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("essential must be a map")
	}
	var values map[string]*rawEssential
	if err := node.Decode(&values); err != nil {
		return err
	}
	*m = values
	return nil
}

type rawEssential struct {
	Arch rawArch `yaml:"arch"`
}

func (e *rawEssential) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == nullTag {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("essential value must be a map")
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value != "arch" {
			return fmt.Errorf("essential value has unknown field %q", node.Content[i].Value)
		}
	}
	type plain rawEssential
	return node.Decode((*plain)(e))
}

type rawArch struct {
	Values []string
}

func (a *rawArch) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == nullTag {
		return nil
	}
	var single string
	if err := node.Decode(&single); err == nil {
		a.Values = []string{single}
		return nil
	}
	var list []string
	if err := node.Decode(&list); err != nil {
		return errors.New("arch must be a string or a list of strings")
	}
	a.Values = list
	return nil
}

type rawPath struct {
	Make     bool    `yaml:"make"`
	Mode     *uint32 `yaml:"mode"`
	Copy     string  `yaml:"copy"`
	Text     *string `yaml:"text"`
	Symlink  string  `yaml:"symlink"`
	Mutable  bool    `yaml:"mutable"`
	Until    string  `yaml:"until"`
	Arch     rawArch `yaml:"arch"`
	Generate string  `yaml:"generate"`
	Prefer   string  `yaml:"prefer"`
}

func decodePackage(data []byte) (rawPackage, error) {
	var raw rawPackage
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return rawPackage{}, errors.New("slice definition is empty")
		}
		return rawPackage{}, fmt.Errorf("slice definition is invalid: %w", err)
	}
	if err := rejectInterpolation(data); err != nil {
		return rawPackage{}, fmt.Errorf("slice definition is invalid: %w", err)
	}
	var extra yaml.Node
	switch err := decoder.Decode(&extra); {
	case err == nil:
		return rawPackage{}, errors.New("slice definition must contain one YAML document")
	case !errors.Is(err, io.EOF):
		return rawPackage{}, fmt.Errorf("slice definition is invalid: %w", err)
	}
	return raw, nil
}
