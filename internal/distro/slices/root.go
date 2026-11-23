// Package slices parses and validates upstream chisel v3 catalogue metadata.
package slices

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

// CatalogueFormat is the only root catalogue format supported by Vapor.
const CatalogueFormat = "v3"

// Catalogue is the validated root chisel.yaml metadata.
type Catalogue struct {
	Format      string
	Maintenance Maintenance
	Archives    map[string]Archive
	PublicKeys  map[string]PublicKey
	Stores      map[string]Store
}

// ParseCatalogue strictly decodes and validates root chisel.yaml metadata.
func ParseCatalogue(data []byte) (*Catalogue, error) {
	raw, err := decodeCatalogue(data)
	if err != nil {
		return nil, err
	}
	if err := validateRoot(&raw); err != nil {
		return nil, err
	}
	return buildCatalogue(&raw)
}

func validateRoot(raw *rawCatalogue) error {
	if raw.Format != CatalogueFormat {
		return fmt.Errorf("catalogue format %q is not supported", raw.Format)
	}
	if len(raw.Archives) == 0 {
		return errors.New("catalogue has no archives")
	}
	return nil
}

func buildCatalogue(raw *rawCatalogue) (*Catalogue, error) {
	keys, err := parsePublicKeys(raw.PublicKeys)
	if err != nil {
		return nil, err
	}
	archives, err := parseArchives(raw.Archives, keys)
	if err != nil {
		return nil, err
	}
	if priorityErr := validatePriorities(archives); priorityErr != nil {
		return nil, priorityErr
	}
	maintenance, err := parseMaintenance(raw.Maintenance, archives)
	if err != nil {
		return nil, err
	}
	stores, err := parseStores(raw.Stores)
	if err != nil {
		return nil, err
	}
	return &Catalogue{
		Format:      raw.Format,
		Maintenance: maintenance,
		Archives:    archives,
		PublicKeys:  keys,
		Stores:      stores,
	}, nil
}

type rawCatalogue struct {
	Format      string                  `yaml:"format"`
	Maintenance rawMaintenance          `yaml:"maintenance"`
	Archives    map[string]rawArchive   `yaml:"archives"`
	PublicKeys  map[string]rawPublicKey `yaml:"public-keys"`
	Stores      map[string]rawStore     `yaml:"stores"`
}

func decodeCatalogue(data []byte) (rawCatalogue, error) {
	var raw rawCatalogue
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return rawCatalogue{}, errors.New("catalogue metadata is empty")
		}
		return rawCatalogue{}, fmt.Errorf("catalogue metadata is invalid: %w", err)
	}
	if err := rejectInterpolation(data); err != nil {
		return rawCatalogue{}, fmt.Errorf("catalogue metadata is invalid: %w", err)
	}
	var extra yaml.Node
	switch err := decoder.Decode(&extra); {
	case err == nil:
		return rawCatalogue{}, errors.New("catalogue metadata must contain one YAML document")
	case !errors.Is(err, io.EOF):
		return rawCatalogue{}, fmt.Errorf("catalogue metadata is invalid: %w", err)
	}
	return raw, nil
}

func validateList(label string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s is empty", label)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("%s contains an empty value", label)
		}
		if seen[value] {
			return fmt.Errorf("%s contains duplicate %q", label, value)
		}
		seen[value] = true
	}
	return nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
