package slices

import (
	"errors"
	"fmt"
)

// Store describes a package store.
type Store struct {
	Name          string
	Kind          string
	Version       string
	DefaultPrefix string
}

type rawStore struct {
	Kind          string `yaml:"kind"`
	Version       string `yaml:"version"`
	DefaultPrefix string `yaml:"default-prefix"`
}

func parseStores(rawStores map[string]rawStore) (map[string]Store, error) {
	stores := make(map[string]Store, len(rawStores))
	for _, name := range sortedKeys(rawStores) {
		store, err := parseStore(name, rawStores[name])
		if err != nil {
			return nil, err
		}
		stores[name] = store
	}
	return stores, nil
}

func parseStore(name string, raw rawStore) (Store, error) {
	if name == "" {
		return Store{}, errors.New("catalogue store name is empty")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"kind", raw.Kind},
		{"version", raw.Version},
		{"default-prefix", raw.DefaultPrefix},
	} {
		if field.value == "" {
			return Store{}, fmt.Errorf("catalogue store %q is missing %s", name, field.name)
		}
	}
	return Store{Name: name, Kind: raw.Kind, Version: raw.Version, DefaultPrefix: raw.DefaultPrefix}, nil
}
