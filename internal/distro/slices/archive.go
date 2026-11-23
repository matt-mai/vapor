package slices

import (
	"errors"
	"fmt"
)

var proServices = map[string]bool{
	"esm-apps":     true,
	"esm-infra":    true,
	"fips":         true,
	"fips-updates": true,
}

// Archive is one package archive declared by the catalogue, in declaration order.
type Archive struct {
	Name        string
	Version     string
	Suites      []string
	Components  []string
	Priority    int
	Pro         string
	PublicKeys  []string
	hasPriority bool
}

type rawArchive struct {
	Version    string   `yaml:"version"`
	Suites     []string `yaml:"suites"`
	Components []string `yaml:"components"`
	Priority   *int     `yaml:"priority"`
	Pro        string   `yaml:"pro"`
	PublicKeys []string `yaml:"public-keys"`
}

func parseArchives(rawArchives map[string]rawArchive, keys map[string]PublicKey) (map[string]Archive, error) {
	archives := make(map[string]Archive, len(rawArchives))
	for _, name := range sortedKeys(rawArchives) {
		raw := rawArchives[name]
		archive, err := parseArchive(name, &raw, keys)
		if err != nil {
			return nil, err
		}
		archives[name] = archive
	}
	return archives, nil
}

func parseArchive(name string, raw *rawArchive, keys map[string]PublicKey) (Archive, error) {
	if err := validateArchive(name, raw, keys); err != nil {
		return Archive{}, err
	}
	priority, hasPriority, err := parsePriority(name, raw.Priority)
	if err != nil {
		return Archive{}, err
	}
	return Archive{
		Name:        name,
		Version:     raw.Version,
		Suites:      append([]string(nil), raw.Suites...),
		Components:  append([]string(nil), raw.Components...),
		Priority:    priority,
		Pro:         raw.Pro,
		PublicKeys:  append([]string(nil), raw.PublicKeys...),
		hasPriority: hasPriority,
	}, nil
}

func validateArchive(name string, raw *rawArchive, keys map[string]PublicKey) error {
	if name == "" {
		return errors.New("catalogue archive name is empty")
	}
	if raw.Version == "" {
		return fmt.Errorf("catalogue archive %q is missing version", name)
	}
	if err := validateArchiveLists(name, raw); err != nil {
		return err
	}
	if raw.Pro != "" && !proServices[raw.Pro] {
		return fmt.Errorf("catalogue archive %q has unsupported pro service %q", name, raw.Pro)
	}
	return validateArchiveKeys(name, raw.PublicKeys, keys)
}

func validateArchiveLists(name string, raw *rawArchive) error {
	if err := validateList(fmt.Sprintf("catalogue archive %q suites", name), raw.Suites); err != nil {
		return err
	}
	return validateList(fmt.Sprintf("catalogue archive %q components", name), raw.Components)
}

func validateArchiveKeys(name string, refs []string, keys map[string]PublicKey) error {
	if err := validateList(fmt.Sprintf("catalogue archive %q public keys", name), refs); err != nil {
		return err
	}
	for _, key := range refs {
		if _, ok := keys[key]; !ok {
			return fmt.Errorf("catalogue archive %q refers to undefined public key %q", name, key)
		}
	}
	return nil
}

func parsePriority(name string, value *int) (int, bool, error) {
	if value == nil {
		return 0, false, nil
	}
	priority := *value
	if priority == 0 || priority < -1000 || priority > 1000 {
		return 0, false, fmt.Errorf("catalogue archive %q has invalid priority %d", name, priority)
	}
	return priority, true, nil
}

func validatePriorities(archives map[string]Archive) error {
	seen := make(map[int]string, len(archives))
	for _, name := range sortedKeys(archives) {
		archive := archives[name]
		if !archive.hasPriority {
			if len(archives) > 1 {
				return fmt.Errorf("catalogue archive %q is missing priority", name)
			}
			continue
		}
		if previous, ok := seen[archive.Priority]; ok {
			return fmt.Errorf("catalogue archives %q and %q have the same priority", previous, name)
		}
		seen[archive.Priority] = name
	}
	return nil
}
