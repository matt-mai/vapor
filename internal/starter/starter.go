// Package starter generates offline starter specifications without replacing files.
package starter

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/distro"
	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

// Options selects the starter template, image name and explicit output directory.
type Options struct {
	Distro  string
	Release string
	Name    string
	Dir     string
}

// Generate validates and publishes Dir/image.yaml, refusing every existing entry.
func Generate(options Options) error {
	data, err := render(options)
	if err != nil {
		return fmt.Errorf("generate starter: %w", err)
	}
	if err := writeDirectory(options.Dir, data); err != nil {
		return fmt.Errorf("generate starter: %w", err)
	}
	return nil
}

// supportedReleases lists the starter template of each distribution. Both are the
// reviewed baseline, so a generated specification locks without a warning.
var supportedReleases = map[string]string{debianDistro: "trixie", ubuntuDistro: "26.04"}

func render(options Options) ([]byte, error) {
	provider, err := distro.Select(options.Distro, options.Release)
	if err != nil {
		return nil, fmt.Errorf("no starter template: use --distro debian --release trixie or --distro ubuntu --release 26.04")
	}
	if provider.Release() != supportedReleases[provider.Distro()] {
		return nil, fmt.Errorf("no starter template: use --distro debian --release trixie or --distro ubuntu --release 26.04")
	}
	if strings.TrimSpace(options.Dir) == "" || strings.ContainsFunc(options.Dir, unicode.IsControl) {
		return nil, fmt.Errorf("output directory must be nonempty and contain no control characters")
	}
	data := renderYAML(options, provider.Release())
	// Validate the bytes that are published, so a starter cannot declare what a
	// strict read of image.yaml rejects.
	published, err := schemaSpec.DecodeSpec(data)
	if err != nil {
		return nil, fmt.Errorf("validate starter: %w", err)
	}
	schemaSpec.ApplyDefaults(published)
	if err := schemaSpec.ValidateSpec(published); err != nil {
		return nil, fmt.Errorf("validate starter: %w", err)
	}
	return data, nil
}
