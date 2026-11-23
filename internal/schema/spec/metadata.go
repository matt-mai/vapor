package spec

import (
	"errors"
	"fmt"
	"strings"
)

func validateMetadata(tags []string, annotations map[string]string) error {
	seen := make(map[string]bool)
	for i, tag := range tags {
		if err := requirePattern("image tag", tag, `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`); err != nil {
			return fmt.Errorf("tags[%d]: %w", i, err)
		}
		if seen[tag] {
			return fmt.Errorf("tags[%d]: duplicate image tag", i)
		}
		seen[tag] = true
	}
	for key := range annotations {
		if strings.TrimSpace(key) == "" {
			return errors.New("annotation keys must not be blank")
		}
	}
	return nil
}
