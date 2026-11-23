package container_test

import (
	"os"
	"path/filepath"
	"testing"

	schemaSpec "github.com/matt-mai/vapor/internal/schema/spec"
)

const minimalSpec = `version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: "26.04"
`

func loadText(t *testing.T, text string) (*schemaSpec.Spec, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return schemaSpec.LoadSpec(path)
}
