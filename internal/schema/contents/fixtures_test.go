package contents_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/spec"
)

const minimalSpec = `version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: "26.04"
`

func loadText(t *testing.T, text string) (*spec.Spec, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return spec.LoadSpec(path)
}
