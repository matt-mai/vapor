package builder_test

import (
	"context"
	"slices"
	"testing"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/oci"
)

// A tag from the specification reaches a local layout, and it names the build index
// so the digest the build reports is the digest the tag pulls.
func TestLayout_TagsTheBuildIndex(t *testing.T) {
	inputs, _ := contentFixture(t)
	inputs.Spec.Tags = []string{"v1", "26.04"}
	reseal(t, inputs)
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	images, err := input.BuildEach(context.Background(), oci.DefaultCompression, 1,
		func(oci.Platform) error { return nil })
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	layout, err := builder.Layout(images, inputs.Spec.Tags)
	if err != nil {
		t.Fatalf("Layout: %v", err)
	}
	if !slices.Equal(layout.Tags, inputs.Spec.Tags) {
		t.Fatalf("layout tags = %v", layout.Tags)
	}
	if layout.Index.Digest == "" {
		t.Fatal("layout has no index digest")
	}
}
