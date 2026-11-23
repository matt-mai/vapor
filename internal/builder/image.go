package builder

import (
	"context"

	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Image is one platform's finished image: the committed tree, the compressed layer
// that carries it, and the OCI config and manifest built from the layer identity.
type Image struct {
	Platform oci.Platform
	Tree     *vfs.Tree
	Layer    oci.CompressedLayer
	Image    oci.Image
	// Original holds the pre-mutation digest of every mutable path, which is what
	// lets an SBOM say a file was rewritten rather than report a mismatch.
	Original map[string]string
}

// Platforms returns the declared platforms in declaration order.
func (i *Input) Platforms() ([]oci.Platform, error) {
	return oci.DeclaredPlatforms(i.spec.Platforms)
}

// BuildPlatform runs one platform from content assembly to a published layer.
func (i *Input) BuildPlatform(ctx context.Context, platform oci.Platform,
	level oci.CompressionLevel,
) (Image, error) {
	content, err := i.Content(ctx, platform.String())
	if err != nil {
		return Image{}, err
	}
	tree, err := i.Assemble(ctx, content, platform.String())
	if err != nil {
		return Image{}, err
	}
	layer, err := i.compress(ctx, tree, level)
	if err != nil {
		return Image{}, err
	}
	built, err := oci.BuildImage(&oci.ImageInput{
		Platform: platform, Container: i.spec.Container, Annotations: i.spec.Annotations,
		Layers: []oci.CompressedLayer{layer},
	})
	if err != nil {
		return Image{}, err
	}
	return Image{Platform: platform, Tree: tree, Layer: layer, Image: built,
		Original: content.Original}, nil
}
