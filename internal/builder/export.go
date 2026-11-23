package builder

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/vfs"
)

// Layout collects the finished images and their layers into one exportable OCI
// layout, with the local tags an export writes. The index is built here, so a caller
// cannot export manifests that its index does not describe, and a tag descriptor
// names that index, so tagging cannot change the digest the build reports or pushes.
func Layout(images []Image, tags []string) (oci.Layout, error) {
	index, err := BuildIndex(images)
	if err != nil {
		return oci.Layout{}, err
	}
	layers := make([]oci.CompressedLayer, 0, len(images))
	for entry := range images {
		layers = append(layers, images[entry].Layer)
	}
	return oci.Layout{Index: index, Images: imageList(images), Layers: layers,
		Tags: slices.Clone(tags)}, nil
}

// BuildIndex builds the multi-platform index over finished images.
func BuildIndex(images []Image) (oci.Index, error) {
	platforms := make([]oci.Platform, 0, len(images))
	for index := range images {
		platforms = append(platforms, images[index].Platform)
	}
	return oci.BuildIndex(&oci.IndexInput{Images: imageList(images), Platforms: platforms})
}

// compress serializes the tree into a layer and publishes exactly those bytes. The
// layer is spooled to a temporary file rather than held in memory: a multi-platform
// build would otherwise hold every finished layer next to the trees still being
// assembled, and the layer bytes are the one artifact a build does not need to keep.
func (i *Input) compress(ctx context.Context, tree *vfs.Tree,
	level oci.CompressionLevel,
) (oci.CompressedLayer, error) {
	spool, err := os.CreateTemp("", "vapor-layer-*")
	if err != nil {
		return oci.CompressedLayer{}, fmt.Errorf("spool layer: %w", err)
	}
	defer func() {
		_ = spool.Close()
		_ = os.Remove(spool.Name())
	}()
	i.working("compress layer")
	layer, err := oci.CompressLayer(ctx, spool, tree, level)
	if err != nil {
		return oci.CompressedLayer{}, err
	}
	stored, ok := i.blobs.(BlobWriter)
	if !ok {
		return layer, nil
	}
	if err := stored.Store(io.NewSectionReader(spool, 0, layer.Size),
		strings.TrimPrefix(layer.Digest, "sha256:"), layer.Size); err != nil {
		return oci.CompressedLayer{}, fmt.Errorf("store layer: %w", err)
	}
	return layer, nil
}

func imageList(images []Image) []oci.Image {
	result := make([]oci.Image, 0, len(images))
	for index := range images {
		result = append(result, images[index].Image)
	}
	return result
}
