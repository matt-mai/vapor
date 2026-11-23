package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/matt-mai/vapor/internal/schema/container"
)

// Epoch is the timestamp every generated object carries. It is a fixed value, not
// the build time, so an unchanged tree produces unchanged bytes.
var Epoch = epoch

// Platform is the image platform an image config declares.
type Platform struct {
	OS           string
	Architecture string
}

// SupportedPlatforms are the platforms a specification may declare and Vapor can build.
var SupportedPlatforms = []Platform{
	{OS: "linux", Architecture: "amd64"},
	{OS: "linux", Architecture: "arm64"},
}

// ParsePlatform splits a declared `os/arch` platform string.
func ParsePlatform(platform string) (Platform, error) {
	for _, supported := range SupportedPlatforms {
		if platform == supported.String() {
			return supported, nil
		}
	}
	return Platform{}, fmt.Errorf("platform %q is not one of the supported platforms", platform)
}

// String renders the platform as the declaration spells it.
func (p Platform) String() string { return p.OS + "/" + p.Architecture }

// ImageInput is everything one platform image is built from. The layer list is
// ordered: it is the order the layers apply in, from the base up.
type ImageInput struct {
	Platform    Platform
	Container   container.Container
	Annotations map[string]string
	Layers      []CompressedLayer
}

// Image is one platform's image manifest and config, with the identities of both.
type Image struct {
	Platform       Platform
	Config         []byte
	ConfigDigest   string
	Manifest       []byte
	ManifestDigest string
	ManifestSize   int64
	MediaType      string
}

// BuildImage renders the config and manifest for one platform image. It only uses
// declared metadata and layer identities; it does not read the filesystem, resolve
// users, or generate any value from the environment or the clock.
func BuildImage(input *ImageInput) (Image, error) {
	if input == nil {
		return Image{}, errors.New("image input must not be nil")
	}
	if input.Platform.OS == "" || input.Platform.Architecture == "" {
		return Image{}, errors.New("image input requires a platform")
	}
	if len(input.Layers) == 0 {
		return Image{}, errors.New("image input requires at least one layer")
	}
	config, err := configFile(input)
	if err != nil {
		return Image{}, err
	}
	configJSON, err := marshalCanonical(config)
	if err != nil {
		return Image{}, err
	}
	manifest, err := manifestWith(input, configJSON)
	if err != nil {
		return Image{}, err
	}
	manifestJSON, err := marshalCanonical(manifest)
	if err != nil {
		return Image{}, err
	}
	configDigest := digestOf(configJSON)
	manifestDigest := digestOf(manifestJSON)
	return Image{
		Platform:       input.Platform,
		Config:         configJSON,
		ConfigDigest:   configDigest,
		Manifest:       manifestJSON,
		ManifestDigest: manifestDigest,
		ManifestSize:   int64(len(manifestJSON)),
		MediaType:      MediaTypeManifest,
	}, nil
}

// configFile builds the OCI image config from the declared container block. Fields
// that stay empty are omitted, so the config contains only what was declared.
func configFile(input *ImageInput) (v1.ConfigFile, error) {
	config := v1.ConfigFile{
		Architecture: input.Platform.Architecture,
		OS:           input.Platform.OS,
		Created:      v1.Time{Time: epoch},
		Config:       v1.Config{},
		RootFS:       v1.RootFS{Type: "layers"},
	}
	for _, layer := range input.Layers {
		diffID, err := v1.NewHash(layer.Layer.DiffID)
		if err != nil {
			return v1.ConfigFile{}, fmt.Errorf("layer diff id: %w", err)
		}
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, diffID)
		// One history entry per non-empty layer keeps history and diff_ids the same
		// length, which the specification requires for a shared rootfs.
		config.History = append(config.History, v1.History{Created: v1.Time{Time: epoch}})
	}
	containerConfig := input.Container
	config.Config.Entrypoint = append([]string(nil), containerConfig.Entrypoint...)
	config.Config.Cmd = append([]string(nil), containerConfig.Cmd...)
	config.Config.User = containerConfig.User
	config.Config.WorkingDir = containerConfig.Workdir
	config.Config.StopSignal = containerConfig.StopSignal
	if len(containerConfig.Env) > 0 {
		config.Config.Env = environment(containerConfig.Env)
	}
	if len(containerConfig.Ports) > 0 {
		config.Config.ExposedPorts = make(map[string]struct{}, len(containerConfig.Ports))
		for _, port := range containerConfig.Ports {
			config.Config.ExposedPorts[port] = struct{}{}
		}
	}
	return config, nil
}

// environment renders the declared map as name=value pairs in sorted name order.
// The declaration is a mapping and cannot express order, so sorting is the only
// stable choice a reader can predict.
func environment(declared map[string]string) []string {
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, name+"="+declared[name])
	}
	return values
}

// manifestWith assembles the manifest: the config descriptor plus one descriptor per
// layer in order, with the declared annotations and nothing generated.
func manifestWith(input *ImageInput, configJSON []byte) (v1.Manifest, error) {
	configDigest := digestOf(configJSON)
	configHash, err := v1.NewHash(configDigest)
	if err != nil {
		return v1.Manifest{}, fmt.Errorf("config digest: %w", err)
	}
	manifest := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeManifest,
		Config: v1.Descriptor{
			MediaType: MediaTypeConfig,
			Size:      int64(len(configJSON)),
			Digest:    configHash,
		},
		Layers: make([]v1.Descriptor, 0, len(input.Layers)),
	}
	annotations, err := ManifestAnnotations(input.Annotations)
	if err != nil {
		return v1.Manifest{}, err
	}
	manifest.Annotations = annotations
	for i, layer := range input.Layers {
		if err := validateDigest(layer.Digest); err != nil {
			return v1.Manifest{}, fmt.Errorf("layer %d: %w", i, err)
		}
		if layer.Size <= 0 {
			return v1.Manifest{}, fmt.Errorf("layer %d: size must be positive", i)
		}
		digest, err := v1.NewHash(layer.Digest)
		if err != nil {
			return v1.Manifest{}, fmt.Errorf("layer %d: %w", i, err)
		}
		manifest.Layers = append(manifest.Layers, v1.Descriptor{
			MediaType: MediaTypeLayer,
			Size:      layer.Size,
			Digest:    digest,
		})
	}
	return manifest, nil
}

// marshalCanonical renders a value the same way every time: map keys sorted, no
// trailing newline and no HTML escaping, so the digest depends on content alone.
func marshalCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode image metadata: %w", err)
	}
	return encoded, nil
}

// digestOf wraps a sha256 digest in the spelling the rest of the image format uses.
func digestOf(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
