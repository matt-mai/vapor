package oci_test

import (
	"bytes"
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/container"
	"github.com/matt-mai/vapor/internal/vfs"
)

// layers compresses one deterministic tree per name, giving ordered layer identities.
func layers(t *testing.T, names ...string) []oci.CompressedLayer {
	t.Helper()
	result := make([]oci.CompressedLayer, 0, len(names))
	for _, name := range names {
		result = append(result, compressTree(t, name))
	}
	return result
}

// inputOf returns a pointer to an input, since the builder takes the address to keep
// the 192-byte declaration off the stack.
func inputOf(t *testing.T, platform string, layers ...oci.CompressedLayer) *oci.ImageInput {
	t.Helper()
	input := imageInput(platform, layers...)
	return &input
}

func imageInput(platform string, layers ...oci.CompressedLayer) oci.ImageInput {
	parsed, err := oci.ParsePlatform(platform)
	if err != nil {
		panic(err)
	}
	return oci.ImageInput{Platform: parsed, Layers: layers}
}

// TestBuildImage_ConfigPinsContainerDeclarations checks that every declared container
// field reaches the config exactly as declared, with nothing invented.
func TestBuildImage_ConfigPinsContainerDeclarations(t *testing.T) {
	input := imageInput("linux/amd64", layers(t, "a")...)
	input.Container = container.Container{
		User:       "65532:65532",
		Entrypoint: []string{"/app/server", ""},
		Cmd:        []string{"--listen", "", "8080"},
		Workdir:    "/app",
		Ports:      []string{"8080/tcp", "9090/udp"},
		StopSignal: "SIGTERM",
		Env:        map[string]string{"MODE": "production", "ZED": "", "A": "1"},
	}
	image, err := oci.BuildImage(&input)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	config, err := v1.ParseConfigFile(bytes.NewReader(image.Config))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if config.Architecture != "amd64" || config.OS != "linux" {
		t.Fatalf("platform = %s/%s", config.OS, config.Architecture)
	}
	if !config.Created.Equal(oci.Epoch) {
		t.Fatalf("created = %v, want the epoch", config.Created)
	}
	if config.Config.User != "65532:65532" || config.Config.WorkingDir != "/app" ||
		config.Config.StopSignal != "SIGTERM" {
		t.Fatalf("scalar config = %+v", config.Config)
	}
	if !equal(config.Config.Entrypoint, []string{"/app/server", ""}) {
		t.Fatalf("entrypoint = %q", config.Config.Entrypoint)
	}
	if !equal(config.Config.Cmd, []string{"--listen", "", "8080"}) {
		t.Fatalf("cmd = %q", config.Config.Cmd)
	}
	// A mapping cannot express order, so sorted names are the only predictable order.
	if !equal(config.Config.Env, []string{"A=1", "MODE=production", "ZED="}) {
		t.Fatalf("env = %q", config.Config.Env)
	}
	for _, port := range []string{"8080/tcp", "9090/udp"} {
		if _, present := config.Config.ExposedPorts[port]; !present {
			t.Fatalf("port %q missing from %v", port, config.Config.ExposedPorts)
		}
	}
	if len(config.RootFS.DiffIDs) != 1 || config.RootFS.Type != "layers" {
		t.Fatalf("rootfs = %+v", config.RootFS)
	}
	if len(config.History) != len(config.RootFS.DiffIDs) {
		t.Fatalf("history %d entries for %d layers", len(config.History), len(config.RootFS.DiffIDs))
	}
	for _, entry := range config.History {
		if !entry.Created.Equal(oci.Epoch) || entry.EmptyLayer {
			t.Fatalf("history entry = %+v", entry)
		}
	}
}

// TestBuildImage_EmptyContainerIsNotInvented checks the omission rule: no declared
// field means the config carries no value for it, not a default.
func TestBuildImage_EmptyContainerIsNotInvented(t *testing.T) {
	image, err := oci.BuildImage(inputOf(t, "linux/arm64", layers(t, "a")...))
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	config, err := v1.ParseConfigFile(bytes.NewReader(image.Config))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if config.Config.User != "" || config.Config.WorkingDir != "" || config.Config.StopSignal != "" ||
		len(config.Config.Env) != 0 || len(config.Config.ExposedPorts) != 0 ||
		len(config.Config.Entrypoint) != 0 || len(config.Config.Cmd) != 0 {
		t.Fatalf("config invented values: %+v", config.Config)
	}
	if config.Architecture != "arm64" {
		t.Fatalf("architecture = %q", config.Architecture)
	}
}

// TestBuildImage_ManifestDescriptors checks the layer order and descriptor identity
// against the compressed layer identities the caller passed in.
func TestBuildImage_ManifestDescriptors(t *testing.T) {
	layers := layers(t, "a", "b", "c")
	image, err := oci.BuildImage(inputOf(t, "linux/amd64", layers...))
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(image.Manifest))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.MediaType != oci.MediaTypeManifest || manifest.SchemaVersion != 2 {
		t.Fatalf("manifest header = %s/%d", manifest.MediaType, manifest.SchemaVersion)
	}
	if manifest.Config.MediaType != oci.MediaTypeConfig ||
		manifest.Config.Digest.String() != image.ConfigDigest ||
		manifest.Config.Size != int64(len(image.Config)) {
		t.Fatalf("config descriptor = %+v, want %s", manifest.Config, image.ConfigDigest)
	}
	if len(manifest.Layers) != len(layers) {
		t.Fatalf("layers = %d, want %d", len(manifest.Layers), len(layers))
	}
	for i, layer := range layers {
		descriptor := manifest.Layers[i]
		if descriptor.Digest.String() != layer.Digest || descriptor.Size != layer.Size ||
			descriptor.MediaType != oci.MediaTypeLayer {
			t.Fatalf("layer %d = %+v, want %s/%d", i, descriptor, layer.Digest, layer.Size)
		}
	}
	if manifest.Subject != nil || len(manifest.Annotations) != 0 {
		t.Fatalf("manifest carries generated metadata: %+v", manifest)
	}
}

// TestBuildImage_StableDigests is the reproducibility claim: the same input renders
// the same config and manifest bytes, and a digest change always means a real change.
func TestBuildImage_StableDigests(t *testing.T) {
	input := imageInput("linux/amd64", layers(t, "a", "b")...)
	input.Container = container.Container{Env: map[string]string{"B": "2", "A": "1"}, Cmd: []string{"run"}}
	input.Annotations = map[string]string{"org.opencontainers.image.description": "demo"}
	first, err := oci.BuildImage(&input)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	second, err := oci.BuildImage(&input)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if !bytes.Equal(first.Config, second.Config) || !bytes.Equal(first.Manifest, second.Manifest) ||
		first.ManifestDigest != second.ManifestDigest || first.ConfigDigest != second.ConfigDigest {
		t.Fatal("repeated rendering produced different bytes")
	}
	if first.ManifestSize != int64(len(first.Manifest)) {
		t.Fatalf("manifest size = %d, want %d", first.ManifestSize, len(first.Manifest))
	}
}

// TestBuildImage_AnnotationPassthrough checks that declared annotations reach the
// manifest unchanged and that the reserved tag key is still refused here.
func TestBuildImage_AnnotationPassthrough(t *testing.T) {
	input := imageInput("linux/amd64", layers(t, "a")...)
	input.Annotations = map[string]string{"com.example.component": "api", "x": ""}
	image, err := oci.BuildImage(&input)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(image.Manifest))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(manifest.Annotations) != 2 || manifest.Annotations["com.example.component"] != "api" {
		t.Fatalf("annotations = %v", manifest.Annotations)
	}
	input.Annotations = map[string]string{oci.RefNameAnnotation: "v1"}
	if _, err := oci.BuildImage(&input); err == nil {
		t.Fatal("the reserved tag annotation was accepted")
	}
}

// TestBuildImage_Refusals covers the inputs that must not produce an image.
func TestBuildImage_Refusals(t *testing.T) {
	valid := layers(t, "a")
	broken := []oci.CompressedLayer{{Digest: "sha256:00", Size: 1}, {Digest: "bad", Size: 1},
		{Digest: valid[0].Digest}, {Digest: valid[0].Digest, Size: -1}}
	cases := map[string]oci.ImageInput{
		"no platform":   {Layers: valid},
		"no layers":     imageInput("linux/amd64"),
		"bad layer":     imageInput("linux/amd64", broken[0]),
		"non sha256":    imageInput("linux/amd64", broken[1]),
		"missing size":  imageInput("linux/amd64", broken[2]),
		"negative size": imageInput("linux/amd64", broken[3]),
	}
	for name, input := range cases {
		if _, err := oci.BuildImage(&input); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// TestParsePlatform covers the declared platform strings and that an unsupported one
// is refused rather than guessed.
func TestParsePlatform(t *testing.T) {
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		parsed, err := oci.ParsePlatform(platform)
		if err != nil || parsed.String() != platform {
			t.Fatalf("platform %q = %v %v", platform, parsed, err)
		}
	}
	for _, platform := range []string{"", "linux", "linux/386", "linux/arm/v7", "windows/amd64",
		"linux/AMD64", "linux/amd64 ", "/amd64"} {
		if _, err := oci.ParsePlatform(platform); err == nil {
			t.Fatalf("platform %q accepted", platform)
		}
	}
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// compressTree returns one layer whose content depends on name, so distinct layers
// have distinct identities while the encoding stays deterministic.
func compressTree(t *testing.T, name string) oci.CompressedLayer {
	t.Helper()
	tree := vfs.New()
	if err := tree.File("/"+name, []byte("layer "+name+"\n"),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: "demo"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	var buffer bytes.Buffer
	result, err := oci.CompressLayer(context.Background(), &buffer, tree, oci.DefaultCompression)
	if err != nil {
		t.Fatalf("CompressLayer: %v", err)
	}
	return result
}
