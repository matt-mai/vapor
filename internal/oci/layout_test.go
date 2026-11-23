package oci_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/vfs"
)

// layoutStore holds layer bytes by bare digest, the key every Vapor store uses.
type layoutStore struct {
	blobs map[string][]byte
}

func (s *layoutStore) Open(digest string, size int64) (io.ReadCloser, error) {
	body, ok := s.blobs[digest]
	if !ok {
		return nil, errors.New("blob is missing")
	}
	if int64(len(body)) != size {
		return nil, errors.New("blob has the wrong size")
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// layoutFixture builds a real two-platform layout over stored layer bytes.
func layoutFixture(t *testing.T) (*oci.Layout, *layoutStore) {
	t.Helper()
	store := &layoutStore{blobs: make(map[string][]byte)}
	images := make([]oci.Image, 0, 2)
	layers := make([]oci.CompressedLayer, 0, 2)
	for _, name := range []string{"amd64", "arm64"} {
		layer, body := compressed(t, name)
		store.blobs[strings.TrimPrefix(layer.Digest, "sha256:")] = body
		image, err := oci.BuildImage(&oci.ImageInput{
			Platform: mustPlatform(t, "linux/"+name), Layers: []oci.CompressedLayer{layer},
		})
		if err != nil {
			t.Fatalf("BuildImage: %v", err)
		}
		images = append(images, image)
		layers = append(layers, layer)
	}
	index, err := oci.BuildIndex(&oci.IndexInput{
		Images: images, Platforms: []oci.Platform{mustPlatform(t, "linux/amd64"), mustPlatform(t, "linux/arm64")},
	})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	return &oci.Layout{Index: index, Images: images, Layers: layers}, store
}

func mustPlatform(t *testing.T, platform string) oci.Platform {
	t.Helper()
	parsed, err := oci.ParsePlatform(platform)
	if err != nil {
		t.Fatalf("ParsePlatform: %v", err)
	}
	return parsed
}

// compressed returns one layer and the bytes its digest names, serialized once so
// the fixture and its store cannot disagree.
// compressed serializes one layer and returns the bytes its digest names, so the
// fixture store and the layout always agree.
func compressed(t *testing.T, name string) (oci.CompressedLayer, []byte) {
	t.Helper()
	tree := vfs.New()
	if err := tree.File("/"+name, []byte("layer "+name+"\n"),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Package: "demo"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	var buffer bytes.Buffer
	layer, err := oci.CompressLayer(context.Background(), &buffer, tree, oci.DefaultCompression)
	if err != nil {
		t.Fatalf("CompressLayer: %v", err)
	}
	return layer, buffer.Bytes()
}

func TestWriteDirectory_ProducesAValidLayout(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(context.Background(), dst+string(os.PathSeparator), store); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}
	version, err := os.ReadFile(filepath.Join(dst, "oci-layout"))
	if err != nil {
		t.Fatal(err)
	}
	if string(version) != `{"imageLayoutVersion":"1.0.0"}` {
		t.Fatalf("oci-layout = %s", version)
	}
	indexJSON, err := os.ReadFile(filepath.Join(dst, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index v1.IndexManifest
	if err := json.Unmarshal(indexJSON, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 2 {
		t.Fatalf("index lists %d manifests", len(index.Manifests))
	}
	for _, descriptor := range index.Manifests {
		if !strings.HasPrefix(descriptor.Digest.String(), "sha256:") {
			t.Fatalf("descriptor digest = %s", descriptor.Digest)
		}
		blob := filepath.Join(dst, "blobs", "sha256", strings.TrimPrefix(descriptor.Digest.String(), "sha256:"))
		body, err := os.ReadFile(blob)
		if err != nil {
			t.Fatalf("manifest blob: %v", err)
		}
		if sum := sha256.Sum256(body); "sha256:"+hex.EncodeToString(sum[:]) != descriptor.Digest.String() {
			t.Fatalf("manifest %s does not match its bytes", descriptor.Digest)
		}
	}
	for _, layer := range layout.Layers {
		blob := filepath.Join(dst, "blobs", "sha256", strings.TrimPrefix(layer.Digest, "sha256:"))
		info, err := os.Stat(blob)
		if err != nil {
			t.Fatalf("layer blob: %v", err)
		}
		if info.Size() != layer.Size {
			t.Fatalf("layer %s has size %d, want %d", layer.Digest, info.Size(), layer.Size)
		}
	}
}

func TestWriteDirectory_IsRepeatable(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(context.Background(), dst, store); err != nil {
		t.Fatal(err)
	}
	first := treeSnapshot(t, dst)
	other := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(context.Background(), other, store); err != nil {
		t.Fatalf("second export: %v", err)
	}
	second := treeSnapshot(t, other)
	if first != second {
		t.Fatalf("repeated export differs:\n%s\n%s", first, second)
	}
}

func TestWriteDirectory_RefusesAnUnrelatedDestination(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := t.TempDir()
	blobs := filepath.Join(dst, "blobs")
	if err := os.Mkdir(blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(blobs, "notes.txt")
	if err := os.WriteFile(unrelated, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteDirectory(context.Background(), dst, store); err == nil {
		t.Fatal("exported over a directory holding unrelated files")
	}
	body, err := os.ReadFile(unrelated)
	if err != nil || string(body) != "precious\n" {
		t.Fatalf("unrelated file changed: %q %v", body, err)
	}
}

func TestWriteDirectory_RefusesAPoisonedBlob(t *testing.T) {
	layout, store := layoutFixture(t)
	store.blobs[strings.TrimPrefix(layout.Layers[0].Digest, "sha256:")] = []byte("other bytes")
	dst := filepath.Join(t.TempDir(), "image")
	err := layout.WriteDirectory(context.Background(), dst, store)
	if err == nil || !strings.Contains(err.Error(), "wrong size") {
		t.Fatalf("export accepted a poisoned blob: %v", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed export left a destination behind: %v", statErr)
	}
}

// poisonedSource returns the right number of bytes, so only the digest check can
// catch it.
type poisonedSource struct {
	blobs  *layoutStore
	digest string
}

func (s *poisonedSource) Open(digest string, size int64) (io.ReadCloser, error) {
	if digest == s.digest {
		return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), int(size)))), nil
	}
	return s.blobs.Open(digest, size)
}

func TestWriteDirectory_RefusesASourceWithOtherBytes(t *testing.T) {
	layout, store := layoutFixture(t)
	source := &poisonedSource{blobs: store, digest: strings.TrimPrefix(layout.Layers[0].Digest, "sha256:")}
	err := layout.WriteDirectory(context.Background(), filepath.Join(t.TempDir(), "image"), source)
	if err == nil || !strings.Contains(err.Error(), "has content") {
		t.Fatalf("export accepted bytes the digest does not name: %v", err)
	}
}

func TestWriteDirectory_RemovesItsStagingOnFailure(t *testing.T) {
	layout, store := layoutFixture(t)
	delete(store.blobs, strings.TrimPrefix(layout.Layers[0].Digest, "sha256:"))
	parent := t.TempDir()
	if err := layout.WriteDirectory(context.Background(), filepath.Join(parent, "image"), store); err == nil {
		t.Fatal("export succeeded without layer bytes")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed export left %d entries behind", len(entries))
	}
}

func TestWriteTarball_RoundTrips(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image.tar")
	if err := layout.WriteTarball(context.Background(), dst, store, nil); err != nil {
		t.Fatalf("WriteTarball: %v", err)
	}
	members := tarballMembers(t, dst)
	for _, name := range []string{"oci-layout", "index.json"} {
		if _, ok := members[name]; !ok {
			t.Fatalf("tarball has no %s", name)
		}
	}
	for _, layer := range layout.Layers {
		body, ok := members["blobs/sha256/"+strings.TrimPrefix(layer.Digest, "sha256:")]
		if !ok {
			t.Fatalf("tarball has no blob for layer %s", layer.Digest)
		}
		sum := sha256.Sum256(body)
		if "sha256:"+hex.EncodeToString(sum[:]) != layer.Digest {
			t.Fatalf("tarball layer bytes do not match %s", layer.Digest)
		}
	}
	// The two exports share the image blobs but have different root indexes.
	directory := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(context.Background(), directory, store); err != nil {
		t.Fatal(err)
	}
	for name, body := range members {
		if name == "index.json" || name == "blobs/sha256/"+strings.TrimPrefix(layout.Index.Digest, "sha256:") {
			continue
		}
		fromDisk, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("directory export has no %s: %v", name, err)
		}
		if !bytes.Equal(fromDisk, body) {
			t.Fatalf("%s differs between the two sinks", name)
		}
	}
}

func TestWriteTarball_IsRepeatable(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image.tar")
	if err := layout.WriteTarball(context.Background(), dst, store, nil); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "image.tar")
	if repeatedErr := layout.WriteTarball(context.Background(), other, store, nil); repeatedErr != nil {
		t.Fatal(repeatedErr)
	}
	second, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeated tarball export differs")
	}
}

func TestWriteTarball_RefusesDirectoriesAndSymlinks(t *testing.T) {
	layout, store := layoutFixture(t)
	dir := t.TempDir()
	if err := layout.WriteTarball(context.Background(), dir, store, nil); err == nil {
		t.Fatal("exported a tarball over a directory")
	}
	target := filepath.Join(dir, "target.tar")
	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.tar")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteTarball(context.Background(), link, store, nil); err == nil {
		t.Fatal("exported a tarball through a symlink")
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "original\n" {
		t.Fatalf("symlink target changed: %q %v", body, err)
	}
}

func TestLayout_RefusesInconsistentInput(t *testing.T) {
	layout, store := layoutFixture(t)
	if err := (&oci.Layout{}).WriteDirectory(context.Background(), t.TempDir(), store); err == nil {
		t.Fatal("wrote a layout without an index")
	}
	if err := (&oci.Layout{Index: layout.Index}).WriteTarball(context.Background(),
		filepath.Join(t.TempDir(), "empty.tar"), store, nil); err == nil {
		t.Fatal("wrote a layout without images")
	}
	broken := append([]byte(nil), layout.Index.Bytes...)
	broken[0] = ' '
	tampered := &oci.Layout{Index: oci.Index{Bytes: broken}, Images: layout.Images, Layers: layout.Layers}
	if err := tampered.WriteDirectory(context.Background(), filepath.Join(t.TempDir(), "x"), store); err != nil {
		t.Fatalf("index bytes are opaque to the export: %v", err)
	}
	altered := *layout
	altered.Images = append([]oci.Image(nil), layout.Images...)
	altered.Images[0].ManifestDigest = "sha256:" + strings.Repeat("0", 64)
	if err := altered.WriteDirectory(context.Background(), filepath.Join(t.TempDir(), "y"), store); err == nil {
		t.Fatal("exported a manifest whose digest names other bytes")
	}
}

// treeSnapshot renders every path and its size, so a repeated export can be
// compared without reading whole blobs.
func treeSnapshot(t *testing.T, root string) string {
	t.Helper()
	var builder strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		sum := sha256.New()
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		if _, err := io.Copy(sum, file); err != nil {
			return err
		}
		builder.WriteString(relative)
		builder.WriteString(" ")
		builder.WriteString(hex.EncodeToString(sum.Sum(nil)))
		builder.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return builder.String()
}

func tarballMembers(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	members := make(map[string][]byte)
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return members
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !header.ModTime.Equal(oci.Epoch) {
			t.Fatalf("%s has modification time %s", header.Name, header.ModTime)
		}
		members[header.Name] = body
	}
}

// failingSource returns the right number of other bytes, so only the digest check
// can catch it.
type failingSource struct{}

func (s *failingSource) Open(_ string, size int64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(make([]byte, size))), nil
}

func TestCopyBlob_RefusesAPoisonedSource(t *testing.T) {
	layout, _ := layoutFixture(t)
	digest := strings.TrimPrefix(layout.Layers[0].Digest, "sha256:")
	err := layout.WriteTarball(context.Background(), filepath.Join(t.TempDir(), "image.tar"), &failingSource{}, nil)
	if err == nil || !strings.Contains(err.Error(), "has content") {
		t.Fatalf("export accepted bytes that do not match %s: %v", digest, err)
	}
}

func TestCopyBlob_RefusesAShortBlob(t *testing.T) {
	layout, store := layoutFixture(t)
	want := layout.Layers[0].Size
	store.blobs[strings.TrimPrefix(layout.Layers[0].Digest, "sha256:")] = make([]byte, want-1)
	err := layout.WriteDirectory(context.Background(), filepath.Join(t.TempDir(), "image"), store)
	if err == nil || !strings.Contains(err.Error(), "wrong size") {
		t.Fatalf("export accepted a short blob: %v", err)
	}
}

func TestLayout_RefusesAnEmptyDestination(t *testing.T) {
	layout, store := layoutFixture(t)
	if err := layout.WriteDirectory(context.Background(), "", store); err == nil {
		t.Fatal("wrote a layout to an empty path")
	}
	if err := layout.WriteTarball(context.Background(), "", store, nil); err == nil {
		t.Fatal("wrote a tarball to an empty path")
	}
	if err := layout.WriteDirectory(context.Background(), t.TempDir(), nil); err == nil {
		t.Fatal("exported without a blob source")
	}
}

func TestWriteDirectory_RefusesAnEmptyDirectoryOrSymlink(t *testing.T) {
	layout, store := layoutFixture(t)
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, link, link + string(os.PathSeparator)} {
		if err := layout.WriteDirectory(context.Background(), path, store); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("export to %s = %v, want occupied path error", path, err)
		}
	}
	if target, err := os.Readlink(link); err != nil || target != dir {
		t.Fatalf("destination link changed: %q %v", target, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("empty directory changed: %v %v", entries, err)
	}
}

type sourceFunc func(string, int64) (io.ReadCloser, error)

func (f sourceFunc) Open(digest string, size int64) (io.ReadCloser, error) {
	return f(digest, size)
}

func TestWriteDirectory_RefusesAPathOccupiedDuringStaging(t *testing.T) {
	layout, store := layoutFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "image")
	source := sourceFunc(func(digest string, size int64) (io.ReadCloser, error) {
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return nil, err
		}
		return store.Open(digest, size)
	})
	if err := layout.WriteDirectory(t.Context(), dst, source); !errors.Is(err, os.ErrExist) {
		t.Fatalf("staged export = %v, want occupied path error", err)
	}
	if entries, err := os.ReadDir(dst); err != nil || len(entries) != 0 {
		t.Fatalf("destination is not empty: %v %v", entries, err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 1 || entries[0].Name() != "image" {
		t.Fatalf("failed export left unexpected entries: %v %v", entries, err)
	}
}

func TestWriteTarball_RefusesAPathOccupiedDuringStaging(t *testing.T) {
	layout, store := layoutFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "image.tar")
	source := sourceFunc(func(digest string, size int64) (io.ReadCloser, error) {
		if err := os.WriteFile(dst, []byte("keep\n"), 0o600); err != nil {
			return nil, err
		}
		return store.Open(digest, size)
	})
	if err := layout.WriteTarball(t.Context(), dst, source, nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("staged export = %v, want occupied path error", err)
	}
	if body, err := os.ReadFile(dst); err != nil || string(body) != "keep\n" {
		t.Fatalf("destination content changed: %q %v", body, err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 1 || entries[0].Name() != "image.tar" {
		t.Fatalf("failed export left unexpected entries: %v %v", entries, err)
	}
}

// Declared tags reach a local layout as descriptors beside the build index. Each one
// names the same digest, so tagging cannot change what the build reported.
func TestWriteDirectory_WritesTagDescriptors(t *testing.T) {
	layout, store := layoutFixture(t)
	layout.Tags = []string{"v1", "26.04"}
	dst := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(context.Background(), dst, store); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}
	index := readIndex(t, dst)
	if len(index.Manifests) != 4 {
		t.Fatalf("index lists %d descriptors, want 2 images and 2 tags", len(index.Manifests))
	}
	for _, descriptor := range index.Manifests[:2] {
		if descriptor.Annotations != nil {
			t.Fatalf("build descriptor carries annotations: %+v", descriptor.Annotations)
		}
	}
	names := make([]string, 0, 2)
	for _, descriptor := range index.Manifests[2:] {
		if descriptor.Digest.String() != layout.Index.Digest ||
			descriptor.MediaType != types.MediaType(oci.MediaTypeIndex) || descriptor.Size != layout.Index.Size {
			t.Fatalf("tag descriptor = %+v, want the build index %s", descriptor, layout.Index.Digest)
		}
		names = append(names, descriptor.Annotations[oci.RefNameAnnotation])
	}
	if want := []string{"v1", "26.04"}; !slices.Equal(names, want) {
		t.Fatalf("tag names = %v, want %v", names, want)
	}
	// The tagged descriptor points at the index blob, which the layout wrote from
	// the build index, so a reader can pull the tagged image from the directory.
	blob := filepath.Join(dst, "blobs", "sha256", strings.TrimPrefix(layout.Index.Digest, "sha256:"))
	if body, err := os.ReadFile(blob); err != nil || !bytes.Equal(body, layout.Index.Bytes) {
		t.Fatalf("index blob = %d bytes, %v", len(body), err)
	}
}

// Without declared tags the layout's index is the build index byte for byte, so an
// untagged export is unchanged by the tag support.
func TestWriteDirectory_KeepsTheBuildIndexWithoutTags(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(context.Background(), dst, store); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dst, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, layout.Index.Bytes) {
		t.Fatalf("index.json differs from the build index:\n%s", body)
	}
}

func TestWriteTarball_CarriesOneBuildIndexDescriptor(t *testing.T) {
	for _, test := range []struct {
		name string
		tags []string
		want string
	}{
		{name: "untagged"},
		{name: "tagged", tags: []string{"v1", "26.04"}, want: "v1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout, store := layoutFixture(t)
			layout.Tags = test.tags
			dst := filepath.Join(t.TempDir(), "image.tar")
			if err := layout.WriteTarball(t.Context(), dst, store, nil); err != nil {
				t.Fatal(err)
			}
			files := tarballFiles(t, dst)
			var index v1.IndexManifest
			if err := json.Unmarshal(files["index.json"], &index); err != nil {
				t.Fatal(err)
			}
			if len(index.Manifests) != 1 {
				t.Fatalf("index lists %d descriptors, want 1", len(index.Manifests))
			}
			descriptor := index.Manifests[0]
			if descriptor.Digest.String() != layout.Index.Digest || descriptor.Size != layout.Index.Size ||
				string(descriptor.MediaType) != oci.MediaTypeIndex || descriptor.Annotations[oci.RefNameAnnotation] != test.want {
				t.Fatalf("unexpected build index descriptor: %+v", descriptor)
			}
			buildIndex := files["blobs/sha256/"+descriptor.Digest.Hex]
			if !bytes.Equal(buildIndex, layout.Index.Bytes) {
				t.Fatal("archive descriptor does not name the original build index bytes")
			}
			for _, image := range layout.Images {
				if len(files["blobs/sha256/"+strings.TrimPrefix(image.ManifestDigest, "sha256:")]) == 0 {
					t.Fatalf("missing platform manifest %s", image.ManifestDigest)
				}
			}
		})
	}
}

// tarballFiles returns the archive's members by name.
func tarballFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(body))
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read tarball: %v", nextErr)
		}
		content, readErr := io.ReadAll(reader)
		if readErr != nil {
			t.Fatalf("read %s: %v", header.Name, readErr)
		}
		files[header.Name] = content
	}
	return files
}

// A tag the loader would refuse must not reach a layout, so the writer checks the
// grammar itself instead of trusting its caller.
func TestWriteDirectory_RefusesAnInvalidTag(t *testing.T) {
	for _, tags := range [][]string{{".bad"}, {"v1", "v1"}, {""}} {
		t.Run(strings.Join(tags, ","), func(t *testing.T) {
			layout, store := layoutFixture(t)
			layout.Tags = tags
			if err := layout.WriteDirectory(context.Background(), filepath.Join(t.TempDir(), "image"), store); err == nil {
				t.Fatalf("wrote a layout with tags %v", tags)
			}
		})
	}
}

// readIndex parses the index.json of a written layout directory.
func readIndex(t *testing.T, dst string) v1.IndexManifest {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dst, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index v1.IndexManifest
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	return index
}

// A canceled export stops during staging and leaves nothing behind, so an
// interrupted build never leaves a partial layout beside the destination.
func TestWriteDirectory_StopsOnCancellation(t *testing.T) {
	layout, store := layoutFixture(t)
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := layout.WriteDirectory(ctx, filepath.Join(parent, "image"), store)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("export = %v, want context.Canceled", err)
	}
	if entries, readErr := os.ReadDir(parent); readErr != nil || len(entries) != 0 {
		t.Fatalf("canceled export left %v (%v)", entries, readErr)
	}
}

func TestWriteTarball_StopsOnCancellation(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image.tar")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := layout.WriteTarball(ctx, dst, store, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("export = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled export left a destination: %v", err)
	}
}

func TestWriteTarball_StopsWhenCanceledWhileStaging(t *testing.T) {
	layout, store := layoutFixture(t)
	dst := filepath.Join(t.TempDir(), "image.tar")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := sourceFunc(func(digest string, size int64) (io.ReadCloser, error) {
		cancel()
		return store.Open(digest, size)
	})
	if err := layout.WriteTarball(ctx, dst, source, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("export = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled export left a destination: %v", err)
	}
	if leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(dst), ".vapor-tarball-*")); err != nil ||
		len(leftovers) != 0 {
		t.Fatalf("canceled export left staging files: %v %v", leftovers, err)
	}
}

// A nil context must be refused rather than replaced, so a caller cannot export
// without the cancellation the rest of the build honors.
func TestLayoutSinks_RefuseANilContext(t *testing.T) {
	layout, store := layoutFixture(t)
	var noContext context.Context
	if err := layout.WriteDirectory(noContext, filepath.Join(t.TempDir(), "image"), store); err == nil {
		t.Fatal("directory export accepted a nil context")
	}
	if err := layout.WriteTarball(noContext, filepath.Join(t.TempDir(), "image.tar"), store, nil); err == nil {
		t.Fatal("tarball export accepted a nil context")
	}
}

// An artifact-only build gives both platforms the same filesystem, so the same layer
// arrives twice. It is one blob, not a duplicate path.
func TestWriteDirectory_WritesASharedLayerOnce(t *testing.T) {
	store := &layoutStore{blobs: make(map[string][]byte)}
	layer, body := compressed(t, "shared")
	store.blobs[strings.TrimPrefix(layer.Digest, "sha256:")] = body
	images := make([]oci.Image, 0, 2)
	platforms := make([]oci.Platform, 0, 2)
	for _, name := range []string{"amd64", "arm64"} {
		image, err := oci.BuildImage(&oci.ImageInput{
			Platform: mustPlatform(t, "linux/"+name), Layers: []oci.CompressedLayer{layer},
		})
		if err != nil {
			t.Fatalf("BuildImage: %v", err)
		}
		images = append(images, image)
		platforms = append(platforms, mustPlatform(t, "linux/"+name))
	}
	index, err := oci.BuildIndex(&oci.IndexInput{Images: images, Platforms: platforms})
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	layout := &oci.Layout{Index: index, Images: images,
		Layers: []oci.CompressedLayer{layer, layer}}
	dst := filepath.Join(t.TempDir(), "image")
	if writeErr := layout.WriteDirectory(context.Background(), dst, store); writeErr != nil {
		t.Fatalf("WriteDirectory: %v", writeErr)
	}
	path := filepath.Join(dst, "blobs", "sha256", strings.TrimPrefix(layer.Digest, "sha256:"))
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared layer: %v", err)
	}
	if !bytes.Equal(written, body) {
		t.Fatal("shared layer blob does not hold the layer bytes")
	}
	tarball := filepath.Join(t.TempDir(), "image.tar")
	if err := layout.WriteTarball(context.Background(), tarball, store, nil); err != nil {
		t.Fatalf("WriteTarball: %v", err)
	}
	blobPath := "blobs/sha256/" + strings.TrimPrefix(layer.Digest, "sha256:")
	if files := tarballFiles(t, tarball); !bytes.Equal(files[blobPath], body) {
		t.Fatal("tar entry for the shared layer is not the layer")
	}
}

// The same path twice with different bytes is still a conflict: the file holds one.
func TestWriteDirectory_RefusesConflictingBlobs(t *testing.T) {
	layout, store := layoutFixture(t)
	digest := layout.Layers[0].Digest
	layout.Layers = append(layout.Layers, oci.CompressedLayer{
		Digest: digest, Size: layout.Layers[0].Size + 1,
	})
	err := layout.WriteDirectory(context.Background(), filepath.Join(t.TempDir(), "image"), store)
	if err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("WriteDirectory error = %v, want a conflict", err)
	}
}
