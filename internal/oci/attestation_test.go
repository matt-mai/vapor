package oci_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/matt-mai/vapor/internal/oci"
)

// attachmentFixture builds a two-platform layout whose statements are the recognizable
// bytes a test can look for after a round trip.
func attachmentFixture(t *testing.T) (oci.Layout, *layoutStore, []oci.Attached) {
	t.Helper()
	base, store := layoutFixture(t)
	attached, err := oci.Attach(base.Images, map[oci.Platform][]oci.Attachment{
		mustPlatform(t, "linux/amd64"): {
			{Kind: "spdx", MediaType: oci.MediaTypeInToto, Payload: []byte(`{"spdxVersion":"SPDX-2.3"}`)},
			{Kind: "provenance", MediaType: oci.MediaTypeInToto, Payload: []byte(`{"_type":"slsa"}`)},
		},
		mustPlatform(t, "linux/arm64"): {
			{Kind: "spdx", MediaType: oci.MediaTypeInToto, Payload: []byte(`{"spdxVersion":"SPDX-2.3","arm":true}`)},
		},
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	base.Attestations = attached
	return *base, store, attached
}

// attachmentManifest reads one attachment back as a generic document.
func attachmentManifest(t *testing.T, attached *oci.Attached) map[string]any {
	t.Helper()
	manifest := map[string]any{}
	if err := json.Unmarshal(attached.Manifest, &manifest); err != nil {
		t.Fatalf("decode attachment manifest: %v", err)
	}
	return manifest
}

func TestAttach_NamesThePlatformManifestAsSubject(t *testing.T) {
	layout, _, attached := attachmentFixture(t)
	subjects := make(map[string]string, len(layout.Images))
	for position := range layout.Images {
		image := &layout.Images[position]
		subjects[image.Platform.String()] = image.ManifestDigest
	}
	for position := range attached {
		entry := &attached[position]
		subject, ok := attachmentManifest(t, entry)["subject"].(map[string]any)
		if !ok {
			t.Fatalf("%s/%s has no subject", entry.Platform, entry.Kind)
		}
		if subject["digest"] != subjects[entry.Platform.String()] {
			t.Errorf("%s/%s subject = %v, want %s", entry.Platform, entry.Kind,
				subject["digest"], subjects[entry.Platform.String()])
		}
		if subject["mediaType"] != oci.MediaTypeManifest {
			t.Errorf("%s/%s subject media type = %v", entry.Platform, entry.Kind, subject["mediaType"])
		}
	}
}

func TestAttach_IsAnArtifactManifest(t *testing.T) {
	_, _, attached := attachmentFixture(t)
	for position := range attached {
		entry := &attached[position]
		manifest := attachmentManifest(t, entry)
		if manifest["artifactType"] != oci.MediaTypeInToto {
			t.Errorf("%s/%s artifactType = %v", entry.Platform, entry.Kind, manifest["artifactType"])
		}
		config, ok := manifest["config"].(map[string]any)
		if !ok || config["mediaType"] != oci.MediaTypeEmptyConfig {
			t.Fatalf("%s/%s config = %v", entry.Platform, entry.Kind, manifest["config"])
		}
		if config["digest"] != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
			t.Errorf("%s/%s config digest = %v", entry.Platform, entry.Kind, config["digest"])
		}
		layers, ok := manifest["layers"].([]any)
		if !ok || len(layers) != 1 {
			t.Fatalf("%s/%s layers = %v", entry.Platform, entry.Kind, manifest["layers"])
		}
		layer, ok := layers[0].(map[string]any)
		if !ok || layer["mediaType"] != oci.MediaTypeInToto {
			t.Fatalf("%s/%s layer = %v", entry.Platform, entry.Kind, layers[0])
		}
		if layer["digest"] != "sha256:"+sumOf(entry.Payload) {
			t.Errorf("%s/%s layer digest does not name its payload", entry.Platform, entry.Kind)
		}
	}
}

func TestAttach_RefusesAnUnknownPlatform(t *testing.T) {
	layout, _ := layoutFixture(t)
	single := layout.Images[:1]
	missing := layout.Images[1]
	_, err := oci.Attach(single, map[oci.Platform][]oci.Attachment{
		missing.Platform: {
			{Kind: "spdx", MediaType: oci.MediaTypeInToto, Payload: []byte(`{}`)},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "no image to attach them to") {
		t.Fatalf("Attach error = %v", err)
	}
}

func TestAttach_RefusesAnEmptyStatement(t *testing.T) {
	layout, _ := layoutFixture(t)
	cases := map[string]oci.Attachment{
		"no kind":       {MediaType: oci.MediaTypeInToto, Payload: []byte(`{}`)},
		"no media type": {Kind: "spdx", Payload: []byte(`{}`)},
		"no payload":    {Kind: "spdx", MediaType: oci.MediaTypeInToto},
	}
	for name, attachment := range cases {
		_, err := oci.Attach(layout.Images, map[oci.Platform][]oci.Attachment{
			mustPlatform(t, "linux/amd64"): {attachment},
		})
		if err == nil {
			t.Fatalf("%s: Attach accepted a broken attachment", name)
		}
	}
}

func TestWriteDirectory_CarriesAttachments(t *testing.T) {
	layout, store, attached := attachmentFixture(t)
	dir := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(t.Context(), dir, store); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}
	for position := range attached {
		entry := &attached[position]
		for _, blob := range []struct {
			name string
			body []byte
		}{
			{name: "manifest", body: entry.Manifest},
			{name: "payload", body: entry.Payload},
			{name: "config", body: emptyConfigBody},
		} {
			path := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix("sha256:"+sumOf(blob.body), "sha256:"))
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s/%s %s blob: %v", entry.Platform, entry.Kind, blob.name, err)
			}
			if !bytes.Equal(written, blob.body) {
				t.Errorf("%s/%s %s blob differs from what was attached", entry.Platform, entry.Kind, blob.name)
			}
		}
	}
	index := readIndex(t, dir)
	listed := make(map[string]bool, len(index.Manifests))
	for _, descriptor := range index.Manifests {
		listed[descriptor.Digest.String()] = true
	}
	for position := range attached {
		if !listed[attached[position].ManifestDigest] {
			t.Errorf("%s/%s is not listed in index.json", attached[position].Platform, attached[position].Kind)
		}
	}
	tagged := "blobs/sha256/" + strings.TrimPrefix(layout.Index.Digest, "sha256:")
	if _, err := os.Stat(filepath.Join(dir, tagged)); err != nil {
		t.Fatalf("build index blob: %v", err)
	}
}

func TestWriteDirectory_KeepsTheBuildIndexUntouched(t *testing.T) {
	layout, store := layoutFixture(t)
	before := layout.Index.Digest
	attached, err := oci.Attach(layout.Images, map[oci.Platform][]oci.Attachment{
		mustPlatform(t, "linux/amd64"): {
			{Kind: "spdx", MediaType: oci.MediaTypeInToto, Payload: []byte(`{}`)},
		},
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	layout.Attestations = attached
	dir := filepath.Join(t.TempDir(), "image")
	if writeErr := layout.WriteDirectory(t.Context(), dir, store); writeErr != nil {
		t.Fatalf("WriteDirectory: %v", writeErr)
	}
	if layout.Index.Digest != before {
		t.Fatalf("writing attachments changed the build index digest %s to %s", before, layout.Index.Digest)
	}
	index := readIndex(t, dir)
	tagged := "blobs/sha256/" + strings.TrimPrefix(before, "sha256:")
	body, err := os.ReadFile(filepath.Join(dir, tagged))
	if err != nil {
		t.Fatalf("build index blob: %v", err)
	}
	if "sha256:"+sumOf(body) != before {
		t.Fatalf("build index blob does not hash to %s", before)
	}
	if len(index.Manifests) <= len(layout.Images) {
		t.Fatalf("index.json lists %d manifests, want more than %d images",
			len(index.Manifests), len(layout.Images))
	}
}

func TestWriteTarball_OmitsAttachments(t *testing.T) {
	layout, store, attached := attachmentFixture(t)
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := layout.WriteTarball(t.Context(), path, store, nil); err != nil {
		t.Fatalf("WriteTarball: %v", err)
	}
	members := tarballMembers(t, path)
	for position := range attached {
		entry := &attached[position]
		if _, ok := members["blobs/sha256/"+strings.TrimPrefix(entry.ManifestDigest, "sha256:")]; ok {
			t.Errorf("%s/%s attachment manifest is in the archive", entry.Platform, entry.Kind)
		}
		if _, ok := members["blobs/sha256/"+sumOf(entry.Payload)]; ok {
			t.Errorf("%s/%s attachment payload is in the archive", entry.Platform, entry.Kind)
		}
	}
}

// A tagged export lists the attachments too. The tag support and the attachment
// support are different index paths, so a build that both tags its image and attaches
// statements would otherwise lose the statements from index.json while keeping them in
// the layout.
func TestWriteDirectory_CarriesAttachmentsWithTags(t *testing.T) {
	layout, store, attached := attachmentFixture(t)
	layout.Tags = []string{"v1", "26.04"}
	dir := filepath.Join(t.TempDir(), "image")
	if err := layout.WriteDirectory(t.Context(), dir, store); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}
	index := readIndex(t, dir)
	listed := make(map[string]bool, len(index.Manifests))
	for _, descriptor := range index.Manifests {
		listed[descriptor.Digest.String()] = true
	}
	for position := range attached {
		if !listed[attached[position].ManifestDigest] {
			t.Errorf("%s/%s is not listed in index.json", attached[position].Platform, attached[position].Kind)
		}
	}
	names := make(map[string]bool, len(layout.Tags))
	for _, descriptor := range index.Manifests {
		if tag, ok := descriptor.Annotations[oci.RefNameAnnotation]; ok {
			names[tag] = true
		}
	}
	for _, tag := range layout.Tags {
		if !names[tag] {
			t.Errorf("tag %q is missing from index.json", tag)
		}
	}
	if got, want := len(index.Manifests), len(layout.Images)+len(attached)+len(layout.Tags); got != want {
		t.Fatalf("index lists %d descriptors, want %d", got, want)
	}
}

func TestWriteDirectory_IsRepeatableWithAttachments(t *testing.T) {
	snapshots := make([]string, 0, 2)
	for range 2 {
		layout, store, _ := attachmentFixture(t)
		dir := filepath.Join(t.TempDir(), "image")
		if err := layout.WriteDirectory(t.Context(), dir, store); err != nil {
			t.Fatalf("WriteDirectory: %v", err)
		}
		snapshots = append(snapshots, treeSnapshot(t, dir))
	}
	if snapshots[0] != snapshots[1] {
		t.Fatalf("two exports of the same layout differ")
	}
}

// sumOf returns the digest a blob is stored under.
func sumOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// TestPush_UploadsEachStatementByDigest checks that one push writes the image by
// digest, then every statement, then the tag: a reader of the image finds each
// statement through the digest its manifest names and the tag holds the index.
func TestPush_UploadsEachStatementByDigest(t *testing.T) {
	layout, store, attached := attachmentFixture(t)
	host := localRegistry(t)
	reference := repository(t, host, "vapor") + ":v1"
	if _, err := layout.Push(t.Context(), store, []string{reference}, anonymous()...); err != nil {
		t.Fatalf("Push: %v", err)
	}
	for position := range attached {
		entry := &attached[position]
		digest, err := name.NewDigest(repository(t, host, "vapor") + "@" + entry.ManifestDigest)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := remote.Get(digest, anonymous()...)
		if err != nil {
			t.Fatalf("%s/%s: %v", entry.Platform, entry.Kind, err)
		}
		if !bytes.Equal(descriptor.Manifest, entry.Manifest) {
			t.Fatalf("%s/%s manifest in the registry differs", entry.Platform, entry.Kind)
		}
		payloadDigest, err := name.NewDigest(repository(t, host, "vapor") + "@sha256:" + sumOf(entry.Payload))
		if err != nil {
			t.Fatal(err)
		}
		layer, err := remote.Layer(payloadDigest, anonymous()...)
		if err != nil {
			t.Fatalf("%s/%s payload: %v", entry.Platform, entry.Kind, err)
		}
		read, err := layer.Compressed()
		if err != nil {
			t.Fatalf("%s/%s payload: %v", entry.Platform, entry.Kind, err)
		}
		body, err := io.ReadAll(read)
		_ = read.Close()
		if err != nil {
			t.Fatalf("%s/%s payload: %v", entry.Platform, entry.Kind, err)
		}
		if !bytes.Equal(body, entry.Payload) {
			t.Fatalf("%s/%s payload in the registry differs", entry.Platform, entry.Kind)
		}
		configDigest, err := name.NewDigest(repository(t, host, "vapor") +
			"@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
		if err != nil {
			t.Fatal(err)
		}
		configLayer, err := remote.Layer(configDigest, anonymous()...)
		if err != nil {
			t.Fatalf("%s/%s config blob: %v", entry.Platform, entry.Kind, err)
		}
		if size, err := configLayer.Size(); err != nil || size != int64(len(emptyConfigBody)) {
			t.Fatalf("%s/%s config blob size = %d (%v)", entry.Platform, entry.Kind, size, err)
		}
	}
}

func TestPush_KeepsTheTagOnTheBuildIndex(t *testing.T) {
	layout, store, attached := attachmentFixture(t)
	host := localRegistry(t)
	reference := repository(t, host, "vapor") + ":v1"
	if _, err := layout.Push(t.Context(), store, []string{reference}, anonymous()...); err != nil {
		t.Fatalf("Push: %v", err)
	}
	tag, err := name.NewTag(reference)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := remote.Get(tag, anonymous()...)
	if err != nil {
		t.Fatalf("get tag: %v", err)
	}
	if descriptor.Digest.String() != layout.Index.Digest {
		t.Fatalf("tag holds %s, want the build index %s", descriptor.Digest, layout.Index.Digest)
	}
	for position := range attached {
		if descriptor.Digest.String() == attached[position].ManifestDigest {
			t.Fatalf("an attachment replaced the image tag")
		}
	}
}

func TestPush_RefusesARegistryWithoutReferrers(t *testing.T) {
	layout, store, _ := attachmentFixture(t)
	host := registryHost(t, false)
	reference := repository(t, host, "vapor") + ":v1"
	pushed, err := layout.Push(t.Context(), store, []string{reference}, anonymous()...)
	if !errors.Is(err, oci.ErrReferrersUnsupported) {
		t.Fatalf("Push = %v, want ErrReferrersUnsupported", err)
	}
	if !strings.Contains(err.Error(), "Referrers API") {
		t.Fatalf("error = %q, want a sentence about the missing API", err)
	}
	if len(pushed.References) != 0 {
		t.Fatalf("push moved %v before the refusal", pushed.References)
	}
}

// TestPush_WithoutAttachmentsNeedsNoReferrers checks that an image-only push does not
// depend on the registry listing attachments: no statement is uploaded, so no
// Referrers endpoint is needed.
func TestPush_WithoutAttachmentsNeedsNoReferrers(t *testing.T) {
	layout, store := layoutFixture(t)
	layout.Attestations = nil
	host := registryHost(t, false)
	reference := repository(t, host, "vapor") + ":v1"
	pushed, err := layout.Push(t.Context(), store, []string{reference}, anonymous()...)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(pushed.References) != 1 || !strings.HasSuffix(pushed.References[0], ":v1") {
		t.Fatalf("References = %v", pushed.References)
	}
	tag, err := name.NewTag(reference)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := remote.Get(tag, anonymous()...)
	if err != nil {
		t.Fatalf("get tag: %v", err)
	}
	if descriptor.Digest.String() != layout.Index.Digest {
		t.Fatalf("tag holds %s, want the build index %s", descriptor.Digest, layout.Index.Digest)
	}
}

// emptyConfigBody is the config an attachment manifest names: the empty JSON object.
var emptyConfigBody = []byte(`{}`)
