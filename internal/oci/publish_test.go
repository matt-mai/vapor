package oci_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/matt-mai/vapor/internal/oci"
)

// localRegistry starts an in-memory registry with the Referrers API enabled and
// returns its bare host:port.
func localRegistry(t *testing.T) string {
	t.Helper()
	return registryHost(t, true)
}

// registryHost starts an in-memory registry and returns its bare host:port. The
// Referrers API is switched on or off, so a test can choose the registry it talks to.
func registryHost(t *testing.T, referrers bool) string {
	t.Helper()
	server := httptest.NewServer(registry.New(
		registry.Logger(log.New(io.Discard, "", 0)),
		registry.WithReferrersSupport(referrers),
	))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func anonymous() []remote.Option {
	return []remote.Option{remote.WithAuth(authn.Anonymous)}
}

func repository(t *testing.T, host, path string) string {
	t.Helper()
	return host + "/" + path
}

func TestPush_UploadsTheBuiltIndex(t *testing.T) {
	layout, store := layoutFixture(t)
	host := localRegistry(t)
	references := []string{repository(t, host, "vapor") + ":v1", repository(t, host, "vapor") + ":v1-amd64"}

	pushed, err := layout.Push(context.Background(), store, references, anonymous()...)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if pushed.Digest != layout.Index.Digest {
		t.Fatalf("pushed %s, built %s", pushed.Digest, layout.Index.Digest)
	}
	if pushed.Repository != repository(t, host, "vapor") {
		t.Fatalf("pushed to %q", pushed.Repository)
	}
	for _, reference := range references {
		tag, err := name.NewTag(reference)
		if err != nil {
			t.Fatal(err)
		}
		pulled, err := remote.Index(tag, anonymous()...)
		if err != nil {
			t.Fatalf("pull %s: %v", reference, err)
		}
		digest, err := pulled.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if digest.String() != layout.Index.Digest {
			t.Fatalf("tag %s holds %s, want %s", reference, digest, layout.Index.Digest)
		}
		assertPushedImages(t, pulled, layout)
	}
}

// assertPushedImages reads every image back from the registry and compares it with
// what the layout described.
func assertPushedImages(t *testing.T, pulled v1.ImageIndex, layout *oci.Layout) {
	t.Helper()
	manifest, err := pulled.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Manifests) != len(layout.Images) {
		t.Fatalf("registry index lists %d manifests", len(manifest.Manifests))
	}
	for index := range manifest.Manifests {
		image, err := pulled.Image(manifest.Manifests[index].Digest)
		if err != nil {
			t.Fatalf("index image %s: %v", manifest.Manifests[index].Digest, err)
		}
		config, err := image.RawConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if !containsConfig(layout, config) {
			t.Fatal("registry holds a config the layout does not describe")
		}
		layers, err := image.Layers()
		if err != nil {
			t.Fatal(err)
		}
		if len(layers) != 1 {
			t.Fatalf("image has %d layers", len(layers))
		}
	}
}

func containsConfig(layout *oci.Layout, config []byte) bool {
	for index := range layout.Images {
		if bytes.Equal(layout.Images[index].Config, config) {
			return true
		}
	}
	return false
}

func TestPush_LayerBytesMatchTheStore(t *testing.T) {
	layout, store := layoutFixture(t)
	host := localRegistry(t)
	reference := repository(t, host, "vapor") + ":v1"
	if _, err := layout.Push(context.Background(), store, []string{reference}, anonymous()...); err != nil {
		t.Fatalf("Push: %v", err)
	}
	tag, err := name.NewTag(reference)
	if err != nil {
		t.Fatal(err)
	}
	pulled, err := remote.Index(tag, anonymous()...)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	manifest, err := pulled.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	for index := range manifest.Manifests {
		image, err := pulled.Image(manifest.Manifests[index].Digest)
		if err != nil {
			t.Fatal(err)
		}
		layers, err := image.Layers()
		if err != nil {
			t.Fatal(err)
		}
		for _, layer := range layers {
			digest, err := layer.Digest()
			if err != nil {
				t.Fatal(err)
			}
			reader, err := layer.Compressed()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			if closeErr := reader.Close(); err != nil || closeErr != nil {
				t.Fatalf("read layer: %v %v", err, closeErr)
			}
			stored := store.blobs[digest.Hex]
			if !bytes.Equal(body, stored) {
				t.Fatalf("registry layer %s differs from the store", digest)
			}
		}
	}
}

func TestPush_Refusals(t *testing.T) {
	layout, store := layoutFixture(t)
	host := localRegistry(t)
	valid := repository(t, host, "vapor") + ":v1"
	cases := map[string][]string{
		"no references":    nil,
		"empty reference":  {""},
		"digest reference": {repository(t, host, "vapor") + "@sha256:" + strings.Repeat("0", 64)},
		"two repositories": {valid, repository(t, host, "other") + ":v1"},
		"unparsable":       {"not a reference"},
		"missing hostname": {"vapor:v1"},
		"missing tag":      {repository(t, host, "vapor")},
		"tagless second":   {valid, repository(t, host, "other")},
	}
	for name, references := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := layout.Push(context.Background(), store, references, anonymous()...); err == nil {
				t.Fatalf("push accepted %v", references)
			}
		})
	}
	// A nil context must be refused, not silently replaced.
	var noContext context.Context
	if _, err := layout.Push(noContext, store, []string{valid}, anonymous()...); err == nil {
		t.Fatal("push accepted a nil context")
	}
	if _, err := layout.Push(context.Background(), nil, []string{valid}, anonymous()...); err == nil {
		t.Fatal("push accepted a nil source")
	}
}

func TestPush_RefusesAMissingBlob(t *testing.T) {
	layout, store := layoutFixture(t)
	delete(store.blobs, strings.TrimPrefix(layout.Layers[0].Digest, "sha256:"))
	host := localRegistry(t)
	_, err := layout.Push(context.Background(), store,
		[]string{repository(t, host, "vapor") + ":v1"}, anonymous()...)
	if err == nil {
		t.Fatal("pushed a layout without its layer")
	}
	var failure *oci.PushError
	if !errors.As(err, &failure) {
		t.Fatalf("push failure is %T, want a redacted PushError", err)
	}
	if strings.Contains(failure.Error(), "missing") {
		t.Fatalf("push error leaks its cause: %v", failure)
	}
	if failure.Unwrap() == nil {
		t.Fatal("push error has no cause to inspect")
	}
}

func TestPush_RefusesAnUnreachableRegistry(t *testing.T) {
	layout, store := layoutFixture(t)
	_, err := layout.Push(context.Background(), store,
		[]string{"127.0.0.1:1/vapor:v1"}, anonymous()...)
	if err == nil {
		t.Fatal("pushed to a closed port")
	}
	if _, ok := errors.AsType[*oci.PushError](err); !ok {
		t.Fatalf("push failure is %T, want a redacted PushError", err)
	}
}

func TestPush_StopsOnCancellation(t *testing.T) {
	layout, store := layoutFixture(t)
	host := localRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := layout.Push(ctx, store, []string{repository(t, host, "vapor") + ":v1"}, anonymous()...)
	if err == nil {
		t.Fatal("pushed with a canceled context")
	}
}

// renamedIndex proves the push refuses an index whose bytes say something other
// than the digest it claims.
func TestPush_RefusesAnIndexThatDisagreesWithItsDigest(t *testing.T) {
	layout, store := layoutFixture(t)
	altered := *layout
	altered.Index = oci.Index{Bytes: layout.Index.Bytes, Digest: "sha256:" + strings.Repeat("0", 64),
		Size: layout.Index.Size}
	host := localRegistry(t)
	_, err := altered.Push(context.Background(), store,
		[]string{repository(t, host, "vapor") + ":v1"}, anonymous()...)
	if err == nil || !strings.Contains(err.Error(), "is not the built index") {
		t.Fatalf("push accepted an index that disagrees with its digest: %v", err)
	}
}
