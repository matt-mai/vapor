package acquire_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

type fetchFunc func(context.Context, string) (io.ReadCloser, error)

func (f fetchFunc) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	return f(ctx, url)
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func nopCloser(r io.Reader) io.ReadCloser { return io.NopCloser(r) }

//go:fix inline
func newCache(t *testing.T) (*cache.Cache, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func cachedPath(dir, digest string) string {
	return filepath.Join(dir, "sha256", digest[:2], digest)
}

func cachedBytes(t *testing.T, dir, digest string, size int64) []byte {
	t.Helper()
	data, err := os.ReadFile(cachedPath(dir, digest))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != size {
		t.Fatalf("cached size = %d, want %d", len(data), size)
	}
	return data
}

func assertNotCached(t *testing.T, dir, digest string) {
	t.Helper()
	if _, err := os.Stat(cachedPath(dir, digest)); !os.IsNotExist(err) {
		t.Fatalf("blob %s was published: %v", digest, err)
	}
}

func TestPackagesPublishesVerifiedArchives(t *testing.T) {
	store, dir := newCache(t)
	amd := []byte("amd64 archive")
	arm := []byte("arm64 archive")
	urls := make(map[string]bool)
	fetcher := fetchFunc(func(_ context.Context, url string) (io.ReadCloser, error) {
		urls[url] = true
		switch url {
		case "https://example.com/amd.deb":
			return nopCloser(bytes.NewReader(amd)), nil
		case "https://example.com/arm.deb":
			return nopCloser(bytes.NewReader(arm)), nil
		default:
			return nil, errors.New("unexpected URL")
		}
	})
	records, err := acquire.Packages(t.Context(), fetcher, store, []acquire.Package{
		{Platform: "linux/arm64", Name: "zzz", Version: "2.0", Architecture: "arm64",
			URL: "https://example.com/arm.deb", SHA256: digestOf(arm), Size: int64(len(arm))},
		{Platform: "linux/amd64", Name: "aaa", Version: "1.0", Architecture: "amd64",
			URL: "https://example.com/amd.deb", SHA256: digestOf(amd), Size: int64(len(amd))},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Name != "aaa" || records[1].Name != "zzz" {
		t.Fatalf("records = %+v", records)
	}
	if got := cachedBytes(t, dir, digestOf(amd), int64(len(amd))); !bytes.Equal(got, amd) {
		t.Fatalf("amd bytes = %q", got)
	}
	if got := cachedBytes(t, dir, digestOf(arm), int64(len(arm))); !bytes.Equal(got, arm) {
		t.Fatalf("arm bytes = %q", got)
	}
	if !urls["https://example.com/amd.deb"] || !urls["https://example.com/arm.deb"] {
		t.Fatalf("fetched URLs = %+v", urls)
	}
}

func TestPackagesRejectsUnverifiedPayloads(t *testing.T) {
	data := []byte("archive")
	for _, test := range []struct {
		name    string
		pkg     acquire.Package
		wantErr string
	}{
		{
			name: "wrong digest",
			pkg: acquire.Package{Platform: "linux/amd64", Name: "pkg", Version: "1.0",
				Architecture: "amd64", URL: "https://example.com/pkg.deb",
				SHA256: digestOf([]byte("other")), Size: int64(len(data))},
			wantErr: "digest",
		},
		{
			name: "wrong size",
			pkg: acquire.Package{Platform: "linux/amd64", Name: "pkg", Version: "1.0",
				Architecture: "amd64", URL: "https://example.com/pkg.deb",
				SHA256: digestOf(data), Size: int64(len(data)) - 1},
			wantErr: "size",
		},
		{
			name: "oversized declared payload",
			pkg: acquire.Package{Platform: "linux/amd64", Name: "pkg", Version: "1.0",
				Architecture: "amd64", URL: "https://example.com/pkg.deb",
				SHA256: digestOf(data), Size: acquire.MaxPackageSize + 1},
			wantErr: "invalid size",
		},
		{
			name: "incomplete resolution",
			pkg: acquire.Package{Platform: "linux/amd64", Name: "pkg",
				Architecture: "amd64", URL: "https://example.com/pkg.deb",
				SHA256: digestOf(data), Size: int64(len(data))},
			wantErr: "incomplete",
		},
		{
			name: "invalid URL",
			pkg: acquire.Package{Platform: "linux/amd64", Name: "pkg", Version: "1.0",
				Architecture: "amd64", URL: "file:///tmp/pkg.deb",
				SHA256: digestOf(data), Size: int64(len(data))},
			wantErr: "URL",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, dir := newCache(t)
			fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
				return nopCloser(bytes.NewReader(data)), nil
			})
			if _, err := acquire.Packages(t.Context(), fetcher, store, []acquire.Package{test.pkg}, nil); err == nil ||
				!strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
			assertNotCached(t, dir, digestOf(data))
		})
	}
}

func TestPackagesRejectsDuplicateResolution(t *testing.T) {
	store, _ := newCache(t)
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nopCloser(strings.NewReader("x")), nil
	})
	pkg := acquire.Package{Platform: "linux/amd64", Name: "pkg", Version: "1.0",
		Architecture: "amd64", URL: "https://example.com/pkg.deb",
		SHA256: digestOf([]byte("x")), Size: 1}
	if _, err := acquire.Packages(t.Context(), fetcher, store, []acquire.Package{pkg, pkg}, nil); err == nil ||
		!strings.Contains(err.Error(), "twice") {
		t.Fatalf("error = %v", err)
	}
}

func TestPackagesFetchFailureIsRedacted(t *testing.T) {
	store, _ := newCache(t)
	secret := errors.New("token=secret")
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nil, secret
	})
	_, err := acquire.Packages(t.Context(), fetcher, store, []acquire.Package{{
		Platform: "linux/amd64", Name: "pkg", Version: "1.0", Architecture: "amd64",
		URL: "https://example.com/pkg.deb", SHA256: digestOf([]byte("x")), Size: 1,
	}}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, secret) {
		t.Fatalf("cause is not preserved: %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaked cause: %v", err)
	}
	if !strings.Contains(err.Error(), "details redacted") {
		t.Fatalf("error is not safe: %v", err)
	}
}

func TestPackagesHonoursCancellation(t *testing.T) {
	store, _ := newCache(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		called = true
		return nopCloser(strings.NewReader("x")), nil
	})
	_, err := acquire.Packages(ctx, fetcher, store, []acquire.Package{{
		Platform: "linux/amd64", Name: "pkg", Version: "1.0", Architecture: "amd64",
		URL: "https://example.com/pkg.deb", SHA256: digestOf([]byte("x")), Size: 1,
	}}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("fetcher called after cancellation")
	}
}

func TestArtifactsPublishesIntendedPlatforms(t *testing.T) {
	store, dir := newCache(t)
	amd := []byte("amd64 artifact")
	arm := []byte("arm64 artifact")
	fetcher := fetchFunc(func(_ context.Context, url string) (io.ReadCloser, error) {
		switch url {
		case "https://example.com/amd":
			return nopCloser(bytes.NewReader(amd)), nil
		case "https://example.com/arm":
			return nopCloser(bytes.NewReader(arm)), nil
		default:
			return nil, errors.New("unexpected URL")
		}
	})
	records, err := acquire.Artifacts(t.Context(), fetcher, nil, store, []contents.Artifact{{
		Name: "tool", Unpack: new(contents.ArtifactUnpackStandalone), Dest: "/usr/bin/tool", Mode: new("0755"),
		SBOM: contents.ArtifactIdentity{Name: "tool", Version: "1.0"},
		Sources: []contents.ArtifactSource{
			{Platforms: []string{"linux/arm64"}, URL: "https://example.com/arm", SHA256: digestOf(arm)},
			{Platforms: []string{"linux/amd64"}, URL: "https://example.com/amd", SHA256: digestOf(amd)},
		},
	}}, []string{"linux/amd64", "linux/arm64"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Platform != "linux/amd64" || records[1].Platform != "linux/arm64" {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Size != int64(len(amd)) || records[1].Size != int64(len(arm)) {
		t.Fatalf("record sizes = %+v", records)
	}
	if got := cachedBytes(t, dir, digestOf(amd), int64(len(amd))); !bytes.Equal(got, amd) {
		t.Fatalf("amd bytes = %q", got)
	}
	if got := cachedBytes(t, dir, digestOf(arm), int64(len(arm))); !bytes.Equal(got, arm) {
		t.Fatalf("arm bytes = %q", got)
	}
}

func TestArtifactsAcceptsPlatformOnlyScope(t *testing.T) {
	store, dir := newCache(t)
	data := []byte("amd64 only")
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nopCloser(bytes.NewReader(data)), nil
	})
	records, err := acquire.Artifacts(t.Context(), fetcher, nil, store, []contents.Artifact{{
		Name: "tool", Platforms: []string{"linux/amd64"}, Unpack: new(contents.ArtifactUnpackArchive),
		Sources: []contents.ArtifactSource{{
			Platforms: []string{"linux/amd64"}, URL: "https://example.com/a", SHA256: digestOf(data),
		}},
	}}, []string{"linux/amd64", "linux/arm64"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Platform != "linux/amd64" {
		t.Fatalf("records = %+v", records)
	}
	cachedBytes(t, dir, digestOf(data), int64(len(data)))
}

func TestArtifactsRejectsIncompleteCoverage(t *testing.T) {
	store, _ := newCache(t)
	data := []byte("artifact")
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nopCloser(bytes.NewReader(data)), nil
	})
	for _, test := range []struct {
		name     string
		artifact contents.Artifact
		wantErr  string
	}{
		{
			name: "missing platform payload",
			artifact: contents.Artifact{Name: "tool", Unpack: new(contents.ArtifactUnpackStandalone), Sources: []contents.ArtifactSource{
				{Platforms: []string{"linux/amd64"}, URL: "https://example.com/a", SHA256: digestOf(data)},
			}},
			wantErr: "cover every intended platform",
		},
		{
			name: "overlapping sources",
			artifact: contents.Artifact{Name: "tool", Unpack: new(contents.ArtifactUnpackStandalone), Sources: []contents.ArtifactSource{
				{Platforms: []string{"linux/amd64", "linux/arm64"}, URL: "https://example.com/a", SHA256: digestOf(data)},
				{Platforms: []string{"linux/arm64"}, URL: "https://example.com/b", SHA256: digestOf(data)},
			}},
			wantErr: "must not overlap",
		},
		{
			name: "source outside intended scope",
			artifact: contents.Artifact{Name: "tool", Platforms: []string{"linux/amd64"},
				Unpack: new(contents.ArtifactUnpackStandalone), Sources: []contents.ArtifactSource{
					{Platforms: []string{"linux/arm64"}, URL: "https://example.com/a", SHA256: digestOf(data)},
				}},
			wantErr: "subset",
		},
		{
			name: "unpack must be resolved",
			artifact: contents.Artifact{Name: "tool", Sources: []contents.ArtifactSource{
				{Platforms: []string{"linux/amd64", "linux/arm64"}, URL: "https://example.com/a", SHA256: digestOf(data)},
			}},
			wantErr: "unpack",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := acquire.Artifacts(t.Context(), fetcher, nil, store, []contents.Artifact{test.artifact},
				[]string{"linux/amd64", "linux/arm64"}, nil); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestArtifactsRejectsDuplicateNames(t *testing.T) {
	store, _ := newCache(t)
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nil, errors.New("must not fetch")
	})
	data := []byte("x")
	artifact := contents.Artifact{Name: "tool", Platforms: []string{"linux/amd64"}, Unpack: new(contents.ArtifactUnpackArchive),
		Sources: []contents.ArtifactSource{{
			Platforms: []string{"linux/amd64"}, URL: "https://example.com/a", SHA256: digestOf(data),
		}}}
	if _, err := acquire.Artifacts(t.Context(), fetcher, nil, store, []contents.Artifact{artifact, artifact},
		[]string{"linux/amd64"}, nil); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("error = %v", err)
	}
}

func TestArtifactsRejectsWrongDigest(t *testing.T) {
	store, dir := newCache(t)
	data := []byte("artifact")
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nopCloser(bytes.NewReader(data)), nil
	})
	_, err := acquire.Artifacts(t.Context(), fetcher, nil, store, []contents.Artifact{{
		Name: "tool", Platforms: []string{"linux/amd64"}, Unpack: new(contents.ArtifactUnpackArchive),
		Sources: []contents.ArtifactSource{{
			Platforms: []string{"linux/amd64"}, URL: "https://example.com/a", SHA256: digestOf([]byte("other")),
		}},
	}}, []string{"linux/amd64"}, nil)
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("error = %v", err)
	}
	assertNotCached(t, dir, digestOf(data))
}

func TestArtifactsHonoursCancellation(t *testing.T) {
	store, _ := newCache(t)
	ctx, cancel := context.WithCancel(t.Context())
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(readFunc(func([]byte) (int, error) {
			cancel()
			return 0, context.Canceled
		})), nil
	})
	_, err := acquire.Artifacts(ctx, fetcher, nil, store, []contents.Artifact{{
		Name: "tool", Platforms: []string{"linux/amd64"}, Unpack: new(contents.ArtifactUnpackArchive),
		Sources: []contents.ArtifactSource{{
			Platforms: []string{"linux/amd64"}, URL: "https://example.com/a", SHA256: digestOf([]byte("x")),
		}},
	}}, []string{"linux/amd64"}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

//go:fix inline

func TestArtifactsReadsALocalSourceWithoutFetching(t *testing.T) {
	store, dir := newCache(t)
	data := []byte("local payload")
	fetcher := fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nil, errors.New("must not fetch")
	})
	local := localFile{open: func(path string) (io.ReadCloser, error) {
		if path != "files/tool" {
			return nil, errors.New("unexpected path")
		}
		return nopCloser(bytes.NewReader(data)), nil
	}}
	records, err := acquire.Artifacts(t.Context(), fetcher, local, store, []contents.Artifact{{
		Name: "tool", Platforms: []string{"linux/amd64"}, Unpack: new(contents.ArtifactUnpackArchive),
		Sources: []contents.ArtifactSource{{
			Platforms: []string{"linux/amd64"}, Path: "files/tool", SHA256: digestOf(data),
		}},
	}}, []string{"linux/amd64"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Path != "files/tool" || records[0].URL != "" {
		t.Fatalf("records = %+v", records)
	}
	cachedBytes(t, dir, digestOf(data), int64(len(data)))
}

func TestArtifactsRefusesALocalSourceWithoutAReader(t *testing.T) {
	store, _ := newCache(t)
	data := []byte("local payload")
	_, err := acquire.Artifacts(t.Context(), fetchFunc(func(context.Context, string) (io.ReadCloser, error) {
		return nil, errors.New("must not fetch")
	}), nil, store, []contents.Artifact{{
		Name: "tool", Platforms: []string{"linux/amd64"}, Unpack: new(contents.ArtifactUnpackArchive),
		Sources: []contents.ArtifactSource{{
			Platforms: []string{"linux/amd64"}, Path: "files/tool", SHA256: digestOf(data),
		}},
	}}, []string{"linux/amd64"}, nil)
	if err == nil || !strings.Contains(err.Error(), "specification directory") {
		t.Fatalf("error = %v", err)
	}
}

type localFile struct {
	open func(string) (io.ReadCloser, error)
}

func (l localFile) Open(path string) (io.ReadCloser, error) { return l.open(path) }
