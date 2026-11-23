package deb_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func releaseFile(data []byte) deb.ReleaseFile {
	sum := sha256.Sum256(data)
	return deb.ReleaseFile{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func releaseWithFiles(files map[string]deb.ReleaseFile, byHash bool) *deb.Release {
	return &deb.Release{Suite: "resolute", AcquireByHash: byHash, Files: files}
}

func TestSelectIndexFormatPreference(t *testing.T) {
	xzEntry := deb.ReleaseFile{SHA256: strings.Repeat("a", 64), Size: 1}
	gzEntry := deb.ReleaseFile{SHA256: strings.Repeat("b", 64), Size: 2}
	plainEntry := deb.ReleaseFile{SHA256: strings.Repeat("c", 64), Size: 3}
	base := map[string]deb.ReleaseFile{
		"main/binary-amd64/Packages.xz": xzEntry,
		"main/binary-amd64/Packages.gz": gzEntry,
		"main/binary-amd64/Packages":    plainEntry,
	}
	cases := []struct {
		name      string
		files     map[string]deb.ReleaseFile
		format    deb.IndexFormat
		path      string
		wantError string
	}{
		{name: "xz first", files: base, format: deb.IndexFormatXZ, path: "main/binary-amd64/Packages.xz"},
		{name: "gzip second", files: deleteFile(base, "main/binary-amd64/Packages.xz"), format: deb.IndexFormatGzip, path: "main/binary-amd64/Packages.gz"},
		{name: "plain last", files: deleteFile(deleteFile(base, "main/binary-amd64/Packages.xz"), "main/binary-amd64/Packages.gz"), format: deb.IndexFormatPlain, path: "main/binary-amd64/Packages"},
		{name: "none", files: map[string]deb.ReleaseFile{}, wantError: "has no Packages index"},
		{name: "other architecture", files: map[string]deb.ReleaseFile{"main/binary-arm64/Packages.xz": xzEntry}, wantError: "has no Packages index"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			index, err := deb.SelectIndex(releaseWithFiles(test.files, false), "main", "amd64", deb.ByHashPrefer)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if index.Format != test.format || index.Path != test.path {
				t.Fatalf("index = %+v", index)
			}
		})
	}
}

func TestSelectIndexByHash(t *testing.T) {
	hash := strings.Repeat("d", 64)
	files := map[string]deb.ReleaseFile{
		"main/binary-amd64/Packages.xz": {SHA256: hash, Size: 10},
	}
	canonical := "main/binary-amd64/Packages.xz"
	byHash := "main/binary-amd64/by-hash/SHA256/" + hash
	cases := []struct {
		name      string
		advertise bool
		policy    deb.ByHashPolicy
		want      []string
		wantError string
	}{
		{name: "prefer advertised", advertise: true, policy: deb.ByHashPrefer, want: []string{byHash, canonical}},
		{name: "prefer not advertised", policy: deb.ByHashPrefer, want: []string{canonical}},
		{name: "require advertised", advertise: true, policy: deb.ByHashRequire, want: []string{byHash}},
		{name: "require not advertised", policy: deb.ByHashRequire, wantError: "does not advertise"},
		{name: "disable advertised", advertise: true, policy: deb.ByHashDisable, want: []string{canonical}},
		{name: "unknown policy", policy: deb.ByHashPolicy("always"), wantError: "unsupported"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			index, err := deb.SelectIndex(releaseWithFiles(files, test.advertise), "main", "amd64", test.policy)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(index.AcquirePaths, ",") != strings.Join(test.want, ",") {
				t.Fatalf("acquire paths = %q, want %q", index.AcquirePaths, test.want)
			}
		})
	}
}

func TestSelectIndexRejectsUnsafePaths(t *testing.T) {
	files := map[string]deb.ReleaseFile{"main/binary-amd64/Packages.xz": {SHA256: strings.Repeat("a", 64), Size: 1}}
	for _, test := range []struct{ component, architecture string }{
		{component: "../main", architecture: "amd64"},
		{component: "main", architecture: "../amd64"},
		{component: "", architecture: "amd64"},
		{component: "main/updates", architecture: "amd64"},
	} {
		if _, err := deb.SelectIndex(releaseWithFiles(files, false), test.component, test.architecture, deb.ByHashDisable); err == nil {
			t.Fatalf("accepted unsafe component=%q architecture=%q", test.component, test.architecture)
		}
	}
}

func gzipData(t *testing.T, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func xzData(t *testing.T, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := xz.NewWriter(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestVerifyIndexFormats(t *testing.T) {
	content := []byte("Package: demo\nVersion: 1.0\n")
	cases := []struct {
		name   string
		format deb.IndexFormat
		data   []byte
	}{
		{name: "xz", format: deb.IndexFormatXZ, data: xzData(t, content)},
		{name: "gzip", format: deb.IndexFormatGzip, data: gzipData(t, content)},
		{name: "plain", format: deb.IndexFormatPlain, data: content},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			file := releaseFile(test.data)
			index := deb.Index{Format: test.format, SHA256: file.SHA256, Size: file.Size}
			got, err := deb.VerifyIndex(&index, test.data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("content = %q", got)
			}
		})
	}
}

func TestVerifyIndexRejectsCorruptData(t *testing.T) {
	content := []byte("Package: demo\nVersion: 1.0\n")
	compressed := gzipData(t, content)
	file := releaseFile(compressed)
	valid := deb.Index{Format: deb.IndexFormatGzip, SHA256: file.SHA256, Size: file.Size}

	t.Run("tampered byte", func(t *testing.T) {
		tampered := bytes.Clone(compressed)
		tampered[len(tampered)-1] ^= 0xff
		if _, err := deb.VerifyIndex(&valid, tampered); err == nil || !strings.Contains(err.Error(), "SHA256") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("extra byte", func(t *testing.T) {
		if _, err := deb.VerifyIndex(&valid, append(bytes.Clone(compressed), 0)); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("different cache entry", func(t *testing.T) {
		other := releaseFile(gzipData(t, []byte("Package: other\n")))
		index := deb.Index{Format: deb.IndexFormatGzip, SHA256: other.SHA256, Size: other.Size}
		if _, err := deb.VerifyIndex(&index, compressed); err == nil || !strings.Contains(err.Error(), "does not match authenticated metadata") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("truncated stream", func(t *testing.T) {
		truncated := compressed[:len(compressed)-4]
		file := releaseFile(truncated)
		index := deb.Index{Format: deb.IndexFormatGzip, SHA256: file.SHA256, Size: file.Size}
		if _, err := deb.VerifyIndex(&index, truncated); err == nil || !strings.Contains(err.Error(), "decompression failed") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported format", func(t *testing.T) {
		index := valid
		index.Format = deb.IndexFormat("zstd")
		if _, err := deb.VerifyIndex(&index, compressed); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("error = %v", err)
		}
	})
}

func deleteFile(files map[string]deb.ReleaseFile, name string) map[string]deb.ReleaseFile {
	deleted := make(map[string]deb.ReleaseFile, len(files))
	for file, entry := range files {
		if file != name {
			deleted[file] = entry
		}
	}
	return deleted
}
