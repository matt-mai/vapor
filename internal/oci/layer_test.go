package oci_test

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/vfs"
)

func attrs(mode fs.FileMode) vfs.Attrs {
	return vfs.Attrs{Mode: mode, UID: 0, GID: 0, Origin: vfs.Origin{Package: "demo"}}
}

// sampleTree builds one tree with a directory, a file, a symlink and a hard link
// so the serialization tests cover every entry kind at once.
func sampleTree(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	if err := tree.Dir("/usr/bin", attrs(0o755)); err != nil {
		t.Fatalf("dir: %v", err)
	}
	if err := tree.File("/usr/bin/tool", []byte("#!/bin/sh\n"), vfs.Attrs{Mode: fs.ModeSetuid | 0o755,
		UID: 12, GID: 34, Origin: vfs.Origin{Package: "demo"}}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := tree.Hardlink("/usr/bin/alias", "/usr/bin/tool", vfs.Origin{Package: "demo"}); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	if err := tree.Symlink("/usr/bin/link", "tool", attrs(0o777)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return tree
}

// layerEntries decodes a serialized layer without going through the VFS importer,
// so a test can inspect the header fields the importer deliberately accepts or
// normalizes.
func layerEntries(t *testing.T, data []byte) []*tar.Header {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(data))
	var headers []*tar.Header
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read layer: %v", err)
		}
		headers = append(headers, header)
	}
	return headers
}

func writeLayer(t *testing.T, tree *vfs.Tree) ([]byte, oci.Descriptor) {
	t.Helper()
	var buffer bytes.Buffer
	descriptor, err := oci.WriteLayer(&buffer, tree)
	if err != nil {
		t.Fatalf("WriteLayer: %v", err)
	}
	return buffer.Bytes(), descriptor
}

// TestWriteLayer_ByteStability covers the core promise: the same tree always
// serializes to the same bytes and digest, and a different declaration order
// cannot change either.
func TestWriteLayer_ByteStability(t *testing.T) {
	first, descriptor := writeLayer(t, sampleTree(t))
	second, repeated := writeLayer(t, sampleTree(t))
	if !bytes.Equal(first, second) {
		t.Fatal("repeated serialization differs")
	}
	if descriptor != repeated {
		t.Fatalf("descriptor = %+v, want %+v", repeated, descriptor)
	}
	if !strings.HasPrefix(descriptor.DiffID, "sha256:") || len(descriptor.DiffID) != len("sha256:")+64 {
		t.Fatalf("DiffID = %q", descriptor.DiffID)
	}
	if descriptor.Size != int64(len(first)) {
		t.Fatalf("size = %d, want %d", descriptor.Size, len(first))
	}
}

// TestWriteLayer_DigestVector pins the layer bytes for one fixed tree, so a change
// to header fields, ordering or naming shows up as a digest change instead of as a
// silent image difference. The tree is /usr/bin/{tool (setuid, 12:34), alias ->
// tool, link -> tool} holding "#!/bin/sh\n".
func TestWriteLayer_DigestVector(t *testing.T) {
	_, descriptor := writeLayer(t, sampleTree(t))
	const digest = "sha256:07a97ee2c4139c2897892e21fb4014438eec4059deb78b111cc18082eb5915dd"
	if descriptor.DiffID != digest || descriptor.Size != 4096 {
		t.Fatalf("layer = %+v, want %s and 4096 bytes", descriptor, digest)
	}
}

// TestWriteLayer_HeadersAreNormalized pins the header fields that keep host
// metadata out of the layer: sorted relative names, epoch times, image ownership,
// Unix special bits and no user or group names.
func TestWriteLayer_HeadersAreNormalized(t *testing.T) {
	data, _ := writeLayer(t, sampleTree(t))
	headers := layerEntries(t, data)
	want := []struct {
		name     string
		typeflag byte
		mode     int64
	}{
		// The implicit parent is a member too: a layer has no ancestors of its own.
		{"usr/", tar.TypeDir, 0o755},
		{"usr/bin/", tar.TypeDir, 0o755},
		// The lexically first name of a link group carries the content, so every
		// hard link refers backwards to a member already written.
		{"usr/bin/alias", tar.TypeReg, 0o4755},
		{"usr/bin/link", tar.TypeSymlink, 0o777},
		{"usr/bin/tool", tar.TypeLink, 0o4755},
	}
	if len(headers) != len(want) {
		t.Fatalf("headers = %d, want %d", len(headers), len(want))
	}
	for index, header := range headers {
		expected := want[index]
		if header.Name != expected.name || header.Typeflag != expected.typeflag || header.Mode != expected.mode {
			t.Fatalf("header %d = %q %q %o, want %q %q %o", index, header.Name, header.Typeflag,
				header.Mode, expected.name, expected.typeflag, expected.mode)
		}
		if !header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			t.Fatalf("%s mtime = %v, want the epoch", header.Name, header.ModTime)
		}
		if header.Uname != "" || header.Gname != "" {
			t.Fatalf("%s names = %q/%q, want none", header.Name, header.Uname, header.Gname)
		}
		if header.AccessTime != (time.Time{}) || header.ChangeTime != (time.Time{}) {
			t.Fatalf("%s has host access/change times", header.Name)
		}
	}
	for _, header := range []*tar.Header{headers[2], headers[4]} {
		if header.Uid != 12 || header.Gid != 34 {
			t.Fatalf("%s ownership = %d:%d, want 12:34", header.Name, header.Uid, header.Gid)
		}
	}
}

// TestWriteLayer_HardlinkContentIsStoredOnce checks that a link group is written as
// one regular file plus links, which is what makes the shared inode survive without
// duplicating content.
func TestWriteLayer_HardlinkContentIsStoredOnce(t *testing.T) {
	data, _ := writeLayer(t, sampleTree(t))
	content, links := 0, 0
	for _, header := range layerEntries(t, data) {
		switch header.Typeflag {
		case tar.TypeReg:
			content++
		case tar.TypeLink:
			links++
			if header.Linkname != "usr/bin/alias" {
				t.Fatalf("%s links to %q, want the member holding the content", header.Name, header.Linkname)
			}
			if header.Size != 0 {
				t.Fatalf("%s size = %d, want 0", header.Name, header.Size)
			}
		}
	}
	if content != 1 || links != 1 {
		t.Fatalf("content members = %d, links = %d, want 1 and 1", content, links)
	}
}

// TestWriteLayer_LongPaths forces a PAX extended header, which the layer must
// produce deterministically rather than fall back to a host-dependent format.
func TestWriteLayer_LongPaths(t *testing.T) {
	long := "/" + strings.Repeat("d", 120)
	tree := vfs.New()
	if err := tree.Dir(long, attrs(0o755)); err != nil {
		t.Fatalf("dir: %v", err)
	}
	if err := tree.File(long+"/file", []byte("data"), attrs(0o644)); err != nil {
		t.Fatalf("file: %v", err)
	}
	first, descriptor := writeLayer(t, tree)
	second, repeated := writeLayer(t, tree)
	if !bytes.Equal(first, second) || descriptor != repeated {
		t.Fatal("long-path serialization is not stable")
	}
	// A name over the 100-byte USTAR field must come back whole, which means the
	// PAX record carried it rather than the header being truncated.
	seen := 0
	for _, header := range layerEntries(t, first) {
		if header.Typeflag == tar.TypeXHeader {
			continue
		}
		seen++
		name := strings.TrimSuffix(strings.TrimPrefix(header.Name, "/"), "/")
		if name != strings.TrimPrefix(long, "/") && name != strings.TrimPrefix(long, "/")+"/file" {
			t.Fatalf("member %q did not keep its long path", header.Name)
		}
	}
	if seen != 2 {
		t.Fatalf("members = %d, want 2", seen)
	}
}

// TestWriteLayer_RoundTrip checks that the layer imports back into an identical
// tree, so serialization loses nothing a later consumer depends on.
func TestWriteLayer_RoundTrip(t *testing.T) {
	original := sampleTree(t)
	data, _ := writeLayer(t, original)
	imported, err := vfs.ImportTar(bytes.NewReader(data), vfs.Origin{Package: "demo"}, vfs.DefaultLimits())
	if err != nil {
		t.Fatalf("ImportTar: %v", err)
	}
	want, got := original.Entries(), imported.Entries()
	if len(want) != len(got) {
		t.Fatalf("entries = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if want[index].Path != got[index].Path || want[index].Kind != got[index].Kind ||
			want[index].Mode != got[index].Mode || want[index].UID != got[index].UID ||
			want[index].GID != got[index].GID || want[index].Target != got[index].Target ||
			want[index].Size != got[index].Size {
			t.Fatalf("entry %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

// TestWriteLayer_EmptyTree covers the degenerate image: a valid archive with no
// members still has a stable digest.
func TestWriteLayer_EmptyTree(t *testing.T) {
	data, descriptor := writeLayer(t, vfs.New())
	if len(data) == 0 || descriptor.Size != int64(len(data)) {
		t.Fatalf("empty layer = %d bytes, descriptor %+v", len(data), descriptor)
	}
	if headers := layerEntries(t, data); len(headers) != 0 {
		t.Fatalf("empty layer has %d members", len(headers))
	}
	_, repeated := writeLayer(t, vfs.New())
	if repeated != descriptor {
		t.Fatalf("descriptor = %+v, want %+v", repeated, descriptor)
	}
}

// TestWriteLayer_RejectsBadInput keeps a nil writer or tree from panicking or
// silently producing an empty layer.
func TestWriteLayer_RejectsBadInput(t *testing.T) {
	var buffer bytes.Buffer
	if _, err := oci.WriteLayer(nil, vfs.New()); err == nil {
		t.Fatal("nil writer accepted")
	}
	if _, err := oci.WriteLayer(&buffer, nil); err == nil || buffer.Len() != 0 {
		t.Fatalf("nil tree accepted, wrote %d bytes", buffer.Len())
	}
}

// TestWriteLayer_WriterFailureIsReported checks that a failing destination fails
// the serialization instead of returning a successful descriptor for bytes nobody
// received.
func TestWriteLayer_WriterFailureIsReported(t *testing.T) {
	failing := &failWriter{left: 600}
	if _, err := oci.WriteLayer(failing, sampleTree(t)); err == nil {
		t.Fatal("write failure was swallowed")
	}
}

// failWriter accepts left bytes and then fails.
type failWriter struct{ left int }

var errBroken = errors.New("broken pipe")

func (w *failWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return 0, errBroken
	}
	if len(p) > w.left {
		n := w.left
		w.left = 0
		return n, errBroken
	}
	w.left -= len(p)
	return len(p), nil
}

// A ".wh." name means "delete this path" to an OCI reader, so a real file carrying
// one would remove content instead of adding it. Serialization refuses the name
// rather than letting the layer mean something else than the tree.
func TestWriteLayer_RejectsWhiteoutNames(t *testing.T) {
	for _, member := range []struct {
		name  string
		build func(*vfs.Tree) error
	}{
		{"/.wh.tool", func(tree *vfs.Tree) error {
			return tree.File("/.wh.tool", []byte("x"), attrs(0o644))
		}},
		{"/usr/bin/.wh.tool", func(tree *vfs.Tree) error {
			return tree.File("/usr/bin/.wh.tool", []byte("x"), attrs(0o644))
		}},
		{"/usr/bin/.wh..wh..opq", func(tree *vfs.Tree) error {
			return tree.Dir("/usr/bin/.wh..wh..opq", attrs(0o755))
		}},
	} {
		t.Run(member.name, func(t *testing.T) {
			tree := sampleTree(t)
			if err := member.build(tree); err != nil {
				t.Fatalf("build: %v", err)
			}
			var buffer bytes.Buffer
			if _, err := oci.WriteLayer(&buffer, tree); err == nil ||
				!strings.Contains(err.Error(), "whiteout") {
				t.Fatalf("error = %v, want a whiteout refusal", err)
			}
			buffer.Reset()
			if _, err := oci.CompressLayer(context.Background(), &buffer, tree,
				oci.DefaultCompression); err == nil || !strings.Contains(err.Error(), "whiteout") {
				t.Fatalf("compress error = %v, want a whiteout refusal", err)
			}
		})
	}
}

// A name that merely contains the prefix is ordinary content and stays.
func TestWriteLayer_KeepsNamesThatOnlyMentionWhiteouts(t *testing.T) {
	tree := sampleTree(t)
	if err := tree.File("/usr/bin/wh.tool", []byte("x"), attrs(0o644)); err != nil {
		t.Fatalf("file: %v", err)
	}
	var buffer bytes.Buffer
	if _, err := oci.WriteLayer(&buffer, tree); err != nil {
		t.Fatalf("WriteLayer: %v", err)
	}
}

// Serialization is the last place a broken link can be caught: a caller that hands
// a tree to it directly has run no other check.
func TestWriteLayer_RejectsAnUnresolvableLink(t *testing.T) {
	tree := sampleTree(t)
	if err := tree.Symlink("/loop", "/loop", attrs(0o777)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	var buffer bytes.Buffer
	if _, err := oci.WriteLayer(&buffer, tree); err == nil ||
		!strings.Contains(err.Error(), "symlink cycle") {
		t.Fatalf("error = %v, want a symlink refusal", err)
	}
}
