package artifact_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"

	"github.com/matt-mai/vapor/internal/artifact"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	uid, gid int
	content  string
	link     string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Typeflag: entry.typeflag, Mode: entry.mode,
			Uid: entry.uid, Gid: entry.gid, Linkname: entry.link, Format: tar.FormatPAX,
		}
		if entry.typeflag == tar.TypeReg {
			header.Size = int64(len(entry.content))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if entry.typeflag == tar.TypeReg {
			if _, err := writer.Write([]byte(entry.content)); err != nil {
				t.Fatalf("write content: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buffer.Bytes()
}

func standaloneRecord() *lock.Artifact {
	unpack := contents.ArtifactUnpackStandalone
	return &lock.Artifact{
		Name: "server", Platform: "linux/amd64", URL: "https://example.com/server",
		SHA256: strings.Repeat("a", 64), Size: 7, Dest: "/usr/bin/server",
		Unpack: &unpack, Mode: new("0755"), UID: 3, GID: 4,
	}
}

func unpackedRecord(dest string) *lock.Artifact {
	unpack := contents.ArtifactUnpackArchive
	return &lock.Artifact{
		Name: "bundle", Platform: "linux/amd64", URL: "https://example.com/bundle.tar",
		SHA256: strings.Repeat("b", 64), Dest: dest, Unpack: &unpack, UID: 7, GID: 8,
	}
}

func TestPlace_StandaloneFile(t *testing.T) {
	tree, err := artifact.Place(standaloneRecord(), []byte("payload"))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	entry, ok := tree.Lookup("/usr/bin/server")
	if !ok {
		t.Fatal("destination is missing")
	}
	if entry.Kind != vfs.File || entry.Mode != 0o755 || entry.UID != 3 || entry.GID != 4 || entry.Size != 7 {
		t.Fatalf("entry = %+v", entry)
	}
	if len(entry.Origins) != 1 || entry.Origins[0].Package != "server" {
		t.Fatalf("origins = %+v", entry.Origins)
	}
	content, err := tree.Read("/usr/bin/server")
	if err != nil || string(content) != "payload" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
}

func TestPlace_StandaloneSpecialBits(t *testing.T) {
	record := standaloneRecord()
	record.Mode = new("04755")
	tree, err := artifact.Place(record, []byte("payload"))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	entry, _ := tree.Lookup("/usr/bin/server")
	if entry.Mode != fs.ModeSetuid|0o755 {
		t.Fatalf("mode = %v", entry.Mode)
	}
}

func TestPlace_RejectsInvalidStandalone(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lock.Artifact)
		data   []byte
		want   string
	}{
		{name: "root destination", mutate: func(a *lock.Artifact) { a.Dest = "/" }, want: "cannot be placed at the root"},
		{name: "missing mode", mutate: func(a *lock.Artifact) { a.Mode = nil }, want: "requires a mode"},
		{name: "bad octal", mutate: func(a *lock.Artifact) { a.Mode = new("0999") }, want: "is not an octal mode"},
		{name: "size mismatch", data: []byte("too long"), want: "want 7"},
		{name: "unclean destination", mutate: func(a *lock.Artifact) { a.Dest = "/usr/../bin/server" }, want: "not a clean absolute path"},
		{name: "negative ownership", mutate: func(a *lock.Artifact) { a.UID = -1 }, want: "outside the 32-bit range"},
		{name: "unresolved unpack", mutate: func(a *lock.Artifact) { a.Unpack = nil }, want: "resolved unpack setting"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := standaloneRecord()
			if test.mutate != nil {
				test.mutate(record)
			}
			data := test.data
			if data == nil {
				data = []byte("payload")
			}
			if _, err := artifact.Place(record, data); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPlace_RejectsMissingRecord(t *testing.T) {
	if _, err := artifact.Place(nil, nil); err == nil || !strings.Contains(err.Error(), "requires a record") {
		t.Fatalf("error = %v", err)
	}
}

func bundlePayload(t *testing.T) []byte {
	t.Helper()
	return buildTar(t, []tarEntry{
		{name: "./", typeflag: tar.TypeDir, mode: 0o750, uid: 1, gid: 2},
		{name: "./bin/", typeflag: tar.TypeDir, mode: 0o750, uid: 1, gid: 2},
		{name: "./bin/tool", typeflag: tar.TypeReg, mode: 0o755, uid: 1, gid: 2, content: "tool"},
		{name: "./bin/alias", typeflag: tar.TypeLink, link: "./bin/tool"},
		{name: "./etc/", typeflag: tar.TypeDir, mode: 0o755, uid: 1, gid: 2},
		{name: "./etc/config", typeflag: tar.TypeReg, mode: 0o640, uid: 1, gid: 2, content: "config"},
		{name: "./etc/current", typeflag: tar.TypeSymlink, link: "config"},
	})
}

func TestPlace_UnpackedArtifact(t *testing.T) {
	tree, err := artifact.Place(unpackedRecord("/opt/app"), bundlePayload(t))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	dest, ok := tree.Lookup("/opt/app")
	if !ok || dest.Kind != vfs.Dir || dest.Mode != artifact.DefaultDirMode || dest.UID != 7 || dest.GID != 8 {
		t.Fatalf("destination = %+v, ok = %v", dest, ok)
	}
	tool, ok := tree.Lookup("/opt/app/bin/tool")
	if !ok || tool.Mode != 0o755 || tool.UID != 7 || tool.GID != 8 {
		t.Fatalf("tool = %+v, ok = %v", tool, ok)
	}
	config, _ := tree.Lookup("/opt/app/etc/config")
	if config.Mode != 0o640 {
		t.Fatalf("archive mode was not preserved: %v", config.Mode)
	}
	link, _ := tree.Lookup("/opt/app/etc/current")
	if link.Kind != vfs.Symlink || link.Target != "config" {
		t.Fatalf("symlink = %+v", link)
	}
	content, err := tree.Read("/opt/app/bin/tool")
	if err != nil || string(content) != "tool" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
}

// A directory the archive only implies inside its own payload must carry the
// artifact's ownership. Root-owned internal parents would leave a non-root
// application unable to write inside the tree it owns.
func TestPlace_UnpackedOwnsInternalParents(t *testing.T) {
	payload := buildTar(t, []tarEntry{
		{name: "nested/file", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
	})
	tree, err := artifact.Place(unpackedRecord("/opt/app"), payload)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	for _, p := range []string{"/opt/app", "/opt/app/nested", "/opt/app/nested/file"} {
		entry, ok := tree.Lookup(p)
		if !ok {
			t.Fatalf("%s is missing", p)
		}
		if entry.UID != 7 || entry.GID != 8 {
			t.Fatalf("%s is %d:%d, want 7:8", p, entry.UID, entry.GID)
		}
	}
	// A parent above the destination belongs to the image, not the artifact.
	if parent, ok := tree.Lookup("/opt"); !ok || parent.UID != 0 || parent.GID != 0 {
		t.Fatalf("/opt = %+v, ok = %v", parent, ok)
	}
}

func TestPlace_UnpackedPreservesHardLinks(t *testing.T) {
	tree, err := artifact.Place(unpackedRecord("/opt/app"), bundlePayload(t))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	inodes := tree.Inodes()
	if inodes["/opt/app/bin/tool"] != inodes["/opt/app/bin/alias"] {
		t.Fatalf("hard link was not preserved: %v", inodes)
	}
}

func TestPlace_UnpackedCompressedPayloads(t *testing.T) {
	raw := bundlePayload(t)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	tree, err := artifact.Place(unpackedRecord("/opt/app"), compressed.Bytes())
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	content, err := tree.Read("/opt/app/bin/tool")
	if err != nil || string(content) != "tool" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
}

func TestPlace_UnpackedAtRoot(t *testing.T) {
	tree, err := artifact.Place(unpackedRecord("/"), bundlePayload(t))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if _, ok := tree.Lookup("/bin/tool"); !ok {
		t.Fatal("payload was not placed at the root")
	}
	if _, ok := tree.Lookup("/opt/app"); ok {
		t.Fatal("root destination created a directory")
	}
}

func TestPlace_RejectsUnpackedModeOverride(t *testing.T) {
	record := unpackedRecord("/opt/app")
	record.Mode = new("0755")
	_, err := artifact.Place(record, bundlePayload(t))
	if err == nil || !strings.Contains(err.Error(), "preserve archive modes") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlace_RejectsUnsafePayloads(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{
			name:    "absolute member",
			entries: []tarEntry{{name: "/etc/passwd", typeflag: tar.TypeReg, mode: 0o644, content: "x"}},
			want:    "not a clean relative path",
		},
		{
			name:    "parent traversal",
			entries: []tarEntry{{name: "../escape", typeflag: tar.TypeReg, mode: 0o644, content: "x"}},
			want:    "not a clean relative path",
		},
		{
			name: "escaping symlink",
			entries: []tarEntry{
				{name: "./link", typeflag: tar.TypeSymlink, link: "../../etc/shadow"},
			},
			want: "escapes the image root",
		},
		{
			name: "special file",
			entries: []tarEntry{
				{name: "./dev", typeflag: tar.TypeDir, mode: 0o755},
				{name: "./dev/null", typeflag: tar.TypeChar, mode: 0o666},
			},
			want: "unsupported type",
		},
		{
			name: "link outside destination",
			entries: []tarEntry{
				{name: "./payload", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
				{name: "./link", typeflag: tar.TypeSymlink, link: "/payload"},
			},
			want: "outside",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := artifact.Place(unpackedRecord("/opt/app"), buildTar(t, test.entries))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPlace_AbsoluteLinkInsideRootDestination(t *testing.T) {
	// A root destination has no boundary to escape, so an absolute link that
	// resolves inside the payload is accepted.
	payload := buildTar(t, []tarEntry{
		{name: "./payload", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
		{name: "./link", typeflag: tar.TypeSymlink, link: "/payload"},
	})
	if _, err := artifact.Place(unpackedRecord("/"), payload); err != nil {
		t.Fatalf("place: %v", err)
	}
}

func TestPlace_MergesIntoImage(t *testing.T) {
	image := vfs.New()
	if err := image.Dir("/usr", vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("dir: %v", err)
	}
	tree, err := artifact.Place(standaloneRecord(), []byte("payload"))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if err := image.Merge(tree); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if _, ok := image.Lookup("/usr/bin/server"); !ok {
		t.Fatal("artifact was not merged")
	}
}

func TestPlace_MergeConflictIsReported(t *testing.T) {
	image := vfs.New()
	if err := image.File("/usr/bin/server", []byte("other"), vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("file: %v", err)
	}
	tree, err := artifact.Place(standaloneRecord(), []byte("payload"))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if err := image.Merge(tree); err == nil || !strings.Contains(err.Error(), "conflicts with existing") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlace_IsDeterministic(t *testing.T) {
	first, err := artifact.Place(unpackedRecord("/opt/app"), bundlePayload(t))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	second, err := artifact.Place(unpackedRecord("/opt/app"), bundlePayload(t))
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	left, right := first.Entries(), second.Entries()
	if len(left) != len(right) {
		t.Fatalf("entry counts differ: %d and %d", len(left), len(right))
	}
	for i := range left {
		if left[i].Path != right[i].Path || left[i].Mode != right[i].Mode ||
			left[i].Kind != right[i].Kind || left[i].Target != right[i].Target {
			t.Fatalf("entry %d differs: %+v and %+v", i, left[i], right[i])
		}
	}
}

// Placement is only half the flow: the caller merges the tree into the image, and
// merge skips implicit entries. An internal parent that stayed implicit would be
// recreated root-owned there, so the artifact's ownership must survive the merge.
func TestPlace_InternalParentOwnershipSurvivesMerge(t *testing.T) {
	payload := buildTar(t, []tarEntry{
		{name: "nested/file", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
	})
	tree, err := artifact.Place(unpackedRecord("/opt/app"), payload)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	image := vfs.New()
	if err := image.Merge(tree); err != nil {
		t.Fatalf("merge: %v", err)
	}
	for _, p := range []string{"/opt/app", "/opt/app/nested"} {
		entry, ok := image.Lookup(p)
		if !ok || entry.UID != 7 || entry.GID != 8 {
			t.Fatalf("%s = %+v, ok = %v", p, entry, ok)
		}
	}
	if parent, ok := image.Lookup("/opt"); !ok || parent.UID != 0 || !parent.Implicit {
		t.Fatalf("/opt = %+v, ok = %v", parent, ok)
	}
}

// A root destination has no destination directory of its own, so every directory
// the payload implies belongs to the artifact.
func TestPlace_RootDestinationOwnsInternalParents(t *testing.T) {
	payload := buildTar(t, []tarEntry{
		{name: "nested/file", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
	})
	tree, err := artifact.Place(unpackedRecord("/"), payload)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	image := vfs.New()
	if err := image.Merge(tree); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if entry, ok := image.Lookup("/nested"); !ok || entry.UID != 7 || entry.GID != 8 {
		t.Fatalf("/nested = %+v, ok = %v", entry, ok)
	}
}
