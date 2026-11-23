package deb_test

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/vfs"
)

// tarMember describes one synthetic tar member for data or control archives.
type tarMember struct {
	name     string
	typeflag byte
	mode     int64
	uid, gid int
	content  string
	linkname string
}

func buildTar(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, member := range members {
		header := &tar.Header{
			Name:     member.name,
			Typeflag: member.typeflag,
			Mode:     member.mode,
			Uid:      member.uid,
			Gid:      member.gid,
			Linkname: member.linkname,
		}
		if header.Typeflag == tar.TypeReg {
			header.Size = int64(len(member.content))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header %q: %v", member.name, err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(member.content)); err != nil {
				t.Fatalf("write content %q: %v", member.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// syntheticPackage assembles a DEB whose data and control members are real
// tarballs, so extraction is exercised end to end.
func syntheticPackage(t *testing.T, data, control []tarMember) []byte {
	t.Helper()
	builder := &debBuilder{}
	builder.add("debian-binary", []byte("2.0\n"))
	builder.add("control.tar.gz", compressMember(t, deb.CompressionGzip, buildTar(t, control)))
	builder.add("data.tar.gz", compressMember(t, deb.CompressionGzip, buildTar(t, data)))
	return builder.bytes()
}

func standardControl() []tarMember {
	return []tarMember{
		{name: "./control", typeflag: tar.TypeReg, mode: 0o644, content: "Package: demo\nVersion: 1.0\n"},
		{name: "./md5sums", typeflag: tar.TypeReg, mode: 0o644, content: "d41d8cd98f00b204e9800998ecf8427e  usr/bin/tool\n"},
		{name: "./postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nexit 0\n"},
	}
}

func TestExtract_ImportsDataAndRetainsControl(t *testing.T) {
	data := []tarMember{
		{name: "./usr/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, uid: 1, gid: 2, content: "binary"},
		{name: "./usr/bin/alias", typeflag: tar.TypeLink, linkname: "./usr/bin/tool"},
		{name: "./usr/share/doc/demo/copyright", typeflag: tar.TypeReg, mode: 0o644, content: "CC0"},
	}
	origin := vfs.Origin{Package: "demo", Slice: "demo", Path: "slices/demo.yaml"}
	extracted, err := deb.Extract(syntheticPackage(t, data, standardControl()), origin)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	tool, ok := extracted.Tree.Lookup("/usr/bin/tool")
	if !ok || tool.Kind != vfs.File || tool.Mode != fs.FileMode(0o755) || tool.UID != 1 || tool.GID != 2 {
		t.Fatalf("tool = %+v", tool)
	}
	if tool.Origins[0] != origin {
		t.Fatalf("origins = %+v", tool.Origins)
	}
	if content, err := extracted.Tree.Read("/usr/bin/alias"); err != nil || string(content) != "binary" {
		t.Fatalf("hardlink content = %q %v", content, err)
	}
	if content, err := extracted.Tree.Read("/usr/share/doc/demo/copyright"); err != nil || string(content) != "CC0" {
		t.Fatalf("license = %q %v", content, err)
	}
	if content, ok := extracted.Control.Member("postinst"); !ok || !strings.Contains(string(content), "exit 0") {
		t.Fatalf("postinst = %q %v", content, ok)
	}
	if _, ok := extracted.Control.Member("md5sums"); !ok {
		t.Fatal("md5sums evidence is missing")
	}
	names := make([]string, 0, len(extracted.Control.Members))
	for _, member := range extracted.Control.Members {
		names = append(names, member.Name)
	}
	if strings.Join(names, ",") != "control,md5sums,postinst" {
		t.Fatalf("control members = %v", names)
	}
}

func TestExtract_RejectsUnsafePackages(t *testing.T) {
	tests := []struct {
		name    string
		data    []tarMember
		control []tarMember
		want    string
	}{
		{
			name:    "escaping symlink in data",
			data:    []tarMember{{name: "./link", typeflag: tar.TypeSymlink, linkname: "../../etc/shadow"}},
			control: standardControl(),
			want:    "escapes the image root",
		},
		{
			name:    "absolute data path",
			data:    []tarMember{{name: "/etc/passwd", typeflag: tar.TypeReg, mode: 0o644}},
			control: standardControl(),
			want:    "not a clean relative path",
		},
		{
			name:    "special file in data",
			data:    []tarMember{{name: "./dev/null", typeflag: tar.TypeChar, mode: 0o666}},
			control: standardControl(),
			want:    "unsupported type",
		},
		{
			name:    "nested control member",
			data:    []tarMember{{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755}},
			control: []tarMember{{name: "./sub/control", typeflag: tar.TypeReg, mode: 0o644}},
			want:    "not a plain file name",
		},
		{
			name:    "control directory member",
			data:    []tarMember{{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755}},
			control: []tarMember{{name: "./scripts", typeflag: tar.TypeDir, mode: 0o755}},
			want:    "is not a regular file",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := deb.Extract(syntheticPackage(t, test.data, test.control), vfs.Origin{Package: "demo"})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// TestExtract_RejectsDuplicateControlMembers refuses a control archive that names
// one member twice. Member returns a single record, so a duplicate would let an
// audit approve the package from a script it never read while the other script
// stayed in the evidence.
func TestExtract_RejectsDuplicateControlMembers(t *testing.T) {
	tests := []struct {
		name    string
		control []tarMember
	}{
		{
			name: "exact duplicate",
			control: []tarMember{
				{name: "./control", typeflag: tar.TypeReg, mode: 0o644, content: "Package: demo\n"},
				{name: "./postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nexit 0\n"},
				{name: "./postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nldconfig\n"},
			},
		},
		{
			name: "dot-slash alias after the bare name",
			control: []tarMember{
				{name: "./control", typeflag: tar.TypeReg, mode: 0o644, content: "Package: demo\n"},
				{name: "postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nexit 0\n"},
				{name: "./postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nldconfig\n"},
			},
		},
		{
			name: "dot-slash alias before the bare name",
			control: []tarMember{
				{name: "./control", typeflag: tar.TypeReg, mode: 0o644, content: "Package: demo\n"},
				{name: "./postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nldconfig\n"},
				{name: "postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nexit 0\n"},
			},
		},
		{
			name: "duplicate metadata member",
			control: []tarMember{
				{name: "./control", typeflag: tar.TypeReg, mode: 0o644, content: "Package: demo\n"},
				{name: "./md5sums", typeflag: tar.TypeReg, mode: 0o644, content: "a  usr/bin/tool\n"},
				{name: "./md5sums", typeflag: tar.TypeReg, mode: 0o644, content: "b  usr/bin/tool\n"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := deb.Extract(syntheticPackage(t, []tarMember{
				{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "tool"},
			}, test.control), vfs.Origin{Package: "demo"})
			if err == nil || !strings.Contains(err.Error(), "more than one") {
				t.Fatalf("error = %v, want a duplicate-member refusal", err)
			}
		})
	}
}

// The evidence order is a contract, not a property of the archive: members are
// sorted by name however the tarball lists them.
func TestExtract_SortsControlMembers(t *testing.T) {
	control := []tarMember{
		{name: "./postinst", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\nexit 0\n"},
		{name: "./control", typeflag: tar.TypeReg, mode: 0o644, content: "Package: demo\nVersion: 1.0\n"},
	}
	extracted, err := deb.Extract(syntheticPackage(t, []tarMember{
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "tool"},
	}, control), vfs.Origin{Package: "demo"})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	names := make([]string, 0, len(extracted.Control.Members))
	for _, member := range extracted.Control.Members {
		names = append(names, member.Name)
	}
	if strings.Join(names, ",") != "control,postinst" {
		t.Fatalf("control members = %v", names)
	}
}

func TestExtract_AcceptsControlRootEntry(t *testing.T) {
	control := append([]tarMember{{name: "./", typeflag: tar.TypeDir, mode: 0o755}}, standardControl()...)
	extracted, err := deb.Extract(syntheticPackage(t, []tarMember{
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "tool"},
	}, control), vfs.Origin{Package: "demo"})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, ok := extracted.Control.Member("control"); !ok {
		t.Fatalf("control members = %+v", extracted.Control.Members)
	}
}

func TestExtract_RejectsMalformedArchive(t *testing.T) {
	if _, err := deb.Extract([]byte("not a package"), vfs.Origin{Package: "demo"}); err == nil ||
		!strings.Contains(err.Error(), "not an ar archive") {
		t.Fatalf("error = %v", err)
	}
	builder := &debBuilder{}
	builder.add("debian-binary", []byte("2.0\n"))
	builder.add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("not a tar")))
	builder.add("data.tar.gz", compressMember(t, deb.CompressionGzip, buildTar(t, nil)))
	if _, err := deb.Extract(builder.bytes(), vfs.Origin{Package: "demo"}); err == nil ||
		!strings.Contains(err.Error(), "control archive is malformed") {
		t.Fatalf("error = %v", err)
	}
}

func TestExtract_FailureReturnsNoTree(t *testing.T) {
	extracted, err := deb.Extract(syntheticPackage(t, []tarMember{
		{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "one"},
		{name: "./a", typeflag: tar.TypeReg, mode: 0o644, content: "two"},
	}, standardControl()), vfs.Origin{Package: "demo"})
	if err == nil {
		t.Fatalf("conflicting package accepted: %+v", extracted)
	}
	if extracted != nil {
		t.Fatalf("partial extraction returned: %+v", extracted)
	}
}

func TestExtract_MergesIntoImage(t *testing.T) {
	image := vfs.New()
	first, err := deb.Extract(syntheticPackage(t, []tarMember{
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "tool"},
	}, standardControl()), vfs.Origin{Package: "demo"})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if mergeErr := image.Merge(first.Tree); mergeErr != nil {
		t.Fatalf("Merge: %v", mergeErr)
	}
	second, err := deb.Extract(syntheticPackage(t, []tarMember{
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "other"},
	}, standardControl()), vfs.Origin{Package: "other"})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if mergeErr := image.Merge(second.Tree); mergeErr == nil ||
		!strings.Contains(mergeErr.Error(), "conflicts with existing") {
		t.Fatalf("conflicting merge error = %v", mergeErr)
	}
	if content, err := image.Read("/usr/bin/tool"); err != nil || string(content) != "tool" {
		t.Fatalf("image content = %q %v", content, err)
	}
}

func TestExtract_SamePackageTwiceKeepsOrigins(t *testing.T) {
	members := []tarMember{{name: "./usr/bin/tool", typeflag: tar.TypeReg, mode: 0o755, content: "tool"}}
	image := vfs.New()
	for _, origin := range []vfs.Origin{
		{Package: "demo", Slice: "demo", Path: "slices/demo.yaml"},
		{Package: "demo", Slice: "demo_extra", Path: "slices/extra.yaml"},
	} {
		extracted, err := deb.Extract(syntheticPackage(t, members, standardControl()), origin)
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		if err := image.Merge(extracted.Tree); err != nil {
			t.Fatalf("Merge: %v", err)
		}
	}
	tool, _ := image.Lookup("/usr/bin/tool")
	if len(tool.Origins) != 2 {
		t.Fatalf("origins = %+v", tool.Origins)
	}
}
