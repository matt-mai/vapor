package deb_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// debBuilder assembles synthetic DEB archives without executing or unpacking
// anything, so tests exercise only the decoder.
type debBuilder struct {
	members []arMember
}

type arMember struct {
	name string
	body []byte
}

func (b *debBuilder) add(name string, body []byte) *debBuilder {
	b.members = append(b.members, arMember{name: name, body: body})
	return b
}

func (b *debBuilder) bytes() []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, member := range b.members {
		fmt.Fprintf(&buf, "%-16s%-12s%-6s%-6s%-8s%-10s`\n",
			member.name, "0", "0", "0", "100644", fmt.Sprint(len(member.body)))
		buf.Write(member.body)
		if len(member.body)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

func compressMember(t *testing.T, compression deb.Compression, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch compression {
	case deb.CompressionPlain:
		return data
	case deb.CompressionGzip:
		writer := gzip.NewWriter(&buf)
		_, _ = writer.Write(data)
		if err := writer.Close(); err != nil {
			t.Fatalf("gzip: %v", err)
		}
	case deb.CompressionXZ:
		writer, err := xz.NewWriter(&buf)
		if err != nil {
			t.Fatalf("xz writer: %v", err)
		}
		_, _ = writer.Write(data)
		if err := writer.Close(); err != nil {
			t.Fatalf("xz: %v", err)
		}
	case deb.CompressionZstd:
		writer, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		_, _ = writer.Write(data)
		if err := writer.Close(); err != nil {
			t.Fatalf("zstd: %v", err)
		}
	default:
		t.Fatalf("unsupported test compression %q", compression)
	}
	return buf.Bytes()
}

func memberSuffix(compression deb.Compression) string {
	if compression == deb.CompressionPlain {
		return ""
	}
	return "." + string(compression)
}

func syntheticDEB(t *testing.T, controlFormat, dataFormat deb.Compression) []byte {
	t.Helper()
	control := []byte("control tarball bytes")
	data := []byte("data tarball bytes")
	builder := &debBuilder{}
	builder.add("debian-binary", []byte("2.0\n"))
	builder.add("control.tar"+memberSuffix(controlFormat), compressMember(t, controlFormat, control))
	builder.add("data.tar"+memberSuffix(dataFormat), compressMember(t, dataFormat, data))
	return builder.bytes()
}

func TestDecodeArchive_SupportedCompressions(t *testing.T) {
	t.Parallel()
	formats := []deb.Compression{deb.CompressionPlain, deb.CompressionGzip, deb.CompressionXZ, deb.CompressionZstd}
	for _, controlFormat := range formats {
		for _, dataFormat := range formats {
			t.Run(string(controlFormat)+"_"+string(dataFormat), func(t *testing.T) {
				t.Parallel()
				archive, err := deb.DecodeArchive(syntheticDEB(t, controlFormat, dataFormat))
				if err != nil {
					t.Fatalf("DecodeArchive: %v", err)
				}
				defer func() { _ = archive.Close() }()
				if archive.ControlFormat != controlFormat || archive.DataFormat != dataFormat {
					t.Fatalf("formats = %q/%q, want %q/%q",
						archive.ControlFormat, archive.DataFormat, controlFormat, dataFormat)
				}
				if string(archive.Control) != "control tarball bytes" {
					t.Fatalf("control = %q", archive.Control)
				}
				data, err := io.ReadAll(archive.Data)
				if err != nil {
					t.Fatalf("read data: %v", err)
				}
				if string(data) != "data tarball bytes" {
					t.Fatalf("data = %q", data)
				}
			})
		}
	}
}

func TestDecodeArchive_IgnoresTrailingBuilderSignature(t *testing.T) {
	t.Parallel()
	data := (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
		add("control.tar", []byte("control")).add("data.tar", []byte("data")).
		add("_gpgbuilder", []byte("opaque signature")).bytes()
	archive, err := deb.DecodeArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = archive.Close() }()
	body, err := io.ReadAll(archive.Data)
	if err != nil || string(body) != "data" || string(archive.Control) != "control" {
		t.Fatalf("control=%q data=%q error=%v", archive.Control, body, err)
	}
}

func TestDecodeArchive_RejectsMalformedPackages(t *testing.T) {
	t.Parallel()
	valid := syntheticDEB(t, deb.CompressionGzip, deb.CompressionGzip)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty",
			data: nil,
			want: "not an ar archive",
		},
		{
			name: "wrong magic",
			data: []byte("!<thin>\n"),
			want: "not an ar archive",
		},
		{
			name: "truncated header",
			data: append([]byte("!<arch>\n"), "debian-bin"...),
			want: "header is truncated",
		},
		{
			name: "truncated member",
			data: valid[:len(valid)-8],
			want: "member is truncated",
		},
		{
			name: "missing data member",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).bytes(),
			want: "missing a required ar member",
		},
		{
			name: "debian-binary not first",
			data: (&debBuilder{}).add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).
				add("data.tar.gz", compressMember(t, deb.CompressionGzip, []byte("y"))).
				add("debian-binary", []byte("2.0\n")).bytes(),
			want: "debian-binary member is not first",
		},
		{
			name: "wrong format version",
			data: (&debBuilder{}).add("debian-binary", []byte("3.0\n")).
				add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).
				add("data.tar.gz", compressMember(t, deb.CompressionGzip, []byte("y"))).bytes(),
			want: "format version is not 2.0",
		},
		{
			name: "unsupported data compression",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).
				add("data.tar.lzma", []byte("y")).bytes(),
			want: "data member is missing or unsupported",
		},
		{
			name: "suffix without compression",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).
				add("data.tar.", []byte("y")).bytes(),
			want: "data member is missing or unsupported",
		},
		{
			name: "corrupt control bytes",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar.gz", []byte("not gzip")).
				add("data.tar.gz", compressMember(t, deb.CompressionGzip, []byte("y"))).bytes(),
			want: "decompression failed",
		},
		{
			name: "corrupt data bytes",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).
				add("data.tar.gz", []byte("not gzip")).bytes(),
			want: "decompression failed",
		},
		{
			name: "unknown trailing member",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar.gz", compressMember(t, deb.CompressionGzip, []byte("x"))).
				add("data.tar.gz", compressMember(t, deb.CompressionGzip, []byte("y"))).
				add("extra", []byte("z")).bytes(),
			want: "unsupported trailing ar member",
		},
		{
			name: "repeated builder signature",
			data: (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
				add("control.tar", []byte("x")).add("data.tar", []byte("y")).
				add("_gpgbuilder", []byte("s")).add("_gpgbuilder", []byte("s")).bytes(),
			want: "more than 4 ar members",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			archive, err := deb.DecodeArchive(test.data)
			if err == nil {
				_ = archive.Close()
				t.Fatalf("DecodeArchive succeeded, want %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeArchive_RejectsMalformedMemberHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "name with slash",
			header: fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", "a/b", "0", "0", "0", "100644", "0"),
			want:   "member name is invalid",
		},
		{
			name:   "empty name",
			header: fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", "", "0", "0", "0", "100644", "0"),
			want:   "member name is invalid",
		},
		{
			name:   "non-numeric size",
			header: fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", "debian-binary", "0", "0", "0", "100644", "abc"),
			want:   "member size is invalid",
		},
		{
			name:   "bad terminator",
			header: fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10sXX", "debian-binary", "0", "0", "0", "100644", "0"),
			want:   "member header is malformed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := append([]byte("!<arch>\n"), test.header...)
			_, err := deb.DecodeArchive(data)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeArchive_RejectsControlDecompressionBomb(t *testing.T) {
	t.Parallel()
	bomb := make([]byte, deb.MaxControlArchiveSize+1024)
	data := (&debBuilder{}).add("debian-binary", []byte("2.0\n")).
		add("control.tar.gz", compressMember(t, deb.CompressionGzip, bomb)).
		add("data.tar.gz", compressMember(t, deb.CompressionGzip, []byte("y"))).bytes()
	_, err := deb.DecodeArchive(data)
	if err == nil || !strings.Contains(err.Error(), "exceeds the decompression bound") {
		t.Fatalf("error = %v, want a decompression bound error", err)
	}
}
