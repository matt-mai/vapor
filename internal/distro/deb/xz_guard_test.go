package deb_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// bigDictionaryXZ compresses content with a dictionary larger than the decoder
// limit. The library treats ReaderConfig.DictCap as a floor, so a payload built
// this way used to raise the decoder's allocation to whatever it declared.
func bigDictionaryXZ(t *testing.T, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := xz.WriterConfig{DictCap: 128 << 20}.NewWriter(&buffer)
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

func TestVerifyIndexRejectsADictionaryOverTheLimit(t *testing.T) {
	content := []byte("Package: demo\nVersion: 1.0\n")
	compressed := bigDictionaryXZ(t, content)
	sum, size := sha256Of(compressed)
	index := &deb.Index{Format: deb.IndexFormatXZ, SHA256: sum, Size: size}
	if _, err := deb.VerifyIndex(index, compressed); err == nil || !strings.Contains(err.Error(), "dictionary") {
		t.Fatalf("error = %v, want a dictionary rejection", err)
	}
}

func TestMemberReaderRejectsADictionaryOverTheLimit(t *testing.T) {
	payload := bigDictionaryXZ(t, bytes.Repeat([]byte("control\n"), 1024))
	archive := (&debBuilder{}).
		add("debian-binary", []byte("2.0\n")).
		add("control.tar.xz", payload).
		add("data.tar.xz", payload).
		bytes()
	if _, err := deb.DecodeArchive(archive); err == nil || !strings.Contains(err.Error(), "dictionary") {
		t.Fatalf("error = %v, want a dictionary rejection", err)
	}
}
