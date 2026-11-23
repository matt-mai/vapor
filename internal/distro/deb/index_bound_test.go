package deb

import (
	"bytes"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
)

func TestReadBounded(t *testing.T) {
	if data, err := readBounded(strings.NewReader("1234"), 4); err != nil || string(data) != "1234" {
		t.Fatalf("data = %q, error = %v", data, err)
	}
	if _, err := readBounded(strings.NewReader("12345"), 4); err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("error = %v", err)
	}
}

func TestDecompressIndexLimit(t *testing.T) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decompressIndex(IndexFormatGzip, buffer.Bytes(), 128); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}
