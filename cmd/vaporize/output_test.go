package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

func TestOutputWriter_ShortWrite(t *testing.T) {
	t.Parallel()
	w := &outputWriter{Writer: shortWriter{}}
	if _, err := w.Write([]byte("help")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write error = %v, want short write", err)
	}
	if !errors.Is(w.err, io.ErrShortWrite) {
		t.Fatalf("recorded error = %v, want short write", w.err)
	}
}

func TestRun_HelpWriteFailure(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run([]string{"help", "build"}, failingWriter{}, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}
