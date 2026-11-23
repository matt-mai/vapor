package catalogue

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestArchiveBudgetReaderRejectsOversize(t *testing.T) {
	reader := &archiveBudgetReader{reader: bytes.NewReader([]byte("12345")), limit: 4}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("oversized stream accepted")
	}
}

func TestArchiveBudgetReaderAcceptsLimit(t *testing.T) {
	reader := &archiveBudgetReader{reader: bytes.NewReader([]byte("1234")), limit: 4}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "1234" {
		t.Fatalf("data = %q", data)
	}
}

func TestReadCatalogueFileRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	done := make(chan error, 1)
	go func() {
		_, _, readErr := readCatalogueFile(root, "fifo", 1024)
		done <- readErr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO catalogue file was accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("catalogue snapshot blocked on FIFO")
	}
}
