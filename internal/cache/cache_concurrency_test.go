package cache

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoreConcurrentPublication(t *testing.T) {
	t.Parallel()
	c, dir := newTestCache(t)
	data := bytes.Repeat([]byte("concurrent"), 1024)
	digest := digestOf(data)
	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Go(func() {
			errs <- c.Store(bytes.NewReader(data), digest, int64(len(data)))
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(c.blobPath(digest))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("concurrent publication produced wrong bytes")
	}
	assertNoStaging(t, dir)
}

func TestStoreReplacesPoisonedBlob(t *testing.T) {
	t.Parallel()
	c, dir := newTestCache(t)
	data := []byte("good")
	digest := digestOf(data)
	path := c.blobPath(digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("poison"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("poisoned blob was not replaced: %q", got)
	}
	assertNoStaging(t, dir)
}

func TestStoreReadersNeverSeePartialBlob(t *testing.T) {
	t.Parallel()
	c, dir := newTestCache(t)
	data := bytes.Repeat([]byte("partial"), 128*1024)
	digest := digestOf(data)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- c.Store(reader, digest, int64(len(data))) }()

	half := len(data) / 2
	if _, err := writer.Write(data[:half]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.blobPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blob visible before completion: %v", err)
	}
	if _, err := writer.Write(data[half:]); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(c.blobPath(digest))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("published blob is incomplete")
	}
	assertNoStaging(t, dir)
}
