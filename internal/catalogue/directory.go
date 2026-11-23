package catalogue

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

var errCatalogueFileSize = errors.New("catalogue file exceeds the size limit")

// Directory is a local catalogue directory exposed as a read-only fs.FS. Every
// open is confined to the directory and every regular file read is bounded, so
// inspecting a catalogue needs no lock and still takes the snapshot's limits.
type Directory struct{ root *os.Root }

// OpenDirectory confines dir. The caller closes it.
func OpenDirectory(dir string) (*Directory, error) {
	if dir == "" {
		return nil, errors.New("catalogue directory must not be empty")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("open catalogue directory failed")
	}
	return &Directory{root: root}, nil
}

// Close releases the directory handle.
func (d *Directory) Close() error { return d.root.Close() }

// Open returns one catalogue entry. Directories pass through; a regular file is
// capped at MaxTreeFileSize and any other file type is refused.
func (d *Directory) Open(name string) (fs.File, error) {
	// O_NONBLOCK prevents a replacement FIFO from blocking before it is checked.
	file, err := d.root.OpenFile(filepath.FromSlash(name), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		return file, nil
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("catalogue entry %q is not a regular file", name)
	}
	return &limitedFile{File: file}, nil
}

// limitedFile fails past MaxTreeFileSize instead of letting a reader buffer the
// whole file before the size is known.
type limitedFile struct {
	*os.File
	read int64
}

func (f *limitedFile) Read(data []byte) (int, error) {
	if f.read > MaxTreeFileSize {
		return 0, errCatalogueFileSize
	}
	if remaining := MaxTreeFileSize - f.read + 1; int64(len(data)) > remaining {
		data = data[:remaining]
	}
	n, err := f.File.Read(data)
	f.read += int64(n)
	if f.read > MaxTreeFileSize {
		return n, errCatalogueFileSize
	}
	return n, err
}
