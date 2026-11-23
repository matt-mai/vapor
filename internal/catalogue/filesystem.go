package catalogue

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// Opener reads verified content-addressed bytes. *cache.Cache implements it.
type Opener interface {
	Open(digest string, size int64) (io.ReadCloser, error)
}

// FileSystem exposes a catalogue tree as a read-only filesystem, reading each file
// by its recorded digest. The bytes come from the caller's verified store, so a
// snapshot can be re-read offline without the directory it was taken from.
func FileSystem(tree Tree, store Opener) (fs.FS, error) {
	if store == nil {
		return nil, errors.New("catalogue filesystem requires a blob store")
	}
	buffer := &bytes.Buffer{}
	writer := zip.NewWriter(buffer)
	for _, entry := range tree.Entries() {
		if err := writeEntry(writer, &entry, store); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("catalogue filesystem archive: %w", err)
	}
	return zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
}

func writeEntry(writer *zip.Writer, entry *Entry, store Opener) error {
	if entry.Kind == KindDir {
		_, err := writer.Create(entry.Path + "/")
		return err
	}
	file, err := writer.Create(entry.Path)
	if err != nil {
		return err
	}
	if entry.Kind == KindSymlink {
		_, err = io.WriteString(file, entry.Target)
		return err
	}
	data, err := readEntry(store, entry.SHA256, entry.Size)
	if err != nil {
		return fmt.Errorf("catalogue entry %q: %w", entry.Path, err)
	}
	_, err = file.Write(data)
	return err
}

// readEntry reads one recorded file, refusing bytes that do not match its size.
// The store already verifies the digest; the size check keeps a store that ignores
// it from feeding the catalogue a partial file.
func readEntry(store Opener, digest string, size int64) ([]byte, error) {
	reader, err := store.Open(digest, size)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, errors.New("cached input has the wrong size")
	}
	return data, nil
}
