package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeFileAtomic replaces path with data by writing a temporary file beside it and
// renaming it into place, so a reader sees either the previous bytes or the complete
// new ones. The write never follows a symlink planted at the destination: the link is
// what gets replaced.
func writeFileAtomic(path string, data []byte) (err error) {
	name := filepath.Base(path)
	file, err := os.CreateTemp(filepath.Dir(path), ".vapor-"+name+"-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", name, err)
	}
	tempPath := file.Name()
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tempPath)
		}
	}()
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	var syncErr error
	if writeErr == nil {
		syncErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("write temporary file for %s: %w", name, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish %s: %w", name, err)
	}
	published = true
	return nil
}
