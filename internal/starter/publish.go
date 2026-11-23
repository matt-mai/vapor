package starter

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
)

func writeDirectory(dir string, data []byte) (err error) {
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		return fmt.Errorf("create output directory: %w", mkdirErr)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close output directory: %w", closeErr))
		}
	}()
	return publish(root, data)
}

// publish writes and syncs data to a temporary file in root and links it to
// image.yaml without overwriting any existing entry. hardlink is used to avoid
// replacing any existing file, which would be a security risk if the file was
// replaced by an attacker between the write and rename operations.
func publish(root *os.Root, data []byte) (err error) {
	name := ".vaporize-init-" + rand.Text()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create starter temporary file: %w", err)
	}
	defer func() {
		if cleanupErr := root.Remove(name); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove starter temporary file: %w", cleanupErr))
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
		return fmt.Errorf("write/sync/close starter temporary file: %w", err)
	}
	// Linking publishes completed bytes atomically without replacing any entry.
	if err := root.Link(name, "image.yaml"); err != nil {
		return fmt.Errorf("publish image.yaml without overwrite: %w", err)
	}
	return nil
}
