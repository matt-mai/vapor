package lock

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

type lockPublishOps struct {
	createTemp func(dir, pattern string) (*os.File, error)
	write      func(*os.File, []byte) (int, error)
	sync       func(*os.File) error
	close      func(*os.File) error
	rename     func(oldpath, newpath string) error
	remove     func(string) error
}

var defaultLockPublishOps = lockPublishOps{
	createTemp: os.CreateTemp,
	write:      (*os.File).Write,
	sync:       (*os.File).Sync,
	close:      (*os.File).Close,
	rename:     os.Rename,
	remove:     os.Remove,
}

// PublishLockfile writes the canonical YAML encoding to path. It does not verify
// the lock against a spec; callers must do that first.
//
// The destination is never opened or truncated. A 0600 temporary file in the
// same directory is written, synced and closed, then renamed into place. Any
// failure before the rename leaves the previous file untouched and removes the
// temporary file.
func PublishLockfile(path string, lock *Lockfile) error {
	data, err := lock.CanonicalYAML()
	if err != nil {
		return fmt.Errorf("encode lock for publication: %w", err)
	}
	return publishLockfile(path, data, defaultLockPublishOps)
}

func publishLockfile(path string, data []byte, ops lockPublishOps) (err error) {
	file, err := ops.createTemp(filepath.Dir(path), ".vapor-lock-*")
	if err != nil {
		return fmt.Errorf("create lock temporary file: %w", err)
	}
	tempPath := file.Name()
	published := false
	defer func() {
		if published {
			return
		}
		if removeErr := ops.remove(tempPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove lock temporary file: %w", removeErr))
		}
	}()

	written, writeErr := ops.write(file, data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return errors.Join(fmt.Errorf("write lock temporary file: %w", writeErr), closeLockTemp(ops, file))
	}
	if syncErr := ops.sync(file); syncErr != nil {
		return errors.Join(fmt.Errorf("sync lock temporary file: %w", syncErr), closeLockTemp(ops, file))
	}
	if closeErr := ops.close(file); closeErr != nil {
		return fmt.Errorf("close lock temporary file: %w", closeErr)
	}
	if renameErr := ops.rename(tempPath, path); renameErr != nil {
		return fmt.Errorf("publish lock file: %w", renameErr)
	}
	published = true
	return nil
}

func closeLockTemp(ops lockPublishOps, file *os.File) error {
	if err := ops.close(file); err != nil {
		return fmt.Errorf("close lock temporary file: %w", err)
	}
	return nil
}
