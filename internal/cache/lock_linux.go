package cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LockGC acquires the per-cache guard, exclusively for GC or shared for lock publication.
func (c *Cache) LockGC(exclusive bool) (func(), error) {
	// The guard must stay on disk so every process locks the same inode.
	path := filepath.Join(c.dir, ".gc.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache GC guard: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	release := func() { _ = file.Close() }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		release()
		return nil, errors.New("cache GC guard is not a regular file")
	}
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	if err := unix.Flock(fd, mode|unix.LOCK_NB); err != nil {
		release()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("cache is busy; retry when the lock or cache gc command finishes")
		}
		return nil, fmt.Errorf("acquire cache GC guard: %w", err)
	}
	return release, nil
}
