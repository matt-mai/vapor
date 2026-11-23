package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

// IsTerminal reports whether the file is a terminal, so the reporter animates only when
// a person is watching. A file descriptor that is not a terminal answers EINVAL or
// ENOTTY, which is exactly the case to render plainly.
func IsTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}
