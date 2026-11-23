package oci

import "golang.org/x/sys/unix"

func renameNoReplace(staged, dst string) error {
	return unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
}
