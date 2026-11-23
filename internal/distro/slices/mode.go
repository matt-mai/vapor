package slices

import (
	"io/fs"
)

func modeOrDefault(mode uint32, fallback fs.FileMode) fs.FileMode {
	if mode == 0 {
		return fallback
	}
	return fileMode(mode)
}

// fileMode converts a declared Unix mode into the portable representation that
// carries the special bits separately from the permission bits.
func fileMode(mode uint32) fs.FileMode {
	converted := fs.FileMode(mode) & fs.ModePerm
	for bit, special := range map[uint32]fs.FileMode{
		0o4000: fs.ModeSetuid,
		0o2000: fs.ModeSetgid,
		0o1000: fs.ModeSticky,
	} {
		if mode&bit != 0 {
			converted |= special
		}
	}
	return converted
}
