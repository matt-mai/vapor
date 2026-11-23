package builder

import (
	"fmt"
	"io/fs"
	"math"
	"strconv"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/vfs"
)

// declaredOrigin attributes a filesystem.paths[] entry to the specification, which
// is what hardening later protects from its own passes.
const declaredOrigin = "filesystem.paths"

// applyPaths writes the declared filesystem.paths[] entries. Declaring never
// truncates: an existing entry of the same kind keeps its bytes and receives only
// the declared metadata.
func applyPaths(tree *vfs.Tree, entries []filesystem.Path) error {
	origin := vfs.Origin{Path: declaredOrigin}
	for index := range entries {
		entry := &entries[index]
		kind, target, err := declaredEntry(entry)
		if err != nil {
			return err
		}
		mode, err := declaredMode(entry)
		if err != nil {
			return err
		}
		uid, gid, err := declaredOwnership(entry)
		if err != nil {
			return err
		}
		if err := tree.Declare(entry.Path, kind,
			vfs.Attrs{Mode: mode, UID: uid, GID: gid, Origin: origin}, target); err != nil {
			return fmt.Errorf("filesystem.paths %s: %w", entry.Path, err)
		}
	}
	return nil
}

func declaredEntry(entry *filesystem.Path) (vfs.Kind, string, error) {
	switch entry.Type {
	case "directory":
		return vfs.Dir, "", nil
	case "file":
		return vfs.File, "", nil
	case "symlink":
		if entry.Target == nil {
			return "", "", fmt.Errorf("filesystem.paths %s: symlink has no target", entry.Path)
		}
		return vfs.Symlink, *entry.Target, nil
	default:
		return "", "", fmt.Errorf("filesystem.paths %s: unsupported type %q", entry.Path, entry.Type)
	}
}

// declaredOwnership converts the declared ids after checking the range the schema
// already enforces, so a value that slipped past validation cannot wrap.
func declaredOwnership(entry *filesystem.Path) (uint32, uint32, error) {
	if entry.UID < 0 || entry.GID < 0 || uint64(entry.UID) > math.MaxUint32 ||
		uint64(entry.GID) > math.MaxUint32 {
		return 0, 0, fmt.Errorf("filesystem.paths %s: ownership is outside the 32-bit range",
			entry.Path)
	}
	return uint32(entry.UID), uint32(entry.GID), nil
}

// declaredMode converts the declared octal mode, which carries the special bits,
// into the portable form. The schema has already validated the text.
func declaredMode(entry *filesystem.Path) (fs.FileMode, error) {
	if entry.Mode == nil {
		return 0, fmt.Errorf("filesystem.paths %s: mode is not defaulted", entry.Path)
	}
	parsed, err := strconv.ParseUint(*entry.Mode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("filesystem.paths %s: mode %q is not octal", entry.Path, *entry.Mode)
	}
	bits := uint32(parsed)
	mode := fs.FileMode(bits) & fs.ModePerm
	for bit, special := range map[uint32]fs.FileMode{
		0o4000: fs.ModeSetuid,
		0o2000: fs.ModeSetgid,
		0o1000: fs.ModeSticky,
	} {
		if bits&bit != 0 {
			mode |= special
		}
	}
	return mode, nil
}

// synthesize writes the state no package supplies: accounts, timezone, release
