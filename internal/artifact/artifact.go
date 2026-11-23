// Package artifact places verified artifact payloads into an image filesystem.
// It holds the spec-level placement policy; extraction, confinement and
// collision rules come from internal/vfs.
package artifact

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path"
	"strconv"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// DefaultDirMode is the mode of an unpacked artifact's destination directory.
// The declared mode applies to standalone files only, so the destination needs
// a fixed mode rather than an implicit parent's.
const DefaultDirMode fs.FileMode = 0o755

// Place builds a standalone tree holding one verified artifact payload. Apply it
// to an image with Tree.Merge.
//
// A standalone artifact becomes one regular file at its destination. An unpacked
// artifact is extracted with the same path and link confinement as a package
// payload and re-rooted at its destination, which becomes a directory carrying
// the declared ownership. Declared ownership replaces the archive's ownership on
// every extracted entry; archive modes are kept.
//
// An artifact's links must resolve inside its own destination, so a payload
// cannot reach into the rest of the image.
func Place(record *lock.Artifact, data []byte) (*vfs.Tree, error) {
	if record == nil {
		return nil, errors.New("artifact placement requires a record")
	}
	if record.Unpack == nil {
		return nil, fmt.Errorf("artifact %q: placement requires a resolved unpack setting", record.Name)
	}
	if record.Dest != "/" && (!path.IsAbs(record.Dest) || path.Clean(record.Dest) != record.Dest) {
		return nil, fmt.Errorf("artifact %q: destination %q is not a clean absolute path", record.Name, record.Dest)
	}
	if record.Size > 0 && int64(len(data)) != record.Size {
		return nil, fmt.Errorf("artifact %q: payload is %d bytes, want %d", record.Name, len(data), record.Size)
	}
	uid, gid, err := ownership(record)
	if err != nil {
		return nil, err
	}
	origin := vfs.Origin{Package: record.Name, Path: record.Source()}
	switch *record.Unpack {
	case contents.ArtifactUnpackStandalone:
		return standalone(record, data, uid, gid, origin)
	case contents.ArtifactUnpackArchive:
		return unpacked(record, data, uid, gid, origin)
	default:
		return nil, fmt.Errorf("artifact %q: placement %s is not a file placement", record.Name, *record.Unpack)
	}
}

// standalone places one file, so the destination is the entry itself and the
// declared mode is the file's mode.
func standalone(record *lock.Artifact, data []byte, uid, gid uint32, origin vfs.Origin) (*vfs.Tree, error) {
	if record.Dest == "/" {
		return nil, fmt.Errorf("artifact %q: a standalone file cannot be placed at the root", record.Name)
	}
	mode, err := standaloneMode(record.Mode)
	if err != nil {
		return nil, fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	tree := vfs.New()
	attrs := vfs.Attrs{Mode: mode, UID: uid, GID: gid, Origin: origin}
	if err := tree.File(record.Dest, data, attrs); err != nil {
		return nil, err
	}
	return tree, nil
}

// unpacked extracts the payload and re-roots it under the destination. Archive
// modes are preserved, so a declared mode would be a silent override.
func unpacked(record *lock.Artifact, data []byte, uid, gid uint32, origin vfs.Origin) (*vfs.Tree, error) {
	if record.Mode != nil {
		return nil, fmt.Errorf("artifact %q: unpacked artifacts preserve archive modes", record.Name)
	}
	payload, err := vfs.ImportArchive(data, origin, vfs.DefaultLimits())
	if err != nil {
		return nil, fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	dest := record.Dest
	tree := vfs.New()
	if dest != "/" {
		attrs := vfs.Attrs{Mode: DefaultDirMode, UID: uid, GID: gid, Origin: origin}
		if err := tree.Dir(dest, attrs); err != nil {
			return nil, err
		}
	}
	entries := payload.Entries()
	inodes := payload.Inodes()
	placed := make(map[uint64]string, len(entries))
	for i := range entries {
		entry := &entries[i]
		if entry.Implicit {
			continue
		}
		if err := place(tree, payload, entry, dest, uid, gid, origin, inodes, placed); err != nil {
			return nil, fmt.Errorf("artifact %q: %w", record.Name, err)
		}
	}
	if err := ownInternalParents(tree, dest, uid, gid, origin); err != nil {
		return nil, fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	if err := confine(tree, dest); err != nil {
		return nil, fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	return tree, nil
}

// place copies one payload entry to its re-rooted path. Entries sharing an inode
// stay hard links to the first path that carried that inode.
func place(tree, payload *vfs.Tree, entry *vfs.Entry, dest string, uid, gid uint32,
	origin vfs.Origin, inodes map[string]uint64, placed map[uint64]string,
) error {
	target := reRoot(dest, entry.Path)
	attrs := vfs.Attrs{Mode: entry.Mode, UID: uid, GID: gid, Origin: origin}
	switch entry.Kind {
	case vfs.Dir:
		return tree.Dir(target, attrs)
	case vfs.Symlink:
		return tree.Symlink(target, entry.Target, attrs)
	case vfs.File:
		if first, ok := placed[inodes[entry.Path]]; ok {
			return tree.Hardlink(target, first, origin)
		}
		content, err := payload.Read(entry.Path)
		if err != nil {
			return err
		}
		if err := tree.File(target, content, attrs); err != nil {
			return err
		}
		placed[inodes[entry.Path]] = target
		return nil
	default:
		return fmt.Errorf("entry %q has unsupported kind %q", entry.Path, entry.Kind)
	}
}

// ownInternalParents gives the directories an archive only implies inside its own
// payload the artifact's ownership. They would otherwise be root-owned while
// everything around them belongs to the artifact, leaving a non-root application
// unable to write inside its own tree.
//
// They become declarations rather than implicit parents because merge skips
// implicit entries: an implicit parent would be recreated root-owned in the image,
// which is exactly the state this function exists to prevent. Parents above the
// destination keep the image's ownership and stay implicit, because the artifact
// does not own them. A root destination owns every directory it implies.
func ownInternalParents(tree *vfs.Tree, dest string, uid, gid uint32, origin vfs.Origin) error {
	for _, entry := range tree.Entries() {
		if entry.Kind != vfs.Dir || !entry.Implicit {
			continue
		}
		if dest != "/" && !strings.HasPrefix(entry.Path, dest+"/") {
			continue
		}
		attrs := vfs.Attrs{Mode: entry.Mode, UID: uid, GID: gid, Origin: origin}
		if err := tree.Dir(entry.Path, attrs); err != nil {
			return err
		}
	}
	return nil
}

// confine keeps every link inside the artifact's destination. The payload tree
// is standalone, so a link to a parent of the destination would resolve inside
// this tree while pointing outside the artifact in the final image.
func confine(tree *vfs.Tree, dest string) error {
	for _, entry := range tree.Entries() {
		if entry.Kind != vfs.Symlink {
			continue
		}
		resolved, err := tree.Resolve(entry.Path)
		if err != nil {
			return err
		}
		if dest != "/" && resolved != dest && !strings.HasPrefix(resolved, dest+"/") {
			return fmt.Errorf("symlink %q resolves to %q, outside %q", entry.Path, resolved, dest)
		}
	}
	return nil
}

// reRoot prefixes an entry path with the destination. Both are clean absolute
// paths, so concatenation is the join.
func reRoot(dest, p string) string {
	if dest == "/" {
		return p
	}
	return dest + p
}

func ownership(record *lock.Artifact) (uint32, uint32, error) {
	if record.UID < 0 || record.GID < 0 ||
		uint64(record.UID) > math.MaxUint32 || uint64(record.GID) > math.MaxUint32 {
		return 0, 0, fmt.Errorf("artifact %q: ownership is outside the 32-bit range", record.Name)
	}
	return uint32(record.UID), uint32(record.GID), nil
}

// standaloneMode converts a declared octal mode into the portable form that
// carries special bits separately from permission bits.
func standaloneMode(value *string) (fs.FileMode, error) {
	if value == nil {
		return 0, errors.New("a standalone artifact requires a mode")
	}
	parsed, err := strconv.ParseUint(*value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("mode %q is not an octal mode", *value)
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
