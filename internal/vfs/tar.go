package vfs

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"slices"
	"strings"
)

// Limits bounds one tar import. Every field is required: a zero limit would
// silently accept an unbounded archive, so callers pass DefaultLimits or their
// own explicit values.
type Limits struct {
	MaxEntries   int
	MaxFileSize  int64
	MaxTotalSize int64
	MaxPathSize  int
	// MaxStreamSize bounds the decompressed bytes the archive may yield, counting
	// headers, padding and PAX metadata as well as file content. The other fields
	// bound what the import keeps; this one bounds the work it does, because
	// tar.Reader consumes metadata internally before any entry rule applies.
	MaxStreamSize int64
}

// DefaultLimits returns the import bounds used for package payloads. The total
// bound is a memory bound as well: entry content is held in memory.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:   1 << 20,
		MaxFileSize:  1 << 30,
		MaxTotalSize: 4 << 30,
		MaxPathSize:  4096,
		// Twice the content bound, which leaves room for the framing a real
		// archive carries without admitting an archive that is mostly metadata.
		MaxStreamSize: 8 << 30,
	}
}

func (l Limits) validate() error {
	if l.MaxEntries <= 0 || l.MaxFileSize <= 0 || l.MaxTotalSize <= 0 || l.MaxPathSize <= 0 ||
		l.MaxStreamSize <= 0 {
		return errors.New("vfs import limits must all be positive")
	}
	return nil
}

// ImportTar builds a tree from a tar stream whose bytes are already verified.
// Paths must be relative and clean, symlink targets are confined to the root,
// hard links must name an earlier regular file, and special files are rejected
// rather than skipped. Duplicate entries follow the same collision rules as
// direct construction, so an archive cannot overwrite itself.
//
// A symlink whose target does not exist is accepted, because a real filesystem
// allows it and Ubuntu packages ship such links (a man page pointing at a package
// that is not installed). Confinement is what matters: a link may not escape the
// root, loop, or cross a regular file.
//
// The returned tree is standalone; apply it to an image with Merge.
func ImportTar(reader io.Reader, origin Origin, limits Limits) (*Tree, error) {
	if reader == nil {
		return nil, errors.New("vfs tar import requires a reader")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	tree := New()
	// The budget sits beneath tar.Reader, so it counts every decompressed byte the
	// reader consumes, including the metadata it handles without yielding an entry.
	budget := &streamBudget{reader: reader, left: limits.MaxStreamSize}
	archive := tar.NewReader(budget)
	state := &importState{tree: tree, origin: origin, limits: limits}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, importError(err)
		}
		if err := state.entry(archive, header); err != nil {
			return nil, err
		}
	}
	// The tar end-of-archive marker can precede the compression trailer, so the
	// decoder has not validated its checksum yet. Draining the rest through the
	// same budget forces that validation: without it a corrupt trailer reports a
	// successful import. The drain is bounded by MaxStreamSize, not unbounded.
	if _, err := io.Copy(io.Discard, budget); err != nil {
		return nil, importError(err)
	}
	if err := tree.ConfineLinks(); err != nil {
		return nil, err
	}
	return tree, nil
}

// errStreamBound reports an archive that expanded past MaxStreamSize. It is a
// sentinel so the caller can report the stream bound rather than a decode failure,
// which is what a truncated read otherwise looks like.
var errStreamBound = errors.New("vfs tar import exceeds the decompressed stream bound")

// streamBudget fails once the archive has yielded more than left bytes. It is the
// only bound that applies to metadata, because tar.Reader consumes PAX and GNU
// headers itself and never presents them as entries.
//
// The budget is spent exactly when the stream ends on its last byte, so an
// exhausted budget is not an overflow by itself: the next read asks the stream
// whether it has anything left, and only a byte that exists is over the bound.
type streamBudget struct {
	reader io.Reader
	left   int64
}

func (b *streamBudget) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return b.overflow()
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.reader.Read(p)
	b.left -= int64(n)
	return n, err
}

// overflow reports a read past the budget, unless the stream has already ended.
func (b *streamBudget) overflow() (int, error) {
	var probe [1]byte
	n, err := b.reader.Read(probe[:])
	if n > 0 {
		return 0, errStreamBound
	}
	if errors.Is(err, io.EOF) {
		return 0, io.EOF
	}
	return 0, err
}

// importError reports a stream-bound failure as itself and wraps anything else,
// so a caller can distinguish an archive that expanded too far from one that is
// corrupt.
func importError(err error) error {
	if errors.Is(err, errStreamBound) {
		return errStreamBound
	}
	return fmt.Errorf("vfs tar import failed: %w", err)
}

// importState carries the running bounds of one import.
type importState struct {
	tree   *Tree
	origin Origin
	limits Limits
	count  int
	total  int64
}

func (s *importState) entry(archive *tar.Reader, header *tar.Header) error {
	s.count++
	if s.count > s.limits.MaxEntries {
		return fmt.Errorf("vfs tar import exceeds %d entries", s.limits.MaxEntries)
	}
	name, skip, err := importPath(header.Name, header.Typeflag == tar.TypeDir, s.limits.MaxPathSize)
	if err != nil || skip {
		return err
	}
	attrs, err := s.attrs(header)
	if err != nil {
		return fmt.Errorf("vfs tar entry %q: %w", name, err)
	}
	switch header.Typeflag {
	case tar.TypeDir:
		return s.tree.Dir(name, attrs)
	case tar.TypeReg:
		return s.file(archive, header, name, attrs)
	case tar.TypeSymlink:
		if len(header.Linkname) > s.limits.MaxPathSize {
			return fmt.Errorf("vfs tar entry %q has a link target longer than %d bytes", name,
				s.limits.MaxPathSize)
		}
		return s.tree.Symlink(name, header.Linkname, attrs)
	case tar.TypeLink:
		return s.hardlink(header, name)
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return nil
	default:
		return fmt.Errorf("vfs tar entry %q has unsupported type %q", name, header.Typeflag)
	}
}

func (s *importState) file(archive *tar.Reader, header *tar.Header, name string, attrs Attrs) error {
	if header.Size < 0 || header.Size > s.limits.MaxFileSize ||
		header.Size > s.limits.MaxTotalSize-s.total {
		return fmt.Errorf("vfs tar entry %q exceeds the import size bound", name)
	}
	content, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil {
		// A stream bound that runs out mid-entry is the bound ending the read, not a
		// damaged archive, so it keeps its own error.
		if errors.Is(err, errStreamBound) {
			return errStreamBound
		}
		return fmt.Errorf("vfs tar entry %q is truncated", name)
	}
	if int64(len(content)) != header.Size {
		return fmt.Errorf("vfs tar entry %q is truncated", name)
	}
	s.total += header.Size
	return s.tree.File(name, content, attrs)
}

func (s *importState) hardlink(header *tar.Header, name string) error {
	target, skip, err := importPath(header.Linkname, false, s.limits.MaxPathSize)
	if err != nil || skip {
		return fmt.Errorf("vfs tar hardlink %q has an invalid target", name)
	}
	return s.tree.Hardlink(name, target, s.origin)
}

// attrs copies header metadata unchanged. Ownership and mode are preserved for
// later hardening and audit; nothing is normalized here except link modes, which
// Symlink already fixes.
func (s *importState) attrs(header *tar.Header) (Attrs, error) {
	attrs := Attrs{
		Mode:   header.FileInfo().Mode() & permissionBits,
		Origin: s.origin,
	}
	uid, err := identity(header.Uid)
	if err != nil {
		return Attrs{}, err
	}
	gid, err := identity(header.Gid)
	if err != nil {
		return Attrs{}, err
	}
	attrs.UID = uid
	attrs.GID = gid
	return attrs, nil
}

// identity converts a tar identity to the image's 32-bit domain. A negative or
// oversized value is rejected rather than wrapped into a different owner: a
// negative uid read as zero would hand an unprivileged member root ownership.
func identity(value int) (uint32, error) {
	if value < 0 {
		return 0, errors.New("identity is negative")
	}
	if int64(value) > math.MaxUint32 {
		return 0, errors.New("identity exceeds the 32-bit ownership range")
	}
	return uint32(value), nil
}

// importPath normalizes an archive member name to an absolute image path. A
// leading "./" is stripped, a directory's trailing slash is dropped, and the
// root entry itself is skipped.
func importPath(name string, directory bool, maxPath int) (string, bool, error) {
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || name == "." {
		return "", true, nil
	}
	if len(name) > maxPath || path.IsAbs(name) || path.Clean(name) != name || hasParent(name) {
		return "", false, fmt.Errorf("vfs tar entry name %q is not a clean relative path", name)
	}
	return "/" + name, false, nil
}

// hasParent reports whether name walks upwards, which no archive member may do.
func hasParent(name string) bool {
	return slices.Contains(strings.Split(name, "/"), "..")
}

// ConfineLinks verifies that every symlink resolves inside the tree. A link that
// escapes the root, loops, or passes through a regular file fails, because no
// later content could make such a link usable. A target that does not exist is
// accepted: an archive may link into another package, and a Debian package may
// ship a man-page link for a package that is not installed.
//
// Each import checks its own tree, but entries of different packages are only
// combined by Merge, so a cycle or a file-crossing link can appear from two
// individually valid payloads. An assembled image checks the combined tree.
func (t *Tree) ConfineLinks() error {
	for _, entry := range t.Entries() {
		if entry.Kind != Symlink {
			continue
		}
		if _, err := t.Resolve(entry.Path); err != nil {
			return err
		}
	}
	return nil
}
