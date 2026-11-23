// Package oci serializes an image filesystem into deterministic OCI content and
// publishes it to local or registry sinks.
package oci

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/matt-mai/vapor/internal/vfs"
)

// epoch is the modification time of every generated member. Tar stores whole
// seconds, so the Unix epoch is the only value that survives every format without
// a fractional-second record and without depending on a clock.
var epoch = time.Unix(0, 0).UTC()

// Descriptor identifies one serialized layer by its uncompressed identity. The
// compressed digest is a different value and is computed by the compression
// step, never derived from this one.
type Descriptor struct {
	// DiffID is "sha256:<hex>" of the uncompressed tar stream.
	DiffID string
	// Size is the length of the uncompressed tar stream in bytes.
	Size int64
}

// WriteLayer serializes a tree as an uncompressed tar layer and returns its
// uncompressed identity. Entries are written in the tree's sorted path order, so
// declaration order and map iteration cannot reach the bytes.
//
// Names are relative, as OCI layers require; directories carry a trailing slash
// and the image root is not a member, because it declares nothing. Every member
// carries the image's own ownership and mode with an epoch timestamp and no user
// or group names, so no host metadata can enter the layer. The first name of a
// shared inode is written as a regular file and each later name as a hard link to
// it, which is how a whole group survives with its content stored once.
func WriteLayer(dst io.Writer, tree *vfs.Tree) (Descriptor, error) {
	if dst == nil {
		return Descriptor{}, errors.New("layer serialization requires a writer")
	}
	if tree == nil {
		return Descriptor{}, errors.New("layer serialization requires a tree")
	}
	if err := tree.ConfineLinks(); err != nil {
		return Descriptor{}, err
	}
	hash, counted := sha256.New(), &countingWriter{writer: dst}
	archive := tar.NewWriter(io.MultiWriter(hash, counted))
	serializer := &layerWriter{tree: tree, archive: archive, inodes: tree.Inodes(),
		links: make(map[uint64]string)}
	for _, entry := range tree.Entries() {
		if err := serializer.entry(&entry); err != nil {
			return Descriptor{}, err
		}
	}
	// Close writes the end-of-archive marker, so it must be part of the digest and
	// the size rather than a detail of a wrapped writer.
	if err := archive.Close(); err != nil {
		return Descriptor{}, fmt.Errorf("layer serialization failed: %w", err)
	}
	return Descriptor{DiffID: "sha256:" + hex.EncodeToString(hash.Sum(nil)), Size: counted.written}, nil
}

// layerWriter carries the state one serialization needs: the tree it reads from,
// the archive it writes to, and the first path seen for each inode.
type layerWriter struct {
	tree    *vfs.Tree
	archive *tar.Writer
	inodes  map[string]uint64
	links   map[uint64]string
}

func (s *layerWriter) entry(entry *vfs.Entry) error {
	name := strings.TrimPrefix(entry.Path, "/")
	// A reader treats a ".wh." name as a deletion marker, so a file that carries
	// one would delete its neighbors instead of being an ordinary member.
	if base := path.Base(name); strings.HasPrefix(base, ".wh.") {
		return fmt.Errorf("layer entry %q uses the reserved whiteout prefix", entry.Path)
	}
	header := &tar.Header{
		Name:    name,
		Mode:    unixMode(entry.Mode),
		Uid:     int(entry.UID),
		Gid:     int(entry.GID),
		ModTime: epoch,
	}
	switch entry.Kind {
	case vfs.Dir:
		header.Typeflag = tar.TypeDir
		header.Name += "/"
	case vfs.Symlink:
		header.Typeflag = tar.TypeSymlink
		header.Linkname = entry.Target
	case vfs.File:
		if target, linked := s.links[s.inodes[entry.Path]]; linked {
			header.Typeflag = tar.TypeLink
			header.Linkname = strings.TrimPrefix(target, "/")
		} else {
			s.links[s.inodes[entry.Path]] = entry.Path
			header.Typeflag = tar.TypeReg
			header.Size = entry.Size
		}
	default:
		return fmt.Errorf("layer entry %q has unsupported kind %q", entry.Path, entry.Kind)
	}
	if err := s.archive.WriteHeader(header); err != nil {
		return fmt.Errorf("layer entry %q: %w", entry.Path, err)
	}
	if header.Typeflag != tar.TypeReg {
		return nil
	}
	content, err := s.tree.Read(entry.Path)
	if err != nil {
		return fmt.Errorf("layer entry %q: %w", entry.Path, err)
	}
	if _, err := s.archive.Write(content); err != nil {
		return fmt.Errorf("layer entry %q: %w", entry.Path, err)
	}
	return nil
}

// unixMode converts a portable mode back into the tar header's Unix mode, where
// the special bits live in their traditional octal positions instead of beside
// the permission bits.
func unixMode(mode fs.FileMode) int64 {
	value := int64(mode.Perm())
	for special, bit := range map[fs.FileMode]int64{
		fs.ModeSetuid: 0o4000,
		fs.ModeSetgid: 0o2000,
		fs.ModeSticky: 0o1000,
	} {
		if mode&special != 0 {
			value |= bit
		}
	}
	return value
}

// countingWriter records the bytes the archive emitted. The tar writer may fail
// part-way, so the count is taken from successful writes only.
type countingWriter struct {
	writer  io.Writer
	written int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.written += int64(n)
	return n, err
}
