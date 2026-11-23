package deb

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// ControlMember is one retained control-tarball member, already decompressed.
type ControlMember struct {
	Name string
	Data []byte
}

// ControlEvidence is the control tarball kept for later auditing: the control
// stanza, maintainer scripts and package metadata such as md5sums. Members are
// sorted by name so an audit never depends on archive order.
type ControlEvidence struct {
	Members []ControlMember
}

// Member returns the content of one control member.
func (e ControlEvidence) Member(name string) ([]byte, bool) {
	for _, member := range e.Members {
		if member.Name == name {
			return member.Data, true
		}
	}
	return nil, false
}

// Extracted is one verified package applied to a standalone tree. The tree is
// not an image: merge it with vfs.Tree.Merge so a conflicting package cannot
// leave a partially extracted image.
type Extracted struct {
	Tree    *vfs.Tree
	Control ControlEvidence
}

// Extract decodes one verified DEB and imports its data tarball into a fresh
// tree. Nothing is written before the archive decodes, and a failure returns no
// tree at all, so callers cannot observe partial extraction.
func Extract(data []byte, origin vfs.Origin) (*Extracted, error) {
	return ExtractWithin(data, origin, vfs.DefaultLimits())
}

// ExtractWithin extracts with the caller's bounds, so an image built from many
// packages can bound what it holds in total rather than only per archive.
func ExtractWithin(data []byte, origin vfs.Origin, limits vfs.Limits) (*Extracted, error) {
	archive, err := DecodeArchive(data)
	if err != nil {
		return nil, err
	}
	defer func() { _ = archive.Close() }()
	tree, err := vfs.ImportTar(archive.Data, origin, limits)
	if err != nil {
		return nil, err
	}
	control, err := readControlEvidence(archive.Control)
	if err != nil {
		return nil, err
	}
	return &Extracted{Tree: tree, Control: control}, nil
}

// readControlEvidence retains every control member. The control tarball is
// already bounded by MaxControlArchiveSize, but that bound covers the stored
// bytes, and a sparse member's logical contents are synthesized from its holes:
// a tar reader hands back header.Size bytes for one that stores almost nothing.
// Each member's declared size is therefore charged against a total budget
// before it is read, so retained evidence cannot exceed what was bounded.
//
// A name may appear only once. Two members that normalize to the same name leave
// Member returning one of them, so an audit would approve the package from a
// script it never read while the other script stayed in the evidence.
func readControlEvidence(data []byte) (ControlEvidence, error) {
	evidence := ControlEvidence{}
	seen := make(map[string]bool)
	remaining := MaxControlArchiveSize
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			slices.SortFunc(evidence.Members, func(a, b ControlMember) int {
				return strings.Compare(a.Name, b.Name)
			})
			return evidence, nil
		}
		if err != nil {
			return ControlEvidence{}, errors.New("package control archive is malformed")
		}
		member, err := readControlMember(reader, header, &remaining)
		if err != nil {
			return ControlEvidence{}, err
		}
		if member.Name == "" {
			continue
		}
		if seen[member.Name] {
			return ControlEvidence{}, fmt.Errorf("package control archive has more than one %q member",
				member.Name)
		}
		seen[member.Name] = true
		evidence.Members = append(evidence.Members, member)
	}
}

// readControlMember retains one regular member and reports the archive root as
// an empty member, which the caller skips. The member's declared size is checked
// against the budget first: reading to EOF would allocate whatever the header
// claims, which for a sparse member is unrelated to the bytes stored.
func readControlMember(reader io.Reader, header *tar.Header, remaining *int64) (ControlMember, error) {
	if isControlRoot(header) {
		return ControlMember{}, nil
	}
	name, err := controlMemberName(header.Name)
	if err != nil {
		return ControlMember{}, err
	}
	if header.Typeflag != tar.TypeReg {
		return ControlMember{}, fmt.Errorf("package control member %q is not a regular file", name)
	}
	if header.Size < 0 || header.Size > *remaining {
		return ControlMember{}, fmt.Errorf("package control evidence exceeds %d bytes",
			MaxControlArchiveSize)
	}
	// The tar reader stops at the declared size and reports a short payload as an
	// error, so reading this member allocates exactly header.Size.
	content, err := io.ReadAll(reader)
	if err != nil {
		return ControlMember{}, fmt.Errorf("package control member %q is truncated", name)
	}
	*remaining -= header.Size
	return ControlMember{Name: name, Data: content}, nil
}

// isControlRoot reports the archive's own root directory entry, which real
// control tarballs carry and which declares nothing.
func isControlRoot(header *tar.Header) bool {
	return header.Typeflag == tar.TypeDir && (header.Name == "./" || header.Name == "." || header.Name == "/")
}

// controlMemberName normalizes a control member name to a bare file name.
// Control archives are flat; a nested or escaping name is rejected rather than
// flattened, because flattening would let a member shadow another.
func controlMemberName(name string) (string, error) {
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.Contains(name, "/") {
		return "", fmt.Errorf("package control member name %q is not a plain file name", name)
	}
	return name, nil
}
