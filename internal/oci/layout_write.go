package oci

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WriteDirectory stages the layout beside dst and publishes it at a new path.
func (l *Layout) WriteDirectory(ctx context.Context, dst string, source BlobSource) error {
	if ctx == nil {
		return errors.New("layout context must not be nil")
	}
	if dst == "" {
		return errors.New("layout destination must not be empty")
	}
	dst = filepath.Clean(dst)
	if source == nil {
		return errors.New("layout blob source must not be nil")
	}
	entries, err := l.entries(false)
	if err != nil {
		return err
	}
	if destErr := checkNewDestination(dst, "layout"); destErr != nil {
		return destErr
	}
	staging, err := stageLayout(ctx, dst, entries, source)
	if err != nil {
		return err
	}
	// One rename publishes the tree: the destination is either absent or it is the
	// complete layout, and a path that appeared during staging fails the export
	// instead of being replaced. A canceled context after staging does not publish.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, os.RemoveAll(staging))
	}
	if err := renameNoReplace(staging, dst); err != nil {
		return errors.Join(fmt.Errorf("publish layout directory: %w", err), os.RemoveAll(staging))
	}
	return nil
}

// stageLayout writes every entry into a temporary directory beside the
// destination, so a failure never leaves a partial layout where the caller asked
// for one. Staging stops as soon as the context is done, which bounds the work a
// canceled export can do before it gives up.
func stageLayout(ctx context.Context, dst string, entries []layoutEntry, source BlobSource) (string, error) {
	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create layout parent directory: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".vapor-layout-*")
	if err != nil {
		return "", fmt.Errorf("create layout temporary directory: %w", err)
	}
	for index := range entries {
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = os.RemoveAll(staging)
			return "", ctxErr
		}
		if err := writeLayoutFile(staging, &entries[index], source); err != nil {
			_ = os.RemoveAll(staging)
			return "", err
		}
	}
	return staging, nil
}

// writeLayoutFile writes one entry under root, creating its directory. Content
// addressed entries are copied from the source and checked against the digest they
// are named by, so a source that returns other bytes fails the export instead of
// producing a layout that describes bytes it does not hold.
func writeLayoutFile(root string, entry *layoutEntry, source BlobSource) error {
	path := filepath.Join(root, filepath.FromSlash(entry.path))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create layout directory: %w", err)
	}
	//nolint:gosec // a layout is meant to be read by other tools and holds no secrets.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create layout file: %w", err)
	}
	var writeErr error
	if entry.digest == "" {
		writeErr = writeBytes(file, entry.body)
	} else {
		writeErr = copyBlob(file, entry, source)
	}
	if writeErr != nil {
		return errors.Join(writeErr, file.Close())
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close layout file: %w", err)
	}
	return nil
}

func checkNewDestination(dst, kind string) error {
	if dst == "" {
		return fmt.Errorf("%s destination must not be empty", kind)
	}
	_, err := os.Lstat(dst)
	if err == nil {
		return fmt.Errorf("%s destination %q already exists; choose a new path", kind, dst)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s destination: %w", kind, err)
	}
	return nil
}

// WriteTarball stages an uncompressed layout archive beside dst and publishes it
// at a new path. progress observes the bytes written so far and may be nil; it is
// called after each blob is copied, so a caller can draw a bar without polling.
func (l *Layout) WriteTarball(ctx context.Context, dst string, source BlobSource,
	progress func(written, total int64),
) error {
	if ctx == nil {
		return errors.New("tarball context must not be nil")
	}
	if source == nil {
		return errors.New("layout blob source must not be nil")
	}
	entries, err := l.entries(true)
	if err != nil {
		return err
	}
	if destErr := checkNewDestination(dst, "tarball"); destErr != nil {
		return destErr
	}
	file, err := os.CreateTemp(filepath.Dir(dst), ".vapor-tarball-*")
	if err != nil {
		return fmt.Errorf("create tarball temporary file: %w", err)
	}
	tempPath := file.Name()
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tempPath)
		}
	}()
	if err := writeLayoutTarball(ctx, file, entries, source, progress); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := closeTarball(ctx, file, tempPath); err != nil {
		return err
	}
	if err := renameNoReplace(tempPath, dst); err != nil {
		return fmt.Errorf("publish tarball: %w", err)
	}
	published = true
	return nil
}

// closeTarball finishes a staged archive: a canceled context refuses publication,
// then the bytes are synced, closed and given the permissions a reader expects.
func closeTarball(ctx context.Context, file *os.File, path string) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync tarball: %w", err), file.Close())
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close tarball: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // a layout holds no secrets.
		return fmt.Errorf("set tarball permissions: %w", err)
	}
	return nil
}

func writeLayoutTarball(ctx context.Context, dst io.Writer, entries []layoutEntry,
	source BlobSource, progress func(written, total int64),
) error {
	archive := tar.NewWriter(dst)
	total := int64(0)
	for index := range entries {
		total += entries[index].size
	}
	written := int64(0)
	for index := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeTarballEntry(archive, &entries[index], source); err != nil {
			return err
		}
		written += entries[index].size
		if progress != nil {
			progress(written, total)
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("finish tarball: %w", err)
	}
	return nil
}

// writeTarballEntry writes one member, taking its bytes from the entry or the source.
func writeTarballEntry(archive *tar.Writer, entry *layoutEntry, source BlobSource) error {
	header := &tar.Header{
		Name: entry.path, Mode: 0o644, Size: entry.size, Typeflag: tar.TypeReg,
		ModTime: epoch, Format: tar.FormatPAX,
	}
	if err := archive.WriteHeader(header); err != nil {
		return fmt.Errorf("write tarball header: %w", err)
	}
	if entry.digest == "" {
		return writeBytes(archive, entry.body)
	}
	return copyBlob(archive, entry, source)
}

func writeBytes(dst io.Writer, data []byte) error {
	written, err := dst.Write(data)
	if err != nil {
		return fmt.Errorf("write layout data: %w", err)
	}
	if written != len(data) {
		return fmt.Errorf("write layout data: %w", io.ErrShortWrite)
	}
	return nil
}

// copyBlob streams one blob from the source, hashing as it goes and refusing a
// reader whose bytes do not match the digest or size the entry declared.
func copyBlob(dst io.Writer, entry *layoutEntry, source BlobSource) error {
	reader, err := source.Open(strings.TrimPrefix(entry.digest, "sha256:"), entry.size)
	if err != nil {
		return fmt.Errorf("open layout blob: %w", err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(reader, entry.size+1))
	closeErr := reader.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("copy layout blob: %w", err)
	}
	if written != entry.size {
		return fmt.Errorf("layout blob %s has size %d, expected %d", entry.digest, written, entry.size)
	}
	computed := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if computed != entry.digest {
		return fmt.Errorf("layout blob %s has content %s", entry.digest, computed)
	}
	return nil
}
