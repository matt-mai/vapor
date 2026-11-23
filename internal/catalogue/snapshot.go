package catalogue

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// MaxArchiveDecompressedSize bounds tar bytes after decompression. It allows
// maximum-size file content plus one maximum-length path and header per entry.
const MaxArchiveDecompressedSize int64 = MaxTreeContentSize + MaxTreeEntries*(MaxTreePathSize+512)

// MaxArchiveHeaders bounds every header processed from an archive, including
// headers that do not become tree entries.
const MaxArchiveHeaders = MaxTreeEntries + 1

// BlobStore publishes verified content-addressed bytes.
type BlobStore interface {
	Store(reader io.Reader, digest string, size int64) error
}

// SnapshotDirectory resolves declaredPath against specDir, validates its tree
// and caches every regular file byte for offline use.
func SnapshotDirectory(specDir, declaredPath string, store BlobStore) (Tree, error) {
	if specDir == "" {
		return Tree{}, errors.New("spec directory must not be empty")
	}
	if store == nil {
		return Tree{}, errors.New("blob store must not be nil")
	}
	if err := base.ValidateLocalPath(declaredPath); err != nil {
		return Tree{}, err
	}
	root, err := os.OpenRoot(filepath.Join(specDir, filepath.FromSlash(declaredPath)))
	if err != nil {
		return Tree{}, errors.New("open catalogue directory failed")
	}
	defer func() { _ = root.Close() }()

	entries, err := readDirectoryEntries(root, store)
	if err != nil {
		return Tree{}, err
	}
	return NewTree(entries)
}

// SnapshotArchive validates and caches a verified tar or tar.gz catalogue
// archive, then returns its canonical tree.
func SnapshotArchive(data []byte, store BlobStore) (Tree, error) {
	return snapshotArchiveWithHeaderLimit(data, store, MaxArchiveHeaders)
}

// snapshotArchiveWithHeaderLimit is SnapshotArchive with an explicit header
// limit. Walking the real limit means processing a hundred thousand headers, so
// the header-bound test passes a small one.
func snapshotArchiveWithHeaderLimit(data []byte, store BlobStore, maxHeaders int) (Tree, error) {
	if store == nil {
		return Tree{}, errors.New("blob store must not be nil")
	}
	reader, closeReader, err := archiveReader(data)
	if err != nil {
		return Tree{}, err
	}
	if closeReader != nil {
		defer func() { _ = closeReader.Close() }()
	}
	entries, err := readArchiveEntries(reader, store, maxHeaders)
	if err != nil {
		return Tree{}, err
	}
	tree, err := NewTree(entries)
	if err != nil {
		return Tree{}, err
	}
	if err := cacheArchive(data, store); err != nil {
		return Tree{}, err
	}
	return tree, nil
}

func readDirectoryEntries(root *os.Root, store BlobStore) ([]Entry, error) {
	entries := make([]Entry, 0, 64)
	budget := MaxTreeContentSize
	walkErr := fs.WalkDir(root.FS(), ".", func(name string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read catalogue entry %q", name)
		}
		if name == "." {
			return nil
		}
		entry, err := snapshotDirectoryEntry(root, name, &budget, store)
		if err != nil {
			return err
		}
		return appendTreeEntry(&entries, &entry)
	})
	return entries, walkErr
}

func snapshotDirectoryEntry(root *os.Root, name string, budget *int64, store BlobStore) (Entry, error) {
	info, err := root.Lstat(filepath.FromSlash(name))
	if err != nil {
		return Entry{}, fmt.Errorf("read catalogue entry %q", name)
	}
	switch {
	case info.IsDir():
		return Entry{Path: name, Kind: KindDir}, nil
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := root.Readlink(filepath.FromSlash(name))
		if err != nil {
			return Entry{}, fmt.Errorf("read catalogue symlink %q", name)
		}
		return Entry{Path: name, Kind: KindSymlink, Target: target}, nil
	case info.Mode().IsRegular():
		return snapshotDirectoryFile(root, name, info.Size(), budget, store)
	default:
		return Entry{}, fmt.Errorf("catalogue entry %q has an unsupported file type", name)
	}
}

func snapshotDirectoryFile(root *os.Root, name string, size int64, budget *int64,
	store BlobStore) (Entry, error) {
	limit := min(MaxTreeFileSize, *budget)
	if size > limit {
		return Entry{}, fmt.Errorf("catalogue file %q exceeds the size limit", name)
	}
	data, opened, err := readCatalogueFile(root, name, limit)
	if err != nil {
		return Entry{}, err
	}
	*budget -= int64(len(data))
	return cachedFileEntry(name, opened.Mode().Perm()&0o111 != 0, data, store)
}

func readArchiveEntries(reader io.Reader, store BlobStore, maxHeaders int) ([]Entry, error) {
	entries := make([]Entry, 0, 64)
	budget := MaxTreeContentSize
	archive := tar.NewReader(&archiveBudgetReader{reader: reader, limit: MaxArchiveDecompressedSize})
	headers := 0
	for {
		entry, skip, done, err := nextArchiveEntry(archive, &headers, &budget, store, maxHeaders)
		if err != nil {
			return nil, err
		}
		if done {
			return entries, nil
		}
		if skip {
			continue
		}
		if err := appendTreeEntry(&entries, &entry); err != nil {
			return nil, err
		}
	}
}

func nextArchiveEntry(archive *tar.Reader, headers *int, budget *int64, store BlobStore,
	maxHeaders int,
) (Entry, bool, bool, error) {
	header, err := archive.Next()
	if errors.Is(err, io.EOF) {
		return Entry{}, false, true, nil
	}
	if err != nil {
		return Entry{}, false, false, errors.New("catalogue archive is not a valid tar archive")
	}
	*headers++
	if *headers > maxHeaders {
		return Entry{}, false, false, fmt.Errorf("catalogue archive has more than %d headers", maxHeaders)
	}
	entry, skip, err := snapshotArchiveEntry(archive, header, budget, store)
	return entry, skip, false, err
}

func snapshotArchiveEntry(archive *tar.Reader, header *tar.Header, budget *int64, store BlobStore) (Entry, bool, error) {
	name, skip := archiveEntryName(header.Name, header.Typeflag == tar.TypeDir)
	if skip {
		return Entry{}, true, nil
	}
	switch header.Typeflag {
	case tar.TypeDir:
		return Entry{Path: name, Kind: KindDir}, false, nil
	case tar.TypeReg:
		entry, err := snapshotArchiveFile(archive, header, name, budget, store)
		return entry, false, err
	case tar.TypeSymlink:
		return Entry{Path: name, Kind: KindSymlink, Target: header.Linkname}, false, nil
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return Entry{}, true, nil
	default:
		return Entry{}, false, fmt.Errorf("catalogue archive entry %q has an unsupported type", name)
	}
}

func snapshotArchiveFile(archive *tar.Reader, header *tar.Header, name string, budget *int64, store BlobStore) (Entry, error) {
	if header.Size < 0 || header.Size > MaxTreeFileSize || header.Size > *budget {
		return Entry{}, fmt.Errorf("catalogue archive file %q exceeds the size limit", name)
	}
	content, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(content)) != header.Size {
		return Entry{}, errors.New("catalogue archive contains truncated file data")
	}
	*budget -= header.Size
	return cachedFileEntry(name, header.Mode&0o111 != 0, content, store)
}

type archiveBudgetReader struct {
	reader io.Reader
	read   int64
	limit  int64
}

func (r *archiveBudgetReader) Read(data []byte) (int, error) {
	if r.read > r.limit {
		return 0, errors.New("catalogue archive exceeds the decompressed size limit")
	}
	n, err := r.reader.Read(data)
	r.read += int64(n)
	if r.read > r.limit {
		return n, errors.New("catalogue archive exceeds the decompressed size limit")
	}
	return n, err
}

func archiveReader(data []byte) (io.Reader, io.Closer, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return bytes.NewReader(data), nil, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, errors.New("catalogue archive is not valid gzip data")
	}
	return reader, reader, nil
}

func archiveEntryName(name string, directory bool) (string, bool) {
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || name == "." {
		return "", directory
	}
	return name, false
}

func appendTreeEntry(entries *[]Entry, entry *Entry) error {
	if len(*entries) >= MaxTreeEntries {
		return fmt.Errorf("catalogue tree has more than %d entries", MaxTreeEntries)
	}
	*entries = append(*entries, *entry)
	return nil
}

func readCatalogueFile(root *os.Root, name string, limit int64) ([]byte, fs.FileInfo, error) {
	// O_NONBLOCK prevents a replacement FIFO from blocking before the opened
	// descriptor is checked.
	file, err := root.OpenFile(filepath.FromSlash(name), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("read catalogue file %q", name)
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("catalogue file %q is not a regular file", name)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, nil, fmt.Errorf("read catalogue file %q", name)
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("catalogue file %q exceeds the size limit", name)
	}
	return data, info, nil
}

func cachedFileEntry(name string, executable bool, data []byte, store BlobStore) (Entry, error) {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err := store.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		return Entry{}, fmt.Errorf("cache catalogue file %q", name)
	}
	return Entry{
		Path:       name,
		Kind:       KindFile,
		Executable: executable,
		SHA256:     digest,
		Size:       int64(len(data)),
	}, nil
}

func cacheArchive(data []byte, store BlobStore) error {
	sum := sha256.Sum256(data)
	if err := store.Store(bytes.NewReader(data), hex.EncodeToString(sum[:]), int64(len(data))); err != nil {
		return errors.New("cache catalogue archive failed")
	}
	return nil
}
