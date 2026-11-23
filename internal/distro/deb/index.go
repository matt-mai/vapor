package deb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/klauspost/compress/gzip"

	"github.com/ulikunitz/xz"

	"github.com/matt-mai/vapor/internal/xzguard"
)

// MaxIndexSize bounds an uncompressed package index. For scale, the Ubuntu
// 26.04 amd64 indexes are about 7.2 MiB (main), 73.2 MiB (universe) and 1.3 MiB
// (multiverse); universe is the largest. The cap leaves roughly 3.5x headroom
// for archive growth while still bounding the fully buffered index. Exceeding
// it fails the whole index rather than truncating it.
const MaxIndexSize int64 = 256 << 20

// IndexFormat identifies the supported package index encodings.
type IndexFormat string

// Supported package index encodings.
const (
	IndexFormatXZ    IndexFormat = "xz"
	IndexFormatGzip  IndexFormat = "gz"
	IndexFormatPlain IndexFormat = "plain"
)

// ByHashPolicy controls acquisition through the suite's by-hash tree.
type ByHashPolicy string

// By-hash acquisition policies.
const (
	ByHashPrefer  ByHashPolicy = "prefer"
	ByHashRequire ByHashPolicy = "require"
	ByHashDisable ByHashPolicy = "disable"
)

// Index is one authenticated package index selected for acquisition.
type Index struct {
	Component    string
	Architecture string
	// Path is canonical and relative to the suite directory; lock evidence uses it.
	Path   string
	Format IndexFormat
	SHA256 string
	Size   int64
	// AcquirePaths are tried in order. Every candidate is verified against
	// SHA256 and Size, so a by-hash fallback cannot weaken authentication.
	AcquirePaths []string
	// PlainSHA256 and PlainSize are what the signed release says about the same
	// index in the plain Packages path, and 0 when it names none. They are the only
	// authenticated values a decoded index can be checked against.
	PlainSHA256 string
	PlainSize   int64
}

// SelectIndex chooses Packages.xz, then Packages.gz, then Packages from
// authenticated release metadata. The release must already match the target
// suite, architecture and components.
func SelectIndex(release *Release, component, architecture string, policy ByHashPolicy) (Index, error) {
	if !safeIndexValue(component) || !safeIndexValue(architecture) {
		return Index{}, errors.New("invalid index component or architecture")
	}
	formats := []struct {
		format IndexFormat
		suffix string
	}{
		{IndexFormatXZ, ".xz"},
		{IndexFormatGzip, ".gz"},
		{IndexFormatPlain, ""},
	}
	for _, candidate := range formats {
		canonical := path.Join(component, "binary-"+architecture, "Packages"+candidate.suffix)
		file, ok := release.Files[canonical]
		if !ok {
			continue
		}
		acquirePaths, err := indexAcquirePaths(release, component, architecture, canonical, file.SHA256, policy)
		if err != nil {
			return Index{}, err
		}
		// A release names the plain index in its own path, which is the one digest a
		// decoded index can be checked against.
		plain, hasPlain := release.Files[path.Join(component, "binary-"+architecture, "Packages")]
		var plainSHA256 string
		var plainSize int64
		if hasPlain {
			plainSHA256, plainSize = plain.SHA256, plain.Size
		}
		return Index{
			Component:    component,
			Architecture: architecture,
			Path:         canonical,
			Format:       candidate.format,
			SHA256:       file.SHA256,
			Size:         file.Size,
			AcquirePaths: acquirePaths,
			PlainSHA256:  plainSHA256,
			PlainSize:    plainSize,
		}, nil
	}
	return Index{}, fmt.Errorf("release metadata has no Packages index for %s/%s", component, architecture)
}

func indexAcquirePaths(release *Release, component, architecture, canonical, hash string, policy ByHashPolicy) ([]string, error) {
	byHash := path.Join(component, "binary-"+architecture, "by-hash", "SHA256", hash)
	switch policy {
	case ByHashDisable:
		return []string{canonical}, nil
	case ByHashPrefer:
		if release.AcquireByHash {
			return []string{byHash, canonical}, nil
		}
		return []string{canonical}, nil
	case ByHashRequire:
		if !release.AcquireByHash {
			return nil, fmt.Errorf("repository does not advertise Acquire-By-Hash")
		}
		return []string{byHash}, nil
	default:
		return nil, fmt.Errorf("unsupported by-hash policy %q", policy)
	}
}

func safeIndexValue(value string) bool {
	return value != "" && path.Clean(value) == value && !path.IsAbs(value) &&
		!strings.ContainsAny(value, "/\\")
}

// VerifyIndex checks the compressed bytes against authenticated metadata before
// decompressing them with an output bound.
func VerifyIndex(index *Index, compressed []byte) ([]byte, error) {
	if int64(len(compressed)) != index.Size {
		return nil, errors.New("index size does not match authenticated metadata")
	}
	sum := sha256.Sum256(compressed)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), index.SHA256) {
		return nil, errors.New("index SHA256 does not match authenticated metadata")
	}
	return decompressIndex(index.Format, compressed, MaxIndexSize)
}

func decompressIndex(format IndexFormat, data []byte, limit int64) ([]byte, error) {
	switch format {
	case IndexFormatXZ:
		if err := xzguard.Check(data, xzguard.MaxDictionarySize); err != nil {
			return nil, err
		}
		reader, err := xz.ReaderConfig{DictCap: xzguard.MaxDictionarySize}.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("index decompression failed")
		}
		return readBounded(reader, limit)
	case IndexFormatGzip:
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("index decompression failed")
		}
		return readBounded(reader, limit)
	case IndexFormatPlain:
		return readBounded(bytes.NewReader(data), limit)
	default:
		return nil, fmt.Errorf("unsupported index format %q", format)
	}
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errors.New("index decompression failed")
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("index exceeds %d bytes", limit)
	}
	return data, nil
}
