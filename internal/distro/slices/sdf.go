package slices

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

var (
	packageNamePattern = regexp.MustCompile(`^[a-z0-9](?:-?[.a-z0-9+])+$`)
	sliceNamePattern   = regexp.MustCompile(`^[a-z](?:-?[a-z0-9]){2,}$`)
)

var catalogueArchitectures = map[string]bool{
	"amd64":   true,
	"arm64":   true,
	"armhf":   true,
	"i386":    true,
	"ppc64el": true,
	"riscv64": true,
	"s390x":   true,
}

// MaxHintSize is the maximum hint length in bytes.
const MaxHintSize = 40

// Package is one decoded slice definition file.
type Package struct {
	RealName     string
	Name         string
	Archive      string
	Store        string
	DefaultTrack string
	Path         string
	SHA256       string
	Size         int64
	Slices       map[string]Slice
}

// Slice is one named slice in a package.
type Slice struct {
	Package   string
	Name      string
	Hint      string
	Essential map[SliceKey]EssentialInfo
	Contents  map[string]PathInfo
	Mutate    string
}

// SliceKey identifies a package slice.
type SliceKey struct {
	Package string
	Slice   string
}

func (k SliceKey) String() string {
	return k.Package + "_" + k.Slice
}

// EssentialInfo is an essential reference and its architecture filter.
type EssentialInfo struct {
	Arch []string
}

// PathKind is one content operation.
type PathKind string

// Path kinds for content operations.
const (
	PathDir      PathKind = "dir"
	PathCopy     PathKind = "copy"
	PathGlob     PathKind = "glob"
	PathText     PathKind = "text"
	PathSymlink  PathKind = "symlink"
	PathGenerate PathKind = "generate"
)

// PathUntil controls temporary content lifetime.
type PathUntil string

// Temporary path lifetimes.
const (
	UntilNone   PathUntil = ""
	UntilMutate PathUntil = "mutate"
)

// GenerateKind is a generated content operation.
type GenerateKind string

// GenerateManifest emits a manifest for the generated tree.
const GenerateManifest GenerateKind = "manifest"

// PathInfo is one decoded content declaration.
type PathInfo struct {
	Kind     PathKind
	Info     string
	Mode     uint32
	Mutable  bool
	Until    PathUntil
	Arch     []string
	Generate GenerateKind
	Prefer   string
}

// SameContent reports whether two declarations produce identical content.
// Architecture filters, lifetime and preference do not change the bytes.
func (p *PathInfo) SameContent(other *PathInfo) bool {
	return p.Kind == other.Kind &&
		p.Info == other.Info &&
		p.Mode == other.Mode &&
		p.Mutable == other.Mutable &&
		p.Generate == other.Generate
}

// ParsePackages discovers and strictly decodes slices/ and optional bin-slices/
// beneath fsys. The catalogue supplies archive and store references.
func ParsePackages(fsys fs.FS, catalogue *Catalogue) (map[string]*Package, error) {
	if fsys == nil {
		return nil, errors.New("slice definition filesystem must not be nil")
	}
	if catalogue == nil {
		return nil, errors.New("catalogue metadata must not be nil")
	}
	packages := make(map[string]*Package)
	if err := readSDFDirectory(fsys, "slices", catalogue, packages); err != nil {
		return nil, err
	}
	if _, statErr := fs.Stat(fsys, "bin-slices"); statErr == nil {
		if err := readSDFDirectory(fsys, "bin-slices", catalogue, packages); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return nil, errors.New("read bin-slices directory failed")
	}
	return packages, nil
}

func readSDFDirectory(fsys fs.FS, dir string, catalogue *Catalogue, packages map[string]*Package) error {
	info, statErr := fs.Stat(fsys, dir)
	if statErr != nil || !info.IsDir() {
		return fmt.Errorf("read %s directory failed", dir)
	}
	return fs.WalkDir(fsys, dir, func(name string, entry fs.DirEntry, err error) error {
		return readSDFEntry(fsys, dir, name, entry, err, catalogue, packages)
	})
}

func readSDFEntry(fsys fs.FS, dir, name string, entry fs.DirEntry, walkErr error,
	catalogue *Catalogue, packages map[string]*Package) error {
	if walkErr != nil {
		return fmt.Errorf("read %s directory failed", dir)
	}
	if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
		return nil
	}
	base := strings.TrimSuffix(entry.Name(), ".yaml")
	if !packageNamePattern.MatchString(base) {
		return fmt.Errorf("invalid slice definition filename %q", entry.Name())
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return errors.New("read slice definition file failed")
	}
	pkg, err := parsePackage(data, base, name, catalogue)
	if err != nil {
		return err
	}
	if previous, ok := packages[pkg.Name]; ok {
		return fmt.Errorf("package %q is defined more than once: %s and %s", pkg.Name, previous.Path, pkg.Path)
	}
	packages[pkg.Name] = pkg
	return nil
}

func parsePackage(data []byte, name, filePath string, catalogue *Catalogue) (*Package, error) {
	raw, err := decodePackage(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	if raw.Package != name {
		return nil, fmt.Errorf("%s: package field %q does not match filename %q", filePath, raw.Package, name)
	}
	pkg := &Package{
		RealName:     name,
		Name:         name,
		Archive:      raw.Archive,
		Store:        raw.Store,
		DefaultTrack: raw.DefaultTrack,
		Path:         filePath,
		SHA256:       fmt.Sprintf("%x", sha256.Sum256(data)),
		Size:         int64(len(data)),
		Slices:       make(map[string]Slice),
	}
	if targetErr := validatePackageTargets(&raw, catalogue, pkg); targetErr != nil {
		return nil, fmt.Errorf("%s: %w", filePath, targetErr)
	}
	packageEssential, err := parseEssentials(raw.Essential)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	for _, sliceName := range sortedKeys(raw.Slices) {
		slice, sliceErr := parseSlice(pkg, sliceName, raw.Slices[sliceName], packageEssential)
		if sliceErr != nil {
			return nil, fmt.Errorf("%s: %w", filePath, sliceErr)
		}
		pkg.Slices[sliceName] = slice
	}
	return pkg, nil
}
