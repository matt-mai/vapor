// Package snapshot captures declared local inputs and catalogues as immutable bytes.
package snapshot

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/certbundle"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

const (
	roleTrustKey = "trust-key"
	roleCA       = "ca"
	roleVEX      = "vex"
)

// MaxLocalInputSize bounds one trust-key, CA or VEX snapshot.
const MaxLocalInputSize int64 = 64 << 20

// Store publishes verified content-addressed bytes.
type Store interface {
	Store(reader io.Reader, digest string, size int64) error
}

// Catalogue records a local catalogue declaration and its canonical snapshot.
type Catalogue struct {
	Name   string
	Digest string
	Tree   catalogue.Tree
}

// Result records the immutable evidence retained for later offline builds.
type Result struct {
	Inputs     []lock.LocalInput
	Catalogues []Catalogue
}

type declaration struct {
	role         string
	path         string
	fingerprints []string
}

// Snapshot reads every declared trust key, CA source, VEX input and local
// catalogue relative to specDir and caches the exact bytes.
func Snapshot(specDir string, specification *spec.Spec, store Store) (Result, error) {
	if specDir == "" {
		return Result{}, errors.New("spec directory must not be empty")
	}
	if specification == nil {
		return Result{}, errors.New("specification must not be nil")
	}
	if store == nil {
		return Result{}, errors.New("snapshot store must not be nil")
	}
	declarations := collectDeclarations(specification)
	inputs, err := snapshotInputs(specDir, declarations, store)
	if err != nil {
		return Result{}, err
	}
	catalogues, err := snapshotCatalogues(specDir, specification, store)
	if err != nil {
		return Result{}, err
	}
	return Result{Inputs: inputs, Catalogues: catalogues}, nil
}

func collectDeclarations(specification *spec.Spec) []declaration {
	unique := make(map[string]*declaration)
	add := func(role, path string, fingerprints []string) {
		key := role + "\x00" + path
		if existing, ok := unique[key]; ok {
			existing.fingerprints = appendUnique(existing.fingerprints, fingerprints)
			return
		}
		unique[key] = &declaration{role: role, path: path, fingerprints: appendUnique(nil, fingerprints)}
	}
	for i := range specification.Contents.Repositories {
		for _, key := range specification.Contents.Repositories[i].Trust.Keys {
			add(roleTrustKey, key.Path, key.Fingerprints)
		}
	}
	if specification.Filesystem.CA != nil {
		for _, source := range specification.Filesystem.CA.Sources {
			add(roleCA, source, nil)
		}
	}
	for _, input := range specification.VEX.Inputs {
		add(roleVEX, input, nil)
	}
	result := make([]declaration, 0, len(unique))
	for _, item := range unique {
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].role != result[j].role {
			return result[i].role < result[j].role
		}
		return result[i].path < result[j].path
	})
	return result
}

func appendUnique(existing, values []string) []string {
	for _, value := range values {
		found := slices.Contains(existing, value)
		if !found {
			existing = append(existing, value)
		}
	}
	return existing
}

func snapshotInputs(specDir string, declarations []declaration, store Store) ([]lock.LocalInput, error) {
	if len(declarations) == 0 {
		return []lock.LocalInput{}, nil
	}
	root, err := os.OpenRoot(specDir)
	if err != nil {
		return nil, errors.New("open spec directory failed")
	}
	defer func() { _ = root.Close() }()
	result := make([]lock.LocalInput, 0, len(declarations))
	for i := range declarations {
		item := &declarations[i]
		data, err := readLocalFile(root, item.path)
		if err != nil {
			return nil, fmt.Errorf("%s input %q: %w", item.role, item.path, err)
		}
		if err := validateInput(item, data); err != nil {
			return nil, fmt.Errorf("%s input %q: %w", item.role, item.path, err)
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if err := store.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
			return nil, fmt.Errorf("%s input %q: store snapshot: %w", item.role, item.path, err)
		}
		result = append(result, lock.LocalInput{
			Role:   item.role,
			Path:   item.path,
			SHA256: digest,
			Size:   int64(len(data)),
		})
	}
	return result, nil
}

func readLocalFile(root *os.Root, declaredPath string) ([]byte, error) {
	if err := base.ValidateLocalPath(declaredPath); err != nil {
		return nil, err
	}
	name := filepath.FromSlash(declaredPath)
	info, err := root.Stat(name)
	if err != nil {
		return nil, errors.New("inspect input failed")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	// O_NONBLOCK prevents a replacement FIFO from blocking before Stat rejects it.
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open input failed")
	}
	defer func() { _ = file.Close() }()
	if info, err = file.Stat(); err != nil {
		return nil, errors.New("inspect input failed")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if info.Size() > MaxLocalInputSize {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxLocalInputSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxLocalInputSize+1))
	if err != nil {
		return nil, errors.New("read input failed")
	}
	if int64(len(data)) > MaxLocalInputSize {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxLocalInputSize)
	}
	return data, nil
}

// Local opens payload files declared relative to the specification directory. The
// root confines every open, so a path cannot escape the directory it is declared in.
type Local struct{ specDir string }

// NewLocal returns a reader for the specification directory's own files.
func NewLocal(specDir string) Local { return Local{specDir: specDir} }

// Open returns one regular file. The caller closes it.
func (l Local) Open(declaredPath string) (io.ReadCloser, error) {
	if err := base.ValidateLocalPath(declaredPath); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(l.specDir)
	if err != nil {
		return nil, errors.New("open spec directory failed")
	}
	defer func() { _ = root.Close() }()
	name := filepath.FromSlash(declaredPath)
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("inspect artifact payload failed")
	}
	// O_NONBLOCK keeps a replacement FIFO from blocking before Stat rejects it.
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open artifact payload failed")
	}
	if opened, statErr := file.Stat(); statErr != nil || !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("artifact payload must be a regular file")
	}
	return file, nil
}

func validateInput(item *declaration, data []byte) error {
	if containsPrivateKey(data) {
		return errors.New("private key material is not a local input")
	}
	switch item.role {
	case roleTrustKey:
		if _, err := deb.LoadTrustedKeys(data, item.fingerprints); err != nil {
			return fmt.Errorf("invalid public key snapshot: %w", err)
		}
	case roleCA:
		return validateCertificates(data)
	}
	return nil
}

func containsPrivateKey(data []byte) bool {
	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			return true
		}
		rest = remainder
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("openssh-key-v1\x00")) {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(trimmed); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(trimmed); err == nil {
		return true
	}
	_, err := x509.ParseECPrivateKey(trimmed)
	return err == nil
}

// validateCertificates accepts a PEM bundle whose blocks are all public
// certificates. The shared parser owns the spelling of every failure, so a snapshot
// and the image's bundle accept exactly the same files.
func validateCertificates(data []byte) error {
	if _, err := certbundle.Parse(data); err != nil {
		return fmt.Errorf("CA input %w", err)
	}
	return nil
}

func snapshotCatalogues(specDir string, specification *spec.Spec, store Store) ([]Catalogue, error) {
	result := make([]Catalogue, 0, len(specification.Contents.Catalogues))
	for i := range specification.Contents.Catalogues {
		source := &specification.Contents.Catalogues[i]
		if source.Path == nil {
			continue
		}
		tree, err := catalogue.SnapshotDirectory(specDir, *source.Path, store)
		if err != nil {
			return nil, fmt.Errorf("catalogue %q: %w", source.Name, err)
		}
		digest, err := tree.Digest()
		if err != nil {
			return nil, fmt.Errorf("catalogue %q: compute tree digest: %w", source.Name, err)
		}
		result = append(result, Catalogue{Name: source.Name, Digest: digest, Tree: tree})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
