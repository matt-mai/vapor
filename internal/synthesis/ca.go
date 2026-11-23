package synthesis

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/matt-mai/vapor/internal/certbundle"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/vfs"
)

// CA bundle modes. They mirror the spec vocabulary and are re-checked here
// because consumption must not trust an earlier stage to have validated them.
const (
	CAModeAppend  = "append"
	CAModeReplace = "replace"
)

// CAOrigin attributes bundle content to the filesystem declaration.
var CAOrigin = vfs.Origin{Path: "filesystem.ca"}

// CA writes the public certificate bundle at location. sources holds the locked
// bytes for each declared source path; nothing is read from the host.
//
// With no declaration the bundle is derived from the package payload, so an image
// that installs ca-certificates trusts the roots it was configured to trust rather
// than none at all. An image whose payload carries no such configuration is left
// alone.
//
// Append adds the declared certificates to the roots the image already trusts. The
// package's own roots count as trusted here: the bundle at location is written by
// this step, so a package that ships roots rather than a bundle has not put one
// there yet.
func CA(tree *vfs.Tree, location string, bundle *filesystem.CABundle, sources map[string][]byte) error {
	if tree == nil {
		return errors.New("CA synthesis requires an image tree")
	}
	if location == "" {
		return errors.New("CA synthesis requires a bundle location")
	}
	if bundle == nil {
		roots, err := defaultCertificates(tree)
		if err != nil || len(roots) == 0 {
			return err
		}
		return writeCertificates(tree, location, roots)
	}
	if err := validateCAMode(bundle.Mode); err != nil {
		return err
	}
	declared, err := declaredCertificates(bundle.Sources, sources)
	if err != nil {
		return err
	}
	if bundle.Mode == CAModeAppend {
		selected, err := trustedCertificates(tree, location)
		if err != nil {
			return err
		}
		declared = append(selected, declared...)
	}
	return writeCertificates(tree, location, declared)
}

// trustedCertificates returns the certificates append keeps: the bundle already at
// location, or, when there is none, the roots the package payload provides. Reading
// only the bundle would turn append into replace for every image whose bundle this
// step creates, dropping the distribution roots a TLS client needs.
func trustedCertificates(tree *vfs.Tree, location string) ([][]byte, error) {
	selected, err := selectedCertificates(tree, location)
	if err != nil || len(selected) > 0 {
		return selected, err
	}
	return defaultCertificates(tree)
}

// writeCertificates writes the public bundle and every runtime store derived from
// it, so a runtime that keeps its own trust anchors sees the same roots.
func writeCertificates(tree *vfs.Tree, location string, certificates [][]byte) error {
	if err := writeFile(tree, location, encodeCertificates(certificates), CAOrigin); err != nil {
		return err
	}
	return javaTrustStore(tree, dedupeCertificates(certificates))
}

func validateCAMode(mode string) error {
	if mode != CAModeAppend && mode != CAModeReplace {
		return fmt.Errorf("CA bundle mode %q is not append or replace", mode)
	}
	return nil
}

// declaredCertificates returns the certificates of every declared source in
// declaration order.
func declaredCertificates(paths []string, sources map[string][]byte) ([][]byte, error) {
	if len(paths) == 0 {
		return nil, errors.New("CA bundle requires at least one source")
	}
	result := make([][]byte, 0, len(paths))
	for _, name := range paths {
		content, ok := sources[name]
		if !ok {
			return nil, fmt.Errorf("CA source %q is not a locked input", name)
		}
		parsed, err := parseCertificates(name, content)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed...)
	}
	return result, nil
}

// selectedCertificates returns the certificates the image already trusts. A
// missing bundle is empty, but one that exists and cannot be read or parsed
// fails: treating it as empty would silently turn append into replace.
func selectedCertificates(tree *vfs.Tree, location string) ([][]byte, error) {
	content, err := tree.Read(location)
	if err != nil {
		if errors.Is(err, vfs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("CA bundle %s cannot be read: %w", location, err)
	}
	return parseCertificates(location, content)
}

// parseCertificates accepts only public certificate blocks, so private key
// material is refused even if an earlier stage failed to reject it.
func parseCertificates(name string, data []byte) ([][]byte, error) {
	certificates, err := certbundle.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("CA source %q %w", name, err)
	}
	return certificates, nil
}

// encodeCertificates deduplicates by DER bytes and keeps first-seen order, so
// the bundle is a deterministic function of the inputs.
func encodeCertificates(certificates [][]byte) []byte {
	var buffer bytes.Buffer
	seen := make(map[string]bool, len(certificates))
	for _, certificate := range certificates {
		if seen[string(certificate)] {
			continue
		}
		seen[string(certificate)] = true
		// pem.Encode into a bytes.Buffer cannot fail: the block is well formed and
		// the writer has no error state.
		_ = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	}
	return buffer.Bytes()
}
