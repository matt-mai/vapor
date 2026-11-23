// Package attest builds deterministic supply-chain metadata for a finished image.
// Payloads are canonical JSON, their blob identity is a plain SHA-256 of the exact
// bytes, and element identities are domain-separated. It never reads the clock, the
// host or a network.
package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Identity domain labels. Each domain hashes one payload shape, so a payload from
// one domain can never satisfy another.
const (
	DomainPackage  = "vapor.attest.package.v1"
	DomainSlices   = "vapor.attest.slices.v1"
	DomainArtifact = "vapor.attest.artifact.v1"
	DomainModule   = "vapor.attest.module.v1"
)

// Encode renders a payload as canonical JSON: keys sorted recursively, compact, and
// no trailing newline. Sorting key order is what lets a reader rebuild the bytes from
// a decoded document, so the vectors in the reference page are reproducible without
// copying the payload's field order. Encoding/json escapes control characters, so any
// license text or description stays valid JSON without a separate text check.
func Encode(payload any) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode attestation payload: %w", err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err = decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("encode attestation payload: %w", err)
	}
	sorted, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode attestation payload: %w", err)
	}
	return sorted, nil
}

// Digest is the blob identity of exact payload bytes. It is a plain SHA-256 with no
// domain label, because this value names an OCI blob a reader can fetch and verify.
func Digest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Identity is a domain-separated element identity:
// sha256(label_bytes || 0x00 || canonical_json(payload)). The element is described by
// its content and version, never by the mirror it came from, so a mirror change does
// not multiply elements. Source attribution belongs to provenance.
func Identity(domain string, payload any) (string, error) {
	if domain == "" {
		return "", errors.New("attestation identity requires a domain label")
	}
	encoded, err := Encode(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	digest.Write([]byte(domain))
	digest.Write([]byte{0})
	digest.Write(encoded)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// packagePayload is the identity of one whole package on one platform.
type packagePayload struct {
	Platform     string `json:"platform"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

// PackageIdentity names one locked whole package by its platform, name, version,
// native architecture and exact payload bytes.
func PackageIdentity(platform, name, version, architecture, content string, size int64) (string, error) {
	return Identity(DomainPackage, packagePayload{
		Platform: platform, Name: name, Version: version, Architecture: architecture,
		SHA256: content, Size: size,
	})
}

// slicesPayload is the identity of one package's sliced content on one platform. It
// names the package rather than one slice, because a document describes the package
// once: an advisory is filed under the package, so one element per slice would report
// the same finding several times. Slices is the dependency-first closure, which is a
// semantic order and not sorted.
type slicesPayload struct {
	Platform     string   `json:"platform"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	Architecture string   `json:"architecture"`
	Definition   string   `json:"definition"`
	SHA256       string   `json:"sha256"`
	Size         int64    `json:"size"`
	Slices       []string `json:"slices"`
}

// SlicesIdentity names one package's sliced content. Definition is the locked
// selected-definition closure digest, so a different definition file produces a
// different element even when the payload bytes are identical.
func SlicesIdentity(platform, name, version, architecture, definition, content string,
	size int64, closure []string,
) (string, error) {
	return Identity(DomainSlices, slicesPayload{
		Platform: platform, Package: name, Version: version, Architecture: architecture,
		Definition: definition, SHA256: content, Size: size,
		Slices: append([]string{}, closure...),
	})
}

// ArtifactVersion is the declared upstream identity of an artifact, which is what an
// SBOM reports because an artifact payload has no package metadata of its own. CPE is
// absent when the specification declares none, so a payload that only a purl names keeps
// the identity it had before a CPE could be declared.
type ArtifactVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	CPE     string `json:"cpe,omitempty"`
}

// artifactPayload is the identity of one artifact payload on one platform. The URL is
// absent because identity is what the bytes are, not where they were fetched from.
type artifactPayload struct {
	Platform string          `json:"platform"`
	Name     string          `json:"name"`
	Identity ArtifactVersion `json:"identity"`
	SHA256   string          `json:"sha256"`
	Size     int64           `json:"size"`
}

// ArtifactIdentity names one locked artifact payload by its name, platform, declared
// upstream identity and exact bytes.
func ArtifactIdentity(platform, name string, identity ArtifactVersion, content string,
	size int64,
) (string, error) {
	return Identity(DomainArtifact, artifactPayload{
		Platform: platform, Name: name, Identity: identity, SHA256: content, Size: size,
	})
}
