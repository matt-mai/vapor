package attest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// SBOMInput is one platform's locked inputs and the tree built from them. The tree
// says what the image contains; the lock says what each contributor is and where its
// bytes came from. Nothing else is consulted.
type SBOMInput struct {
	// Name is the image name, Platform the platform, and Subject the digest of the
	// platform manifest the document describes.
	Name     string
	Platform string
	Subject  string
	Distro   string
	Release  string

	Packages  []lock.Package
	Slices    []lock.Slice
	Artifacts []lock.Artifact
	Tree      *vfs.Tree
	// Original holds the pre-mutation digest of every mutable path, so a file a slice
	// script rewrote is reported as rewritten rather than silently mismatching the
	// package it came from.
	Original map[string]string
}

// SBOMs returns one payload per platform, or nothing when the spec disables SBOM
// generation. Provenance and VEX are separate payloads and stay unaffected.
func SBOMs(enabled bool, inputs []SBOMInput) ([][]byte, error) {
	if !enabled {
		return nil, nil
	}
	payloads := make([][]byte, 0, len(inputs))
	for position := range inputs {
		payload, err := SPDX(&inputs[position])
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

func (input *SBOMInput) validate() error {
	switch {
	case input.Name == "":
		return errors.New("attest: sbom requires an image name")
	case !safeSegment(input.Name):
		return fmt.Errorf("attest: image name %q is not usable in a document namespace", input.Name)
	case input.Platform == "":
		return errors.New("attest: sbom requires a platform")
	case !safeSegment(input.Platform):
		return fmt.Errorf("attest: platform %q is not usable in a document namespace", input.Platform)
	case !strings.HasPrefix(input.Subject, "sha256:"):
		return errors.New("attest: sbom requires the subject manifest digest")
	case input.Tree == nil:
		return errors.New("attest: sbom requires the built tree")
	}
	return nil
}

// safeSegment reports whether a value needs no escaping inside a document namespace.
func safeSegment(value string) bool {
	for index := 0; index < len(value); index++ {
		switch ch := value[index]; {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case ch == '.', ch == '-', ch == '_', ch == '/', ch == ':':
		default:
			return false
		}
	}
	return true
}
