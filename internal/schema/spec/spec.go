// Package spec decodes and validates Vapor image specifications.
package spec

import (
	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/container"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/schema/policy"
)

// Spec describes one image's identity, metadata, runtime configuration and inputs.
type Spec struct {
	Version     int                   `yaml:"version" json:"version"`
	Name        string                `yaml:"name" json:"name"`
	Image       string                `yaml:"image" json:"image"`
	Tags        []string              `yaml:"tags" json:"tags"`
	Annotations map[string]string     `yaml:"annotations" json:"annotations"`
	Distro      string                `yaml:"distro" json:"distro"`
	Release     string                `yaml:"release" json:"release"`
	Platforms   []string              `yaml:"platforms" json:"platforms"`
	Container   container.Container   `yaml:"container" json:"container"`
	Contents    contents.Contents     `yaml:"contents" json:"contents"`
	Filesystem  filesystem.Filesystem `yaml:"filesystem" json:"filesystem"`
	Hardening   policy.Hardening      `yaml:"hardening" json:"hardening"`
	SBOM        attestation.SBOM      `yaml:"sbom" json:"sbom"`
	VEX         attestation.VEX       `yaml:"vex" json:"vex"`
}
