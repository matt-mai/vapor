// Package policy defines post-mutation hardening and slice limits.
package policy

import (
	"errors"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// Hardening controls post-mutation passes; nil flags default to true, except
// KeepPackageSources, which defaults to false.
type Hardening struct {
	StripDocs      *bool `yaml:"strip-docs" json:"strip-docs"`
	StripShells    *bool `yaml:"strip-shells" json:"strip-shells"`
	StripAptDpkg   *bool `yaml:"strip-apt-dpkg" json:"strip-apt-dpkg"`
	RemoveSUIDSGID *bool `yaml:"remove-suid-sgid" json:"remove-suid-sgid"`
	// KeepPackageSources writes the apt sources and keyrings of the locked
	// repositories, for an image that installs packages at runtime.
	KeepPackageSources *bool `yaml:"keep-package-sources" json:"keep-package-sources"`
}

// ApplyDefaults enables hardening passes and fills policy defaults.
func ApplyDefaults(hardening *Hardening, engine *contents.SliceEngine) {
	if hardening.StripDocs == nil {
		hardening.StripDocs = new(true)
	}
	if hardening.StripShells == nil {
		hardening.StripShells = new(true)
	}
	if hardening.StripAptDpkg == nil {
		hardening.StripAptDpkg = new(true)
	}
	if hardening.RemoveSUIDSGID == nil {
		hardening.RemoveSUIDSGID = new(true)
	}
	if hardening.KeepPackageSources == nil {
		hardening.KeepPackageSources = new(false)
	}
	if engine.MaxSteps == nil {
		engine.MaxSteps = new(100_000)
	}
}

// PackageSources reports whether the finished image keeps apt sources and keyrings.
func PackageSources(hardening Hardening) bool {
	return hardening.KeepPackageSources != nil && *hardening.KeepPackageSources
}

// Validate checks the slice engine budget.
func Validate(engine contents.SliceEngine) error {
	budget := engine.MaxSteps
	if budget == nil || *budget <= 0 {
		return errors.New("contents.slices-engine.max-steps must be a positive integer")
	}
	return nil
}
