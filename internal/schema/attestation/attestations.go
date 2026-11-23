// Package attestation defines SBOM and VEX declarations.
package attestation

// SBOM controls future SPDX generation, without changing license preservation.
type SBOM struct {
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

// VEX declares local inputs and explicit claims, never a live vulnerability lookup.
type VEX struct {
	Inputs           []string       `yaml:"inputs" json:"inputs"`
	CheckAbsentPaths *bool          `yaml:"check-absent-paths" json:"check-absent-paths"`
	Assertions       []VEXAssertion `yaml:"assertions" json:"assertions"`
}

// VEXAssertion targets a locked package or artifact on every image platform.
type VEXAssertion struct {
	Vulnerability string   `yaml:"vulnerability" json:"vulnerability"`
	Package       *string  `yaml:"package" json:"package"`
	Artifact      *string  `yaml:"artifact" json:"artifact"`
	Status        string   `yaml:"status" json:"status"`
	Justification *string  `yaml:"justification" json:"justification"`
	Statement     string   `yaml:"statement" json:"statement"`
	AbsentPaths   []string `yaml:"absent-paths" json:"absent-paths"`
}

// ApplyDefaults enables SBOM and VEX checks.
func ApplyDefaults(sbom *SBOM, vex *VEX) {
	if sbom.Enabled == nil {
		sbom.Enabled = new(true)
	}
	if vex.CheckAbsentPaths == nil {
		vex.CheckAbsentPaths = new(true)
	}
}
