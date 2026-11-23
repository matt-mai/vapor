package attestation

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/filesystem"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// Validate checks VEX inputs and assertions.
func Validate(vex VEX) error {
	seen := make(map[string]bool)
	for i, input := range vex.Inputs {
		if err := base.ValidateLocalPath(input); err != nil {
			return fmt.Errorf("vex.inputs[%d]: %w", i, err)
		}
		if seen[input] {
			return errors.New("duplicate VEX input path")
		}
		seen[input] = true
	}
	claims := make(map[[3]string]bool)
	for i := range vex.Assertions {
		claim := &vex.Assertions[i]
		if err := validateVEXAssertion(claim, vex.CheckAbsentPaths); err != nil {
			return fmt.Errorf("vex.assertions[%d]: %w", i, err)
		}
		key := vexClaimKey(claim)
		if claims[key] {
			return errors.New("duplicate VEX assertion identity")
		}
		claims[key] = true
	}
	return nil
}

func vexClaimKey(claim *VEXAssertion) [3]string {
	key := [3]string{claim.Vulnerability, "package", ""}
	if claim.Package != nil {
		key[2] = *claim.Package
		return key
	}
	key[1], key[2] = "artifact", *claim.Artifact
	return key
}

func containsControl(value string) bool {
	return strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	})
}

func validateVEXAssertion(claim *VEXAssertion, check *bool) error {
	if strings.TrimSpace(claim.Vulnerability) == "" || strings.TrimSpace(claim.Vulnerability) != claim.Vulnerability ||
		containsControl(claim.Vulnerability) {
		return errors.New("vulnerability must be a nonblank single-line identifier without surrounding whitespace")
	}
	if (claim.Package == nil) == (claim.Artifact == nil) {
		return errors.New("exactly one package or artifact is required")
	}
	if claim.Package != nil {
		if err := base.ValidatePackageVersion(*claim.Package, nil); err != nil {
			return err
		}
	} else if err := base.ValidateInputName(*claim.Artifact); err != nil {
		return err
	}
	if strings.TrimSpace(claim.Statement) == "" {
		return errors.New("statement must be nonblank")
	}
	return validateVEXStatus(claim, check)
}

// VEX status labels, as the VEX working group defines them.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// justifications are the fixed labels a not_affected claim may state.
var justifications = []string{
	"component_not_present", "vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// IsVEXStatus reports whether a status is one of the four labels VEX defines.
func IsVEXStatus(status string) bool {
	switch status {
	case StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation:
		return true
	}
	return false
}

// IsVEXJustification reports whether a not_affected claim may state a justification.
func IsVEXJustification(justification string) bool {
	return slices.Contains(justifications, justification)
}

func validateVEXStatus(claim *VEXAssertion, check *bool) error {
	if claim.Status == StatusNotAffected {
		return validateNotAffected(claim, check)
	}
	switch claim.Status {
	case StatusAffected, StatusFixed, StatusUnderInvestigation:
		if claim.Justification != nil || claim.AbsentPaths != nil {
			return errors.New("only not_affected permits justification or absent-paths")
		}
	default:
		return errors.New("unsupported VEX status")
	}
	return nil
}

func validateNotAffected(claim *VEXAssertion, check *bool) error {
	if claim.Justification == nil {
		return errors.New("not_affected requires justification")
	}
	if !IsVEXJustification(*claim.Justification) {
		return errors.New("unsupported VEX justification")
	}
	if check == nil || (*check && len(claim.AbsentPaths) == 0) {
		return errors.New("not_affected requires nonempty absent-paths when checking is enabled")
	}
	seen := make(map[string]bool)
	for i, entry := range claim.AbsentPaths {
		if err := filesystem.ValidateImagePath(entry, false); err != nil {
			return fmt.Errorf("absent-paths[%d]: %w", i, err)
		}
		if seen[entry] {
			return errors.New("duplicate absent path")
		}
		seen[entry] = true
	}
	return nil
}
