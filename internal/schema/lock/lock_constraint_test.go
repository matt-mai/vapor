package lock

import (
	"strings"
	"testing"
)

// A lock records the exact version it resolved, so verifying it means asking
// whether the spec's expression allows that version, not whether the two strings
// are equal.
func TestVerifyLockfile_ConstraintVersusResolvedVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		constraint string
		accepted   bool
	}{
		{"= 3.0", true},
		{"= 3.0-1", true},
		{"~> 3.0", true},
		{">= 2, < 4", true},
		{"!= 3.0-2", true},
		{"~> 2.0", false},
		{"> 3.0", false},
		{"!= 3.0-1", false},
	}
	for _, test := range tests {
		t.Run(test.constraint, func(t *testing.T) {
			t.Parallel()
			spec, lock := validMultiPlatformLock(t)
			// The lock keeps the version it resolved, so only the spec changes and
			// only its digest has to follow.
			spec.Contents.Packages[0].Version = new(test.constraint)
			digest, err := spec.SpecDigest()
			if err != nil {
				t.Fatal(err)
			}
			lock.SpecDigest = digest
			err = VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults())
			switch {
			case test.accepted && err != nil:
				t.Fatalf("%q rejected a satisfying version: %v", test.constraint, err)
			case !test.accepted && err == nil:
				t.Fatalf("%q accepted an unsatisfying version", test.constraint)
			case !test.accepted && !strings.Contains(err.Error(), "does not satisfy"):
				t.Fatalf("%q failed for another reason: %v", test.constraint, err)
			}
		})
	}
}
