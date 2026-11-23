package lock

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/base"
)

func verifyLockContent(field string, content Content) error {
	if err := validateLockPath(content.Path); err != nil {
		return fmt.Errorf("%s content path: %w", field, err)
	}
	if err := checkLockHash(field+" content", content.SHA256); err != nil {
		return err
	}
	return checkLockSize(field+" content", content.Size)
}

func nativeArchitecture(platform string) (string, bool) {
	switch platform {
	case platformAMD64:
		return "amd64", true
	case platformARM64:
		return "arm64", true
	default:
		return "", false
	}
}

func checkLockHash(field, value string) error {
	return base.RequirePattern(field+" SHA256", value, `^[0-9a-f]{64}$`)
}

func checkLockDerived(field, value string) error {
	return base.RequirePattern(field, value, `^sha256:[0-9a-f]{64}$`)
}

func checkLockSize(field string, size int64) error {
	if size < 0 {
		return fmt.Errorf("%s size must not be negative", field)
	}
	return nil
}

func validateLockArchive(value string) error {
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return errors.New("archive name must be nonempty and control-free")
	}
	return nil
}

func validateLockPath(value string) error {
	if value == "" || value == "." || path.IsAbs(value) || path.Clean(value) != value ||
		strings.Contains(value, "\\") || strings.ContainsFunc(value, unicode.IsControl) {
		return errors.New("path must be nonempty, clean and repository-relative")
	}
	for part := range strings.SplitSeq(value, "/") {
		if part == ".." {
			return errors.New("path must not contain parent traversal")
		}
	}
	return nil
}

// RepositoryID implements the domain-separated repository identity contract.
func RepositoryID(name, platform, architecture, url, suite string) string {
	payload, _ := json.Marshal(map[string]string{
		"architecture": architecture,
		"name":         name,
		"platform":     platform,
		"suite":        suite,
		"url":          url,
	})
	digest := sha256.New()
	digest.Write([]byte("vapor.lock.repository.v1"))
	digest.Write([]byte{0})
	digest.Write(payload)
	return fmt.Sprintf("sha256:%x", digest.Sum(nil))
}
