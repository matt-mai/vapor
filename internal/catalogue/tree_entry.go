package catalogue

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

func validateEntry(entry *Entry) error {
	if err := validatePath(entry.Path); err != nil {
		return err
	}
	switch entry.Kind {
	case KindDir:
		if entry.Executable || entry.SHA256 != "" || entry.Size != 0 || entry.Target != "" {
			return fmt.Errorf("catalogue directory %q has file or link metadata", entry.Path)
		}
	case KindFile:
		return validateFileEntry(entry)
	case KindSymlink:
		if entry.Executable || entry.SHA256 != "" || entry.Size != 0 {
			return fmt.Errorf("catalogue symlink %q has file metadata", entry.Path)
		}
		if err := validateTarget(entry.Target); err != nil {
			return fmt.Errorf("catalogue symlink %q: %w", entry.Path, err)
		}
	default:
		return fmt.Errorf("catalogue tree entry %q has unsupported kind %q", entry.Path, entry.Kind)
	}
	return nil
}
func validateFileEntry(entry *Entry) error {
	if entry.Target != "" {
		return fmt.Errorf("catalogue file %q has a link target", entry.Path)
	}
	if !validSHA256(entry.SHA256) {
		return fmt.Errorf("catalogue file %q has an invalid SHA256", entry.Path)
	}
	if entry.Size < 0 || entry.Size > MaxTreeFileSize {
		return fmt.Errorf("catalogue file %q has an invalid size", entry.Path)
	}
	return nil
}
func validatePath(value string) error {
	if value == "" || len(value) > MaxTreePathSize || !utf8.ValidString(value) ||
		strings.ContainsRune(value, 0) || strings.ContainsRune(value, '\\') ||
		path.IsAbs(value) || path.Clean(value) != value || value == "." {
		return fmt.Errorf("catalogue tree path %q is not a clean relative UTF-8 path", value)
	}
	for segment := range strings.SplitSeq(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("catalogue tree path %q contains an invalid segment", value)
		}
	}
	return nil
}
func validateTarget(target string) error {
	if target == "" || len(target) > MaxTreeTargetSize || !utf8.ValidString(target) || strings.ContainsRune(target, 0) {
		return errors.New("target is not a valid UTF-8 link target")
	}
	if path.IsAbs(target) {
		return errors.New("target is absolute")
	}
	return nil
}
func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
