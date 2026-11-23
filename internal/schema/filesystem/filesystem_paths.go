package filesystem

import (
	"errors"
	"fmt"
	"math"
	"path"
	"strings"
	"unicode"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// ValidateImagePath requires a clean absolute POSIX path, optionally allowing root.
func ValidateImagePath(value string, allowRoot bool) error {
	if !path.IsAbs(value) || path.Clean(value) != value || strings.Contains(value, "\\") ||
		strings.ContainsFunc(value, unicode.IsControl) || (!allowRoot && value == "/") {
		return errors.New("expected a clean absolute POSIX path without control characters or backslashes")
	}
	return nil
}

func validateIDs(ids ...*int) error {
	for _, id := range ids {
		if id == nil || *id < 0 || uint64(*id) > math.MaxUint32 {
			return errors.New("uid/gid must be present uint32-range integers")
		}
	}
	return nil
}

func validateFilesystemPaths(entries []Path) error {
	types := make(map[string]string)
	for i := range entries {
		entry := &entries[i]
		if _, exists := types[entry.Path]; exists {
			return errors.New("duplicate filesystem path")
		}
		types[entry.Path] = entry.Type
		if err := validateFilesystemPath(*entry); err != nil {
			return fmt.Errorf("filesystem.paths[%d]: %w", i, err)
		}
	}
	return validatePathAncestors(entries, types)
}

func validatePathAncestors(entries []Path, types map[string]string) error {
	for _, entry := range entries {
		for parent := path.Dir(entry.Path); ; parent = path.Dir(parent) {
			if kind, exists := types[parent]; exists && kind != pathDirectory {
				return errors.New("filesystem path has an explicitly declared non-directory ancestor")
			}
			if parent == "/" {
				break
			}
		}
	}
	return nil
}

func validateFilesystemPath(entry Path) error {
	if entry.Type != pathDirectory && entry.Type != pathFile && entry.Type != pathSymlink {
		return errors.New("filesystem path type must be directory, file or symlink")
	}
	if err := ValidateImagePath(entry.Path, entry.Type == pathDirectory); err != nil {
		return err
	}
	if err := validateIDs(&entry.UID, &entry.GID); err != nil {
		return err
	}
	if entry.Mode == nil {
		return errors.New("filesystem path requires a defaulted mode")
	}
	if err := base.RequirePattern("filesystem path mode", *entry.Mode, `^(0[0-7]{3}|0[1-7][0-7]{3})$`); err != nil {
		return err
	}
	if entry.Type == pathSymlink {
		if *entry.Mode != "0777" || entry.Target == nil {
			return errors.New("symlink requires mode 0777 and a target")
		}
		return validateSymlinkTarget(entry.Path, *entry.Target)
	}
	if entry.Target != nil {
		return errors.New("target is only allowed for symlinks")
	}
	return nil
}

func validateSymlinkTarget(destination, target string) error {
	if target == "" || path.Clean(target) != target || strings.Contains(target, "\\") || strings.ContainsFunc(target,
		unicode.IsControl) {
		return errors.New("symlink target must be a nonempty clean POSIX path")
	}
	if !path.IsAbs(target) {
		if err := validateRelativeTarget(destination, target); err != nil {
			return err
		}
	}
	resolved := target
	if !path.IsAbs(target) {
		resolved = path.Join(path.Dir(destination), target)
	}
	if resolved == destination {
		return errors.New("symlink must not target itself")
	}
	return nil
}

func validateRelativeTarget(destination, target string) error {
	depth := len(strings.Split(strings.Trim(path.Dir(destination), "/"), "/"))
	if path.Dir(destination) == "/" {
		depth = 0
	}
	for part := range strings.SplitSeq(target, "/") {
		switch part {
		case "..":
			depth--
		case ".":
		default:
			depth++
		}
		if depth < 0 {
			return errors.New("relative symlink target escapes image root")
		}
	}
	return nil
}
