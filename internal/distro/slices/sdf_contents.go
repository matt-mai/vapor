package slices

import (
	"errors"
	"fmt"
	"strings"
)

func parseContents(pkgName, sliceName string, raw map[string]*rawPath) (map[string]PathInfo, error) {
	contents := make(map[string]PathInfo, len(raw))
	for _, contentPath := range sortedKeys(raw) {
		info, err := parseContent(pkgName, sliceName, contentPath, raw[contentPath])
		if err != nil {
			return nil, err
		}
		contents[contentPath] = info
	}
	return contents, nil
}

func parseContent(pkgName, sliceName, contentPath string, raw *rawPath) (PathInfo, error) {
	isDir, err := validContentPath(contentPath)
	if err != nil {
		return PathInfo{}, fmt.Errorf("slice %s_%s has %w", pkgName, sliceName, err)
	}
	if raw == nil {
		raw = &rawPath{}
	}
	if untilErr := validateUntil(raw.Until); untilErr != nil {
		return PathInfo{}, fmt.Errorf("slice %s_%s path %s has %w", pkgName, sliceName, contentPath, untilErr)
	}
	if archErr := validateArchList(raw.Arch.Values); archErr != nil {
		return PathInfo{}, fmt.Errorf("slice %s_%s path %s has %w", pkgName, sliceName, contentPath, archErr)
	}
	kind, info, err := contentKind(pkgName, sliceName, contentPath, raw, isDir)
	if err != nil {
		return PathInfo{}, err
	}
	if raw.Mutable && kind != PathText && (kind != PathCopy || isDir) {
		return PathInfo{}, fmt.Errorf("slice %s_%s path %s mutable is not a regular file", pkgName, sliceName, contentPath)
	}
	if raw.Prefer != "" && raw.Prefer == pkgName {
		return PathInfo{}, fmt.Errorf("slice %s_%s path %s cannot prefer its own package", pkgName, sliceName, contentPath)
	}
	mode, err := contentMode(raw.Mode)
	if err != nil {
		return PathInfo{}, fmt.Errorf("slice %s_%s path %s has %w", pkgName, sliceName, contentPath, err)
	}
	return PathInfo{
		Kind:     kind,
		Info:     info,
		Mode:     mode,
		Mutable:  raw.Mutable,
		Until:    PathUntil(raw.Until),
		Arch:     append([]string(nil), raw.Arch.Values...),
		Generate: GenerateKind(raw.Generate),
		Prefer:   raw.Prefer,
	}, nil
}

func contentKind(pkgName, sliceName, contentPath string, raw *rawPath, isDir bool) (PathKind, string, error) {
	if raw.Generate != "" {
		return generateKind(pkgName, sliceName, contentPath, raw)
	}
	if strings.ContainsAny(contentPath, "*?") {
		return globKind(pkgName, sliceName, contentPath, raw)
	}
	return concreteKind(pkgName, sliceName, contentPath, raw, isDir)
}

func generateKind(pkgName, sliceName, contentPath string, raw *rawPath) (PathKind, string, error) {
	if raw.Make || raw.Text != nil || raw.Mode != nil || raw.Copy != "" || raw.Symlink != "" ||
		raw.Mutable || raw.Until != "" || raw.Prefer != "" {
		return "", "", fmt.Errorf("slice %s_%s path %s has invalid generate options", pkgName, sliceName, contentPath)
	}
	if err := validateGeneratePath(contentPath); err != nil {
		return "", "", fmt.Errorf("slice %s_%s has invalid generate path: %s", pkgName, sliceName, err)
	}
	return PathGenerate, "", nil
}

func globKind(pkgName, sliceName, contentPath string, raw *rawPath) (PathKind, string, error) {
	if raw.Make || raw.Text != nil || raw.Mode != nil || raw.Copy != "" || raw.Symlink != "" ||
		raw.Mutable || raw.Prefer != "" {
		return "", "", fmt.Errorf("slice %s_%s path %s has invalid glob options", pkgName, sliceName, contentPath)
	}
	return PathGlob, "", nil
}

func concreteKind(pkgName, sliceName, contentPath string, raw *rawPath, isDir bool) (PathKind, string, error) {
	var kinds []PathKind
	info := ""
	if raw.Make {
		if !isDir {
			return "", "", fmt.Errorf("slice %s_%s path %s must end in / for make", pkgName, sliceName, contentPath)
		}
		kinds = append(kinds, PathDir)
	}
	if raw.Text != nil {
		kinds = append(kinds, PathText)
		info = *raw.Text
	}
	if raw.Symlink != "" {
		kinds = append(kinds, PathSymlink)
		info = raw.Symlink
	}
	if raw.Copy != "" {
		kinds = append(kinds, PathCopy)
		info = raw.Copy
		if info == contentPath {
			info = ""
		}
	}
	if len(kinds) == 0 {
		return PathCopy, "", nil
	}
	if len(kinds) != 1 {
		names := make([]string, len(kinds))
		for i, kind := range kinds {
			names[i] = string(kind)
		}
		return "", "", fmt.Errorf("slice %s_%s path %s has conflicting kinds: %s",
			pkgName, sliceName, contentPath, strings.Join(names, ", "))
	}
	return kinds[0], info, nil
}

func (p *rawPath) Dir() bool {
	return p.Make
}

func validateUntil(value string) error {
	switch PathUntil(value) {
	case UntilNone, UntilMutate:
		return nil
	default:
		return fmt.Errorf("invalid until value %q", value)
	}
}

func validateGeneratePath(value string) error {
	if !strings.HasSuffix(value, "/**") {
		return errors.New("path does not end with /**")
	}
	dirPath := strings.TrimSuffix(value, "**")
	if strings.ContainsAny(dirPath, "*?") {
		return errors.New("path contains wildcard characters in addition to trailing **")
	}
	return nil
}

func contentMode(mode *uint32) (uint32, error) {
	if mode == nil {
		return 0, nil
	}
	if *mode > 0o7777 {
		return 0, errors.New("invalid mode")
	}
	return *mode, nil
}
