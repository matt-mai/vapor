package deb

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

func parseRelease(data []byte) (Release, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return Release{}, errors.New("release metadata is malformed")
	}
	var (
		release Release
		seen    = make(map[string]bool)
		section string
	)
	for line := range strings.SplitSeq(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if err := parseReleaseLine(line, &release, seen, &section); err != nil {
			return Release{}, err
		}
	}
	return release, nil
}

func parseReleaseLine(line string, release *Release, seen map[string]bool, section *string) error {
	if line == "" {
		*section = ""
		return nil
	}
	if line[0] == ' ' || line[0] == '\t' {
		if *section == sha256Section {
			return parseReleaseFile(line, release)
		}
		return nil
	}
	*section = ""
	field, value, ok := strings.Cut(line, ":")
	if !ok || field == "" || strings.TrimSpace(field) != field {
		return errors.New("release metadata is malformed")
	}
	if seen[field] {
		return fmt.Errorf("release metadata repeats %s", field)
	}
	seen[field] = true
	nextSection, err := applyReleaseField(release, field, strings.TrimSpace(value))
	if err != nil {
		return err
	}
	*section = nextSection
	return nil
}

func applyReleaseField(release *Release, field, value string) (string, error) {
	switch field {
	case "Origin":
		release.Origin = value
	case "Label":
		release.Label = value
	case "Suite":
		release.Suite = value
	case "Version":
		release.Version = value
	case "Codename":
		release.Codename = value
	case "Date":
		release.Date = value
	case "Valid-Until":
		release.ValidUntil = value
	case "Architectures":
		release.Architectures = strings.Fields(value)
	case "Components":
		release.Components = strings.Fields(value)
	case "Acquire-By-Hash":
		if err := applyAcquireByHash(release, value); err != nil {
			return "", err
		}
	case sha256Section:
		return sha256Section, nil
	}
	return "", nil
}

func applyAcquireByHash(release *Release, value string) error {
	switch strings.ToLower(value) {
	case "yes":
		release.AcquireByHash = true
	case "no":
	default:
		return errors.New("release metadata is malformed")
	}
	return nil
}

func parseReleaseFile(line string, release *Release) error {
	fields := strings.Fields(line)
	if len(fields) != 3 || len(fields[0]) != 64 {
		return errors.New("release metadata is malformed")
	}
	for _, c := range []byte(fields[0]) {
		if !isHex(c) {
			return errors.New("release metadata is malformed")
		}
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || size < 0 || !safeRelativePath(fields[2]) {
		return errors.New("release metadata is malformed")
	}
	if release.Files == nil {
		release.Files = make(map[string]ReleaseFile)
	}
	if _, exists := release.Files[fields[2]]; exists {
		return errors.New("release metadata is malformed")
	}
	release.Files[fields[2]] = ReleaseFile{SHA256: strings.ToLower(fields[0]), Size: size}
	return nil
}

func safeRelativePath(value string) bool {
	if value == "" || path.Clean(value) != value || path.IsAbs(value) || strings.ContainsRune(value, '\\') {
		return false
	}
	for segment := range strings.SplitSeq(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
