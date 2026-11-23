package synthesis

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// StatusPath is where dpkg records the state of every package it knows about.
const StatusPath = "/var/lib/dpkg/status"

// InfoDir is where dpkg keeps the per-package files it reads beside the status
// records, one set per package.
const InfoDir = "/var/lib/dpkg/info"

// MaxControlStanzaSize bounds one control stanza accepted for the database.
const MaxControlStanzaSize = 1 << 20

const (
	fieldPackage      = "Package"
	fieldVersion      = "Version"
	fieldArchitecture = "Architecture"
	fieldStatus       = "Status"
	fieldMultiArch    = "Multi-Arch"
)

// PackageStatus is the dpkg state a package is recorded with.
type PackageStatus string

const (
	// StatusInstalled marks a whole package, whose every file is present.
	StatusInstalled PackageStatus = "install ok installed"
	// StatusUnpacked marks a sliced package: its selected files are present but
	// dpkg never configured it. Scanners read unpacked records, so a slice stays
	// visible to vulnerability scanning instead of silently disappearing.
	StatusUnpacked PackageStatus = "install ok unpacked"
)

// PackageDatabaseOrigin attributes every record to the package database itself
// rather than to a slice, because a whole package and a slice of it share one
// record.
var PackageDatabaseOrigin = vfs.Origin{Path: "filesystem.packages"}

// FileLists writes the list of files each package contributed to the image, at
// the path dpkg looks for it. Without that file every dpkg query warns that the
// files list is missing, `dpkg -L` prints nothing and `dpkg --verify` cannot tell
// a complete package from one whose files are gone.
//
// The list describes the image as the caller presents it, so a build writes it
// after hardening: a package's stripped documentation is no longer in the image
// and listing it would make `dpkg --verify` report it missing. A package whose
// content hardening removed entirely gets neither a list nor a status record.
func FileLists(tree *vfs.Tree, packages []PackageState) error {
	if tree == nil {
		return errors.New("package file lists require an image tree")
	}
	owned, files := ownedPaths(tree)
	for index := range packages {
		pkg := &packages[index]
		name, err := fileListName(pkg)
		if err != nil {
			return err
		}
		if !files[pkg.Name] {
			continue
		}
		if err := writeFile(tree, InfoDir+"/"+name+".list", encodeFileList(owned[pkg.Name]), PackageDatabaseOrigin); err != nil {
			return err
		}
	}
	return nil
}

// PackageState is one package the image contains, described by the control
// stanza of the verified package it came from.
type PackageState struct {
	Name         string
	Version      string
	Architecture string
	Status       PackageStatus
	Control      []byte
}

// PackageDatabase writes dpkg status records for the packages in the image. It
// never runs dpkg or a maintainer script: the records are derived from verified
// control stanzas, so the image describes itself without a package manager
// having configured it.
//
// A package that contributed no file is left out. Its record would claim a
// package the image does not have: a slice whose content is only directories and
// symlinks leaves nothing behind, while the record makes a scanner report the
// package's advisories against an image that cannot execute its code. What the
// image contains is what the tree holds, so a record follows the files.
//
// Records the image already carries and no selected package accounts for are
// kept verbatim, so an artifact-supplied record survives.
func PackageDatabase(tree *vfs.Tree, packages []PackageState) error {
	if tree == nil {
		return errors.New("package database synthesis requires an image tree")
	}
	_, files := ownedPaths(tree)
	records, err := statusRecords(packages)
	if err != nil {
		return err
	}
	records = recordsWithFiles(records, files)
	existing, err := existingStanzas(tree)
	if err != nil {
		return err
	}
	content := encodeStatus(records, uncoveredStanzas(existing, records))
	if len(content) == 0 {
		return nil
	}
	return writeFile(tree, StatusPath, content, PackageDatabaseOrigin)
}

// recordsWithFiles keeps the records of packages that own at least one regular
// file. Validation runs over every package, so a malformed stanza is still an
// error even when the package no longer contributes a record.
func recordsWithFiles(records []statusRecord, files map[string]bool) []statusRecord {
	kept := make([]statusRecord, 0, len(records))
	for _, record := range records {
		if files[record.name] {
			kept = append(kept, record)
		}
	}
	return kept
}

// ownedPaths groups the image entries by the package whose payload carried them,
// and reports which packages own a regular file. An implicit ancestor was never in
// a package, so it is not owned by one.
func ownedPaths(tree *vfs.Tree) (paths map[string][]string, files map[string]bool) {
	paths = make(map[string][]string)
	files = make(map[string]bool)
	for _, entry := range tree.Entries() {
		if entry.Implicit {
			continue
		}
		for _, origin := range entry.Origins {
			if origin.Package == "" {
				continue
			}
			paths[origin.Package] = append(paths[origin.Package], entry.Path)
			if entry.Kind == vfs.File {
				files[origin.Package] = true
			}
		}
	}
	return paths, files
}

// fileListName is the file dpkg reads one package's list from. dpkg qualifies a
// name with the architecture only for a `Multi-Arch: same` package, which is the
// only kind that can be present twice; qualifying any other package makes dpkg
// look for a file nothing wrote.
func fileListName(pkg *PackageState) (string, error) {
	if pkg.Name == "" {
		return "", errors.New("package file list entry has no name")
	}
	fields, err := parseControlStanza(pkg.Name, pkg.Control)
	if err != nil {
		return "", err
	}
	for _, field := range fields {
		if field.name != fieldMultiArch || field.value != "same" {
			continue
		}
		if pkg.Architecture == "" {
			return "", fmt.Errorf("package %q is %s: same but has no architecture", pkg.Name, fieldMultiArch)
		}
		return pkg.Name + ":" + pkg.Architecture, nil
	}
	return pkg.Name, nil
}
func encodeFileList(paths []string) []byte {
	if len(paths) == 0 {
		return nil
	}
	return []byte(strings.Join(paths, "\n") + "\n")
}

// statusRecord is one validated stanza ready to be written.
type statusRecord struct {
	name         string
	architecture string
	version      string
	status       PackageStatus
	fields       []controlField
}

func statusRecords(packages []PackageState) ([]statusRecord, error) {
	records := make([]statusRecord, 0, len(packages))
	for index := range packages {
		record, err := statusRecordFor(&packages[index])
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	slices.SortFunc(records, func(first, second statusRecord) int {
		if order := strings.Compare(first.name, second.name); order != 0 {
			return order
		}
		return strings.Compare(first.architecture, second.architecture)
	})
	return mergeStatusRecords(records)
}
func statusRecordFor(pkg *PackageState) (statusRecord, error) {
	switch pkg.Status {
	case StatusInstalled, StatusUnpacked:
	case "":
		return statusRecord{}, fmt.Errorf("package %q has no status", pkg.Name)
	default:
		return statusRecord{}, fmt.Errorf("package %q has an invalid status %q", pkg.Name, pkg.Status)
	}
	if pkg.Name == "" {
		return statusRecord{}, errors.New("package database entry has no name")
	}
	fields, err := parseControlStanza(pkg.Name, pkg.Control)
	if err != nil {
		return statusRecord{}, err
	}
	fields = dropStatusFields(fields)
	if pkg.Status == StatusUnpacked {
		fields = dropRelations(fields)
	}
	if err := checkControlIdentity(pkg, fields); err != nil {
		return statusRecord{}, err
	}
	if err := requireControlFields(pkg.Name, fields); err != nil {
		return statusRecord{}, err
	}
	return statusRecord{
		name:         pkg.Name,
		architecture: pkg.Architecture,
		version:      pkg.Version,
		status:       pkg.Status,
		fields:       fields,
	}, nil
}

// requireControlFields rejects a stanza a scanner cannot attribute to a package,
// because a record without an identity is worse than no record at all.
func requireControlFields(name string, fields []controlField) error {
	for _, required := range []string{fieldPackage, fieldVersion} {
		if !slices.ContainsFunc(fields, func(field controlField) bool { return field.name == required }) {
			return fmt.Errorf("package %q control stanza has no %s field", name, required)
		}
	}
	return nil
}

// relationFields are the control fields that declare dependencies between whole
// packages. A slice ships part of a package, so these relations describe files the
// image does not have.
var relationFields = []string{
	"Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances", "Breaks",
	"Conflicts", "Provides", "Replaces", "Built-Using",
}

// dropRelations removes dependency relations from a sliced package's record. A
// package manager reads a record claiming "install ok unpacked" together with
// relations it cannot satisfy as a broken database and then refuses every later
// operation, `apt-get install` included. The slice's real dependency set was
// resolved at lock time, so nothing is lost: what the image contains is the
// closure the lock recorded, not the relations of the package it came from.
func dropRelations(fields []controlField) []controlField {
	kept := fields[:0]
	for _, field := range fields {
		if slices.Contains(relationFields, field.name) {
			continue
		}
		kept = append(kept, field)
	}
	return kept
}

// dropStatusFields removes any Status field from a control stanza. The database's
// Status is synthesized from the package state, so a retained one would appear
// twice and a consumer could read the contradictory value instead.
func dropStatusFields(fields []controlField) []controlField {
	kept := fields[:0]
	for _, field := range fields {
		if strings.EqualFold(field.name, fieldStatus) {
			continue
		}
		kept = append(kept, field)
	}
	return kept
}

// mergeStatusRecords collapses records for the same package and architecture. A
// whole package and a slice of it share one record, and the whole package wins
// because it is the stronger claim.
func mergeStatusRecords(records []statusRecord) ([]statusRecord, error) {
	merged := make([]statusRecord, 0, len(records))
	for _, record := range records {
		last := len(merged) - 1
		if last < 0 || merged[last].name != record.name || merged[last].architecture != record.architecture {
			merged = append(merged, record)
			continue
		}
		if merged[last].version != record.version {
			return nil, fmt.Errorf("package %q is recorded at versions %q and %q",
				record.name, merged[last].version, record.version)
		}
		if record.status == StatusInstalled {
			merged[last].status = StatusInstalled
		}
	}
	return merged, nil
}
func encodeStatus(records []statusRecord, existing []statusStanza) []byte {
	var buffer strings.Builder
	for _, record := range records {
		for _, field := range record.fields {
			if field.name == fieldPackage {
				buffer.WriteString(fieldPackage + ": ")
				buffer.WriteString(field.value)
				buffer.WriteString("\n")
				buffer.WriteString(fieldStatus + ": ")
				buffer.WriteString(string(record.status))
				buffer.WriteString("\n")
				continue
			}
			buffer.WriteString(field.name)
			buffer.WriteString(": ")
			buffer.WriteString(field.value)
			buffer.WriteString("\n")
		}
		buffer.WriteString("\n")
	}
	for _, stanza := range existing {
		buffer.WriteString(stanza.text)
		buffer.WriteString("\n\n")
	}
	return []byte(buffer.String())
}
