package attest

import (
	"sort"
	"strconv"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// SPDX document values. A document describes one platform image, so the namespace is
// derived from that image rather than from a distribution.
const (
	spdxVersion      = "SPDX-2.3"
	spdxDataLicense  = "CC0-1.0"
	spdxDocumentID   = "SPDXRef-DOCUMENT"
	spdxNoAssertion  = "NOASSERTION"
	spdxCreator      = "Tool: vaporize"
	spdxSHA1         = "SHA1"
	spdxSHA256       = "SHA256"
	spdxNamespace    = "https://mattnet.de/vapor/spdx/"
	spdxEpoch        = "1970-01-01T00:00:00Z"
	kindPackage      = "Package"
	kindSlice        = "Slice"
	kindArtifact     = "Artifact"
	kindModule       = "Module"
	copyrightSuffix  = "/copyright"
	documentationDir = "/usr/share/doc/"
	purlCategory     = "PACKAGE-MANAGER"
	purlType         = "purl"
	securityCategory = "SECURITY"
	cpeType          = "cpe23Type"
)

// SPDX returns the canonical bytes of one platform's SPDX 2.3 document.
//
// An element appears only when the final tree still holds content it contributed, so
// a package that hardening emptied is absent rather than claimed. Files no locked
// input contributed are attributed to the document.
func SPDX(input *SBOMInput) ([]byte, error) {
	document, err := input.document()
	if err != nil {
		return nil, err
	}
	return Encode(document)
}

type spdxDocument struct {
	SPDXID            string             `json:"SPDXID"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	DataLicense       string             `json:"dataLicense"`
	DocumentNamespace string             `json:"documentNamespace"`
	Name              string             `json:"name"`
	SPDXVersion       string             `json:"spdxVersion"`
	Packages          []spdxPackage      `json:"packages"`
	Files             []spdxFile         `json:"files"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo,omitempty"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	Checksums        []spdxChecksum `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternal `json:"externalRefs,omitempty"`
	PackageFileName  string         `json:"packageFileName,omitempty"`
	Comment          string         `json:"comment,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternal struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxFile struct {
	SPDXID    string         `json:"SPDXID"`
	FileName  string         `json:"fileName"`
	Checksums []spdxChecksum `json:"checksums"`
	Comment   string         `json:"comment,omitempty"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func (input *SBOMInput) document() (spdxDocument, error) {
	if err := input.validate(); err != nil {
		return spdxDocument{}, err
	}
	found, err := input.walk()
	if err != nil {
		return spdxDocument{}, err
	}
	// One assignment feeds both lists, so a file and the relationships that name it
	// cannot disagree. The identifiers belong to the format, not to the walked content.
	identifiers := assignFileIDs(found.files)
	document := spdxDocument{
		SPDXID:            spdxDocumentID,
		CreationInfo:      spdxCreationInfo{Created: spdxEpoch, Creators: []string{spdxCreator}},
		DataLicense:       spdxDataLicense,
		DocumentNamespace: input.namespace(),
		Name:              input.Name + " " + input.Platform,
		SPDXVersion:       spdxVersion,
		Files:             spdxFiles(found.files, identifiers),
		Relationships:     relationships(found, identifiers),
	}
	document.Packages = make([]spdxPackage, 0, len(found.elements))
	for _, element := range found.elements {
		document.Packages = append(document.Packages, input.packageOf(element))
	}
	return document, nil
}

// namespace identifies the document by the image it describes, so two documents are
// never mistaken for the same one.
func (input *SBOMInput) namespace() string {
	return spdxNamespace + input.Name + "/" + input.Platform + "/" +
		strings.TrimPrefix(input.Subject, "sha256:")
}

// documentFilePath renders a tree path the way SPDX 2.3 section 8.1 wants it: relative
// to the package root a reader resolves it against, which for an image root filesystem
// is "/". A leading slash there is a shape error, not a detail.
func documentFilePath(path string) string {
	return strings.TrimPrefix(path, "/")
}

// spdxFiles renders the tree's files. The identifiers come from assignFileIDs, which is
// what keeps two paths whose identifiers collide apart.
func spdxFiles(files []file, identifiers map[string]string) []spdxFile {
	rendered := make([]spdxFile, 0, len(files))
	for _, current := range files {
		rendered = append(rendered, spdxFile{
			SPDXID:    identifiers[current.path],
			FileName:  documentFilePath(current.path),
			Checksums: fileChecksums(current),
			Comment:   fileComment(current),
		})
	}
	return rendered
}

// fileChecksums lists the file's content twice: the SHA-1 SPDX 2.3 makes mandatory and
// the SHA-256 a reader is more likely to check a container against.
func fileChecksums(current file) []spdxChecksum {
	return []spdxChecksum{
		{Algorithm: spdxSHA1, ChecksumValue: current.sha1},
		{Algorithm: spdxSHA256, ChecksumValue: current.hash},
	}
}

// fileComment marks a file a slice script rewrote. The checksum is the content the
// image holds, so without the note a reader would read the mismatch as corrupt.
func fileComment(current file) string {
	if current.modified {
		return "This file was modified while the image was assembled."
	}
	return ""
}

// packageOf renders one element. Counts, checksums and versions come from the lock;
// only the presence of the element and its files come from the tree.
func (input *SBOMInput) packageOf(found *element) spdxPackage {
	spdx := spdxPackage{
		SPDXID:           elementID(found.identity),
		Name:             found.reported,
		VersionInfo:      found.version,
		DownloadLocation: spdxNoAssertion,
		FilesAnalyzed:    true,
	}
	switch found.kind {
	case kindPackage:
		spdx.Checksums = []spdxChecksum{{Algorithm: spdxSHA256, ChecksumValue: found.checksum}}
		spdx.PackageFileName = found.reported + "_" + found.version + "_" + found.arch + ".deb"
		spdx.ExternalRefs = purlRef(packageURL(found.vendor, found.release,
			found.reported, found.version, found.arch, found.upstream))
		spdx.ExternalRefs = append(spdx.ExternalRefs, optionalCPE(found)...)
		spdx.Comment = "This package is included whole." + input.licenseNote(found)
	case kindSlice:
		// One element covers every slice of the package, because an advisory is filed
		// under the package: the purl, the name and the version have to be the package's,
		// and the comment says which slices the image actually holds.
		spdx.Name = found.archive
		spdx.ExternalRefs = purlRef(packageURL(found.vendor, found.release,
			found.archive, found.version, found.arch, found.upstream))
		spdx.ExternalRefs = append(spdx.ExternalRefs, optionalCPE(found)...)
		spdx.Comment = "This package is present as slices " +
			strings.Join(found.slices, ", ") + "." + input.licenseNote(found)
	case kindArtifact:
		spdx.Checksums = []spdxChecksum{{Algorithm: spdxSHA256, ChecksumValue: found.checksum}}
		spdx.ExternalRefs = purlRef(artifactURL(found.reported, found.version))
		// A payload that is not a package has no purl a database can follow, so the
		// declared CPE is the only handle a scanner has on it.
		spdx.ExternalRefs = append(spdx.ExternalRefs, optionalCPE(found)...)
		spdx.Comment = "This package is the artifact payload."
	case kindModule:
		// A vendored module has no payload of its own to checksum: its files belong to the
		// payload that carried it, and the package URL is what a scanner follows.
		spdx.ExternalRefs = purlRef(found.locator)
		spdx.Comment = "This package is vendored inside the payload of another package."
	}
	return spdx
}

// purlRef wraps a locator as the external reference a scanner reads package URLs from.
func purlRef(locator string) []spdxExternal {
	return []spdxExternal{{ReferenceCategory: purlCategory, ReferenceType: purlType,
		ReferenceLocator: locator}}
}

// cpeRef wraps a CPE 2.3 name as the external reference a scanner matches advisories
// against.
func cpeRef(name string) spdxExternal {
	return spdxExternal{ReferenceCategory: securityCategory, ReferenceType: cpeType,
		ReferenceLocator: name}
}

// optionalCPE is the reference an element carries when the specification declared a CPE
// for it. A package a vendor publishes is matched by its own index, if any, and by
// nothing when the vendor files no advisories a purl can reach; the declared CPE names it
// in a database that does.
func optionalCPE(found *element) []spdxExternal {
	named := declaredCPE(found.cpe, found.version)
	if named == "" {
		return nil
	}
	return []spdxExternal{cpeRef(named)}
}

// declaredCPE renders a declared CPE against the version the lock recorded. A `*` in the
// version field inherits it, so one declaration stays correct as the package moves, and
// both attestation documents name the version rather than an all-versions identifier.
//
// A declaration the validator would have refused yields no reference rather than a
// guess.
func declaredCPE(declared, version string) string {
	if declared == "" {
		return ""
	}
	fields := contents.SplitCPE(declared)
	const versionField = 5
	if len(fields) != 13 || fields[versionField] != "*" || version == "" {
		return declared
	}
	// A Debian version carries an epoch, and a colon in a field would read as a field
	// separator, so the version is escaped rather than pasted in.
	fields[versionField] = contents.EscapeCPEField(version)
	return strings.Join(fields, ":")
}

// licenseNote points at the license text hardening kept, when the image has it. The
// note is absent otherwise, because a pointer to a removed file is a false claim.
func (input *SBOMInput) licenseNote(found *element) string {
	if found.archive == "" {
		return ""
	}
	path := documentationDir + found.archive + copyrightSuffix
	if _, exists := input.Tree.Lookup(path); !exists {
		return ""
	}
	return " The license text is " + path + "."
}

// relationships connects the document to the elements it describes and each element to
// the files it contributed. A slice is described by the document rather than contained
// by its package, because a sliced package is not a whole package in this image.
func relationships(found content, identifiers map[string]string) []spdxRelationship {
	lines := make([]spdxRelationship, 0, len(found.unowned)+len(found.elements))
	for _, element := range found.elements {
		identifier := elementID(element.identity)
		lines = append(lines, spdxRelationship{SPDXElementID: spdxDocumentID,
			RelationshipType: "DESCRIBES", RelatedSPDXElement: identifier})
		for _, path := range element.files {
			lines = append(lines, spdxRelationship{SPDXElementID: identifier,
				RelationshipType: "CONTAINS", RelatedSPDXElement: identifiers[path]})
		}
	}
	for _, path := range found.unowned {
		lines = append(lines, spdxRelationship{SPDXElementID: spdxDocumentID,
			RelationshipType: "CONTAINS", RelatedSPDXElement: identifiers[path]})
	}
	sort.Slice(lines, func(left, right int) bool {
		if lines[left].SPDXElementID != lines[right].SPDXElementID {
			return lines[left].SPDXElementID < lines[right].SPDXElementID
		}
		if lines[left].RelationshipType != lines[right].RelationshipType {
			return lines[left].RelationshipType < lines[right].RelationshipType
		}
		return lines[left].RelatedSPDXElement < lines[right].RelatedSPDXElement
	})
	return lines
}

// assignFileIDs gives every path its document identifier in tree order, so the files
// and the relationships that point at them cannot disagree. A path whose identifier is
// already taken, because another path has the same punctuation, gets a "-<repeat>"
// suffix: SPDX allows no other way to keep two elements apart, and the suffix still
// fits its identifier grammar.
func assignFileIDs(files []file) map[string]string {
	identifiers := make(map[string]string, len(files))
	taken := make(map[string]bool, len(files))
	for _, current := range files {
		base := fileID(current.path)
		identifier := base
		for repeat := 2; taken[identifier]; repeat++ {
			identifier = base + "-" + strconv.Itoa(repeat)
		}
		taken[identifier] = true
		identifiers[current.path] = identifier
	}
	return identifiers
}

// elementID turns an element identity into an SPDX identifier. The identity is
// "sha256:" and 64 hex digits, which the identifier grammar accepts once the colon
// becomes "-", so a document names an element by what the element is.
func elementID(identity string) string {
	return "SPDXRef-" + strings.Replace(identity, ":", "-", 1)
}

// fileID builds a file's base identifier from its path. SPDX identifiers allow only
// letters, digits, "." and "-", so anything else becomes "-"; assignFileIDs keeps two
// paths whose identifiers collide apart.
func fileID(value string) string {
	var builder strings.Builder
	builder.WriteString("SPDXRef-File-")
	for index := 0; index < len(value); index++ {
		switch ch := value[index]; {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '.':
			builder.WriteByte(ch)
		default:
			builder.WriteByte('-')
		}
	}
	return builder.String()
}
