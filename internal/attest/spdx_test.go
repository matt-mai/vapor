package attest_test

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/vfs"
)

// sbomDocument decodes a payload so a test can assert on it.
type sbomDocument struct {
	SPDXID            string `json:"SPDXID"`
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	DocumentNamespace string `json:"documentNamespace"`
	Name              string `json:"name"`
	CreationInfo      struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages      []sbomPackage      `json:"packages"`
	Files         []sbomFile         `json:"files"`
	Relationships []sbomRelationship `json:"relationships"`
}

type sbomPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	PackageFileName  string `json:"packageFileName"`
	Comment          string `json:"comment"`
	Checksums        []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`
	ExternalRefs []struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type sbomFile struct {
	SPDXID    string `json:"SPDXID"`
	FileName  string `json:"fileName"`
	Comment   string `json:"comment"`
	Checksums []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`
}

type sbomRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func decodeSBOM(t *testing.T, payload []byte) sbomDocument {
	t.Helper()
	var document sbomDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode sbom: %v", err)
	}
	return document
}

func packageNamed(t *testing.T, document sbomDocument, name string) sbomPackage {
	t.Helper()
	for position := range document.Packages {
		if found := &document.Packages[position]; found.SPDXID == name || found.Name == name {
			return *found
		}
	}
	t.Fatalf("no package %q in %v", name, packageIDs(document))
	return sbomPackage{}
}

// spdxID is the identifier spdx.go builds from an element identity.
func spdxID(identity string) string {
	return "SPDXRef-" + strings.Replace(identity, ":", "-", 1)
}

func packageIDs(document sbomDocument) []string {
	ids := make([]string, 0, len(document.Packages))
	for position := range document.Packages {
		ids = append(ids, document.Packages[position].SPDXID)
	}
	return ids
}

// TestSPDX_DescribesTheImage checks the document identity: it names the platform, it
// is namespaced by the subject it describes, and it is created at the Unix epoch.
func TestSPDX_DescribesTheImage(t *testing.T) {
	input, _ := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" {
		t.Fatalf("header = %s / %s", document.SPDXVersion, document.DataLicense)
	}
	if document.Name != "fixture-image linux/amd64" {
		t.Fatalf("name = %q", document.Name)
	}
	want := "https://mattnet.de/vapor/spdx/fixture-image/linux/amd64/" + strings.Repeat("ee", 32)
	if document.DocumentNamespace != want {
		t.Fatalf("namespace = %q, want %q", document.DocumentNamespace, want)
	}
	if document.CreationInfo.Created != "1970-01-01T00:00:00Z" {
		t.Fatalf("created = %q", document.CreationInfo.Created)
	}
	if len(document.CreationInfo.Creators) != 1 || document.CreationInfo.Creators[0] != "Tool: vaporize" {
		t.Fatalf("creators = %v", document.CreationInfo.Creators)
	}
}

// TestSPDX_AttributesEveryFile checks that each file in the tree appears once and is
// reachable from a lock record, the document itself, or a marked rewrite.
func TestSPDX_AttributesEveryFile(t *testing.T) {
	input, wanted := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	paths := make(map[string]bool, len(document.Files))
	for _, file := range document.Files {
		if strings.HasPrefix(file.FileName, "/") {
			t.Fatalf("file %s is absolute; SPDX 2.3 section 8.1 wants a relative path", file.FileName)
		}
		if paths[file.FileName] {
			t.Fatalf("file %s appears twice", file.FileName)
		}
		paths[file.FileName] = true
		if !carriesBothChecksums(file) {
			t.Fatalf("%s checksums = %+v", file.FileName, file.Checksums)
		}
	}
	for _, entry := range input.Tree.Entries() {
		if entry.Kind == vfs.File && !paths[strings.TrimPrefix(entry.Path, "/")] {
			t.Fatalf("tree file %s is missing from the document", entry.Path)
		}
	}
	if len(paths) != len(document.Files) {
		t.Fatalf("files = %d, want %d", len(document.Files), len(paths))
	}
	if comment := fileNamed(t, document, wanted.modifiedFile).Comment; comment == "" {
		t.Fatal("rewritten file is not marked")
	}
	if comment := fileNamed(t, document, wanted.packageFile).Comment; comment != "" {
		t.Fatalf("unchanged file is marked %q", comment)
	}
}

// TestSPDX_RelationshipsWalkFromDocumentToFile checks that a consumer can reach every
// file: the document describes every element, and each element contains its files.
func TestSPDX_RelationshipsWalkFromDocumentToFile(t *testing.T) {
	input, wanted := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	described := map[string]bool{}
	contained := map[string][]string{}
	for _, line := range document.Relationships {
		if line.SPDXElementID == "SPDXRef-DOCUMENT" && line.RelationshipType == "DESCRIBES" {
			described[line.RelatedSPDXElement] = true
		}
		contained[line.SPDXElementID] = append(contained[line.SPDXElementID], line.RelatedSPDXElement)
	}
	for _, id := range []string{spdxID(wanted.packageElement), spdxID(wanted.sliceElement),
		spdxID(wanted.artifactElement)} {
		if !described[id] {
			t.Fatalf("document does not describe %s", id)
		}
	}
	if len(described) != len(document.Packages) {
		t.Fatalf("document describes %d of %d elements", len(described), len(document.Packages))
	}
	if !contains(contained[spdxID(wanted.packageElement)], wanted.packageFile) {
		t.Fatal("package does not contain its file")
	}
	if !contains(contained["SPDXRef-DOCUMENT"], wanted.declaredFile) {
		t.Fatal("declared file is not attributed to the document")
	}
	if !contains(contained["SPDXRef-DOCUMENT"], wanted.synthesized) {
		t.Fatal("synthesized file is not attributed to the document")
	}
	if !contains(contained[spdxID(wanted.sliceElement)], wanted.sliceFile) {
		t.Fatal("slice does not contain its file")
	}
	if !contains(contained[spdxID(wanted.artifactElement)], wanted.artifactFile) {
		t.Fatal("artifact does not contain its file")
	}
	if !contains(contained[spdxID(wanted.packageElement)], wanted.license) {
		t.Fatal("license file is not attributed to its package")
	}
	assertNoDanglingReferences(t, document)
}

func contains(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}

// carriesBothChecksums reports a file that has the SHA-1 SPDX 2.3 requires and the
// SHA-256 Vapor adds beside it.
func carriesBothChecksums(file sbomFile) bool {
	lengths := map[string]int{"SHA1": 40, "SHA256": 64}
	if len(file.Checksums) != len(lengths) {
		return false
	}
	for _, found := range file.Checksums {
		length, ok := lengths[found.Algorithm]
		if !ok || len(found.ChecksumValue) != length {
			return false
		}
	}
	return true
}

func checksum(file sbomFile, algorithm string) string {
	for _, found := range file.Checksums {
		if found.Algorithm == algorithm {
			return found.ChecksumValue
		}
	}
	return ""
}

func fileNamed(t *testing.T, document sbomDocument, id string) sbomFile {
	t.Helper()
	for _, file := range document.Files {
		if file.SPDXID == id {
			return file
		}
	}
	t.Fatalf("no file %s", id)
	return sbomFile{}
}

// assertNoDanglingReferences checks that every relationship names an element the
// document defines, which is what a schema check cannot see.
func assertNoDanglingReferences(t *testing.T, document sbomDocument) {
	t.Helper()
	known := map[string]bool{"SPDXRef-DOCUMENT": true}
	for position := range document.Packages {
		known[document.Packages[position].SPDXID] = true
	}
	for _, found := range document.Files {
		known[found.SPDXID] = true
	}
	for _, line := range document.Relationships {
		if !known[line.SPDXElementID] {
			t.Fatalf("relationship from unknown element %s", line.SPDXElementID)
		}
		if !known[line.RelatedSPDXElement] {
			t.Fatalf("relationship to unknown element %s", line.RelatedSPDXElement)
		}
	}
}

// TestSPDX_PackageDetailsComeFromTheLock checks that a whole package reports its
// version, archive checksum and a purl a scanner can match.
func TestSPDX_PackageDetailsComeFromTheLock(t *testing.T) {
	input, wanted := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	found := packageNamed(t, decodeSBOM(t, payload), spdxID(wanted.packageElement))
	if found.VersionInfo != "9.4-3ubuntu1" || found.PackageFileName != "coreutils_9.4-3ubuntu1_amd64.deb" {
		t.Fatalf("package = %+v", found)
	}
	if found.DownloadLocation != "NOASSERTION" || !found.FilesAnalyzed {
		t.Fatalf("package = %+v", found)
	}
	if len(found.Checksums) != 1 || found.Checksums[0].ChecksumValue != strings.Repeat("a", 64) {
		t.Fatalf("checksums = %+v", found.Checksums)
	}
	if len(found.ExternalRefs) != 1 {
		t.Fatalf("external refs = %+v", found.ExternalRefs)
	}
	ref := found.ExternalRefs[0]
	want := "pkg:deb/ubuntu/coreutils@9.4-3ubuntu1?arch=amd64&distro=ubuntu-26.04"
	if ref.ReferenceCategory != "PACKAGE-MANAGER" || ref.ReferenceType != "purl" ||
		ref.ReferenceLocator != want {
		t.Fatalf("external ref = %+v, want locator %q", ref, want)
	}
	if !strings.Contains(found.Comment, "/usr/share/doc/coreutils/copyright") {
		t.Fatalf("comment does not point at the license: %q", found.Comment)
	}
}

// TestSPDX_SlicePointsAtItsPackage checks the whole/sliced distinction: the slice is a
// container package, contained by the package it was cut from, and its files are its
// own.
func TestSPDX_SlicePointsAtItsPackage(t *testing.T) {
	slicePurl := "pkg:deb/ubuntu/libc6@2.41-1?arch=all&distro=ubuntu-26.04"
	input, wanted := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	slice := packageNamed(t, document, spdxID(wanted.sliceElement))
	if slice.VersionInfo != "2.41-1" || len(slice.Checksums) != 0 {
		t.Fatalf("slice = %+v", slice)
	}
	// The purl is the package's, which is the product a VEX claim about the slice
	// resolves to, so the two payloads join on it.
	if len(slice.ExternalRefs) != 1 ||
		slice.ExternalRefs[0].ReferenceLocator != slicePurl {
		t.Fatalf("slice external refs = %+v", slice.ExternalRefs)
	}
	if strings.Contains(slice.Comment, "/usr/share/doc") {
		t.Fatalf("slice points at a license it does not have: %q", slice.Comment)
	}
	for position := range document.Packages {
		if document.Packages[position].SPDXID == "SPDXRef-Package-libc6" {
			t.Fatal("a package that is only sliced is reported as a whole package")
		}
	}
	if !contains(containedBy(document), wanted.sliceFile) {
		t.Fatal("slice file is not attributed")
	}
}

func containedBy(document sbomDocument) []string {
	files := map[string]bool{}
	for _, found := range document.Files {
		files[found.SPDXID] = true
	}
	related := make([]string, 0, len(files))
	for _, line := range document.Relationships {
		if files[line.RelatedSPDXElement] && line.RelationshipType == "CONTAINS" {
			related = append(related, line.RelatedSPDXElement)
		}
	}
	return related
}

// TestSPDX_ArtifactUsesDeclaredIdentity checks that an artifact is named by its
// declared upstream identity and that its URL never reaches the payload.
func TestSPDX_ArtifactUsesDeclaredIdentity(t *testing.T) {
	input, wanted := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	found := packageNamed(t, decodeSBOM(t, payload), spdxID(wanted.artifactElement))
	if found.Name != "server" || found.VersionInfo != "1.0" {
		t.Fatalf("artifact = %+v", found)
	}
	if len(found.ExternalRefs) != 1 || found.ExternalRefs[0].ReferenceLocator != "pkg:generic/server@1.0" {
		t.Fatalf("artifact external refs = %+v", found.ExternalRefs)
	}
	if strings.Contains(string(payload), "example.invalid") {
		t.Fatal("artifact payload contains the fetch endpoint")
	}
}

// TestSPDX_OmitsContentTheTreeDoesNotHave checks the whole point of generating from
// the finished tree: a locked package that contributed nothing is not claimed.
func TestSPDX_OmitsContentTheTreeDoesNotHave(t *testing.T) {
	input, _ := newSBOMFixture()
	// A second locked package with no surviving file, as hardening leaving nothing
	// behind would produce.
	input.Packages = append(input.Packages, lock.Package{Platform: "linux/amd64",
		Name: "ca-certificates", Version: "20240203", Architecture: "all",
		Content: lock.Content{Path: "pool/ca-certificates.deb",
			SHA256: strings.Repeat("d", 64), Size: 42}})
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	for position := range document.Packages {
		if document.Packages[position].Name == "ca-certificates" {
			t.Fatal("a package with no content in the image is claimed")
		}
	}
	assertNoDanglingReferences(t, document)
}

// TestSPDX_RefusesAnUnknownContributor checks that a tree file attributed to a package
// the lock does not contain is an error rather than a silent omission.
func TestSPDX_RefusesAnUnknownContributor(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Packages = nil
	if _, err := attest.SPDX(input); err == nil {
		t.Fatal("unknown contributor accepted")
	}
}

// TestSPDX_IsByteStable checks that the same inputs produce the same bytes, and that
// declaration order does not matter.
func TestSPDX_IsByteStable(t *testing.T) {
	first, _ := newSBOMFixture()
	second, _ := newSBOMFixture()
	firstPayload, err := attest.SPDX(first)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	secondPayload, err := attest.SPDX(second)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	if !bytes.Equal(firstPayload, secondPayload) {
		t.Fatal("two identical builds produced different documents")
	}
	// Reversing the locked record order is not a different image.
	reversed := *first
	reversed.Packages = []lock.Package{first.Packages[0]}
	reversed.Slices = append([]lock.Slice{}, first.Slices...)
	reversed.Artifacts = append([]lock.Artifact{}, first.Artifacts...)
	again, err := attest.SPDX(&reversed)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	if !bytes.Equal(firstPayload, again) {
		t.Fatal("record order changed the document")
	}
}

// TestSPDX_IgnoresOtherPlatforms checks that an amd64 document never names an arm64
// payload, so two platforms cannot be confused for each other.
func TestSPDX_IgnoresOtherPlatforms(t *testing.T) {
	input, _ := newSBOMFixture()
	input.Slices = append(input.Slices, lock.Slice{Platform: "linux/arm64", Package: "libc6",
		Version: "2.41-1", Architecture: "all"})
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	if strings.Contains(string(payload), "arm64") {
		t.Fatal("document mentions another platform")
	}
}

// TestSPDX_TwoPlatformsProduceSeparateDocuments checks that building both platforms
// stays independent: one document per platform, each naming only its own records and
// its own subject, and each stable on a second build.
func TestSPDX_TwoPlatformsProduceSeparateDocuments(t *testing.T) {
	amd64Input, _ := newSBOMFixture()
	arm64Input := *amd64Input
	arm64Input.Platform = "linux/arm64"
	arm64Input.Subject = "sha256:" + strings.Repeat("ff", 32)
	arm64Input.Packages = copyPackages(amd64Input.Packages, "linux/arm64")
	arm64Input.Slices = copySlices(amd64Input.Slices, "linux/arm64")
	arm64Input.Artifacts = copyArtifacts(amd64Input.Artifacts, "linux/arm64")

	first, err := attest.SBOMs(true, []attest.SBOMInput{*amd64Input, arm64Input})
	if err != nil {
		t.Fatalf("SBOMs: %v", err)
	}
	second, err := attest.SBOMs(true, []attest.SBOMInput{*amd64Input, arm64Input})
	if err != nil {
		t.Fatalf("SBOMs: %v", err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("payloads = %d and %d, want 2", len(first), len(second))
	}
	for position := range first {
		if !bytes.Equal(first[position], second[position]) {
			t.Fatalf("platform %d is not byte stable", position)
		}
	}
	if bytes.Equal(first[0], first[1]) {
		t.Fatal("both platforms produced the same document")
	}
	amd64, arm64 := decodeSBOM(t, first[0]), decodeSBOM(t, first[1])
	if !strings.HasSuffix(amd64.Name, "linux/amd64") || !strings.HasSuffix(arm64.Name, "linux/arm64") {
		t.Fatalf("names = %q and %q", amd64.Name, arm64.Name)
	}
	if !strings.Contains(amd64.DocumentNamespace, strings.Repeat("ee", 32)) ||
		!strings.Contains(arm64.DocumentNamespace, strings.Repeat("ff", 32)) {
		t.Fatalf("namespaces = %q and %q", amd64.DocumentNamespace, arm64.DocumentNamespace)
	}
	if strings.Contains(string(first[0]), "/linux/arm64") ||
		strings.Contains(string(first[1]), "/linux/amd64") {
		t.Fatal("a document names the other platform")
	}
}

func copyPackages(records []lock.Package, platform string) []lock.Package {
	copied := make([]lock.Package, 0, len(records))
	for position := range records {
		record := records[position]
		record.Platform = platform
		copied = append(copied, record)
	}
	return copied
}

func copySlices(records []lock.Slice, platform string) []lock.Slice {
	copied := make([]lock.Slice, 0, len(records))
	for position := range records {
		record := records[position]
		record.Platform = platform
		copied = append(copied, record)
	}
	return copied
}

func copyArtifacts(records []lock.Artifact, platform string) []lock.Artifact {
	copied := make([]lock.Artifact, 0, len(records))
	for position := range records {
		record := records[position]
		record.Platform = platform
		copied = append(copied, record)
	}
	return copied
}

// TestSPDX_RefusesMissingIdentity checks the inputs a namespace and subject need.
func TestSPDX_RefusesMissingIdentity(t *testing.T) {
	cases := map[string]func(*attest.SBOMInput){
		"name":     func(input *attest.SBOMInput) { input.Name = "" },
		"space":    func(input *attest.SBOMInput) { input.Name = "two words" },
		"platform": func(input *attest.SBOMInput) { input.Platform = "" },
		"subject":  func(input *attest.SBOMInput) { input.Subject = "" },
		"tree":     func(input *attest.SBOMInput) { input.Tree = nil },
	}
	for name, change := range cases {
		input, _ := newSBOMFixture()
		change(input)
		if _, err := attest.SPDX(input); err == nil {
			t.Fatalf("missing %s accepted", name)
		}
	}
}

// loadSchema reads the published SPDX 2.3.1 schema the validator is checked against.
func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("testdata/spdx-2.3.1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

// TestSPDX_ChecksumsMatchTheTree checks that a file checksum is the content the image
// holds, not the content the archive delivered.
func TestSPDX_ChecksumsMatchTheTree(t *testing.T) {
	input, wanted := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	file := fileNamed(t, document, wanted.modifiedFile)
	if checksum(file, "SHA1") != digestOfSHA1([]byte("rewritten")) {
		t.Fatalf("sha1 = %s, want the final bytes", checksum(file, "SHA1"))
	}
	if checksum(file, "SHA256") != digestOf([]byte("rewritten")) {
		t.Fatalf("sha256 = %s, want the final bytes", checksum(file, "SHA256"))
	}
}

// spdxIdentifier is the identifier grammar the SPDX 2.3 schema enforces.
var spdxIdentifier = regexp.MustCompile(`^SPDXRef-[a-zA-Z0-9.-]+$`)

// TestSPDX_TellsApartPathsThatShareAnIdentifier checks the case where SPDX's identifier
// grammar collapses two image paths: "/a-b" and "/a_b" both become SPDXRef-File--a-b, so
// one element would silently stand for two files and its relationships would merge.
func TestSPDX_TellsApartPathsThatShareAnIdentifier(t *testing.T) {
	tree := vfs.New()
	for _, path := range []string{"/a-b", "/a_b"} {
		if err := tree.File(path, []byte(path), vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Path: "filesystem.paths"}}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := attest.SPDX(&attest.SBOMInput{Name: "clash", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ee", 32), Distro: "ubuntu", Release: "26.04",
		Tree: tree})
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	document := decodeSBOM(t, payload)
	identifiers := make(map[string]string, len(document.Files))
	for _, file := range document.Files {
		if !spdxIdentifier.MatchString(file.SPDXID) {
			t.Fatalf("%s is not an SPDX identifier", file.SPDXID)
		}
		if other, taken := identifiers[file.SPDXID]; taken {
			t.Fatalf("%s and %s share the identifier %s", other, file.FileName, file.SPDXID)
		}
		identifiers[file.SPDXID] = file.FileName
	}
	if len(identifiers) != 2 {
		t.Fatalf("files = %+v", document.Files)
	}
	contained := map[string]bool{}
	for _, line := range document.Relationships {
		if line.RelationshipType == "CONTAINS" {
			contained[line.RelatedSPDXElement] = true
		}
	}
	for identifier := range identifiers {
		if !contained[identifier] {
			t.Fatalf("%s (%s) is not contained by anything", identifier, identifiers[identifier])
		}
	}
	assertNoDanglingReferences(t, document)
}

// TestSPDX_MergesTwoSlicesOfOnePackage checks the case a package appears as several
// slices: the document describes the package once, because an advisory is filed under
// the package and one element per slice would report the same finding once per slice.
func TestSPDX_MergesTwoSlicesOfOnePackage(t *testing.T) {
	tree := vfs.New()
	for _, slice := range []string{"libs", "core"} {
		if err := tree.File("/usr/lib/"+slice, []byte(slice), vfs.Attrs{Mode: 0o644,
			Origin: vfs.Origin{Package: "libc6", Slice: "libc6_" + slice,
				Path: "pool/libc6.deb"}}); err != nil {
			t.Fatal(err)
		}
	}
	input := &attest.SBOMInput{Name: "slices", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ee", 32), Distro: "ubuntu", Release: "26.04",
		Slices: []lock.Slice{{Platform: "linux/amd64", Package: "libc6", Version: "2.41-1",
			Architecture: "all", Content: lock.Content{Path: "pool/libc6.deb",
				SHA256: strings.Repeat("b", 64), Size: 5678},
			Selected: []string{"libs", "core"}, Closure: []string{"core", "libs"},
			DefinitionDigest: "sha256:" + strings.Repeat("d", 64)}},
		Tree: tree}
	document := decodeSBOM(t, mustSPDX(t, input))
	if len(document.Packages) != 1 {
		t.Fatalf("packages = %+v, want one element for the package", document.Packages)
	}
	current := &document.Packages[0]
	if len(current.ExternalRefs) != 1 ||
		current.ExternalRefs[0].ReferenceLocator != "pkg:deb/ubuntu/libc6@2.41-1?arch=all&distro=ubuntu-26.04" {
		t.Fatalf("%s external refs = %+v", current.SPDXID, current.ExternalRefs)
	}
	if !strings.Contains(current.Comment, "slices core, libs") {
		t.Fatalf("%s comment = %q, want every locked slice of the package",
			current.SPDXID, current.Comment)
	}
}

// TestSPDX_ElementIDFollowsTheElement checks the contract the identifiers are documented
// to keep: an element's identifier is its domain-separated identity, so a change the
// identity covers changes the identifier. A name-derived identifier would survive a
// version bump and let a reader mistake one element for another.
func TestSPDX_ElementIDFollowsTheElement(t *testing.T) {
	base, _ := newSBOMFixture()
	before := packageIDs(decodeSBOM(t, mustSPDX(t, base)))

	changes := map[string]func(*attest.SBOMInput){
		"package version": func(input *attest.SBOMInput) {
			input.Packages[0].Version = "9.4-3ubuntu2"
		},
		"package content": func(input *attest.SBOMInput) {
			input.Packages[0].Content.SHA256 = strings.Repeat("f", 64)
		},
		"slice definition": func(input *attest.SBOMInput) {
			input.Slices[0].DefinitionDigest = "sha256:" + strings.Repeat("9", 64)
		},
		// The identity covers the dependency-first closure, so adding a slice the lock
		// pulled in changes the identifier even though Selected is unchanged.
		"slice closure": func(input *attest.SBOMInput) {
			input.Slices[0].Closure = append(input.Slices[0].Closure, "etc")
		},
		"artifact identity": func(input *attest.SBOMInput) {
			input.Artifacts[0].SBOM.Version = "1.1"
		},
	}
	for name, change := range changes {
		changed, _ := newSBOMFixture()
		change(changed)
		after := packageIDs(decodeSBOM(t, mustSPDX(t, changed)))
		if slices.Equal(before, after) {
			t.Fatalf("%s changed no identifier: %v", name, after)
		}
	}
}

func mustSPDX(t *testing.T, input *attest.SBOMInput) []byte {
	t.Helper()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	return payload
}

// TestSPDX_ArtifactCPEReachesTheDocument checks that a declared CPE is written beside the
// purl. A pkg:generic URL indexes nothing, so without the CPE a payload that is not a
// package cannot be scanned at all.
func TestSPDX_ArtifactCPEReachesTheDocument(t *testing.T) {
	const cpe = "cpe:2.3:a:python_software_foundation:python:3.15.2:*:*:*:*:*:*:*"
	tree := vfs.New()
	if err := tree.File("/usr/local/bin/tool", []byte("tool"), vfs.Attrs{Mode: 0o755,
		Origin: vfs.Origin{Package: "cpython", Path: "https://example.invalid/cpython"}}); err != nil {
		t.Fatal(err)
	}
	input := &attest.SBOMInput{Name: "artifacts", Platform: "linux/amd64",
		Subject: "sha256:" + strings.Repeat("ee", 32), Distro: "ubuntu", Release: "26.04",
		Artifacts: []lock.Artifact{{Name: "cpython", Platform: "linux/amd64",
			URL:    "https://example.invalid/cpython",
			SHA256: strings.Repeat("c", 64), Size: 9012,
			SBOM: contents.ArtifactIdentity{Name: "python", Version: "3.15.2", CPE: cpe}}},
		Tree: tree}
	document := decodeSBOM(t, mustSPDX(t, input))
	references := document.Packages[0].ExternalRefs
	if len(references) != 2 {
		t.Fatalf("external refs = %+v, want a purl and a CPE", references)
	}
	if references[1].ReferenceCategory != "SECURITY" || references[1].ReferenceType != "cpe23Type" ||
		references[1].ReferenceLocator != cpe {
		t.Fatalf("CPE reference = %+v", references[1])
	}
	// The CPE is part of what the element is, so a specification that changes it
	// describes a different payload.
	without := mustIdentity(attest.ArtifactIdentity("linux/amd64", "cpython",
		attest.ArtifactVersion{Name: "python", Version: "3.15.2"}, strings.Repeat("c", 64), 9012))
	if document.Packages[0].SPDXID == spdxID(without) {
		t.Fatal("declaring a CPE did not change the element identity")
	}
}
