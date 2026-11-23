package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/ui"
)

// attestationPhase renders the statements of every platform, after the images exist
// and before anything is exported.
const attestationPhase = 3

// The three formats a build can attach, as the short names a file and a report use.
const (
	kindSPDX       = "spdx"
	kindProvenance = "provenance"
	kindVEX        = "vex"
)

// statement is one rendered statement of one platform and the format it belongs to.
// document is the bare payload (SPDX, SLSA predicate, OpenVEX), which is what a scanner
// reads, and body is the in-toto statement that binds it to the image digest.
type statement struct {
	kind      string
	mediaType string
	document  []byte
	body      []byte
}

// buildAttestations renders one statement per platform and enabled format, writes them
// when a directory was asked for, and attaches them to the platform manifests. The
// payloads describe the image that was just built, so what a reader fetches and what
// it describes cannot disagree.
func (options *buildOptions) buildAttestations(reporter *ui.Reporter,
	built []builder.Image,
) ([]oci.Attached, error) {
	if err := options.reportPhase(reporter, attestationPhase, "render attestations", ""); err != nil {
		return nil, err
	}
	documents, err := attest.SBOMs(*options.spec.SBOM.Enabled, options.sbomInputs(built))
	if err != nil {
		return nil, err
	}
	attachments := make(map[oci.Platform][]oci.Attachment, len(built))
	rendered := make([]platformStatement, 0, len(built))
	for position := range built {
		if err := options.render(reporter, &built[position], documents, position,
			attachments, &rendered); err != nil {
			return nil, err
		}
	}
	if err := options.writeAttestations(rendered); err != nil {
		return nil, err
	}
	images := make([]oci.Image, 0, len(built))
	for position := range built {
		images = append(images, built[position].Image)
	}
	return oci.Attach(images, attachments)
}

// render produces one platform's statements and files them for attachment and for
// writing. documents holds one SPDX document per image, in build order, and nothing at
// all when the switch is off.
func (options *buildOptions) render(reporter *ui.Reporter, image *builder.Image,
	documents [][]byte, position int, attachments map[oci.Platform][]oci.Attachment,
	rendered *[]platformStatement,
) error {
	var spdx []byte
	if position < len(documents) {
		spdx = documents[position]
	}
	statements, err := options.platformStatements(image, spdx)
	if err != nil {
		return err
	}
	for _, entry := range statements {
		attachments[image.Platform] = append(attachments[image.Platform], oci.Attachment{
			Kind: entry.kind, MediaType: entry.mediaType, Payload: entry.body,
		})
		*rendered = append(*rendered, platformStatement{
			platform: image.Platform.String(), statement: entry,
		})
	}
	details := fmt.Sprintf("%d statements for %s", len(statements), image.Platform)
	return options.reportPhase(reporter, attestationPhase, "render attestations", details)
}

// platformStatement is one rendered statement with the platform it describes.
type platformStatement struct {
	platform  string
	statement statement
}

// sbomInputs describes every platform to the SPDX generator, in the order the images
// were built, so one call produces one document per platform.
func (options *buildOptions) sbomInputs(built []builder.Image) []attest.SBOMInput {
	inputs := make([]attest.SBOMInput, 0, len(built))
	for position := range built {
		image := &built[position]
		inputs = append(inputs, attest.SBOMInput{
			Name: options.spec.Image, Platform: image.Platform.String(),
			Subject: image.Image.ManifestDigest,
			Distro:  options.lock.Provider.Distro, Release: options.lock.Provider.Release,
			Packages: options.lock.Packages, Slices: options.lock.Slices,
			Artifacts: options.lock.Artifacts, Tree: image.Tree, Original: image.Original,
		})
	}
	return inputs
}

// platformStatements renders the statements one platform's spec enabled. SPDX follows
// sbom.enabled through the documents it was handed, provenance is always produced, and
// VEX is produced only when the spec makes a claim about this platform.
func (options *buildOptions) platformStatements(image *builder.Image,
	spdx []byte,
) ([]statement, error) {
	platform := image.Platform.String()
	subject := image.Image.ManifestDigest
	statements := make([]statement, 0, 3)
	if spdx != nil {
		entry, err := options.statement(kindSPDX, attest.PredicateTypeSPDX, subject, spdx)
		if err != nil {
			return nil, err
		}
		statements = append(statements, entry)
	}
	provenance, err := attest.Provenance(&attest.ProvenanceInput{
		Name: options.spec.Image, Platform: platform, Subject: subject, Lock: options.lock,
		Toolchain: attest.Toolchain{Name: "vaporize", Version: toolchainVersion()},
	})
	if err != nil {
		return nil, err
	}
	entry, err := options.statement(kindProvenance, attest.PredicateTypeSLSA, subject, provenance)
	if err != nil {
		return nil, err
	}
	statements = append(statements, entry)
	vex, err := options.vexStatement(image)
	if err != nil {
		return nil, err
	}
	statements = append(statements, vex...)
	return statements, nil
}

// vexStatement checks the spec's claims against one platform's finished tree and
// renders the document. A platform nobody claimed anything about produces nothing,
// because an OpenVEX document has to state something.
func (options *buildOptions) vexStatement(image *builder.Image) ([]statement, error) {
	vexInput := &attest.VEXInput{
		Name: options.spec.Image, Subject: image.Image.ManifestDigest, Tree: image.Tree,
		AbsentChecks: *options.spec.VEX.CheckAbsentPaths,
		Platform:     image.Platform.String(),
		Distro:       options.lock.Provider.Distro, Release: options.lock.Provider.Release,
		Claims: options.spec.VEX.Assertions, Packages: options.lock.Packages,
		Slices: options.lock.Slices, Artifacts: options.lock.Artifacts,
	}
	for _, document := range options.documents {
		imported, err := attest.ImportClaims(vexInput, document)
		if err != nil {
			return nil, fmt.Errorf("import VEX input: %w", err)
		}
		vexInput.Imported = append(vexInput.Imported, imported...)
	}
	payload, err := attest.VEX(vexInput)
	if errors.Is(err, attest.ErrNoClaims) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry, err := options.statement(kindVEX, attest.PredicateTypeOpenVEX,
		image.Image.ManifestDigest, payload)
	if err != nil {
		return nil, err
	}
	return []statement{entry}, nil
}

// statement binds a bare document to the image digest with an in-toto statement, which
// is the layer format, and keeps the document beside it for the directory output. A
// key wraps the statement in a DSSE envelope; the document is signed by nothing,
// because a signature covers the statement that carries it.
func (options *buildOptions) statement(kind, predicateType, subject string,
	document []byte,
) (statement, error) {
	wrapped, err := attest.DocumentStatement(predicateType, subject, options.spec.Image, document)
	if err != nil {
		return statement{}, err
	}
	signed, isSigned, err := attest.MaybeSigned(options.key, attest.PayloadTypeInToto, wrapped)
	if err != nil {
		return statement{}, err
	}
	return statement{
		kind: kind, mediaType: mediaTypeOf(isSigned), document: document, body: signed,
	}, nil
}

// attestationKinds are the statement formats a build can write, so a file naming one
// of them is a file a build wrote.
var attestationKinds = []string{kindSPDX, kindProvenance, kindVEX}

// writeAttestations writes the bare document of every statement when a directory was
// asked for. A bare document is what a scanner reads, so the files can be consumed
// without unwrapping anything; the signature lives on the attached statement alone.
// Each file is replaced by a rename, so a reader sees the previous document or the
// complete new one.
//
// The directory may be reused, so a file this build would have written and did not is
// removed: a claim this build withdrew would otherwise stay behind and be read beside
// the new statements as if it still held.
func (options *buildOptions) writeAttestations(rendered []platformStatement) error {
	if options.attestationsDir == "" {
		return nil
	}
	if err := os.MkdirAll(options.attestationsDir, 0o750); err != nil {
		return fmt.Errorf("create attestations directory: %w", err)
	}
	written := make(map[string]bool, len(rendered))
	for position := range rendered {
		entry := &rendered[position]
		name := attestationFileName(options.spec.Image, entry.platform, entry.statement.kind)
		written[name] = true
		path := filepath.Join(options.attestationsDir, name)
		if err := writeFileAtomic(path, entry.statement.document); err != nil {
			return fmt.Errorf("write attestation %s: %w", name, err)
		}
	}
	return options.retireAttestations(written)
}

// retireAttestations removes the statements of this image that this build did not
// write. Only a name this image could have produced is removed, so a directory shared
// with another image keeps that image's files.
func (options *buildOptions) retireAttestations(written map[string]bool) error {
	entries, err := os.ReadDir(options.attestationsDir)
	if err != nil {
		return fmt.Errorf("read attestations directory: %w", err)
	}
	prefix := attestationImagePrefix(options.spec.Image)
	for _, entry := range entries {
		name := entry.Name()
		if written[name] || entry.IsDir() || !couldHaveWritten(name, prefix) {
			continue
		}
		if err := os.Remove(filepath.Join(options.attestationsDir, name)); err != nil {
			return fmt.Errorf("remove retired attestation %s: %w", name, err)
		}
	}
	return nil
}

// attestationImagePrefix is the part of an attestation file name that names the image,
// with the separator that follows it.
func attestationImagePrefix(name string) string {
	return strings.NewReplacer("/", "-", ":", "-").Replace(name) + "-"
}

// couldHaveWritten reports whether a name is one this image's build writes: the image
// name, then a platform, then one of the kinds. A file a scan or a person left in the
// directory keeps its own name and is not touched.
func couldHaveWritten(name, prefix string) bool {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return false
	}
	for _, kind := range attestationKinds {
		if strings.HasSuffix(rest, "-"+kind+".json") {
			return true
		}
	}
	return false
}

// mediaTypeOf names the encoded bytes, so a consumer reads a signed envelope as a DSSE
// envelope and an unsigned statement as a statement instead of trusting the file name.
func mediaTypeOf(signed bool) string {
	if signed {
		return oci.MediaTypeDSSE
	}
	return oci.MediaTypeInToto
}

// attestationFileName turns an image, platform and kind into one file name, so a
// statement is recognizable outside the directory it was written to.
func attestationFileName(name, platform, kind string) string {
	replacer := strings.NewReplacer("/", "-", ":", "-")
	return replacer.Replace(name) + "-" + replacer.Replace(platform) + "-" + kind + ".json"
}

// toolchainVersion names the build that produced a statement. It is the module version
// the tool was built from, so two builds by the same release carry the same value. A
// binary built by a release pipeline carries no module version, so it reports the
// version stamped into it instead, which is the same value for the same release.
func toolchainVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "development"
}
