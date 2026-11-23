package oci

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Attestation media types. An attached statement is a layer of an empty artifact
// manifest whose subject is the platform manifest it describes, which is the layout
// cosign writes and a registry's referrers API indexes.
const (
	// MediaTypeDSSE names a DSSE envelope layer.
	MediaTypeDSSE = "application/vnd.dsse.envelope.v1+json"
	// MediaTypeInToto names an unsigned in-toto statement layer.
	MediaTypeInToto = "application/vnd.in-toto+json"
	// MediaTypeOpenVEX names an unsigned OpenVEX document layer.
	MediaTypeOpenVEX = "application/vnd.openvex+json"
	// MediaTypeEmptyConfig names the empty config an artifact manifest carries. An
	// artifact has no runtime configuration, so the empty document is the honest one.
	MediaTypeEmptyConfig = "application/vnd.oci.empty.v1+json"
)

// emptyConfig is the config blob of every attestation manifest: `{}`, two bytes.
var emptyConfig = []byte("{}")

// AnnotationTitle names an attachment in the artifact manifest, so a reader can tell
// the statements of one platform apart without opening them.
const AnnotationTitle = "org.opencontainers.image.title"

// Attachment is one statement attached to a platform manifest. Kind is the short name
// an output file and an annotation use ("spdx", "provenance", "vex"), and MediaType is
// the payload's media type, which becomes the manifest's artifactType.
type Attachment struct {
	Kind      string
	MediaType string
	Payload   []byte
}

// Attached is a finished attachment: the manifest that carries it, its payload and
// the empty config beside them, all content addressed.
type Attached struct {
	Platform       Platform
	Kind           string
	MediaType      string
	Payload        []byte
	Manifest       []byte
	ManifestDigest string
	// Descriptor is what a directory layout index lists for this attachment, with the
	// platform it belongs to. It is not part of the build index the build reports.
	Descriptor v1.Descriptor
}

// Attach builds one artifact manifest per attachment. Each manifest's subject is the
// platform manifest, never the index: an attachment that named the index would change
// the index digest, and an index cannot describe a manifest that describes it.
func Attach(images []Image, attachments map[Platform][]Attachment) ([]Attached, error) {
	subjects := make(map[Platform]Image, len(images))
	for position := range images {
		subjects[images[position].Platform] = images[position]
	}
	platforms := make([]Platform, 0, len(attachments))
	for platform := range attachments {
		platforms = append(platforms, platform)
	}
	slices.SortFunc(platforms, func(left, right Platform) int {
		return strings.Compare(left.String(), right.String())
	})
	attached := make([]Attached, 0, len(attachments))
	for _, platform := range platforms {
		image, ok := subjects[platform]
		if !ok {
			return nil, fmt.Errorf("attachments for %s: no image to attach them to", platform)
		}
		subject := image.SubjectOf()
		if err := subject.Validate(); err != nil {
			return nil, fmt.Errorf("attachments for %s: %w", platform, err)
		}
		for _, attachment := range attachments[platform] {
			finished, err := attach(subject, platform, attachment)
			if err != nil {
				return nil, err
			}
			attached = append(attached, finished)
		}
	}
	return attached, nil
}

// attach assembles and encodes one artifact manifest.
func attach(subject Subject, platform Platform, attachment Attachment) (Attached, error) {
	if attachment.Kind == "" {
		return Attached{}, errors.New("oci: an attachment requires a kind")
	}
	if len(attachment.Payload) == 0 {
		return Attached{}, fmt.Errorf("oci: %s attachment is empty", attachment.Kind)
	}
	if attachment.MediaType == "" {
		return Attached{}, fmt.Errorf("oci: %s attachment has no media type", attachment.Kind)
	}
	manifest := artifactManifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeManifest,
		ArtifactType:  attachment.MediaType,
		Config: artifactDescriptor{
			MediaType:    MediaTypeEmptyConfig,
			ArtifactType: MediaTypeEmptyConfig,
			Digest:       digestOf(emptyConfig),
			Size:         int64(len(emptyConfig)),
		},
		Layers: []artifactDescriptor{{
			MediaType: attachment.MediaType,
			Digest:    digestOf(attachment.Payload),
			Size:      int64(len(attachment.Payload)),
			Annotations: map[string]string{
				AnnotationTitle: attachment.Kind + ".json",
			},
		}},
		Subject: artifactDescriptor{
			MediaType: subject.MediaType,
			Digest:    subject.Digest,
			Size:      subject.Size,
		},
		Annotations: map[string]string{
			AnnotationTitle: platform.String() + " " + attachment.Kind,
		},
	}
	encoded, err := marshalCanonical(manifest)
	if err != nil {
		return Attached{}, err
	}
	digest := digestOf(encoded)
	size := int64(len(encoded))
	return Attached{
		Platform: platform, Kind: attachment.Kind, MediaType: attachment.MediaType,
		Payload: attachment.Payload, Manifest: encoded, ManifestDigest: digest,
		Descriptor: v1.Descriptor{
			MediaType:    types.MediaType(MediaTypeManifest),
			Digest:       v1.Hash{Algorithm: "sha256", Hex: strings.TrimPrefix(digest, "sha256:")},
			Size:         size,
			ArtifactType: attachment.MediaType,
			Platform:     &v1.Platform{OS: platform.OS, Architecture: platform.Architecture},
			Annotations:  map[string]string{AnnotationTitle: platform.String() + " " + attachment.Kind},
		},
	}, nil
}

// artifactManifest is the manifest of an attached statement. It is written by hand
// because a statement is an artifact, not an image: it has an artifactType, an empty
// config and a subject, and the image manifest struct has none of those.
type artifactManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	ArtifactType  string               `json:"artifactType"`
	Config        artifactDescriptor   `json:"config"`
	Layers        []artifactDescriptor `json:"layers"`
	Subject       artifactDescriptor   `json:"subject"`
	Annotations   map[string]string    `json:"annotations,omitempty"`
}

// artifactDescriptor is one entry of an artifact manifest. It spells out its own
// fields rather than reusing the image descriptor, whose platform entry an artifact
// must not carry.
type artifactDescriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// entries lists the payload, the empty config and the manifest of every attachment.
// The payload is carried here because it is not in any other part of the layout.
func attachmentEntries(attached []Attached) ([]layoutEntry, error) {
	entries := make([]layoutEntry, 0, 3*len(attached))
	for position := range attached {
		entry := &attached[position]
		payload, err := blobEntry(digestOf(entry.Payload), entry.Payload)
		if err != nil {
			return nil, fmt.Errorf("%s %s payload: %w", entry.Platform, entry.Kind, err)
		}
		config, err := blobEntry(digestOf(emptyConfig), emptyConfig)
		if err != nil {
			return nil, err
		}
		manifest, err := blobEntry(entry.ManifestDigest, entry.Manifest)
		if err != nil {
			return nil, fmt.Errorf("%s %s manifest: %w", entry.Platform, entry.Kind, err)
		}
		entries = append(entries, payload, config, manifest)
	}
	return entries, nil
}
