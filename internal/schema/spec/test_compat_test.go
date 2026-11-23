package spec

import (
	"reflect"

	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/container"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/schema/policy"
)

type (
	Contents         = contents.Contents
	PackageRequest   = contents.PackageRequest
	SliceRequest     = contents.SliceRequest
	CatalogueSource  = contents.CatalogueSource
	Endpoint         = contents.Endpoint
	Repository       = contents.Repository
	Trust            = contents.Trust
	TrustKey         = contents.TrustKey
	Freshness        = contents.Freshness
	Artifact         = contents.Artifact
	ArtifactSource   = contents.ArtifactSource
	ArtifactIdentity = contents.ArtifactIdentity
	SliceEngine      = contents.SliceEngine

	Filesystem   = filesystem.Filesystem
	Path         = filesystem.Path
	Accounts     = filesystem.Accounts
	UserAccount  = filesystem.UserAccount
	GroupAccount = filesystem.GroupAccount
	CABundle     = filesystem.CABundle

	Container    = container.Container
	Hardening    = policy.Hardening
	SBOM         = attestation.SBOM
	VEX          = attestation.VEX
	VEXAssertion = attestation.VEXAssertion
)

func decodeSpec(data []byte) (*Spec, error) { return DecodeSpec(data) }

func applyDefaults(value *Spec) { ApplyDefaults(value) }

func copySpec(value *Spec) (*Spec, error) { return CopySpec(value) }

func canonicalSpec(value *Spec) ([]byte, error) { return CanonicalSpec(value) }

func canonicalValue(value reflect.Value) (any, error) { return CanonicalValue(value) }

func checkDigestText(value reflect.Value) error { return CheckDigestText(value) }
