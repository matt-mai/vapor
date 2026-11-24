// Package distro selects distribution providers and defines their shared contract.
package distro

import (
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/debian"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
	"github.com/matt-mai/vapor/internal/synthesis"
)

// Provider is the distribution policy for one image release.
//
// A provider owns release, repository and archive policy for its distribution.
// Shared DEB/APT mechanics live in internal/distro/deb; catalogue and slice
// semantics are distribution-independent.
type Provider interface {
	// Distro returns the distribution identifier this provider implements.
	Distro() string
	// Release returns the release the provider was selected for.
	Release() string
	// ReleaseWarnings returns non-fatal release diagnostics, such as an untested
	// baseline. They do not authorize skipping trust or identity checks, and are
	// not locked content or digest input.
	ReleaseWarnings() []string
	// Architecture maps an OCI platform to its native package architecture.
	Architecture(platform string) (string, error)
	// Archives returns the archives the provider itself serves, each with its own
	// endpoint, suites, components and keys. A specification that names only
	// packages is read from these, so it does not restate a reviewed endpoint or
	// key. Each archive's keys are evidence for its own suites only.
	Archives() []deb.SignedArchive
	// DefaultTrust returns every reviewed key snapshot, across all archives, for a
	// caller that cannot name an archive. Explicit trust replaces them; it never
	// merges.
	DefaultTrust() []deb.KeySnapshot
	// AllowedSuites returns every suite an image of this release may read, whether
	// it comes from the provider archive or from an explicit repository. An empty
	// list leaves the suites to the declaration, which is what Ubuntu does.
	AllowedSuites() []string
	// ReleaseMatching returns the rules authenticated release metadata must
	// satisfy. Suites, architecture and components come from the request, so a
	// provider fills only the matching rules.
	ReleaseMatching() deb.ReleaseIdentity
	// ProTrust returns reviewed key snapshots for a Pro service when its archive
	// has no explicit trust. Explicit trust replaces them; it never merges.
	ProTrust(service string) []deb.KeySnapshot
	// BaseAccountMasters returns the files the distribution's packages ship in place
	// of a populated account database. Synthesis merges them into whatever the image
	// already has, so the paths are policy and live here rather than in synthesis.
	BaseAccountMasters() synthesis.BaseAccountMasters
	// CABundlePath returns where the provider's images keep the public certificate
	// bundle. Synthesis takes the location as an argument so no distribution path
	// is hardcoded outside provider policy.
	CABundlePath() string
	// ReleaseIdentity returns the os-release fields this provider considers
	// authoritative, keyed by field name. Synthesis uses them to fill missing
	// release state and to reject an override that contradicts the provider. A
	// field the provider does not pin is absent from the map.
	ReleaseIdentity() map[string]string
}

// providers lists implemented distributions explicitly. A missing entry is an
// unsupported distribution, never a request for a generic fallback.
var providers = map[string]func(release string) (Provider, error){
	"ubuntu": func(release string) (Provider, error) { return ubuntu.New(release), nil },
	"debian": func(release string) (Provider, error) { return debian.New(release) },
}

var (
	_ Provider = (*ubuntu.Provider)(nil)
	_ Provider = (*debian.Provider)(nil)
)

// Select returns the provider for a distribution and release. Unsupported
// distributions and releases a provider refuses both fail here, so no caller can
// hold a provider whose policy it does not know.
func Select(distribution, release string) (Provider, error) {
	newProvider, ok := providers[distribution]
	if !ok {
		return nil, fmt.Errorf("distribution %q is not supported", distribution)
	}
	return newProvider(release)
}
