// Package ubuntu implements Ubuntu distribution policy.
package ubuntu

import (
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

const (
	distroName   = "ubuntu"
	archiveAMD64 = "https://archive.ubuntu.com/ubuntu"
	archiveARM64 = "https://ports.ubuntu.com/ubuntu-ports"
)

// currentRelease is the release the provider's reviewed data describes.
const currentRelease = "26.04"

// testedReleases is a diagnostic baseline, not an allowlist: other numeric
// releases still attempt resolution with current catalogue/configuration data.
var testedReleases = map[string]bool{currentRelease: true}

// caBundlePath is where Ubuntu's ca-certificates package writes the bundle.
const caBundlePath = "/etc/ssl/certs/ca-certificates.crt"

// codenames maps reviewed Ubuntu release codenames to their canonical version.
// Unknown codenames are accepted as release identity and reported as untested.
var codenames = map[string]string{"resolute": currentRelease}

// Provider is Ubuntu policy for one release.
type Provider struct {
	release string
}

// New returns the Ubuntu provider for a numeric release or codename.
func New(release string) *Provider {
	if canonical, ok := codenames[release]; ok {
		release = canonical
	}
	return &Provider{release: release}
}

// Distro implements distro.Provider.
func (p *Provider) Distro() string { return distroName }

// Release implements distro.Provider.
func (p *Provider) Release() string { return p.release }

// CABundlePath implements distro.Provider. Ubuntu's ca-certificates package
// installs the bundle here and both /etc/ssl/certs and /usr/lib/ssl link to it.
func (p *Provider) CABundlePath() string { return caBundlePath }

// ReleaseWarnings implements distro.Provider. It never supplies a suite:
// suites come from the catalogue or explicit repository configuration.
func (p *Provider) ReleaseWarnings() []string {
	if testedReleases[p.release] {
		return nil
	}
	return []string{fmt.Sprintf("ubuntu release %q is not a tested baseline; resolution will be attempted", p.release)}
}

// AllowedSuites implements distro.Provider. Ubuntu's suites come from the
// declaration, so there is no provider-owned list to check against.
func (p *Provider) AllowedSuites() []string { return nil }

// ReleaseMatching implements distro.Provider. Ubuntu signs a fixed suite, so the
// exact suite match applies and components keep their plain names.
func (p *Provider) ReleaseMatching() deb.ReleaseIdentity { return deb.ReleaseIdentity{} }

// releaseNames maps reviewed releases to the descriptive name Ubuntu publishes
// in os-release. An unreviewed release has no pinned name, so synthesis falls
// back to whatever the selected release state says.
var releaseNames = map[string]string{
	currentRelease: "Ubuntu 26.04 LTS",
}

// ReleaseIdentity implements distro.Provider.
func (p *Provider) ReleaseIdentity() map[string]string {
	identity := map[string]string{
		"ID":         "ubuntu",
		"ID_LIKE":    "debian",
		"VERSION_ID": p.release,
	}
	if codename := p.codename(); codename != "" {
		identity["VERSION_CODENAME"] = codename
	}
	if name := releaseNames[p.release]; name != "" {
		identity["NAME"], identity["VERSION"] = name, name
	}
	return identity
}

// codename returns the reviewed codename for a numeric release, or the release
// itself when it was given as a codename.
func (p *Provider) codename() string {
	for name, version := range codenames {
		if version == p.release {
			return name
		}
	}
	return ""
}

// Architecture implements distro.Provider.
func (p *Provider) Architecture(platform string) (string, error) {
	architecture, ok := deb.Architecture(platform)
	if !ok {
		return "", fmt.Errorf("unsupported platform %q", platform)
	}
	return architecture, nil
}
