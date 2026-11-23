// Package debian implements Debian distribution policy.
package debian

import (
	"bytes"
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// distroName is the provider name and the name of its main archive.
const distroName = "debian"

// mainArchive serves both supported platforms; Debian publishes them together.
const mainArchive = "https://deb.debian.org/debian"

// securityArchive and securityArchiveURL name the archive that publishes security
// fixes. It is a separate host with separate keys.
const (
	securityArchive    = "debian-security"
	securityArchiveURL = "https://security.debian.org/debian-security"
)

// caBundlePath is where Debian's ca-certificates package writes the bundle.
const caBundlePath = "/etc/ssl/certs/ca-certificates.crt"

// updatesSuffix names the suite that carries point releases beside the codename.
const updatesSuffix = "-updates"

// securitySuffix names the suite Debian publishes security fixes under, on its own
// host.
const securitySuffix = "-security"

// testedRelease is the release whose archive data is reviewed. It is a warning
// baseline, not an allowlist.
const testedRelease = "trixie"

// bookworm is the previous release; it locks but is not the reviewed baseline.
const bookworm = "bookworm"

// releases map the known codenames to the version number Debian publishes in
// os-release as VERSION_ID.
var releases = map[string]string{testedRelease: "13", bookworm: "12"}

// codenames are the known releases, canonical as codenames.
var codenames = map[string]string{testedRelease: testedRelease, bookworm: bookworm}

// aliases map version numbers to the codename that identifies the release.
var aliases = map[string]string{"13": testedRelease, "12": bookworm}

// movingAliases name whatever release is current today, so they cannot identify
// a locked image.
var movingAliases = map[string]bool{
	"stable": true, "oldstable": true, "oldoldstable": true,
	"testing": true, "unstable": true, "experimental": true,
}

// Provider is Debian policy for one release.
type Provider struct {
	release string
}

// New returns the Debian provider for a codename or version number. A moving
// alias and an unmappable number are errors; an unfamiliar codename is accepted
// as the release identity and reported as untested.
func New(release string) (*Provider, error) {
	canonical, err := canonicalRelease(release)
	if err != nil {
		return nil, err
	}
	return &Provider{release: canonical}, nil
}

// Distro implements distro.Provider.
func (p *Provider) Distro() string { return distroName }

// Release implements distro.Provider. The canonical release is the codename.
func (p *Provider) Release() string { return p.release }

// CABundlePath implements distro.Provider.
func (p *Provider) CABundlePath() string { return caBundlePath }

// ReleaseWarnings implements distro.Provider. Bookworm and codenames Vapor has
// not reviewed still lock, but an unfamiliar codename also needs explicit
// repositories and trust keys, which only the specification can supply.
func (p *Provider) ReleaseWarnings() []string {
	switch {
	case p.release == testedRelease:
		return nil
	case codenames[p.release] != "":
		return []string{fmt.Sprintf("debian release %q is not the tested baseline %q; resolution will be attempted",
			p.release, testedRelease)}
	default:
		return []string{fmt.Sprintf("debian release %q is not a known release; "+
			"declare explicit repositories and trust keys, and expect resolution to be attempted", p.release)}
	}
}

// ReleaseIdentity implements distro.Provider. Debian's os-release carries no
// ID_LIKE and no UBUNTU_CODENAME, so the provider pins neither: a selected package
// claiming them is a contradiction synthesis reports. An unknown codename has no
// version number, and the provider does not invent one.
func (p *Provider) ReleaseIdentity() map[string]string {
	// Debian publishes neither field. The empty entries tell synthesis the
	// distribution has no such field, so a selected package claiming one is refused.
	identity := map[string]string{
		"ID": distroName, "VERSION_CODENAME": p.release, "ID_LIKE": "", "UBUNTU_CODENAME": "",
	}
	if release := releases[p.release]; release != "" {
		identity["VERSION_ID"] = release
	}
	return identity
}

// Architecture implements distro.Provider.
func (p *Provider) Architecture(platform string) (string, error) {
	architecture, ok := deb.Architecture(platform)
	if !ok {
		return "", fmt.Errorf("unsupported platform %q", platform)
	}
	return architecture, nil
}

// Archives implements distro.Provider with the reviewed archives of a known
// codename. Debian publishes ordinary packages in the main archive and security
// fixes on another host, and the two are signed by different keys, so each is a
// separate archive with its own endpoint, suites and keys. An unreviewed codename
// gets none: only a specification can say where its packages come from.
func (p *Provider) Archives() []deb.SignedArchive {
	suites := []string{p.release, p.release + updatesSuffix}
	switch p.release {
	case bookworm:
		return []deb.SignedArchive{
			mainArchiveEntry(archiveKey12Fingerprint, bookwormArchiveKey, suites),
			securityArchiveEntry(securityKey12Fingerprint, bookwormSecurityKey, p.release),
		}
	case testedRelease:
		return []deb.SignedArchive{
			mainArchiveEntry(archiveKey13Fingerprint, trixieArchiveKey, suites),
			securityArchiveEntry(securityKey13Fingerprint, trixieSecurityKey, p.release),
		}
	default:
		return nil
	}
}

// mainArchiveEntry is the reviewed main archive: both supported platforms, one
// host, and the suites a codename and its point releases are published under.
func mainArchiveEntry(fingerprint string, key []byte, suites []string) deb.SignedArchive {
	return deb.SignedArchive{
		Name: distroName,
		Endpoints: map[string]string{
			deb.PlatformAMD64: mainArchive,
			deb.PlatformARM64: mainArchive,
		},
		Suites: suites, Components: []string{"main"},
		Keys: []deb.KeySnapshot{{Fingerprints: []string{fingerprint}, Data: bytes.Clone(key)}},
	}
}

// securityArchiveEntry is the reviewed security archive. Its name is the one a
// specification declares to add it beside the main archive.
func securityArchiveEntry(fingerprint string, key []byte, release string) deb.SignedArchive {
	return deb.SignedArchive{
		Name: securityArchive,
		Endpoints: map[string]string{
			deb.PlatformAMD64: securityArchiveURL,
			deb.PlatformARM64: securityArchiveURL,
		},
		Suites: []string{release + securitySuffix}, Components: []string{"main"},
		Keys: []deb.KeySnapshot{{Fingerprints: []string{fingerprint}, Data: bytes.Clone(key)}},
	}
}

// DefaultTrust implements distro.Provider with the reviewed keys of every archive
// for a known codename. A caller that needs one archive's keys reads them from
// Archives instead, so a security key is never evidence for a main-archive suite.
func (p *Provider) DefaultTrust() []deb.KeySnapshot {
	var snapshots []deb.KeySnapshot
	for _, archive := range p.Archives() {
		snapshots = append(snapshots, archive.Keys...)
	}
	return snapshots
}

// ProTrust implements distro.Provider. Debian has no Pro equivalent.
func (p *Provider) ProTrust(string) []deb.KeySnapshot { return nil }

// AllowedSuites implements distro.Provider. A release reads three suites: its own,
// its updates and its security suite. Anything else belongs to another release, so
// an explicitly declared repository cannot widen it.
func (p *Provider) AllowedSuites() []string {
	return []string{p.release, p.release + updatesSuffix, p.release + securitySuffix}
}

// ReleaseMatching implements distro.Provider. Debian signs a moving suite name
// beside a fixed codename, so releases match on the codename, and the security
// archive's updates/<component> names resolve to the plain component.
func (p *Provider) ReleaseMatching() deb.ReleaseIdentity {
	return deb.ReleaseIdentity{MatchCodename: true, PrefixedComponents: true}
}

func canonicalRelease(release string) (string, error) {
	if release == "" {
		return "", fmt.Errorf("debian release is empty")
	}
	if movingAliases[release] {
		return "", fmt.Errorf("debian release %q is a moving alias; name a codename", release)
	}
	if codename, ok := aliases[release]; ok {
		return codename, nil
	}
	if isNumber(release) {
		return "", fmt.Errorf("debian release %q is not a known version number", release)
	}
	return release, nil
}

// isNumber reports a version-like release. A codename never starts with a digit.
func isNumber(value string) bool {
	return '0' <= value[0] && value[0] <= '9'
}
