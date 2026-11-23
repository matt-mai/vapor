package ubuntu

import (
	"bytes"
	_ "embed"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// Reviewed full fingerprints. Rotation requires an explicit policy change.
const (
	archiveKeyFingerprint = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
	appsKeyFingerprint    = "E8A443CE358113D187BEE0E6AB01A101DB53907B"
	esmKeyFingerprint     = "56F7650A24C9E9ECF87C4D8D4067E40313CB4B13"
	fipsKeyFingerprint    = "E23341B2A1467EDBF07057D6C1997C40EDE22758"
)

//go:embed keys/ubuntu-archive-key-2018.asc
var archiveKeyArmor []byte

//go:embed keys/ubuntu-apps-key.asc
var appsKeyArmor []byte

//go:embed keys/ubuntu-esm-key-v2.asc
var esmKeyArmor []byte

//go:embed keys/ubuntu-fips-key-v1.asc
var fipsKeyArmor []byte

// DefaultTrust implements distro.Provider for the Ubuntu archive.
func (p *Provider) DefaultTrust() []deb.KeySnapshot {
	return []deb.KeySnapshot{{
		Fingerprints: []string{archiveKeyFingerprint},
		Data:         bytes.Clone(archiveKeyArmor),
	}}
}

// ProTrust implements distro.Provider for Ubuntu Pro services.
func (p *Provider) ProTrust(service string) []deb.KeySnapshot {
	switch service {
	case "esm-apps":
		return []deb.KeySnapshot{{Fingerprints: []string{appsKeyFingerprint}, Data: bytes.Clone(appsKeyArmor)}}
	case "esm-infra":
		return []deb.KeySnapshot{{Fingerprints: []string{esmKeyFingerprint}, Data: bytes.Clone(esmKeyArmor)}}
	case "fips", "fips-updates":
		return []deb.KeySnapshot{{Fingerprints: []string{fipsKeyFingerprint}, Data: bytes.Clone(fipsKeyArmor)}}
	default:
		return nil
	}
}

// Archives implements distro.Provider. Ubuntu publishes amd64 packages from
// archive.ubuntu.com and arm64 packages from the ports archive, and both are signed
// by the same reviewed archive key. Suites are left to the catalogue and the
// declared repositories, so they are not listed here.
func (p *Provider) Archives() []deb.SignedArchive {
	return []deb.SignedArchive{{
		Name: distroName,
		Endpoints: map[string]string{
			deb.PlatformAMD64: archiveAMD64,
			deb.PlatformARM64: archiveARM64,
		},
		Keys: []deb.KeySnapshot{{Fingerprints: []string{archiveKeyFingerprint}, Data: bytes.Clone(archiveKeyArmor)}},
	}}
}
