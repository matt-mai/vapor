package debian

import _ "embed"

// Reviewed archive keys, one snapshot per archive and release. The fingerprints are
// the primary keys listed at https://ftp-master.debian.org/keys.html, and each
// snapshot keeps the bound signing subkeys, because that is what signs a release.
//
// Source: https://ftp-master.debian.org/keys/archive-key-{12,13}.asc and
// https://ftp-master.debian.org/keys/archive-key-{12,13}-security.asc, retrieved
// 2026-11-20. The same keys ship in Debian's archive keyring package. All of them
// expire in 2035, so a rotation is a deliberate change here.
const (
	archiveKey12Fingerprint  = "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8"
	securityKey12Fingerprint = "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"
	archiveKey13Fingerprint  = "04B54C3CDCA79751B16BC6B5225629DF75B188BD"
	securityKey13Fingerprint = "5E04A1E3223A19A20706E20F9904613D4CCE68C6"
)

var (
	//go:embed keys/debian-archive-key-12.asc
	bookwormArchiveKey []byte

	//go:embed keys/debian-security-archive-key-12.asc
	bookwormSecurityKey []byte

	//go:embed keys/debian-archive-key-13.asc
	trixieArchiveKey []byte

	//go:embed keys/debian-security-archive-key-13.asc
	trixieSecurityKey []byte
)
