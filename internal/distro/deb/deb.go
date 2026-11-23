// Package deb implements shared Debian package and APT repository mechanics.
package deb

// Supported image platforms.
const (
	PlatformAMD64 = "linux/amd64"
	PlatformARM64 = "linux/arm64"
)

// Architecture maps an OCI platform to its native Debian architecture.
func Architecture(platform string) (string, bool) {
	switch platform {
	case PlatformAMD64:
		return "amd64", true
	case PlatformARM64:
		return "arm64", true
	default:
		return "", false
	}
}
