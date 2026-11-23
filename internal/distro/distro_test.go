package distro_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestSelect_Ubuntu(t *testing.T) {
	t.Parallel()
	provider, err := distro.Select("ubuntu", "26.04")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := provider.Distro(), "ubuntu"; got != want {
		t.Fatalf("Distro() = %q, want %q", got, want)
	}
	if got, want := provider.Release(), "26.04"; got != want {
		t.Fatalf("Release() = %q, want %q", got, want)
	}
	architecture, err := provider.Architecture("linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if architecture != "amd64" {
		t.Fatalf("Architecture(linux/amd64) = %q, want amd64", architecture)
	}
	endpoint, ok := provider.Archives()[0].Endpoint("linux/arm64")
	if !ok || endpoint != "https://ports.ubuntu.com/ubuntu-ports" {
		t.Fatalf("archive endpoint for linux/arm64 = %q, want the ports archive", endpoint)
	}
}

func TestSelect_CodenameNormalizes(t *testing.T) {
	t.Parallel()
	provider, err := distro.Select("ubuntu", "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := provider.Release(), "26.04"; got != want {
		t.Fatalf("Release() = %q, want %q", got, want)
	}
	if warnings := provider.ReleaseWarnings(); len(warnings) != 0 {
		t.Fatalf("ReleaseWarnings() = %q, want none", warnings)
	}
}

func TestSelect_UntestedReleaseWarnsButResolves(t *testing.T) {
	t.Parallel()
	provider, err := distro.Select("ubuntu", "26.10")
	if err != nil {
		t.Fatal(err)
	}
	if warnings := provider.ReleaseWarnings(); len(warnings) == 0 {
		t.Fatal("ReleaseWarnings() is empty for an untested release")
	}
	if _, err := provider.Architecture("linux/amd64"); err != nil {
		t.Fatalf("Architecture(linux/amd64): %v", err)
	}
	if _, err := provider.Architecture("linux/386"); err == nil {
		t.Fatal("Architecture(linux/386) succeeded for an untested release, want an error")
	}
}

// Debian versions and codenames both resolve to the codename, which is the identity a
// lock records, so the two spellings cannot drift apart.
func TestSelect_Debian(t *testing.T) {
	t.Parallel()
	for _, release := range []string{"trixie", "13"} {
		provider, err := distro.Select("debian", release)
		if err != nil {
			t.Fatalf("Select(debian, %q): %v", release, err)
		}
		if got, want := provider.Distro(), "debian"; got != want {
			t.Fatalf("Distro() = %q, want %q", got, want)
		}
		if got, want := provider.Release(), "trixie"; got != want {
			t.Fatalf("Select(debian, %q).Release() = %q, want %q", release, got, want)
		}
		if warnings := provider.ReleaseWarnings(); len(warnings) != 0 {
			t.Fatalf("ReleaseWarnings() = %q, want none", warnings)
		}
		archives := provider.Archives()
		if len(archives) != 2 {
			t.Fatalf("Archives() has %d entries, want main and security", len(archives))
		}
		if got, want := archives[0].Name, "debian"; got != want {
			t.Fatalf("Archives()[0].Name = %q, want %q", got, want)
		}
		if got, want := archives[0].Suites, []string{"trixie", "trixie-updates"}; !slices.Equal(got, want) {
			t.Fatalf("main archival suites = %v, want %v", got, want)
		}
		if got, want := archives[1].Name, "debian-security"; got != want {
			t.Fatalf("Archives()[1].Name = %q, want %q", got, want)
		}
		if got, want := archives[1].Suites, []string{"trixie-security"}; !slices.Equal(got, want) {
			t.Fatalf("security archival suites = %v, want %v", got, want)
		}
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			architecture, err := provider.Architecture(platform)
			if err != nil {
				t.Fatal(err)
			}
			if architecture != strings.TrimPrefix(platform, "linux/") {
				t.Fatalf("Architecture(%q) = %q", platform, architecture)
			}
			for _, archive := range archives {
				if _, ok := archive.Endpoint(platform); !ok {
					t.Fatalf("archive %q has no endpoint for %q", archive.Name, platform)
				}
			}
		}
		if got := provider.DefaultTrust(); len(got) != 2 {
			t.Fatalf("DefaultTrust() has %d snapshots, want main and security", len(got))
		}
	}
}

// A moving alias names a suite that changes under an image, so selection refuses it
// rather than locking whichever release happens to be current.
func TestSelect_DebianRejectsMovingAlias(t *testing.T) {
	t.Parallel()
	for _, release := range []string{"stable", "testing", "unstable", "oldstable"} {
		provider, err := distro.Select("debian", release)
		if err == nil || !strings.Contains(err.Error(), "moving alias") {
			t.Fatalf("Select(debian, %q) = %v, %v", release, provider, err)
		}
	}
}

func TestSelect_UnsupportedDistribution(t *testing.T) {
	t.Parallel()
	for _, distribution := range []string{"alpine", "Ubuntu", ""} {
		provider, err := distro.Select(distribution, "26.04")
		if err == nil {
			t.Fatalf("Select(%q) returned %v, want an error", distribution, provider)
		}
		if !strings.Contains(err.Error(), "is not supported") {
			t.Fatalf("Select(%q) error = %q, want an unsupported-distribution error", distribution, err)
		}
	}
}

// TestProvider_ArchivesScopeKeysToTheirOwnSuites checks that Debian's two archives
// carry different endpoints and different keys: the whole point of listing an archive
// with its suites is that one archive's key cannot vouch for the other's release.
func TestProvider_ArchivesScopeKeysToTheirOwnSuites(t *testing.T) {
	t.Parallel()
	provider, err := distro.Select("debian", "trixie")
	if err != nil {
		t.Fatal(err)
	}
	archives := provider.Archives()
	if len(archives) != 2 {
		t.Fatalf("Archives() has %d entries, want main and security", len(archives))
	}
	main, security := archives[0], archives[1]
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		mainEndpoint, ok := main.Endpoint(platform)
		if !ok || mainEndpoint != "https://deb.debian.org/debian" {
			t.Fatalf("main endpoint for %s = %q", platform, mainEndpoint)
		}
		securityEndpoint, ok := security.Endpoint(platform)
		if !ok || securityEndpoint != "https://security.debian.org/debian-security" {
			t.Fatalf("security endpoint for %s = %q", platform, securityEndpoint)
		}
	}
	mainKeys := keyFingerprints(main.Keys)
	securityKeys := keyFingerprints(security.Keys)
	if len(mainKeys) == 0 || len(securityKeys) == 0 {
		t.Fatalf("archives have no keys: main %v security %v", mainKeys, securityKeys)
	}
	for _, fingerprint := range securityKeys {
		if slices.Contains(mainKeys, fingerprint) {
			t.Fatalf("fingerprint %s signs both archives", fingerprint)
		}
	}
	if suites := security.Suites; !slices.Equal(suites, []string{"trixie-security"}) {
		t.Fatalf("security suites = %v", suites)
	}
	if suites := main.Suites; slices.Contains(suites, "trixie-security") {
		t.Fatalf("main suites include the security suite: %v", suites)
	}
}

func keyFingerprints(snapshots []deb.KeySnapshot) []string {
	var fingerprints []string
	for i := range snapshots {
		fingerprints = append(fingerprints, snapshots[i].Fingerprints...)
	}
	return fingerprints
}
