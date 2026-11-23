package debian_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/distro/debian"
)

func TestNewAliases(t *testing.T) {
	t.Parallel()
	for release, want := range map[string]string{
		"trixie": "trixie", "13": "trixie", "bookworm": "bookworm", "12": "bookworm",
	} {
		provider, err := debian.New(release)
		if err != nil {
			t.Fatalf("New(%q): %v", release, err)
		}
		if provider.Release() != want {
			t.Errorf("New(%q).Release() = %q, want %q", release, provider.Release(), want)
		}
		if provider.Distro() != "debian" {
			t.Errorf("New(%q).Distro() = %q", release, provider.Distro())
		}
	}
}

func TestNewRejects(t *testing.T) {
	t.Parallel()
	for _, release := range []string{
		"", "stable", "oldstable", "oldoldstable", "testing", "unstable", "experimental",
		"11", "14", "99.1",
	} {
		provider, err := debian.New(release)
		if err == nil {
			t.Fatalf("New(%q) returned %v, want an error", release, provider)
		}
	}
}

func TestNewUnknownCodename(t *testing.T) {
	t.Parallel()
	provider, err := debian.New("forky")
	if err != nil {
		t.Fatal(err)
	}
	if provider.Release() != "forky" {
		t.Fatalf("Release() = %q, want the codename preserved", provider.Release())
	}
	warnings := provider.ReleaseWarnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "explicit repositories and trust keys") {
		t.Fatalf("ReleaseWarnings() = %q", warnings)
	}
}

func TestReleaseWarnings(t *testing.T) {
	t.Parallel()
	if warnings := mustNew(t, "trixie").ReleaseWarnings(); len(warnings) != 0 {
		t.Fatalf("ReleaseWarnings(trixie) = %q, want none", warnings)
	}
	warnings := mustNew(t, "bookworm").ReleaseWarnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not the tested baseline") {
		t.Fatalf("ReleaseWarnings(bookworm) = %q", warnings)
	}
	// The alias and the codename are the same lock identity, warnings included.
	if mustNew(t, "12").Release() != mustNew(t, "bookworm").Release() {
		t.Fatal("12 and bookworm did not canonicalize to the same release")
	}
}

func TestArchitectureAndEndpoint(t *testing.T) {
	t.Parallel()
	provider := mustNew(t, "trixie")
	for platform, want := range map[string]string{
		"linux/amd64": "amd64", "linux/arm64": "arm64",
	} {
		architecture, err := provider.Architecture(platform)
		if err != nil || architecture != want {
			t.Errorf("Architecture(%q) = %q, %v; want %q", platform, architecture, err, want)
		}
		archive := provider.Archives()[0]
		if endpoint, ok := archive.Endpoint(platform); !ok || endpoint != "https://deb.debian.org/debian" {
			t.Errorf("main archive endpoint for %q = %q, %v", platform, endpoint, ok)
		}
	}
	for _, platform := range []string{"linux/386", "all", ""} {
		if _, err := provider.Architecture(platform); err == nil {
			t.Errorf("Architecture(%q) succeeded, want an error", platform)
		}
		for _, archive := range provider.Archives() {
			if _, ok := archive.Endpoint(platform); ok {
				t.Errorf("archive %q endpoint for %q exists, want none", archive.Name, platform)
			}
		}
	}
}

func TestTrustAndIdentity(t *testing.T) {
	t.Parallel()
	provider := mustNew(t, "trixie")
	if trust := provider.ProTrust("esm-apps"); len(trust) != 0 {
		t.Fatalf("ProTrust() = %v, want none", trust)
	}
	if provider.CABundlePath() != "/etc/ssl/certs/ca-certificates.crt" {
		t.Fatalf("CABundlePath() = %q", provider.CABundlePath())
	}
}

func TestReleaseIdentity(t *testing.T) {
	t.Parallel()
	want := map[string]map[string]string{
		"trixie":   {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"},
		"13":       {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"},
		"bookworm": {"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"},
	}
	for release, fields := range want {
		identity := mustNew(t, release).ReleaseIdentity()
		for key, value := range fields {
			if identity[key] != value {
				t.Errorf("New(%q).ReleaseIdentity()[%q] = %q, want %q", release, key, identity[key], value)
			}
		}
		// The empty entries are the fields Debian does not publish.
		if len(identity) != len(fields)+2 {
			t.Errorf("New(%q).ReleaseIdentity() = %v, want %d fields", release, identity, len(fields)+2)
		}
		for _, absent := range []string{"ID_LIKE", "UBUNTU_CODENAME"} {
			if value, ok := identity[absent]; !ok || value != "" {
				t.Errorf("New(%q).ReleaseIdentity()[%q] = %q, want an empty entry", release, absent, value)
			}
		}
	}
}

// An unknown codename has no version number, so the provider does not invent one.
func TestReleaseIdentityUnknownCodename(t *testing.T) {
	t.Parallel()
	identity := mustNew(t, "forky").ReleaseIdentity()
	if identity["VERSION_CODENAME"] != "forky" || identity["ID"] != "debian" {
		t.Fatalf("ReleaseIdentity() = %v", identity)
	}
	if _, ok := identity["VERSION_ID"]; ok {
		t.Fatalf("ReleaseIdentity() invented a VERSION_ID: %v", identity)
	}
}

// Selection and the package's own constructor must agree on the canonical release, so
// every entry point locks the same identity.
func TestRegistration(t *testing.T) {
	t.Parallel()
	selected, err := distro.Select("debian", "13")
	if err != nil {
		t.Fatal(err)
	}
	direct := mustNew(t, "trixie")
	if selected.Release() != direct.Release() || selected.Distro() != direct.Distro() {
		t.Fatalf("Select(debian, 13) = %s/%s, New(trixie) = %s/%s",
			selected.Distro(), selected.Release(), direct.Distro(), direct.Release())
	}
	if _, err := distro.Select("debian", "stable"); err == nil {
		t.Fatal("Select(debian, stable) succeeded, want a refusal")
	}
}

func mustNew(t *testing.T, release string) *debian.Provider {
	t.Helper()
	provider, err := debian.New(release)
	if err != nil {
		t.Fatalf("New(%q): %v", release, err)
	}
	return provider
}
