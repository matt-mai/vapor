package ubuntu_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/ubuntu"
)

func TestProvider_Architecture(t *testing.T) {
	t.Parallel()
	provider := ubuntu.New("26.04")
	tests := []struct {
		platform string
		want     string
	}{
		{platform: "linux/amd64", want: "amd64"},
		{platform: "linux/arm64", want: "arm64"},
	}
	for _, test := range tests {
		got, err := provider.Architecture(test.platform)
		if err != nil {
			t.Errorf("Architecture(%q): %v", test.platform, err)
			continue
		}
		if got != test.want {
			t.Errorf("Architecture(%q) = %q, want %q", test.platform, got, test.want)
		}
	}
	for _, platform := range []string{"linux/386", "all", ""} {
		if _, err := provider.Architecture(platform); err == nil {
			t.Errorf("Architecture(%q) succeeded, want an error", platform)
		}
	}
}

func TestProvider_Codenames(t *testing.T) {
	t.Parallel()
	known := ubuntu.New("resolute")
	if known.Release() != "26.04" {
		t.Fatalf("Release(resolute) = %q, want 26.04", known.Release())
	}
	if warnings := known.ReleaseWarnings(); len(warnings) != 0 {
		t.Fatalf("ReleaseWarnings(resolute) = %q, want none", warnings)
	}
	unknown := ubuntu.New("ferocious")
	if unknown.Release() != "ferocious" {
		t.Fatalf("Release(ferocious) = %q, want the codename preserved", unknown.Release())
	}
	if warnings := unknown.ReleaseWarnings(); len(warnings) != 1 {
		t.Fatalf("ReleaseWarnings(ferocious) = %q, want one warning", warnings)
	}
}

func TestProvider_ReleaseWarnings(t *testing.T) {
	t.Parallel()
	if warnings := ubuntu.New("26.04").ReleaseWarnings(); len(warnings) != 0 {
		t.Fatalf("ReleaseWarnings(26.04) = %q, want none", warnings)
	}
	for _, release := range []string{"26.10", "24.04", "99.04"} {
		warnings := ubuntu.New(release).ReleaseWarnings()
		if len(warnings) != 1 {
			t.Fatalf("ReleaseWarnings(%q) = %q, want one warning", release, warnings)
		}
		if !strings.Contains(warnings[0], "not a tested baseline") {
			t.Errorf("ReleaseWarnings(%q) = %q, want an untested-baseline warning", release, warnings[0])
		}
		if strings.Contains(warnings[0], "resolute") {
			t.Errorf("ReleaseWarnings(%q) = %q, want no codename mapping", release, warnings[0])
		}
	}
}

func TestProvider_ArchivesServePlatformsFromTheirOwnHosts(t *testing.T) {
	t.Parallel()
	archives := ubuntu.New("26.04").Archives()
	if len(archives) != 1 {
		t.Fatalf("Archives() has %d entries, want one", len(archives))
	}
	for platform, want := range map[string]string{
		"linux/amd64": "https://archive.ubuntu.com/ubuntu",
		"linux/arm64": "https://ports.ubuntu.com/ubuntu-ports",
	} {
		got, ok := archives[0].Endpoint(platform)
		if !ok || got != want {
			t.Errorf("archive endpoint for %q = %q, %v; want %q", platform, got, ok, want)
		}
	}
	for _, platform := range []string{"linux/386", "all", ""} {
		if _, ok := archives[0].Endpoint(platform); ok {
			t.Errorf("archive endpoint for %q exists, want none", platform)
		}
	}
}

func TestProvider_ArchivesLeaveSuitesToTheDeclaration(t *testing.T) {
	t.Parallel()
	archives := ubuntu.New("26.04").Archives()
	if len(archives) != 1 {
		t.Fatalf("Archives() has %d entries, want the one Ubuntu archive", len(archives))
	}
	archive := archives[0]
	if len(archive.Suites) != 0 || len(archive.Components) != 0 {
		t.Fatalf("archive suites %v components %v, want none", archive.Suites, archive.Components)
	}
	if archive.Endpoints["linux/amd64"] != "https://archive.ubuntu.com/ubuntu" ||
		archive.Endpoints["linux/arm64"] != "https://ports.ubuntu.com/ubuntu-ports" {
		t.Fatalf("archive endpoints = %v", archive.Endpoints)
	}
	if len(archive.Keys) != 1 {
		t.Fatalf("archive has %d keys, want the one Ubuntu archive key", len(archive.Keys))
	}
}

func TestReleaseIdentity(t *testing.T) {
	identity := ubuntu.New("26.04").ReleaseIdentity()
	want := map[string]string{
		"ID": "ubuntu", "ID_LIKE": "debian", "VERSION_ID": "26.04",
		"VERSION_CODENAME": "resolute", "NAME": "Ubuntu 26.04 LTS", "VERSION": "Ubuntu 26.04 LTS",
	}
	for key, value := range want {
		if identity[key] != value {
			t.Fatalf("%s = %q, want %q", key, identity[key], value)
		}
	}
}

func TestReleaseIdentityAcceptsCodename(t *testing.T) {
	if identity := ubuntu.New("resolute").ReleaseIdentity(); identity["VERSION_ID"] != "26.04" {
		t.Fatalf("VERSION_ID = %q", identity["VERSION_ID"])
	}
}

func TestReleaseIdentityOmitsUnreviewedNames(t *testing.T) {
	identity := ubuntu.New("24.04").ReleaseIdentity()
	if identity["VERSION_ID"] != "24.04" || identity["ID"] != "ubuntu" {
		t.Fatalf("identity = %v", identity)
	}
	if _, ok := identity["NAME"]; ok {
		t.Fatalf("unreviewed release pinned a name: %v", identity)
	}
	if _, ok := identity["VERSION_CODENAME"]; ok {
		t.Fatalf("unreviewed release pinned a codename: %v", identity)
	}
}
