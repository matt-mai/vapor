package deb_test

import (
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestCheckReleaseIdentity(t *testing.T) {
	release := deb.Release{
		Suite:         "resolute",
		Architectures: []string{"amd64", "arm64"},
		Components:    []string{"main", "restricted", "universe"},
	}
	cases := []struct {
		name     string
		expected deb.ReleaseIdentity
		wantErr  string
	}{
		{name: "match", expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "amd64", Components: []string{"main", "restricted"}}},
		{name: "all components", expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "arm64", Components: []string{"main", "universe"}}},
		{name: "no components requested", expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "amd64"}},
		{name: "missing expected suite", expected: deb.ReleaseIdentity{Architecture: "amd64"}, wantErr: "expected release suite is empty"},
		{name: "missing expected architecture", expected: deb.ReleaseIdentity{Suite: "resolute"}, wantErr: "expected release architecture is empty"},
		{name: "wrong suite", expected: deb.ReleaseIdentity{Suite: "noble", Architecture: "amd64"}, wantErr: "does not match"},
		{name: "missing architecture", expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "i386"}, wantErr: "does not list architecture"},
		{name: "missing component", expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "amd64", Components: []string{"multiverse"}}, wantErr: "does not list component"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := deb.CheckReleaseIdentity(&release, test.expected)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}

	noSuite := deb.Release{Architectures: []string{"amd64"}}
	if err := deb.CheckReleaseIdentity(&noSuite, deb.ReleaseIdentity{Suite: "resolute", Architecture: "amd64"}); err == nil {
		t.Fatal("accepted metadata without a suite")
	}
}

func TestCheckReleaseIdentityRequiresCodename(t *testing.T) {
	release := deb.Release{
		Suite:         "stable",
		Codename:      "trixie",
		Architectures: []string{"amd64", "arm64"},
		Components:    []string{"main", "contrib"},
	}
	codename := deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true}
	if err := deb.CheckReleaseIdentity(&release, codename); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		release  deb.Release
		expected deb.ReleaseIdentity
		wantErr  string
	}{
		{
			name:     "moving suite still matches its codename",
			release:  release,
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
		},
		{
			name:     "codename mode ignores a matching suite",
			release:  deb.Release{Suite: "trixie", Codename: "bookworm", Architectures: []string{"amd64"}},
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
			wantErr:  `release codename "bookworm" does not match "trixie"`,
		},
		{
			name:     "missing codename never falls back to the suite",
			release:  deb.Release{Suite: "trixie", Architectures: []string{"amd64"}},
			expected: deb.ReleaseIdentity{Suite: "trixie", Architecture: "amd64", MatchCodename: true},
			wantErr:  "release metadata has no codename",
		},
		{
			name:     "suite mode is unchanged",
			release:  deb.Release{Suite: "resolute-updates", Codename: "resolute", Architectures: []string{"amd64"}},
			expected: deb.ReleaseIdentity{Suite: "resolute", Architecture: "amd64"},
			wantErr:  `release suite "resolute-updates" does not match "resolute"`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := deb.CheckReleaseIdentity(&test.release, test.expected)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestCheckReleaseIdentityPrefixedComponents(t *testing.T) {
	release := deb.Release{
		Suite:         "trixie-security",
		Codename:      "trixie-security",
		Architectures: []string{"amd64"},
		Components:    []string{"updates/main"},
	}
	expected := deb.ReleaseIdentity{Suite: "trixie-security", Architecture: "amd64", Components: []string{"main"}}
	if err := deb.CheckReleaseIdentity(&release, expected); err == nil {
		t.Fatal("accepted a prefixed component without the mode enabled")
	}
	expected.PrefixedComponents = true
	if err := deb.CheckReleaseIdentity(&release, expected); err != nil {
		t.Fatal(err)
	}

	for _, component := range []string{"contrib", "/main", "updates/../main", "updates/other/main"} {
		release.Components = []string{component}
		expected.Components = []string{"main"}
		if err := deb.CheckReleaseIdentity(&release, expected); err == nil {
			t.Fatalf("accepted %q as component main", component)
		}
	}
}

func TestCheckFreshness(t *testing.T) {
	now := time.Date(2026, time.April, 23, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour).Format(time.RFC1123)
	past := now.Add(-time.Hour).Format(time.RFC1123)
	offset := now.Add(time.Hour).Format(time.RFC1123Z)
	cases := []struct {
		name       string
		validUntil string
		policy     deb.FreshnessPolicy
		now        time.Time
		wantErr    string
	}{
		{name: "if-present absent", policy: deb.FreshnessIfPresent},
		{name: "require absent", policy: deb.FreshnessRequire, wantErr: "required"},
		{name: "if-present valid", validUntil: future, policy: deb.FreshnessIfPresent},
		{name: "require valid", validUntil: future, policy: deb.FreshnessRequire},
		{name: "offset valid", validUntil: offset, policy: deb.FreshnessIfPresent},
		{name: "if-present expired", validUntil: past, policy: deb.FreshnessIfPresent, wantErr: "expired"},
		{name: "require expired", validUntil: past, policy: deb.FreshnessRequire, wantErr: "expired"},
		{name: "exact boundary", validUntil: now.Format(time.RFC1123), policy: deb.FreshnessIfPresent, wantErr: "expired"},
		{name: "just before boundary", validUntil: now.Format(time.RFC1123), policy: deb.FreshnessIfPresent, now: now.Add(-time.Second)},
		{name: "malformed", validUntil: "not a date", policy: deb.FreshnessIfPresent, wantErr: "not a valid date"},
		{name: "unknown timezone abbreviation", validUntil: "Thu, 23 Apr 2026 13:00:00 XYZ", policy: deb.FreshnessIfPresent, wantErr: "not a valid date"},
		{name: "non-UTC timezone abbreviation", validUntil: "Thu, 23 Apr 2026 13:00:00 GMT", policy: deb.FreshnessIfPresent, wantErr: "not a valid date"},
		{name: "negative numeric offset", validUntil: "Thu, 23 Apr 2026 13:00:00 -0700", policy: deb.FreshnessIfPresent},
		{name: "empty under require", validUntil: "", policy: deb.FreshnessRequire, wantErr: "required"},
		{name: "unknown policy", policy: deb.FreshnessPolicy("ignore"), wantErr: "unsupported"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			release := deb.Release{ValidUntil: test.validUntil}
			checkNow := test.now
			if checkNow.IsZero() {
				checkNow = now
			}
			err := deb.CheckFreshness(&release, test.policy, checkNow)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}
