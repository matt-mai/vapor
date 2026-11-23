package ubuntu_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/distro/ubuntu"
)

const reviewedArchiveFingerprint = "F6ECB3762474EDA9D21B7022871920D1991BC93C"

func TestProviderDefaultTrust(t *testing.T) {
	t.Parallel()
	provider := ubuntu.New("26.04")
	snapshots := provider.DefaultTrust()
	if len(snapshots) != 1 {
		t.Fatalf("DefaultTrust returned %d snapshots, want 1", len(snapshots))
	}
	snapshot := snapshots[0]
	if len(snapshot.Fingerprints) != 1 || snapshot.Fingerprints[0] != reviewedArchiveFingerprint {
		t.Fatalf("fingerprints = %q, want the reviewed archive fingerprint", snapshot.Fingerprints)
	}
	if !strings.Contains(string(snapshot.Data), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Error("default trust is not an armored public key block")
	}
	keys, err := deb.LoadTrustedKeys(snapshot.Data, snapshot.Fingerprints)
	if err != nil {
		t.Fatalf("LoadTrustedKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != reviewedArchiveFingerprint {
		t.Fatalf("default trust parsed to %d keys, want the reviewed fingerprint", len(keys))
	}

	snapshot.Fingerprints[0] = "mutated"
	snapshot.Data[0] = 'X'
	again := provider.DefaultTrust()[0]
	if again.Fingerprints[0] != reviewedArchiveFingerprint || again.Data[0] == 'X' {
		t.Error("DefaultTrust returned mutable state shared with the caller")
	}
}

func TestProviderProTrust(t *testing.T) {
	t.Parallel()
	provider := ubuntu.New("26.04")
	for service, fingerprint := range map[string]string{
		"esm-apps":     "E8A443CE358113D187BEE0E6AB01A101DB53907B",
		"esm-infra":    "56F7650A24C9E9ECF87C4D8D4067E40313CB4B13",
		"fips":         "E23341B2A1467EDBF07057D6C1997C40EDE22758",
		"fips-updates": "E23341B2A1467EDBF07057D6C1997C40EDE22758",
	} {
		snapshots := provider.ProTrust(service)
		if len(snapshots) != 1 {
			t.Fatalf("%s: ProTrust returned %d snapshots, want 1", service, len(snapshots))
		}
		snapshot := snapshots[0]
		if len(snapshot.Fingerprints) != 1 || snapshot.Fingerprints[0] != fingerprint {
			t.Fatalf("%s: fingerprints = %q, want %q", service, snapshot.Fingerprints, fingerprint)
		}
		keys, err := deb.LoadTrustedKeys(snapshot.Data, snapshot.Fingerprints)
		if err != nil {
			t.Fatalf("%s: LoadTrustedKeys: %v", service, err)
		}
		if len(keys) != 1 || !strings.EqualFold(keys[0].Fingerprint, fingerprint) {
			t.Fatalf("%s: parsed %d keys", service, len(keys))
		}
		snapshot.Fingerprints[0] = "mutated"
		snapshot.Data[0] = 'X'
		again := provider.ProTrust(service)[0]
		if again.Fingerprints[0] != fingerprint || again.Data[0] == 'X' {
			t.Errorf("%s: ProTrust returned mutable state shared with the caller", service)
		}
	}
	if got := provider.ProTrust("unknown"); got != nil {
		t.Fatalf("unknown service returned %#v", got)
	}
}
