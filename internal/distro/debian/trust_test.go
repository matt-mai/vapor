package debian_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

// The samples are the archives' own InRelease files, pinned by digest so a test
// never follows the live archive. The verification time is inside the signed
// window: the main archives state no Valid-Until, while the security samples
// expire a week after signing.
var pinnedReleases = []struct {
	name       string
	file       string
	sha256     string
	release    string
	suite      string
	codename   string
	components []string
	security   bool
}{
	{
		name: "trixie main", file: "inrelease-trixie",
		sha256:  "0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675",
		release: "trixie", suite: "trixie", codename: "trixie",
		components: []string{"main", "contrib"},
	},
	{
		name: "bookworm main", file: "inrelease-bookworm",
		sha256:  "77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa",
		release: "bookworm", suite: "bookworm", codename: "bookworm",
		components: []string{"main", "contrib"},
	},
	{
		name: "trixie security", file: "inrelease-trixie-security",
		sha256:  "7399b7a2ec90a604a939245a9d189e5c326a90ab10fa3b6ff58f806cfb6d9767",
		release: "trixie", suite: "trixie-security", codename: "trixie-security",
		components: []string{"main", "contrib"}, security: true,
	},
	{
		name: "bookworm security", file: "inrelease-bookworm-security",
		sha256:  "c3c214ad3b76440fc7bc20f4cf79be28815f53deb7770081556055300236eb0b",
		release: "bookworm", suite: "bookworm-security", codename: "bookworm-security",
		components: []string{"main", "contrib"}, security: true,
	},
}

// insideTheWindow is after every sample was signed and before the security
// samples' Valid-Until, so the expiry checks mean something.
var insideTheWindow = time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)

func load(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// snapshotKeys loads the reviewed keys of one archive for a release.
func snapshotKeys(t *testing.T, release string, security bool) []deb.PublicKey {
	t.Helper()
	snapshots := mustNew(t, release).DefaultTrust()
	wanted := snapshots[0]
	if security {
		wanted = snapshots[1]
	}
	keys, err := deb.LoadTrustedKeys(wanted.Data, wanted.Fingerprints)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// The reviewed snapshots parse, keep their signing subkeys, and match the
// fingerprints the Debian archive page lists.
func TestTrustSnapshots(t *testing.T) {
	t.Parallel()
	for _, release := range []string{"trixie", "13", "bookworm", "12"} {
		snapshots := mustNew(t, release).DefaultTrust()
		if len(snapshots) != 2 {
			t.Fatalf("New(%q).DefaultTrust() has %d snapshots, want main and security", release, len(snapshots))
		}
		for _, snapshot := range snapshots {
			// Exactly one primary key and no private material, so the shipped
			// bytes are what was reviewed.
			key, err := deb.ParseKeyring(snapshot.Data)
			if err != nil {
				t.Fatalf("New(%q) snapshot: %v", release, err)
			}
			if key.Fingerprint != snapshot.Fingerprints[0] {
				t.Fatalf("snapshot fingerprint %s, key is %s", snapshot.Fingerprints[0], key.Fingerprint)
			}
			// A release is signed by a subkey, so a snapshot without one could
			// not authenticate anything.
			if len(key.Entity.Subkeys) == 0 {
				t.Fatalf("New(%q) key %s kept no signing subkey", release, key.Fingerprint)
			}
		}
	}
	// An unreviewed codename has no keys, and that is reported rather than
	// silently trusting whatever the archive ships.
	if snapshots := mustNew(t, "forky").DefaultTrust(); len(snapshots) != 0 {
		t.Fatalf("unknown release has default trust: %v", snapshots)
	}
}

// Each pinned sample authenticates with its own release's reviewed keys, and the
// recorded signer is the primary key even though a subkey signed.
func TestPinnedReleaseSamples(t *testing.T) {
	t.Parallel()
	for _, sample := range pinnedReleases {
		t.Run(sample.name, func(t *testing.T) {
			data := load(t, sample.file)
			sum := sha256.Sum256(data)
			if digest := hex.EncodeToString(sum[:]); digest != sample.sha256 {
				t.Fatalf("sample changed: sha256 %s, pinned %s", digest, sample.sha256)
			}
			keys := snapshotKeys(t, sample.release, sample.security)
			verified, err := deb.VerifyInRelease(data, keys, deb.VerifyOptions{
				Policy: deb.EnforceExpiry,
				Now:    insideTheWindow,
			})
			if err != nil {
				t.Fatal(err)
			}
			if verified.Metadata.Codename != sample.codename {
				t.Fatalf("codename = %q, want %q", verified.Metadata.Codename, sample.codename)
			}
			if len(verified.Signers) != 1 || verified.Signers[0] != keys[0].Fingerprint {
				t.Fatalf("signers = %v, want the primary key %s", verified.Signers, keys[0].Fingerprint)
			}
			identity := deb.ReleaseIdentity{
				Suite: sample.suite, Architecture: "amd64", Components: sample.components,
				MatchCodename: true, PrefixedComponents: true,
			}
			if err := deb.CheckReleaseIdentity(&verified.Metadata, identity); err != nil {
				t.Fatal(err)
			}
			// The security archive lists components as updates/main, while index
			// paths and locks keep the plain name.
			if _, ok := verified.Metadata.Files["main/binary-amd64/Packages.xz"]; !ok {
				t.Fatal("sample has no main amd64 index")
			}
		})
	}
}

// Debian cross-signs: both releases' archive keys sign both main archives, and
// trixie-security is signed by both security keys. So "the" signer of a sample is
// whatever the trusted snapshot makes it, and a lock records that key rather than
// the only key that signed. Replay then refuses any other.
func TestPinnedReleaseReplayKeepsRecordedSigner(t *testing.T) {
	t.Parallel()
	// trixie main under bookworm's reviewed key, which signs it too.
	bookwormKeys := snapshotKeys(t, "bookworm", false)
	verified, err := deb.VerifyInRelease(load(t, "inrelease-trixie"), bookwormKeys, deb.VerifyOptions{
		Policy: deb.EnforceExpiry,
		Now:    insideTheWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
	trixieKeys := snapshotKeys(t, "trixie", false)
	if verified.Signers[0] == trixieKeys[0].Fingerprint {
		t.Fatal("trixie main verified under bookworm keys, but recorded the trixie key")
	}
	// A lock that recorded the trixie key cannot be replayed under a key set in
	// which only the bookworm key is trusted.
	if _, err := deb.VerifyInRelease(load(t, "inrelease-trixie"), bookwormKeys, deb.VerifyOptions{
		Policy:   deb.IgnoreExpiry,
		Accepted: []string{trixieKeys[0].Fingerprint},
	}); err == nil {
		t.Fatal("replayed with a signer the lock did not record")
	}
}

// A release that only one security key signed is not interchangeable with the
// other release's security archive.
func TestPinnedSecurityArchivesAreNotInterchangeable(t *testing.T) {
	t.Parallel()
	if _, err := deb.VerifyInRelease(load(t, "inrelease-bookworm-security"),
		snapshotKeys(t, "trixie", true), deb.VerifyOptions{
			Policy: deb.EnforceExpiry,
			Now:    insideTheWindow,
		}); err == nil {
		t.Fatal("verified bookworm-security with the trixie security key")
	}
}

// The security key cannot vouch for the main archive, nor the other way round.
func TestPinnedReleaseRejectsOtherArchiveKeys(t *testing.T) {
	t.Parallel()
	for _, sample := range pinnedReleases {
		t.Run(sample.name, func(t *testing.T) {
			if _, err := deb.VerifyInRelease(load(t, sample.file),
				snapshotKeys(t, sample.release, !sample.security),
				deb.VerifyOptions{Policy: deb.EnforceExpiry, Now: insideTheWindow}); err == nil {
				t.Fatal("verified with the other archive's key")
			}
		})
	}
}

// The security samples carry a Valid-Until, so they stop being usable a week after
// signing. The main archives declare none, which a permissive policy accepts and a
// requiring policy refuses; the acquisition policy is decided in 10.1.6.
func TestPinnedReleaseFreshness(t *testing.T) {
	t.Parallel()
	after := time.Date(2026, time.November, 28, 0, 0, 0, 0, time.UTC)
	for _, sample := range pinnedReleases {
		t.Run(sample.name, func(t *testing.T) {
			verified, err := deb.VerifyInRelease(load(t, sample.file),
				snapshotKeys(t, sample.release, sample.security),
				deb.VerifyOptions{Policy: deb.EnforceExpiry, Now: after})
			if err != nil {
				t.Fatal(err)
			}
			if err := deb.CheckFreshness(&verified.Metadata, deb.FreshnessRequire, after); err == nil {
				t.Fatal("accepted stale metadata")
			}
			if sample.security {
				return
			}
			if err := deb.CheckFreshness(&verified.Metadata, deb.FreshnessIfPresent, after); err != nil {
				t.Fatalf("main archive refused without a Valid-Until: %v", err)
			}
		})
	}
}
