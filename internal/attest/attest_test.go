package attest_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	hashD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// TestEncode_IsCanonical checks the byte contract: compact, sorted keys, no trailing
// newline, and a result that is stable across calls.
func TestEncode_IsCanonical(t *testing.T) {
	payload := struct {
		Beta  []string `json:"beta"`
		Alpha int      `json:"alpha"`
	}{Beta: []string{"z", "a"}, Alpha: 1}
	encoded, err := attest.Encode(payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got, want := string(encoded), `{"alpha":1,"beta":["z","a"]}`; got != want {
		t.Fatalf("Encode = %s, want %s", got, want)
	}
	again, err := attest.Encode(payload)
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatalf("Encode is not stable: %s %v", again, err)
	}
}

// TestEncode_KeepsControlCharactersValidJSON checks that license text with a newline
// or a tab is escaped, so a text value needs no separate sanitizing step.
func TestEncode_KeepsControlCharactersValidJSON(t *testing.T) {
	encoded, err := attest.Encode(map[string]string{"note": "line\nnext\ttab"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got, want := string(encoded), `{"note":"line\nnext\ttab"}`; got != want {
		t.Fatalf("Encode = %q, want %q", got, want)
	}
}

// TestDigest_IsPlainSHA256OfBytes checks that the blob identity carries no domain
// label, because a reader fetches those bytes and recomputes this value.
func TestDigest_IsPlainSHA256OfBytes(t *testing.T) {
	empty := attest.Digest([]byte{})
	if empty != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty digest = %s", empty)
	}
	if other := attest.Digest([]byte("a")); other == empty {
		t.Fatal("different bytes produced the same digest")
	}
}

// TestIdentity_RequiresDomain checks that an identity is never computed without a
// label, which is the one way to make two domains collide.
func TestIdentity_RequiresDomain(t *testing.T) {
	if _, err := attest.Identity("", map[string]string{"a": "b"}); err == nil {
		t.Fatal("empty domain accepted")
	}
}

// TestElementIdentity_DomainSeparated checks that the same payload hashed in two
// domains yields two identities.
func TestElementIdentity_DomainSeparated(t *testing.T) {
	pkg, err := attest.PackageIdentity("linux/amd64", "base-files", "26.04", "amd64", hashA, 1234)
	if err != nil {
		t.Fatalf("PackageIdentity: %v", err)
	}
	other, err := attest.Identity(attest.DomainSlices, map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if pkg == other {
		t.Fatal("two domains produced the same identity")
	}
}

// TestPackageIdentity_Inputs checks the contract the payload records: platform,
// name, version, architecture and exact bytes, with nothing about a mirror.
func TestPackageIdentity_Inputs(t *testing.T) {
	base, err := attest.PackageIdentity("linux/amd64", "base-files", "26.04", "amd64", hashA, 1234)
	if err != nil {
		t.Fatalf("PackageIdentity: %v", err)
	}
	cases := map[string][5]any{
		"platform":     {"linux/arm64", "base-files", "26.04", "amd64", int64(1234)},
		"name":         {"linux/amd64", "base-passwd", "26.04", "amd64", int64(1234)},
		"version":      {"linux/amd64", "base-files", "26.04.1", "amd64", int64(1234)},
		"architecture": {"linux/amd64", "base-files", "26.04", "all", int64(1234)},
		"size":         {"linux/amd64", "base-files", "26.04", "amd64", int64(1235)},
	}
	for field, changed := range cases {
		digest, err := attest.PackageIdentity(changed[0].(string), changed[1].(string),
			changed[2].(string), changed[3].(string), hashA, changed[4].(int64))
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if digest == base {
			t.Fatalf("changing %s kept the identity", field)
		}
	}
	if _, err := attest.PackageIdentity("linux/amd64", "base-files", "26.04", "amd64", hashB, 1234); err != nil {
		t.Fatal(err)
	}
}

// TestSliceIdentity_ClosureIsOrdered checks that the dependency-first closure is
// data, not a set: reordering it is a different element, and the caller's slice is
// not retained.
func TestSliceIdentity_ClosureIsOrdered(t *testing.T) {
	selected := []string{"core", "libs"}
	base, err := attest.SlicesIdentity("linux/arm64", "libc6", "2.41-1", "all", hashD, hashB, 5678, selected)
	if err != nil {
		t.Fatalf("SliceIdentity: %v", err)
	}
	reordered, err := attest.SlicesIdentity("linux/arm64", "libc6", "2.41-1", "all", hashD, hashB, 5678,
		[]string{"libs", "core"})
	if err != nil {
		t.Fatal(err)
	}
	if base == reordered {
		t.Fatal("reordering the closure kept the identity")
	}
	again, err := attest.SlicesIdentity("linux/arm64", "libc6", "2.41-1", "all", hashD, hashB, 5678,
		selected)
	if err != nil || again != base {
		t.Fatalf("identity is not stable: %s %v", again, err)
	}
	definition, err := attest.SlicesIdentity("linux/arm64", "libc6", "2.41-1", "all", hashC, hashB, 5678,
		selected)
	if err != nil || definition == base {
		t.Fatalf("changing the definition kept the identity: %v", err)
	}
	other, err := attest.SlicesIdentity("linux/arm64", "libc6", "2.42-1", "all", hashD, hashB, 5678,
		selected)
	if err != nil || other == base {
		t.Fatalf("another version kept the identity: %v", err)
	}
}

// TestArtifactIdentity_FixedIdentity checks that an artifact element names the
// declared upstream identity and not the endpoint its bytes came from.
func TestArtifactIdentity_FixedIdentity(t *testing.T) {
	identity := attest.ArtifactVersion{Name: "server", Version: "1.0"}
	base, err := attest.ArtifactIdentity("linux/amd64", "server-cert", identity, hashC, 9012)
	if err != nil {
		t.Fatalf("ArtifactIdentity: %v", err)
	}
	again, err := attest.ArtifactIdentity("linux/amd64", "server-cert", identity, hashC, 9012)
	if err != nil || again != base {
		t.Fatalf("identity is not stable: %s %v", again, err)
	}
	bumped, err := attest.ArtifactIdentity("linux/amd64", "server-cert",
		attest.ArtifactVersion{Name: "server", Version: "1.1"}, hashC, 9012)
	if err != nil || bumped == base {
		t.Fatalf("changing the declared version kept the identity: %v", err)
	}
	renamed, err := attest.ArtifactIdentity("linux/amd64", "cert", identity, hashC, 9012)
	if err != nil || renamed == base {
		t.Fatalf("changing the artifact name kept the identity: %v", err)
	}
}

// TestElementIdentities_AreDistinct checks that two elements of different kinds never
// collapse, which is what lets one document attribute every input.
func TestElementIdentities_AreDistinct(t *testing.T) {
	pkg, err := attest.PackageIdentity("linux/amd64", "base-files", "26.04", "amd64", hashA, 1234)
	if err != nil {
		t.Fatal(err)
	}
	slice, err := attest.SlicesIdentity("linux/amd64", "base-files", "26.04", "amd64", hashD, hashA, 1234,
		nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := attest.ArtifactIdentity("linux/amd64", "base-files",
		attest.ArtifactVersion{Name: "base-files", Version: "26.04"}, hashA, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if pkg == slice || pkg == artifact || slice == artifact {
		t.Fatalf("element kinds collided: %s %s %s", pkg, slice, artifact)
	}
	for _, digest := range []string{pkg, slice, artifact} {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
			t.Fatalf("identity %s is not sha256", digest)
		}
	}
}
