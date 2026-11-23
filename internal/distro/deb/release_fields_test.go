package deb_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestVerifyReleaseChecksums(t *testing.T) {
	entity, _ := entities(t)
	hash := strings.Repeat("A", 64)
	payload := releasePayload + "Acquire-By-Hash: yes\nSHA256:\n " + hash + " 123 main/binary-amd64/Packages.xz\n " + strings.Repeat("b", 64) + " 0 main/binary-amd64/Packages\n"
	verified, err := deb.VerifyInRelease(signInRelease(t, entity, payload), trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Metadata.AcquireByHash {
		t.Fatal("Acquire-By-Hash was not parsed")
	}
	entry, ok := verified.Metadata.Files["main/binary-amd64/Packages.xz"]
	if !ok || entry.SHA256 != strings.Repeat("a", 64) || entry.Size != 123 {
		t.Fatalf("entry = %+v, present = %v", entry, ok)
	}
	if entry, ok := verified.Metadata.Files["main/binary-amd64/Packages"]; !ok || entry.Size != 0 {
		t.Fatalf("plain entry = %+v, present = %v", entry, ok)
	}
}

func TestVerifyReleaseRejectsMalformedChecksums(t *testing.T) {
	entity, _ := entities(t)
	valid := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		payload string
	}{
		{name: "short hash", payload: "SHA256:\n " + strings.Repeat("a", 63) + " 1 main/Packages\n"},
		{name: "non-hex hash", payload: "SHA256:\n " + strings.Repeat("g", 64) + " 1 main/Packages\n"},
		{name: "negative size", payload: "SHA256:\n " + valid + " -1 main/Packages\n"},
		{name: "non-numeric size", payload: "SHA256:\n " + valid + " huge main/Packages\n"},
		{name: "absolute path", payload: "SHA256:\n " + valid + " 1 /main/Packages\n"},
		{name: "traversing path", payload: "SHA256:\n " + valid + " 1 main/../Packages\n"},
		{name: "missing path", payload: "SHA256:\n " + valid + " 1\n"},
		{name: "duplicate path", payload: "SHA256:\n " + valid + " 1 main/Packages\n " + valid + " 2 main/Packages\n"},
		{name: "bad acquire-by-hash", payload: "Acquire-By-Hash: maybe\n"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := releasePayload + test.payload
			if _, err := deb.VerifyInRelease(signInRelease(t, entity, payload), trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry}); err == nil {
				t.Fatal("accepted malformed checksum metadata")
			}
		})
	}
}
