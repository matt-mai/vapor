package deb

import (
	"encoding/base64"
	"testing"
)

// The CRC24 constants are locked down here because a checksum that silently computes
// the wrong value would reject every real signature while looking correct in code.
// RFC 4880 gives no test vector, so this uses the check value the same polynomial has
// for "123456789", which is 0x21CF02.
func TestArmorChecksumKnownValue(t *testing.T) {
	t.Parallel()
	checksum := base64.StdEncoding.EncodeToString([]byte{0x21, 0xCF, 0x02})
	if !validArmorChecksum([]byte("123456789"), []byte(checksum)) {
		t.Fatalf("CRC24 of %q did not match %s", "123456789", checksum)
	}
	for _, body := range []string{"", "12345678", "1234567890"} {
		if validArmorChecksum([]byte(body), []byte(checksum)) {
			t.Fatalf("CRC24 of %q matched the checksum for %q", body, "123456789")
		}
	}
	// A checksum line that is not three bytes, or not base64, is refused rather than
	// compared.
	for _, malformed := range []string{"", "AAAA", "!!!!", "AAAAAA=="} {
		if validArmorChecksum([]byte("123456789"), []byte(malformed)) {
			t.Fatalf("accepted malformed checksum %q", malformed)
		}
	}
}
