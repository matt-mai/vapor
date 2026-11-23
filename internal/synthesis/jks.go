package synthesis

import (
	"crypto/sha1" //nolint:gosec // JKS integrity digest is SHA-1 by format; it is not a security boundary here.
	"encoding/binary"
	"sort"
	"strconv"
)

// A JKS trust store is the one format every Java version reads without a system
// property: PKCS12 needs a password Java does not supply by default, and no
// version registers a PEM keystore type. The format is written here rather than
// with keytool because assembly must not run another program.
//
// The store is deterministic: entries are ordered by certificate bytes, their
// aliases follow that order and the per-entry timestamp is the epoch, so two
// builds of the same roots produce the same file.
const (
	jksMagic   = 0xFEEDFEED
	jksVersion = 2
	jksTagCert = 2
	// jksWhitener is mixed into the integrity digest. The provider includes it so
	// the digest is not a plain hash of the password and the body.
	jksWhitener = "Mighty Aphrodite"
)

// encodeJKS writes the certificates as a JKS trust store protected by password.
// Java accepts both an empty and a non-empty password for trusted-certificate
// entries, so callers pass the one their tooling expects.
func encodeJKS(certificates [][]byte, password string) []byte {
	sorted := dedupeCertificates(certificates)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i]) < string(sorted[j])
	})

	var store jksWriter
	store.uint32(jksMagic)
	store.uint32(jksVersion)
	store.uint32(uint32(len(sorted))) //nolint:gosec // entry count of an in-memory store
	for index, certificate := range sorted {
		store.uint32(jksTagCert)
		// Aliases must be unique within a store; the position is enough because
		// the order is a function of the certificate bytes alone.
		store.utf("ca" + strconv.Itoa(index))
		store.uint64(0)
		store.utf("X.509")
		store.uint32(uint32(len(certificate))) //nolint:gosec // DER length of a parsed certificate
		store.buffer = append(store.buffer, certificate...)
	}

	// The trailing digest is SHA-1 over the password as UTF-16BE, a fixed whitener
	// string and the store body. Java does not verify it for trusted certificates,
	// but keytool refuses to read a store whose digest does not match, so it is
	// written exactly as the provider writes it.
	digest := sha1.New() //nolint:gosec // see the import: the format fixes the algorithm.
	for _, unit := range utf16BE(password) {
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], unit)
		digest.Write(encoded[:])
	}
	digest.Write([]byte(jksWhitener))
	digest.Write(store.buffer)
	return digest.Sum(store.buffer)
}

// utf16BE encodes a password the way the JKS digest expects it.
func utf16BE(password string) []uint16 {
	units := make([]uint16, 0, len(password))
	for _, r := range password {
		if r > 0xFFFF {
			r = 0xFFFD
		}
		units = append(units, uint16(r))
	}
	return units
}

// dedupeCertificates drops repeated certificates, keeping first-seen order.
func dedupeCertificates(certificates [][]byte) [][]byte {
	seen := make(map[string]bool, len(certificates))
	result := make([][]byte, 0, len(certificates))
	for _, certificate := range certificates {
		if seen[string(certificate)] {
			continue
		}
		seen[string(certificate)] = true
		result = append(result, certificate)
	}
	return result
}

type jksWriter struct {
	buffer []byte
}

func (w *jksWriter) uint32(value uint32) {
	w.buffer = binary.BigEndian.AppendUint32(w.buffer, value)
}

func (w *jksWriter) uint64(value uint64) {
	w.buffer = binary.BigEndian.AppendUint64(w.buffer, value)
}

// utf writes a 2-byte length followed by UTF-8 bytes, which is how the JKS
// format names the alias and the certificate type.
func (w *jksWriter) utf(value string) {
	// The alias and type names are literals or a small index, so they fit.
	w.buffer = binary.BigEndian.AppendUint16(w.buffer, uint16(len(value))) //nolint:gosec // bounded by format literals
	w.buffer = append(w.buffer, value...)
}
