package deb

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// signatureBody unwraps an armored signature and passes binary data through.
//
// The armor is decoded here rather than through armor.Decode, which skips leading
// garbage, ends a block at EOF when the closing line is missing, and reads no further
// than the block: a Release.gpg is one complete file, so every byte of it has to belong
// to the signature.
func signatureBody(signature []byte) (io.Reader, error) {
	trimmed := bytes.TrimLeft(signature, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte(armorBegin)) {
		return bytes.NewReader(signature), nil
	}
	body, err := armoredBody(trimmed)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(body), nil
}

const (
	armorBegin = "-----BEGIN PGP SIGNATURE-----"
	armorEnd   = "-----END PGP SIGNATURE-----"
)

// armoredBody decodes exactly one armor block: a signature header, optional armor
// headers, the base64 body, an optional CRC24 line, the closing line, and nothing but
// whitespace after it. Trailing whitespace on a line is ignored, as armor defines it.
func armoredBody(data []byte) ([]byte, error) {
	lines := bytes.Split(data, []byte("\n"))
	if armorLine(lines[0]) != armorBegin {
		return nil, errors.New("signature armor does not start with its opening line")
	}
	index, err := skipArmorHeaders(lines)
	if err != nil {
		return nil, err
	}
	body, checksum, index, err := readArmorBody(lines, index)
	if err != nil {
		return nil, err
	}
	if index == len(lines) {
		return nil, errors.New("signature armor ends before its closing line")
	}
	if len(bytes.TrimSpace(bytes.Join(lines[index+1:], []byte("\n")))) != 0 {
		return nil, errors.New("signature armor has data after its closing line")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(body))
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("signature armor holds no decodable signature")
	}
	if checksum != nil && !validArmorChecksum(decoded, checksum) {
		return nil, errors.New("signature armor checksum does not match")
	}
	return decoded, nil
}

// skipArmorHeaders returns the index of the blank line that ends the headers.
func skipArmorHeaders(lines [][]byte) (int, error) {
	for index := 1; index < len(lines); index++ {
		line := armorLine(lines[index])
		if line == "" {
			return index + 1, nil
		}
		if !validArmorHeader(line) {
			return 0, errors.New("signature armor has a malformed header")
		}
	}
	return 0, errors.New("signature armor ends inside its headers")
}

// readArmorBody returns the base64 body and checksum, and the index of the closing
// line.
func readArmorBody(lines [][]byte, index int) ([]byte, []byte, int, error) {
	var body, checksum []byte
	for ; index < len(lines); index++ {
		line := armorLine(lines[index])
		switch {
		case line == armorEnd:
			return body, checksum, index, nil
		case line == "":
			return nil, nil, 0, errors.New("signature armor has a blank line in its body")
		case strings.HasPrefix(line, "="):
			if checksum != nil {
				return nil, nil, 0, errors.New("signature armor repeats its checksum")
			}
			checksum = []byte(line[1:])
		case checksum != nil:
			return nil, nil, 0, errors.New("signature armor continues after its checksum")
		default:
			body = append(body, line...)
		}
	}
	return body, checksum, index, nil
}

// armorLine returns one line without its line ending or trailing whitespace.
func armorLine(line []byte) string {
	return strings.TrimRight(string(line), " \t\r")
}

// validArmorHeader accepts the printable "Key: value" lines the armor format allows.
func validArmorHeader(line string) bool {
	key, _, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(key) == "" {
		return false
	}
	// Armor headers are ASCII text: a control character or anything above DEL is not
	// a header, whatever else it might be.
	for _, char := range line {
		if char < 0x20 || char > 0x7e {
			return false
		}
	}
	return true
}

// validArmorChecksum compares the trailing CRC24 line with the body.
//
// Armor ends with a checksum line: a single "=", then base64 of the three CRC bytes.
// The value is the CRC24 that RFC 4880 section 6.1 defines, and its constants are
// the ones that section names: the register starts at 0xB704CE and the generator is
// 0x1864CFB, a 24-bit polynomial with an implicit leading x^24 term. The register
// shifts left one bit at a time and folds that leading term back in as 0x864CFB.
func validArmorChecksum(body, checksum []byte) bool {
	const (
		// crcInit seeds the register.
		crcInit = 0xB704CE
		// crcTopBit is the bit the shift moves out of the register. The generator
		// includes the term for that bit, so folding it back in both cancels the
		// shifted-out bit and applies the polynomial.
		crcTopBit     = 0x1000000
		crcPolynomial = 0x1864CFB
		// crcMask keeps the register at 24 bits between rounds.
		crcMask = 0xFFFFFF
	)
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(checksum))
	if err != nil || len(decoded) != 3 {
		return false
	}
	crc := uint32(crcInit)
	for _, b := range body {
		// Feed one byte into the top of the register, then reduce.
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&crcTopBit != 0 {
				crc ^= crcPolynomial
			}
		}
	}
	crc &= crcMask
	return decoded[0] == byte((crc>>16)&0xFF) && decoded[1] == byte((crc>>8)&0xFF) &&
		decoded[2] == byte(crc&0xFF)
}
