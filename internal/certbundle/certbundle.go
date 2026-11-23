// Package certbundle reads a PEM certificate bundle as a stream, so a hostile line
// count costs no memory. Snapshotting a local CA input and writing the image's
// bundle both use it, and both accept the same files.
package certbundle

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Errors a caller reports with its own subject, such as "CA input" or the source path.
var (
	ErrMalformedBlock = errors.New("contains a malformed certificate block")
	ErrInvalidBlock   = errors.New("contains an invalid certificate")
	ErrOutsideBlock   = errors.New("contains data outside certificate blocks")
	ErrNoCertificate  = errors.New("contains no public certificate")
	ErrNotCertificate = errors.New("is not a public certificate")
)

const (
	begin = "-----BEGIN "
	end   = "-----END "
	// whitespace is the set of bytes allowed between certificate blocks.
	whitespace = " \t\r\n"
)

// Parse returns the DER bytes of every certificate in the bundle, in file order.
//
// Published bundles such as Mozilla's cacert.pem put a heading, a comment or a rule
// around the blocks, so text outside a block is accepted when it has that shape: a
// comment line, a rule of repeated punctuation, or a title directly above a rule.
// Anything else outside a block is refused rather than dropped, because a bundle is
// trust material and unrecognized bytes are not silently the same as absent ones.
//
// The input is scanned once and nothing is allocated per line.
func Parse(data []byte) ([][]byte, error) {
	blocks, err := blockLines(data)
	if err != nil {
		return nil, err
	}
	var certificates [][]byte
	for {
		blocks = bytes.TrimLeft(blocks, whitespace)
		// pem.Decode searches ahead for a block, so it would skip bytes that are not a
		// block at all. A segment must start with one: what reaches here is block
		// lines and whitespace, nothing else.
		if !bytes.HasPrefix(blocks, []byte(begin)) {
			break
		}
		block, remainder, ok := decodeBlock(blocks)
		if !ok {
			return nil, ErrMalformedBlock
		}
		parsed, err := certificatesOf(block)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, parsed...)
		blocks = remainder
	}
	if len(certificates) == 0 {
		return nil, ErrNoCertificate
	}
	return certificates, nil
}

// blockLines keeps the lines that belong to a PEM block and refuses unexpected text
// around them. A block line is copied; block content is bounded by the input size,
// and the copy is what lets the PEM parser run without the bundle's prose.
func blockLines(data []byte) ([]byte, error) {
	var kept bytes.Buffer
	gate := outsideText{}
	for len(data) > 0 {
		line, rest := nextLine(data)
		data = rest
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte(begin)) {
			if gate.title {
				return nil, ErrOutsideBlock
			}
			kept.Write(line)
			kept.WriteByte('\n')
			var err error
			if data, err = copyBlockLines(data, &kept); err != nil {
				return nil, err
			}
			continue
		}
		if !gate.accept(trimmed) {
			return nil, ErrOutsideBlock
		}
	}
	if gate.title {
		return nil, ErrOutsideBlock
	}
	return kept.Bytes(), nil
}

// copyBlockLines copies a block to its END line and returns what follows it.
func copyBlockLines(data []byte, kept *bytes.Buffer) ([]byte, error) {
	for len(data) > 0 {
		line, rest := nextLine(data)
		kept.Write(line)
		kept.WriteByte('\n')
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte(end)) {
			return rest, nil
		}
		data = rest
	}
	return nil, ErrMalformedBlock
}

// outsideText tracks text between blocks, and whether it is a title still waiting for
// its underline. A heading is the only prose a published bundle carries, and it is
// only a heading above the rule.
type outsideText struct {
	title bool
}

// accept reports whether a trimmed line may sit between blocks.
func (o *outsideText) accept(line []byte) bool {
	switch {
	case len(line) == 0 || bytes.HasPrefix(line, []byte("#")):
		return !o.title
	case isRule(line):
		o.title = false
		return true
	default:
		settled := !o.title
		o.title = true
		return settled
	}
}

// nextLine splits off the first line without its newline. The returned slice shares
// the input, so a bundle's prose is never copied.
func nextLine(data []byte) ([]byte, []byte) {
	if before, after, ok := bytes.Cut(data, []byte{'\n'}); ok {
		return before, after
	}
	return data, nil
}

// isRule reports a heading's underline, such as the "======" under a bundle's
// section title.
func isRule(line []byte) bool {
	if len(line) < 3 {
		return false
	}
	for _, char := range line {
		if char != line[0] {
			return false
		}
	}
	switch line[0] {
	case '=', '-', '_', '*', '~', '^':
		return true
	default:
		return false
	}
}

// certificatesOf accepts one public certificate block and returns the DER of every
// certificate it holds.
func certificatesOf(block *pem.Block) ([][]byte, error) {
	switch block.Type {
	case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE":
	default:
		return nil, fmt.Errorf("contains %q, which %w", block.Type, ErrNotCertificate)
	}
	parsed, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(parsed) == 0 {
		return nil, ErrInvalidBlock
	}
	result := make([][]byte, 0, len(parsed))
	for _, certificate := range parsed {
		result = append(result, certificate.Raw)
	}
	return result, nil
}

// decodeBlock decodes the PEM block that starts at data and returns it with the
// bytes after it. pem.Decode searches ahead, so it would skip a malformed block and
// hand back a later one; the block is delimited first and decoded on its own, which
// leaves nothing to skip.
func decodeBlock(data []byte) (*pem.Block, []byte, bool) {
	if !bytes.HasPrefix(data, []byte(begin)) {
		return nil, nil, false
	}
	endAt := bytes.Index(data, []byte(end))
	if endAt < 0 {
		return nil, nil, false
	}
	// A second BEGIN before the END means the first block was never terminated.
	if bytes.Contains(data[len(begin):endAt], []byte(begin)) {
		return nil, nil, false
	}
	// The END line may be the last line of a file that has no final newline.
	stop := len(data)
	if lineEnd := bytes.IndexByte(data[endAt:], '\n'); lineEnd >= 0 {
		stop = endAt + lineEnd + 1
	}
	block, remainder := pem.Decode(data[:stop])
	if block == nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, nil, false
	}
	return block, data[stop:], true
}
