package certbundle_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/certbundle"
)

func certificate(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func subjects(t *testing.T, certificates [][]byte) []string {
	t.Helper()
	result := make([]string, 0, len(certificates))
	for _, der := range certificates {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, parsed.Subject.CommonName)
	}
	return result
}

// A published bundle is blocks plus a heading, a comment and a rule.
func TestParse_AcceptsPublishedBundleText(t *testing.T) {
	bundle := append([]byte("##\n## Bundle of CA Root Certificates\n##\n\n"), certificate(t, "first")...)
	bundle = append(bundle, []byte("Example Root CA\n==================\n\n")...)
	bundle = append(bundle, certificate(t, "second")...)
	bundle = append(bundle, []byte("# trailing comment\n")...)
	certificates, err := certbundle.Parse(bundle)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := strings.Join(subjects(t, certificates), ","); got != "first,second" {
		t.Fatalf("certificates are %s", got)
	}
}

// A block may be the last line of a file with no final newline.
func TestParse_AcceptsAMissingFinalNewline(t *testing.T) {
	bundle := bytes.TrimRight(certificate(t, "last"), "\n")
	certificates, err := certbundle.Parse(bundle)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("parsed %d certificates", len(certificates))
	}
}

func TestParse_Refusals(t *testing.T) {
	valid := certificate(t, "valid")
	cases := map[string]struct {
		data   []byte
		target error
	}{
		"empty":                    {nil, certbundle.ErrNoCertificate},
		"whitespace only":          {[]byte("\n\n  \n"), certbundle.ErrNoCertificate},
		"prose":                    {[]byte("not a certificate\n"), certbundle.ErrOutsideBlock},
		"prose after a block":      {append(append([]byte{}, valid...), []byte("more prose\n")...), certbundle.ErrOutsideBlock},
		"title without a rule":     {append([]byte("A Title\n"), valid...), certbundle.ErrOutsideBlock},
		"unterminated block":       {append([]byte("-----BEGIN CERTIFICATE-----\n"), valid...), certbundle.ErrMalformedBlock},
		"malformed block":          {append([]byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), valid...), certbundle.ErrMalformedBlock},
		"invalid certificate":      {append(append([]byte{}, valid...), append([]byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), valid...)...), certbundle.ErrInvalidBlock},
		"private key":              {[]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"), certbundle.ErrNotCertificate},
		"public key block":         {pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}), certbundle.ErrNotCertificate},
		"certificate request":      {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("x")}), certbundle.ErrNotCertificate},
		"trailing prose on a line": {append(append([]byte{}, valid...), []byte("x\n")...), certbundle.ErrOutsideBlock},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := certbundle.Parse(testCase.data); !errors.Is(err, testCase.target) {
				t.Fatalf("error = %v, want %v", err, testCase.target)
			}
		})
	}
}

// A newline-heavy input must not allocate per line. Blank lines are accepted as
// bundle spacing, so this input is parsed in full; a line table over it would cost
// twenty-four bytes of slice header per input byte, so a mebibyte of newlines is
// already twenty-four times the bound. The allocation is constant at every size — the
// property is linearity, not this size — and the race detector pays roughly fifty
// times the per-line cost, so the input stays small enough for it to finish.
func TestParse_BoundsMemoryForALineHeavyInput(t *testing.T) {
	const size = 1 << 20
	data := append(bytes.Repeat([]byte("\n"), size), certificate(t, "heavy")...)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := certbundle.Parse(data); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("parsing %d bytes allocated %d bytes", len(data), allocated)
	if allocated > 8<<20 {
		t.Fatalf("parsing %d bytes allocated %d bytes", len(data), allocated)
	}
}
