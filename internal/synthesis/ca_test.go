package synthesis_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

const bundlePath = "/etc/ssl/certs/ca-certificates.crt"

// certificatePEM returns a self-signed certificate with the given common name.
func certificatePEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func caBundle(mode string, sources ...string) *filesystem.CABundle {
	return &filesystem.CABundle{Mode: mode, Sources: sources}
}

func TestCA_ReplaceWritesDeclaredCertificates(t *testing.T) {
	first := certificatePEM(t, "first")
	second := certificatePEM(t, "second")
	tree := vfs.New()
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem", "b.pem"),
		map[string][]byte{"a.pem": first, "b.pem": second}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"first", "second"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

// bundleSubjects returns the subject common names of every certificate in a
// PEM bundle, in order.
func bundleSubjects(t *testing.T, content string) []string {
	t.Helper()
	rest := []byte(content)
	var subjects []string
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		subjects = append(subjects, parsed.Subject.CommonName)
		rest = remainder
	}
	return subjects
}

func TestCA_ReplaceDropsSelectedRoots(t *testing.T) {
	tree := treeWithFile(t, bundlePath, string(certificatePEM(t, "selected")))
	declared := certificatePEM(t, "declared")
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": declared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"declared"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

func TestCA_AppendKeepsSelectedRoots(t *testing.T) {
	selected := certificatePEM(t, "selected")
	tree := treeWithFile(t, bundlePath, string(selected))
	declared := certificatePEM(t, "declared")
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "a.pem"),
		map[string][]byte{"a.pem": declared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"selected", "declared"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

func TestCA_AppendWithoutSelectedBundle(t *testing.T) {
	declared := certificatePEM(t, "declared")
	tree := vfs.New()
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "a.pem"),
		map[string][]byte{"a.pem": declared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"declared"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

func TestCA_DeduplicatesEquivalentCertificates(t *testing.T) {
	shared := certificatePEM(t, "shared")
	tree := vfs.New()
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem", "b.pem"),
		map[string][]byte{"a.pem": shared, "b.pem": shared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if count := strings.Count(readFile(t, tree, bundlePath), "BEGIN CERTIFICATE"); count != 1 {
		t.Fatalf("bundle has %d certificates, want 1", count)
	}
}

func TestCA_AppendDeduplicatesAgainstSelected(t *testing.T) {
	shared := certificatePEM(t, "shared")
	tree := treeWithFile(t, bundlePath, string(shared))
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "a.pem"),
		map[string][]byte{"a.pem": shared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if count := strings.Count(readFile(t, tree, bundlePath), "BEGIN CERTIFICATE"); count != 1 {
		t.Fatalf("bundle has %d certificates, want 1", count)
	}
}

func TestCA_RejectsInvalidInput(t *testing.T) {
	valid := certificatePEM(t, "valid")
	cases := []struct {
		name   string
		bundle *filesystem.CABundle
		source map[string][]byte
		want   string
	}{
		{"unknown mode", caBundle("merge", "a.pem"), map[string][]byte{"a.pem": valid}, "is not append or replace"},
		{"empty mode", caBundle("", "a.pem"), map[string][]byte{"a.pem": valid}, "is not append or replace"},
		{"no sources", caBundle(synthesis.CAModeReplace), map[string][]byte{}, "requires at least one source"},
		{"unlocked source", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{}, "is not a locked input"},
		{"no certificate", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": {}}, "no public certificate"},
		{"prose outside a block", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": []byte("not a certificate\n")}, "outside certificate blocks"},
		{"private key", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")}, "is not a public certificate"},
		{"leading partial block", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": append(
			[]byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), valid...)}, "invalid certificate"},
		{"leading malformed key block", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": append(
			[]byte("-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"), valid...)}, "malformed certificate block"},
		{"leading malformed certificate block", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": append(
			[]byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), valid...)}, "malformed certificate block"},
		{"unterminated block", caBundle(synthesis.CAModeReplace, "a.pem"), map[string][]byte{"a.pem": append(
			[]byte("-----BEGIN CERTIFICATE-----\n"), valid...)}, "malformed certificate block"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := synthesis.CA(vfs.New(), bundlePath, testCase.bundle, testCase.source)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %v does not contain %q", err, testCase.want)
			}
		})
	}
}

func TestCA_RejectsInvalidArguments(t *testing.T) {
	valid := certificatePEM(t, "valid")
	sources := map[string][]byte{"a.pem": valid}
	if err := synthesis.CA(nil, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"), sources); err == nil ||
		!strings.Contains(err.Error(), "requires an image tree") {
		t.Fatalf("error %v does not mention the tree", err)
	}
	if err := synthesis.CA(vfs.New(), "", caBundle(synthesis.CAModeReplace, "a.pem"), sources); err == nil ||
		!strings.Contains(err.Error(), "requires a bundle location") {
		t.Fatalf("error %v does not mention the location", err)
	}
	if err := synthesis.CA(vfs.New(), bundlePath, nil, sources); err != nil {
		t.Fatalf("omitted CA bundle failed: %v", err)
	}
}

func TestCA_RejectsMalformedSelectedBundle(t *testing.T) {
	tree := treeWithFile(t, bundlePath, "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
	err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "a.pem"),
		map[string][]byte{"a.pem": certificatePEM(t, "valid")})
	if err == nil || !strings.Contains(err.Error(), "is not a public certificate") {
		t.Fatalf("error %v does not reject the selected bundle", err)
	}
}

// TestCA_FailsOnUnreadableSelectedBundle guards against degrading append into
// replace: a bundle that exists but cannot be read must not look empty.
func TestCA_FailsOnUnreadableSelectedBundle(t *testing.T) {
	tree := vfs.New()
	if err := tree.Dir("/etc/ssl/certs/ca-certificates.crt", vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "a.pem"),
		map[string][]byte{"a.pem": certificatePEM(t, "declared")})
	if err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("error %v does not report the unreadable bundle", err)
	}
}

func TestCA_ReplacesSymlinkedBundle(t *testing.T) {
	tree := vfs.New()
	if err := tree.Symlink(bundlePath, "/usr/share/ca-certificates/bundle.crt", vfs.Attrs{}); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	declared := certificatePEM(t, "declared")
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": declared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	entry, ok := tree.Lookup(bundlePath)
	if !ok || entry.Kind != vfs.File || entry.Mode.Perm() != 0o644 {
		t.Fatalf("bundle entry is %+v", entry)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"declared"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

func TestCA_IsDeterministic(t *testing.T) {
	first := certificatePEM(t, "first")
	second := certificatePEM(t, "second")
	sources := map[string][]byte{"a.pem": first, "b.pem": second}
	var previous string
	for range 5 {
		tree := vfs.New()
		if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem", "b.pem"), sources); err != nil {
			t.Fatalf("CA: %v", err)
		}
		content := readFile(t, tree, bundlePath)
		if previous != "" && content != previous {
			t.Fatal("bundle output is not deterministic")
		}
		previous = content
	}
}

// A published bundle carries a title, comments and a rule between certificates.
// None of that is certificate data, and the blocks themselves stay strict.
func TestCA_AcceptsTextOutsideBlocks(t *testing.T) {
	valid := certificatePEM(t, "commented")
	second := certificatePEM(t, "second")
	bundle := append([]byte("##\n## Bundle of CA Root Certificates\n##\n\n"), valid...)
	bundle = append(bundle, []byte("Example Root CA\n==================\n\n")...)
	bundle = append(bundle, second...)
	bundle = append(bundle, []byte("# trailing comment\n")...)
	tree := vfs.New()
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": bundle}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"commented", "second"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

// An image that installs ca-certificates carries the roots and the list of
// enabled ones, but the bundle itself is written by a maintainer script Vapor
// never runs. The default bundle must be what that script would have produced.
func TestCA_DefaultBundleUsesEnabledRoots(t *testing.T) {
	first := certificatePEM(t, "first")
	second := certificatePEM(t, "second")
	disabled := certificatePEM(t, "disabled")
	tree := vfs.New()
	writeRoot(t, tree, "Example_CA.pem", first)
	writeRoot(t, tree, "Second_CA.pem", second)
	writeRoot(t, tree, "Disabled_CA.pem", disabled)
	writeCAConfig(t, tree, "# comment\nExample_CA.pem\n!Disabled_CA.pem\nSecond_CA.pem\nmissing.pem\n")
	if err := synthesis.CA(tree, bundlePath, nil, nil); err != nil {
		t.Fatalf("CA: %v", err)
	}
	subjects := bundleSubjects(t, readFile(t, tree, bundlePath))
	if !slices.Equal(subjects, []string{"first", "second"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

// Debian ships the roots and the update-ca-certificates tool but no list of the
// enabled ones, so the roots the package carries are what it means to enable.
func TestCA_DefaultBundleFallsBackToEveryRoot(t *testing.T) {
	first := certificatePEM(t, "first")
	second := certificatePEM(t, "second")
	tree := vfs.New()
	writeRoot(t, tree, "mozilla/First_CA.pem", first)
	writeRoot(t, tree, "mozilla/Second_CA.pem", second)
	if err := synthesis.CA(tree, bundlePath, nil, nil); err != nil {
		t.Fatalf("CA: %v", err)
	}
	subjects := bundleSubjects(t, readFile(t, tree, bundlePath))
	if !slices.Equal(subjects, []string{"first", "second"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

// Without the certificate package there is nothing to derive and nothing to write.
func TestCA_DefaultBundleNeedsPackageData(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.CA(tree, bundlePath, nil, nil); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, ok := tree.Lookup(bundlePath); ok {
		t.Fatal("a tree without the certificate package must not gain a bundle")
	}
}

// A listed root that escapes the package directory is not trust material.
func TestCA_DefaultBundleIgnoresRootsOutsideThePackage(t *testing.T) {
	root := certificatePEM(t, "root")
	tree := vfs.New()
	writeOutsideRoot(t, tree, "/outside.pem", root)
	writeCAConfig(t, tree, "../../outside.pem\n")
	if err := synthesis.CA(tree, bundlePath, nil, nil); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, ok := tree.Lookup(bundlePath); ok {
		t.Fatal("a root outside the package directory must not be trusted")
	}
}

// Certificate clients read one bundle, so two images built from the same payload
// must produce the same bytes.
func TestCA_DefaultBundleIsDeterministic(t *testing.T) {
	first := certificatePEM(t, "first")
	second := certificatePEM(t, "second")
	var previous string
	for range 3 {
		tree := vfs.New()
		writeRoot(t, tree, "a.pem", first)
		writeRoot(t, tree, "b.pem", second)
		writeCAConfig(t, tree, "b.pem\na.pem\n")
		if err := synthesis.CA(tree, bundlePath, nil, nil); err != nil {
			t.Fatalf("CA: %v", err)
		}
		content := readFile(t, tree, bundlePath)
		if previous != "" && content != previous {
			t.Fatal("default bundle output is not deterministic")
		}
		previous = content
	}
	if subjects := bundleSubjects(t, previous); !slices.Equal(subjects, []string{"second", "first"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}

func writeRoot(t *testing.T, tree *vfs.Tree, name string, content []byte) {
	t.Helper()
	if err := tree.File("/usr/share/ca-certificates/"+name, content,
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Path: "test"}}); err != nil {
		t.Fatalf("write root %s: %v", name, err)
	}
}

func writeCAConfig(t *testing.T, tree *vfs.Tree, content string) {
	t.Helper()
	if err := tree.File("/etc/ca-certificates.conf", []byte(content),
		vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Path: "test"}}); err != nil {
		t.Fatalf("write CA config: %v", err)
	}
}

func writeOutsideRoot(t *testing.T, tree *vfs.Tree, location string, content []byte) {
	t.Helper()
	if err := tree.File(location, content, vfs.Attrs{Mode: 0o644, Origin: vfs.Origin{Path: "test"}}); err != nil {
		t.Fatalf("write %s: %v", location, err)
	}
}

// TestCA_AppendKeepsTheDistributionRoots is the defect this covers: the bundle at
// location is written by this step, so a package that ships roots rather than a
// bundle has not put one there yet. Reading only the bundle made append behave like
// replace and silently dropped every distribution root a TLS client needs.
func TestCA_AppendKeepsTheDistributionRoots(t *testing.T) {
	distribution := certificatePEM(t, "distribution")
	tree := vfs.New()
	writeRoot(t, tree, "distribution.crt", distribution)
	writeCAConfig(t, tree, "distribution.crt\n")
	declared := certificatePEM(t, "declared")
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "a.pem"),
		map[string][]byte{"a.pem": declared}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if subjects := bundleSubjects(t, readFile(t, tree, bundlePath)); !slices.Equal(subjects, []string{"distribution", "declared"}) {
		t.Fatalf("bundle subjects are %v", subjects)
	}
}
