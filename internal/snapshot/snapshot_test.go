package snapshot_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/schema/attestation"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/filesystem"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/snapshot"
)

const archiveFingerprint = "F6ECB3762474EDA9D21B7022871920D1991BC93C"

func TestSnapshotCachesDeclaredInputsAndCatalogues(t *testing.T) {
	dir := t.TempDir()
	key := readFixture(t, filepath.Join("..", "distro", "ubuntu", "keys", "ubuntu-archive-key-2018.asc"))
	certificate := append(selfSignedCertificate(t, "ca"), selfSignedCertificate(t, "chain")...)
	writeFile(t, dir, "keys/archive.asc", key)
	writeFile(t, dir, "certs/ca.pem", certificate)
	writeFile(t, dir, "vex/review.json", []byte(`{"statements":[]}`))
	writeFile(t, dir, "catalogues/local/chisel.yaml", []byte("format: chisel-v3\n"))

	specification := snapshotSpec()
	store := newStore(t)
	result, err := snapshot.Snapshot(dir, specification, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Inputs) != 3 {
		t.Fatalf("inputs = %+v", result.Inputs)
	}
	want := []struct{ role, path string }{
		{"ca", "certs/ca.pem"},
		{"trust-key", "keys/archive.asc"},
		{"vex", "vex/review.json"},
	}
	for i, item := range want {
		input := result.Inputs[i]
		if input.Role != item.role || input.Path != item.path || input.Size <= 0 {
			t.Fatalf("input[%d] = %+v", i, input)
		}
		reader, openErr := store.Open(input.SHA256, input.Size)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, readErr := io.ReadAll(reader); readErr != nil {
			t.Fatal(readErr)
		}
		_ = reader.Close()
	}
	if len(result.Catalogues) != 1 || result.Catalogues[0].Name != "local" || result.Catalogues[0].Digest == "" {
		t.Fatalf("catalogues = %+v", result.Catalogues)
	}
	entries := result.Catalogues[0].Tree.Entries()
	if len(entries) != 1 || entries[0].Path != "chisel.yaml" {
		t.Fatalf("entries = %+v", entries)
	}

	// A changed source produces a new snapshot, while the locked bytes survive.
	vexDigest := result.Inputs[2].SHA256
	vexSize := result.Inputs[2].Size
	writeFile(t, dir, "vex/review.json", []byte(`{"changed":true}`))
	changed, err := snapshot.Snapshot(dir, snapshotSpec(), store)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Inputs[2].SHA256 == vexDigest {
		t.Fatal("changed VEX source did not change snapshot identity")
	}
	reader, err := store.Open(vexDigest, vexSize)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(data) != `{"statements":[]}` {
		t.Fatalf("cached VEX = %q, %v", data, err)
	}
	if removeErr := os.RemoveAll(filepath.Join(dir, "catalogues", "local")); removeErr != nil {
		t.Fatal(removeErr)
	}
	entry := result.Catalogues[0].Tree.Entries()[0]
	reader, err = store.Open(entry.SHA256, entry.Size)
	if err != nil {
		t.Fatal(err)
	}
	catalogueBytes, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(catalogueBytes) != "format: chisel-v3\n" {
		t.Fatalf("cached catalogue = %q, %v", catalogueBytes, err)
	}
	if _, err := snapshot.Snapshot(dir, snapshotSpec(), store); err == nil {
		t.Fatal("deleted catalogue was accepted")
	}
}

func TestSnapshotRejectsPrivateAndInvalidCertificates(t *testing.T) {
	privateKey := privateKeyPEM(t, "private_marker")
	certificate := selfSignedCertificate(t, "ca")
	cases := map[string][]byte{
		"garbage":             []byte("not a certificate"),
		"private key":         privateKey,
		"certificate+key":     append(append([]byte{}, certificate...), privateKey...),
		"no certificate":      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}),
		"certificate request": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("x")}),
		"leading garbage":     append([]byte("garbage"), certificate...),
		"malformed block": append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
			certificate...),
		"unterminated block": append([]byte("-----BEGIN CERTIFICATE-----\n"), certificate...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "certs/ca.pem", data)
			_, err := snapshot.Snapshot(dir, caOnlySpec(), newStore(t))
			if err == nil {
				t.Fatal("invalid CA input was accepted")
			}
			if strings.Contains(err.Error(), "private_marker") {
				t.Fatal("error leaked private key material")
			}
		})
	}
}

// Published bundles carry a title, comments and a rule between certificates.
// None of that is certificate data, so only the blocks themselves are checked.
func TestSnapshotAcceptsTextOutsideBlocks(t *testing.T) {
	certificate := selfSignedCertificate(t, "ca")
	bundle := append([]byte("##\n## Bundle of CA Root Certificates\n##\n\n"), certificate...)
	bundle = append(bundle, []byte("Example Root CA\n==================\n")...)
	dir := t.TempDir()
	writeFile(t, dir, "certs/ca.pem", bundle)
	if _, err := snapshot.Snapshot(dir, caOnlySpec(), newStore(t)); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotRejectsPrivateTrustKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keys/archive.asc", privateKeyPEM(t, "secret_marker"))
	specification := snapshotSpec()
	_, err := snapshot.Snapshot(dir, specification, newStore(t))
	if err == nil || strings.Contains(err.Error(), "secret_marker") {
		t.Fatalf("error = %v", err)
	}
}

func TestSnapshotRejectsPrivateKeyInVEXInput(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "vex/review.json", privateKeyPEM(t, "vex_secret"))
	specification := snapshotSpec()
	specification.Filesystem.CA = nil
	specification.Contents.Repositories = nil
	_, err := snapshot.Snapshot(dir, specification, newStore(t))
	if err == nil || strings.Contains(err.Error(), "vex_secret") {
		t.Fatalf("error = %v", err)
	}
}

func TestSnapshotRejectsIncompleteTrustKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keys/archive.asc", readFixture(t, filepath.Join("..", "distro", "ubuntu", "keys", "ubuntu-archive-key-2018.asc")))
	specification := snapshotSpec()
	specification.Filesystem.CA = nil
	specification.VEX.Inputs = nil
	specification.Contents.Repositories[0].Trust.Keys[0].Fingerprints = []string{strings.Repeat("A", 40)}
	_, err := snapshot.Snapshot(dir, specification, newStore(t))
	if err == nil {
		t.Fatal("trust key without its configured fingerprint was accepted")
	}
}

func TestSnapshotRejectsMissingTrustKey(t *testing.T) {
	dir := t.TempDir()
	specification := snapshotSpec()
	specification.Filesystem.CA = nil
	specification.VEX.Inputs = nil
	if _, err := snapshot.Snapshot(dir, specification, newStore(t)); err == nil {
		t.Fatal("missing trust key was accepted")
	}
}

func TestSnapshotRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "key.asc"), 0o600); err != nil {
		t.Fatal(err)
	}
	specification := snapshotSpec()
	specification.Filesystem.CA = nil
	specification.VEX.Inputs = nil
	store := newStore(t)
	done := make(chan error, 1)
	go func() {
		_, err := snapshot.Snapshot(dir, specification, store)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO input was accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot blocked on FIFO input")
	}
}

func TestSnapshotRejectsMissingInputs(t *testing.T) {
	dir := t.TempDir()
	_, err := snapshot.Snapshot(dir, caOnlySpec(), newStore(t))
	if err == nil {
		t.Fatal("missing CA input was accepted")
	}
	if _, err := snapshot.Snapshot("", caOnlySpec(), newStore(t)); err == nil {
		t.Fatal("empty spec directory was accepted")
	}
	if _, err := snapshot.Snapshot(dir, nil, newStore(t)); err == nil {
		t.Fatal("nil specification was accepted")
	}
	if _, err := snapshot.Snapshot(dir, caOnlySpec(), nil); err == nil {
		t.Fatal("nil store was accepted")
	}
}

func TestSnapshotReadsTrustInputsAboveTheSpecDirectory(t *testing.T) {
	base := t.TempDir()
	certificate := selfSignedCertificate(t, "ca")
	writeFile(t, base, "ca/ca.pem", certificate)
	writeFile(t, base, "keys/archive.asc", readFixture(t,
		filepath.Join("..", "distro", "ubuntu", "keys", "ubuntu-archive-key-2018.asc")))
	writeFile(t, base, "vex/review.json", []byte(`{"statements":[]}`))
	writeFile(t, base, "images/app/catalogues/local/chisel.yaml", []byte("format: chisel-v3\n"))
	specDir := filepath.Join(base, "images", "app")
	if err := os.MkdirAll(specDir, 0o700); err != nil {
		t.Fatal(err)
	}
	specification := snapshotSpec()
	specification.Contents.Repositories[0].Trust.Keys[0].Path = "../../keys/archive.asc"
	specification.Filesystem.CA.Sources = []string{"../../ca/ca.pem"}
	specification.VEX.Inputs = []string{"../../vex/review.json"}
	result, err := snapshot.Snapshot(specDir, specification, newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ role, path string }{
		{"ca", "../../ca/ca.pem"},
		{"trust-key", "../../keys/archive.asc"},
		{"vex", "../../vex/review.json"},
	}
	if len(result.Inputs) != len(want) {
		t.Fatalf("inputs = %+v", result.Inputs)
	}
	for i, item := range want {
		if result.Inputs[i].Role != item.role || result.Inputs[i].Path != item.path ||
			result.Inputs[i].Size <= 0 {
			t.Fatalf("input[%d] = %+v", i, result.Inputs[i])
		}
	}
}

func TestSnapshotRefusesAnInputThatLeavesTheClimbedAncestor(t *testing.T) {
	base := t.TempDir()
	writeFile(t, base, "ca/ca.pem", selfSignedCertificate(t, "ca"))
	if err := os.Symlink("/etc/passwd", filepath.Join(base, "ca", "link.pem")); err != nil {
		t.Fatal(err)
	}
	specDir := filepath.Join(base, "images", "app")
	if err := os.MkdirAll(specDir, 0o700); err != nil {
		t.Fatal(err)
	}
	specification := caOnlySpec()
	specification.Filesystem.CA.Sources = []string{"../../ca/link.pem"}
	if _, err := snapshot.Snapshot(specDir, specification, newStore(t)); err == nil {
		t.Fatal("a symlink out of the climbed ancestor was accepted")
	}
}

func TestSnapshotKeepsRolesSeparateForSamePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "shared.pem", selfSignedCertificate(t, "shared"))
	specification := caOnlySpec()
	specification.Filesystem.CA.Sources = []string{"shared.pem"}
	specification.VEX.Inputs = []string{"shared.pem"}
	result, err := snapshot.Snapshot(dir, specification, newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Inputs) != 2 || result.Inputs[0].Role != "ca" || result.Inputs[1].Role != "vex" {
		t.Fatalf("inputs = %+v", result.Inputs)
	}
	if result.Inputs[0].SHA256 != result.Inputs[1].SHA256 {
		t.Fatal("same bytes produced different digests")
	}
}

func snapshotSpec() *spec.Spec {
	return &spec.Spec{
		Contents: contents.Contents{
			Catalogues: []contents.CatalogueSource{
				{Name: "local", Path: new("catalogues/local")},
				{Name: "remote", URL: new("https://example.com/catalogue")},
			},
			Repositories: []contents.Repository{{
				Trust: contents.Trust{Keys: []contents.TrustKey{{
					Path: "keys/archive.asc", Fingerprints: []string{archiveFingerprint},
				}}},
			}},
		},
		Filesystem: filesystem.Filesystem{
			CA: &filesystem.CABundle{Mode: "append", Sources: []string{"certs/ca.pem"}},
		},
		VEX: attestation.VEX{Inputs: []string{"vex/review.json"}},
	}
}

func caOnlySpec() *spec.Spec {
	return &spec.Spec{Filesystem: filesystem.Filesystem{
		CA: &filesystem.CABundle{Mode: "replace", Sources: []string{"certs/ca.pem"}},
	}}
}

func newStore(t *testing.T) *cache.Cache {
	t.Helper()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func selfSignedCertificate(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func privateKeyPEM(t *testing.T, marker string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Comment": marker}, Bytes: der})
}

func TestLocalOpensAPayloadInsideTheSpecDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "files/tool", []byte("payload"))
	local := snapshot.NewLocal(dir)
	reader, err := local.Open("files/tool")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil || string(data) != "payload" {
		t.Fatalf("payload = %q, %v", data, readErr)
	}
}

func TestLocalRefusesPathsOutsideTheSpecDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "files/tool", []byte("payload"))
	if err := os.WriteFile(filepath.Join(dir, "files", "link"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "files", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "files", "tool"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	local := snapshot.NewLocal(dir)
	for _, path := range []string{"../tool", "/etc/passwd", "files/../tool", "", "link"} {
		if _, err := local.Open(path); err == nil {
			t.Errorf("%q: escaping path accepted", path)
		}
	}
	if _, err := local.Open("files/missing"); err == nil {
		t.Error("missing payload accepted")
	}
}
