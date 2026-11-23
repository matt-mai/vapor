package verify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/klauspost/compress/gzip"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/verify"
)

const oldValidUntil = "Thu, 01 Jan 2004 00:00:00 UTC"

type testKeys struct {
	first, second *openpgp.Entity
	err           error
}

var generatedKeys = sync.OnceValue(func() testKeys {
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEd25519}
	first, err := openpgp.NewEntity("Vapor Verify One", "", "one@example.com", config)
	if err != nil {
		return testKeys{err: err}
	}
	second, err := openpgp.NewEntity("Vapor Verify Two", "", "two@example.com", config)
	if err != nil {
		return testKeys{err: err}
	}
	return testKeys{first: first, second: second}
})

func keys(t *testing.T) (*openpgp.Entity, *openpgp.Entity) {
	t.Helper()
	generated := generatedKeys()
	if generated.err != nil {
		t.Fatal(generated.err)
	}
	return generated.first, generated.second
}

type fixture struct {
	dir    string
	cache  *cache.Cache
	lock   *lock.Lockfile
	entity *openpgp.Entity
}

type fixtureOptions struct {
	format       string
	trusted      *openpgp.Entity
	signer       *openpgp.Entity
	countersign  *openpgp.Entity
	prepend      bool
	recorded     []string
	validity     string
	indexPath    string
	signerConfig *packet.Config
	// suite is the locked suite; signedSuite and codename are what the release
	// itself signs, so a test can build a Debian-shaped release whose signed suite
	// is the moving name beside a fixed codename.
	suite       string
	signedSuite string
	codename    string
	// source is the Source field the signed index declares for demo.
	source string
}

func newFixture(t *testing.T, options fixtureOptions) *fixture {
	t.Helper()
	if options.format == "" {
		options.format = deb.ReleaseFormatInRelease
	}
	if options.validity == "" {
		options.validity = oldValidUntil
	}
	if options.indexPath == "" {
		options.indexPath = "main/binary-amd64/Packages.gz"
	}
	if options.suite == "" {
		options.suite = "resolute"
	}
	if options.signedSuite == "" {
		options.signedSuite = options.suite
	}
	if options.codename == "" {
		options.codename = options.signedSuite
	}
	dir := t.TempDir()
	blobs, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	indexData := gzipPackages(t, options.source)
	indexDigest := storeBlob(t, blobs, indexData)
	payload := releasePayload(indexDigest, int64(len(indexData)), options.validity, options.indexPath,
		options.signedSuite, options.codename)
	release, signatureData, signature := signedRelease(t, options.format, options.signer, payload, options.signerConfig)
	if options.countersign != nil {
		release, signatureData, signature = countersignRelease(t, options, release, signatureData, signature)
	}
	recorded := options.recorded
	if len(recorded) == 0 {
		recorded = []string{fingerprint(options.signer)}
	}
	releaseDigest := storeBlob(t, blobs, release)
	if signatureData != nil && storeBlob(t, blobs, signatureData) != signature.SHA256 {
		t.Fatal("stored signature digest changed")
	}
	entity := options.trusted
	if entity == nil {
		entity = options.signer
	}
	keyDigest := storeBlob(t, blobs, publicKey(t, entity))
	locked := &lock.Lockfile{Repositories: []lock.Repository{{
		ID:           "ubuntu-resolute-amd64",
		Name:         "ubuntu",
		Platform:     "linux/amd64",
		Architecture: "amd64",
		URL:          "https://archive.ubuntu.com/ubuntu",
		Suite:        options.suite,
		Trust: lock.RepositoryTrust{Keys: []lock.RepositoryKey{{
			Fingerprint: fingerprint(entity),
			Path:        "keys/ubuntu.asc",
			SHA256:      keyDigest,
			Size:        int64(len(publicKey(t, entity))),
		}}},
		Release: lock.RepositoryRelease{
			Format:     options.format,
			Path:       releasePath(options.format),
			SHA256:     releaseDigest,
			Size:       int64(len(release)),
			ValidUntil: new(options.validity),
			Signers:    recorded,
			Signature:  signature,
		},
		Indexes: []lock.Index{{
			Component: "main",
			Path:      options.indexPath,
			SHA256:    indexDigest,
			Size:      int64(len(indexData)),
		}},
	}}}
	return &fixture{dir: dir, cache: blobs, lock: locked, entity: entity}
}

// countersignRelease appends a second signature, so the first packet comes from a
// key the lock did not record.
func countersignRelease(t *testing.T, options fixtureOptions, release, signatureData []byte,
	signature *lock.Content) ([]byte, []byte, *lock.Content) {
	t.Helper()
	if options.format == deb.ReleaseFormatDetached {
		var second bytes.Buffer
		if err := openpgp.ArmoredDetachSign(&second, options.countersign,
			bytes.NewReader(release), nil); err != nil {
			t.Fatal(err)
		}
		var buffer bytes.Buffer
		if options.prepend {
			buffer.Write(second.Bytes())
			buffer.Write(signatureData)
		} else {
			buffer.Write(signatureData)
			buffer.Write(second.Bytes())
		}
		countersigned := buffer.Bytes()
		return release, countersigned, &lock.Content{
			Path:   signature.Path,
			SHA256: digest(countersigned),
			Size:   int64(len(countersigned)),
		}
	}
	block, _ := clearsign.Decode(release)
	body, err := io.ReadAll(block.ArmoredSignature.Body)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := openpgp.DetachSign(&buffer, options.countersign, bytes.NewReader(block.Bytes), nil); err != nil {
		t.Fatal(err)
	}
	second := buffer.Bytes()
	packets := make([]byte, 0, len(body)+len(second))
	order := [][]byte{body, second}
	if options.prepend {
		order = [][]byte{second, body}
	}
	for _, chunk := range order {
		packets = append(packets, chunk...)
	}
	return rearm(t, block.Headers, block.Bytes, packets), nil, nil
}

// rearm rebuilds a clear-signed message around an existing body of signature
// packets.
func rearm(t *testing.T, headers textproto.MIMEHeader, signed, packets []byte) []byte {
	t.Helper()
	var signatureBlock bytes.Buffer
	armorWriter, err := armor.Encode(&signatureBlock, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := armorWriter.Write(packets); err != nil {
		t.Fatal(err)
	}
	if err := armorWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var message bytes.Buffer
	message.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\n")
	for key, values := range headers {
		for _, value := range values {
			fmt.Fprintf(&message, "%s: %s\n", key, value)
		}
	}
	message.WriteString("\n")
	for line := range strings.SplitSeq(string(signed), "\n") {
		if strings.HasPrefix(line, "-") {
			message.WriteString("- ")
		}
		message.WriteString(line)
		message.WriteString("\n")
	}
	message.Write(signatureBlock.Bytes())
	return message.Bytes()
}

func releasePayload(indexDigest string, indexSize int64, validity, indexPath, suite, codename string) []byte {
	return fmt.Appendf(nil, `Origin: Debian
Label: Debian
Suite: %s
Version: 26.04
Codename: %s
Date: Thu, 23 Apr 2026 17:07:15 UTC
Valid-Until: %s
Architectures: amd64 arm64
Components: main restricted
SHA256:
 %s %d %s
`, suite, codename, validity, indexDigest, indexSize, indexPath)
}

func signedRelease(t *testing.T, format string, entity *openpgp.Entity, payload []byte, config *packet.Config) ([]byte, []byte, *lock.Content) {
	t.Helper()
	if format == deb.ReleaseFormatDetached {
		var buffer bytes.Buffer
		if err := openpgp.ArmoredDetachSign(&buffer, entity, bytes.NewReader(payload), config); err != nil {
			t.Fatal(err)
		}
		signature := buffer.Bytes()
		return payload, signature, &lock.Content{
			Path:   "dists/resolute/Release.gpg",
			SHA256: digest(signature),
			Size:   int64(len(signature)),
		}
	}
	var buffer bytes.Buffer
	writer, err := clearsign.Encode(&buffer, entity.PrivateKey, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes(), nil, nil
}

func releasePath(format string) string {
	if format == deb.ReleaseFormatDetached {
		return "dists/resolute/Release"
	}
	return "dists/resolute/InRelease"
}

func gzipPackages(t *testing.T, source string) []byte {
	t.Helper()
	declared := ""
	if source != "" {
		declared = "Source: " + source + "\n"
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writeString(writer, `Package: demo
Version: 1.0-1
Architecture: amd64
`+declared+`Filename: pool/main/d/demo/demo_1.0-1_amd64.deb
Size: 42
SHA256: `+strings.Repeat("a", 64)+`

`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeString(writer io.Writer, value string) (int, error) {
	return io.WriteString(writer, value)
}

func publicKey(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func storeBlob(t *testing.T, blobs *cache.Cache, data []byte) string {
	t.Helper()
	digest := digest(data)
	if err := blobs.Store(bytes.NewReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	return digest
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fingerprint(entity *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
}

func TestVerifyRepositoriesAuthenticatesPackageSelections(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	repo := signed.lock.Repositories[0].ID
	content := lock.Content{
		Path: "pool/main/d/demo/demo_1.0-1_amd64.deb", SHA256: strings.Repeat("a", 64), Size: 42,
	}
	signed.lock.Packages = []lock.Package{{
		Name: "demo", Version: "1.0-1", Architecture: "amd64", Repository: repo, Content: content,
	}}
	signed.lock.Slices = []lock.Slice{{
		Package: "demo", Version: "1.0-1", Architecture: "amd64", Repository: repo, Content: content,
	}}
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatalf("matching selections rejected: %v", err)
	}

	const missing = "payload is not present in its authenticated repository index"
	signed.lock.Packages[0].Content.Size++
	if err := verify.Repositories(signed.lock, signed.cache); err == nil ||
		!strings.Contains(err.Error(), `package "demo": `+missing) {
		t.Fatalf("expected whole package evidence rejection, got %v", err)
	}
	signed.lock.Packages[0].Content = content
	signed.lock.Slices[0].Content.SHA256 = strings.Repeat("b", 64)
	if err := verify.Repositories(signed.lock, signed.cache); err == nil ||
		!strings.Contains(err.Error(), `slice "demo": `+missing) {
		t.Fatalf("expected slice evidence rejection, got %v", err)
	}
}

func TestVerifyRepositoriesAuthenticatesSourcePackage(t *testing.T) {
	t.Parallel()
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first, source: "demo-src"})
	repo := signed.lock.Repositories[0].ID
	content := lock.Content{
		Path: "pool/main/d/demo/demo_1.0-1_amd64.deb", SHA256: strings.Repeat("a", 64), Size: 42,
	}
	signed.lock.Packages = []lock.Package{{
		Name: "demo", Version: "1.0-1", Architecture: "amd64", Source: "demo-src",
		Repository: repo, Content: content,
	}}
	signed.lock.Slices = []lock.Slice{{
		Package: "demo", Version: "1.0-1", Architecture: "amd64", Source: "demo-src",
		Repository: repo, Content: content,
	}}
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatalf("matching selections rejected: %v", err)
	}

	// The payload still matches, so only the source name can name the fault.
	const wrongSource = "source \"other-src\" does not match its authenticated repository index"
	signed.lock.Packages[0].Source = "other-src"
	if err := verify.Repositories(signed.lock, signed.cache); err == nil ||
		!strings.Contains(err.Error(), `package "demo": `+wrongSource) {
		t.Fatalf("expected whole package source rejection, got %v", err)
	}
	signed.lock.Packages[0].Source = "demo-src"
	signed.lock.Slices[0].Source = ""
	if err := verify.Repositories(signed.lock, signed.cache); err == nil ||
		!strings.Contains(err.Error(), `slice "demo": source "" does not match`) {
		t.Fatalf("expected slice source rejection, got %v", err)
	}
}

func TestVerifyRepositoriesChecksFinalIndexAfterMatchingSelections(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	repository := signed.lock.Repositories[0]
	const finalPath = "restricted/binary-amd64/Packages"
	content := lock.Content{
		Path: "pool/main/d/demo/demo_1.0-1_amd64.deb", SHA256: strings.Repeat("a", 64), Size: 42,
	}
	signed.lock.Packages = []lock.Package{{
		Name: "demo", Version: "1.0-1", Architecture: "amd64", Repository: repository.ID, Content: content,
	}}
	second := repository
	second.ID = "second"
	signed.lock.Slices = []lock.Slice{{
		Package: "demo", Version: "1.0-1", Architecture: "amd64", Repository: second.ID, Content: content,
	}}
	for _, test := range []struct {
		name, final string
	}{
		{"valid", ""},
		{"malformed", "missing field separator\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			last := lock.Index{Component: "restricted", Path: finalPath, Size: int64(len(test.final)),
				SHA256: storeBlob(t, signed.cache, []byte(test.final))}
			index := repository.Indexes[0]
			payload := releasePayload(index.SHA256, index.Size, oldValidUntil, index.Path, repository.Suite, repository.Suite)
			payload = fmt.Appendf(payload, " %s %d %s\n", last.SHA256, last.Size, last.Path)
			release, _, _ := signedRelease(t, second.Release.Format, first, payload, nil)
			second.Release.SHA256, second.Release.Size = storeBlob(t, signed.cache, release), int64(len(release))
			second.Indexes = []lock.Index{index, last}
			signed.lock.Repositories = []lock.Repository{repository, second}

			err := verify.Repositories(signed.lock, signed.cache)
			if test.name == "valid" && err != nil {
				t.Fatal(err)
			}
			if test.name == "malformed" && (err == nil || !strings.Contains(err.Error(), `index "`+finalPath+`"`)) {
				t.Fatalf("verification error = %v; want malformed final index error", err)
			}
		})
	}
}

func TestVerifyRepositoriesInRelease(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRepositoriesDetachedRelease(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{format: deb.ReleaseFormatDetached, signer: first})
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRepositoriesReplaysOldExpiry(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first, validity: "Thu, 01 Jan 2004 00:00:00 UTC"})
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatalf("old valid lock did not replay: %v", err)
	}
}

func TestVerifyRepositoriesReplaysExpiredSignature(t *testing.T) {
	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEd25519,
		Time:            func() time.Time { return time.Now().Add(-2 * time.Hour) },
		KeyLifetimeSecs: 3600,
		SigLifetimeSecs: 3600,
	}
	entity, err := openpgp.NewEntity("Expired", "", "expired@example.com", config)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fixtureOptions{signer: entity, signerConfig: config})
	if err := verify.Repositories(f.lock, f.cache); err != nil {
		t.Fatal(err)
	}
}

// Replay keeps the signer the lock recorded even when another trusted signature
// comes first, so a second signature cannot replace the recorded evidence.
func TestVerifyRepositoriesKeepsRecordedSigner(t *testing.T) {
	first, second := keys(t)
	// The recorded signer is first, its signature is the second packet.
	signed := newFixture(t, fixtureOptions{
		signer: first, countersign: second, prepend: true, recorded: []string{fingerprint(first)},
	})
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatal(err)
	}
}

// Ignoring expiry on replay must not turn an expired recorded signer into a
// different one that happens to be valid today.
func TestVerifyRepositoriesKeepsExpiredRecordedSigner(t *testing.T) {
	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEd25519,
		Time:            func() time.Time { return time.Now().Add(-2 * time.Hour) },
		KeyLifetimeSecs: 3600,
		SigLifetimeSecs: 3600,
	}
	expired, err := openpgp.NewEntity("Expired", "", "expired@example.com", config)
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := keys(t)
	// The expired signature comes first, so a verifier that trusted packet order
	// or today's expiry would land on the valid one instead.
	signed := newFixture(t, fixtureOptions{
		signer: expired, countersign: valid, prepend: true, signerConfig: config,
		recorded: []string{fingerprint(expired)},
	})
	if err := verify.Repositories(signed.lock, signed.cache); err != nil {
		t.Fatalf("expired recorded signer did not replay: %v", err)
	}
}

func TestVerifyRepositoriesRejectsTamperedEvidence(t *testing.T) {
	first, _ := keys(t)
	tests := []struct {
		name string
		file string
		blob func(*fixture) string
	}{
		{"release", "release", func(f *fixture) string { return f.lock.Repositories[0].Release.SHA256 }},
		{"index", "index", func(f *fixture) string { return f.lock.Repositories[0].Indexes[0].SHA256 }},
		{"key", "key", func(f *fixture) string { return f.lock.Repositories[0].Trust.Keys[0].SHA256 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := newFixture(t, fixtureOptions{signer: first})
			tamperBlob(t, signed.dir, tt.blob(signed))
			if err := verify.Repositories(signed.lock, signed.cache); err == nil {
				t.Fatal("tampered evidence accepted")
			}
		})
	}
}

func TestVerifyRepositoriesRejectsWrongSigner(t *testing.T) {
	first, second := keys(t)
	signed := newFixture(t, fixtureOptions{trusted: first, signer: second})
	if err := verify.Repositories(signed.lock, signed.cache); err == nil ||
		!strings.Contains(err.Error(), "signature") {
		t.Fatalf("wrong signer: %v", err)
	}
}

func TestVerifyRepositoriesRejectsMismatchedLock(t *testing.T) {
	first, second := keys(t)
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"signers", func(f *fixture) { f.lock.Repositories[0].Release.Signers = []string{fingerprint(second)} }},
		{"valid until", func(f *fixture) { f.lock.Repositories[0].Release.ValidUntil = new("Thu, 01 Jan 2026 00:00:00 UTC") }},
		{"index hash", func(f *fixture) { f.lock.Repositories[0].Indexes[0].SHA256 = strings.Repeat("b", 64) }},
		{"index path", func(f *fixture) { f.lock.Repositories[0].Indexes[0].Path = "../Packages.gz" }},
		{"missing index", func(f *fixture) { f.lock.Repositories[0].Indexes[0].Path = "main/binary-amd64/Packages.xz" }},
		{"suite", func(f *fixture) { f.lock.Repositories[0].Suite = "jammy" }},
		{"format", func(f *fixture) { f.lock.Repositories[0].Release.Format = deb.ReleaseFormatDetached }},
		{"missing signature", func(f *fixture) { f.lock.Repositories[0].Release.Signature = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := newFixture(t, fixtureOptions{signer: first})
			if tt.name == "missing signature" {
				signed = newFixture(t, fixtureOptions{format: deb.ReleaseFormatDetached, signer: first})
			}
			tt.mutate(signed)
			if err := verify.Repositories(signed.lock, signed.cache); err == nil {
				t.Fatal("mismatched lock accepted")
			}
		})
	}
}

func TestVerifyRepositoriesRedactsBlobErrors(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	secret := errors.New("open /home/alice/.cache/vapor/sha256/aa/bb: permission denied")
	tests := []struct {
		name    string
		store   verify.BlobStore
		message string
	}{
		{"open", blobStoreFunc(func(string, int64) (io.ReadCloser, error) {
			return nil, secret
		}), "open key evidence failed"},
		{"read", blobStoreFunc(func(string, int64) (io.ReadCloser, error) {
			return failingBlob{readErr: secret}, nil
		}), "read key evidence failed"},
		{"close", blobStoreFunc(func(string, int64) (io.ReadCloser, error) {
			return failingBlob{closeErr: secret}, nil
		}), "close key evidence failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verify.Repositories(signed.lock, test.store)
			if err == nil {
				t.Fatal("blob error accepted")
			}
			if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %q, want %q", err, test.message)
			}
			if strings.Contains(err.Error(), "/home/alice") {
				t.Fatalf("error exposes host path: %v", err)
			}
			if !errors.Is(err, secret) {
				t.Fatalf("cause lost: %v", err)
			}
		})
	}
}

func TestVerifyRepositoriesRedactsCachePath(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	digest := signed.lock.Repositories[0].Trust.Keys[0].SHA256
	if err := os.Remove(filepath.Join(signed.dir, "sha256", digest[:2], digest)); err != nil {
		t.Fatal(err)
	}
	err := verify.Repositories(signed.lock, signed.cache)
	if err == nil {
		t.Fatal("missing blob accepted")
	}
	if strings.Contains(err.Error(), signed.dir) || strings.Contains(err.Error(), "open cache blob") {
		t.Fatalf("error exposes cache path: %v", err)
	}
	if !strings.Contains(err.Error(), "open key evidence failed") {
		t.Fatalf("error = %v", err)
	}
}

type blobStoreFunc func(string, int64) (io.ReadCloser, error)

func (f blobStoreFunc) Open(digest string, size int64) (io.ReadCloser, error) {
	return f(digest, size)
}

type failingBlob struct {
	readErr  error
	closeErr error
}

func (b failingBlob) Read([]byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return 0, io.EOF
}

func (b failingBlob) Close() error {
	return b.closeErr
}

func TestVerifyRepositoriesEmptyLock(t *testing.T) {
	blobs, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.Repositories(&lock.Lockfile{}, blobs); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRepositoriesRejectsOversizedEvidence(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	signed.lock.Repositories[0].Release.Size = deb.MaxReleaseSize + 1
	if err := verify.Repositories(signed.lock, signed.cache); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized release: %v", err)
	}
}

func TestVerifyRepositoriesRejectsNilArguments(t *testing.T) {
	first, _ := keys(t)
	signed := newFixture(t, fixtureOptions{signer: first})
	if err := verify.Repositories(nil, signed.cache); err == nil {
		t.Fatal("nil lock accepted")
	}
	if err := verify.Repositories(signed.lock, nil); err == nil {
		t.Fatal("nil store accepted")
	}
}

func tamperBlob(t *testing.T, dir, digest string) {
	t.Helper()
	path := filepath.Join(dir, "sha256", digest[:2], digest)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// replayPolicy is a provider whose releases match on the signed codename and whose
// components may carry a prefix, the shape Debian needs.
type replayPolicy struct {
	codename, prefixed, own bool
	scope                   []string
}

func (p replayPolicy) ReleaseMatching(string) deb.ReleaseIdentity {
	return deb.ReleaseIdentity{MatchCodename: p.codename, PrefixedComponents: p.prefixed, OwnIdentity: p.own}
}

func (p replayPolicy) PackageScope(string) []string { return p.scope }

// A repository with its own identity signs a release name of its own, so replay has to
// accept it for the same reason acquisition did. Its keys still authenticate it.
func TestVerifyRepositoriesAcceptsOwnIdentity(t *testing.T) {
	t.Parallel()
	signer, _ := keys(t)
	// nginx.org signs `Suite: stable` beside `Codename: resolute`: the codename agrees
	// with the request, the suite names the vendor's own channel.
	fixture := newFixture(t, fixtureOptions{signer: signer, suite: "resolute", signedSuite: "stable", codename: "resolute"})
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{codename: true}); err != nil {
		t.Fatalf("codename matching rejected a stable-suite release: %v", err)
	}
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{}); err == nil {
		t.Fatal("exact suite matching accepted a release that signs stable")
	}
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{own: true}); err != nil {
		t.Fatalf("own identity rejected a release that signs stable: %v", err)
	}
}

// Own identity accepts a release whose codename also differs, because the repository is
// not the base distribution and only its keys say what it is.
func TestVerifyRepositoriesOwnIdentityIgnoresTheReleaseName(t *testing.T) {
	t.Parallel()
	signer, _ := keys(t)
	fixture := newFixture(t, fixtureOptions{signer: signer, suite: "vendor", signedSuite: "stable", codename: "stable"})
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{own: true}); err != nil {
		t.Fatalf("own identity rejected a vendor release: %v", err)
	}
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{codename: true}); err == nil {
		t.Fatal("codename matching accepted an unrelated vendor codename")
	}
}

// A Debian-shaped release signs the moving suite `stable` beside the fixed codename,
// so it replays only under codename matching and never under the exact-suite rule.
func TestVerifyRepositoriesUsesProviderMatching(t *testing.T) {
	t.Parallel()
	signer, _ := keys(t)
	fixture := newFixture(t, fixtureOptions{signer: signer, suite: "trixie", signedSuite: "stable", codename: "trixie"})
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache,
		replayPolicy{codename: true, prefixed: true}); err != nil {
		t.Fatalf("codename matching rejected a trixie release: %v", err)
	}
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{}); err == nil {
		t.Fatal("exact suite matching accepted a release that signs stable")
	}
	if err := verify.Repositories(fixture.lock, fixture.cache); err == nil {
		t.Fatal("the default policy accepted a release that signs stable")
	}
}

// Codename matching does not fall back to the suite: a release signing `trixie` is
// refused for a lock naming `trixie-security`.
func TestVerifyRepositoriesRejectsOtherCodename(t *testing.T) {
	t.Parallel()
	signer, _ := keys(t)
	fixture := newFixture(t, fixtureOptions{
		signer: signer, suite: "trixie-security", signedSuite: "stable-security", codename: "trixie",
	})
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{codename: true}); err == nil {
		t.Fatal("accepted a trixie release for a trixie-security lock")
	}
}

// The default policy keeps today's exact-suite rule, so a lock without a provider
// still refuses a release whose signed suite differs.
func TestVerifyRepositoriesDefaultMatchingIsExact(t *testing.T) {
	t.Parallel()
	signer, _ := keys(t)
	fixture := newFixture(t, fixtureOptions{signer: signer, suite: "trixie"})
	if err := verify.Repositories(fixture.lock, fixture.cache); err != nil {
		t.Fatal(err)
	}
	// The Ubuntu rules demand the exact signed suite and no codename match, which this
	// release satisfies because the codename equals the suite.
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, replayPolicy{}); err != nil {
		t.Fatal(err)
	}
}

// A repository declared for one package name may only supply that name. Selection
// applies the scope, so a lock that names an out-of-scope package from the same
// repository has to be refused on replay as well; otherwise editing the lock, or one
// written before the scope was enforced, would spend authority it never granted.
func TestVerifyRepositoriesEnforcesTheDeclaredPackageScope(t *testing.T) {
	t.Parallel()
	signer, _ := keys(t)
	fixture := newFixture(t, fixtureOptions{signer: signer})
	repo := fixture.lock.Repositories[0].ID
	content := lock.Content{
		Path: "pool/main/d/demo/demo_1.0-1_amd64.deb", SHA256: strings.Repeat("a", 64), Size: 42,
	}
	fixture.lock.Packages = []lock.Package{{
		Name: "demo", Version: "1.0-1", Architecture: "amd64", Repository: repo, Content: content,
	}}
	scoped := replayPolicy{scope: []string{"demo"}}
	if err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, scoped); err != nil {
		t.Fatalf("in-scope package rejected: %v", err)
	}
	fixture.lock.Packages[0].Name = "apt"
	fixture.lock.Packages[0].Source = ""
	err := verify.RepositoriesWithPolicy(fixture.lock, fixture.cache, scoped)
	want := `package "apt": repository "` + fixture.lock.Repositories[0].Name +
		`" was not declared for this package`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}
