package lockinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro/deb"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
)

func testCache(t *testing.T) *cache.Cache {
	t.Helper()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestTreeFSServesCachedFile(t *testing.T) {
	t.Parallel()
	store := testCache(t)
	data := []byte("format: v3\n")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err := store.Store(bytesReader(data), digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	tree, err := catalogue.NewTree([]catalogue.Entry{{
		Path: "chisel.yaml", Kind: catalogue.KindFile, SHA256: digest, Size: int64(len(data)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := treeFS(tree, store)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile(fsys, "chisel.yaml")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %q, err=%v", got, err)
	}
	if _, err := treeFS(tree, testCache(t)); err == nil {
		t.Fatal("accepted a missing cached blob")
	}
}

type byteReader struct{ data []byte }

func bytesReader(data []byte) *byteReader { return &byteReader{data: data} }

func (reader *byteReader) Read(p []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, reader.data)
	reader.data = reader.data[n:]
	return n, nil
}

func TestDefaultTrustRecordsAndStoresKeys(t *testing.T) {
	t.Parallel()
	store := testCache(t)
	request := &Request{Cache: store}
	entity, err := openpgp.NewEntity("Test", "", "test@example.invalid", debianEntityConfig)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	armorWriter, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := entity.Serialize(armorWriter); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := armorWriter.Close(); writeErr != nil {
		t.Fatal(writeErr)
	}
	key := buffer.Bytes()
	fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
	snapshots := []deb.KeySnapshot{{Fingerprints: []string{fingerprint}, Data: key}}
	trust, err := repositoryTrust(request, &slicespkg.Binding{DefaultTrust: snapshots})
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.records) != 1 || trust.records[0].Path != "" || trust.records[0].Fingerprint != fingerprint {
		t.Fatalf("records=%+v", trust.records)
	}
	sum := sha256.Sum256(key)
	if _, err := store.Open(hex.EncodeToString(sum[:]), int64(len(key))); err != nil {
		t.Fatalf("provider key was not cached: %v", err)
	}
}

func TestValidateRequestRejectsIncompleteInputs(t *testing.T) {
	t.Parallel()
	if err := validateRequest(context.Background(), nil); err == nil {
		t.Fatal("accepted nil request")
	}
	request := &Request{Spec: &spec.Spec{}}
	if err := validateRequest(t.Context(), request); err == nil {
		t.Fatal("accepted incomplete request")
	}
}

func TestSliceHelpers(t *testing.T) {
	t.Parallel()
	repo := &repository{record: lock.Repository{Suite: "main", ID: "id"}}
	set := &archiveSet{repos: []*repository{repo}}
	if got := repositoryForSuite(set, "main"); got != "id" {
		t.Fatalf("repository = %q", got)
	}
	if got := repositoryForSuite(set, "other"); got != "" {
		t.Fatalf("unexpected repository %q", got)
	}
	if _, err := slicePackage(set, &slicespkg.PackageSelection{RealName: "a", Version: "1"}); err == nil {
		t.Fatal("accepted a missing package")
	}
}
