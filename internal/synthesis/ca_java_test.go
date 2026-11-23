package synthesis_test

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/pem"
	"slices"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

const (
	// javaKeystore is where Debian's Java packages point their trust store, and
	// where a JDK 9 or newer runtime reads it.
	javaKeystoreTarget = "/etc/ssl/certs/adoptium/cacerts"
	javaKeystoreJDK9   = "/usr/lib/jvm/temurin-21-jre-amd64/lib/security/cacerts"
	javaKeystoreJDK8   = "/usr/lib/jvm/temurin-8-jre-amd64/jre/lib/security/cacerts"
	javaKeystoreJDK25  = "/usr/lib/jvm/temurin-25-jdk-amd64/lib/security/cacerts"
)

// treeWithJavaKeystore returns a tree holding the dangling trust-store links a
// Debian Java package installs, without the file their maintainer script would
// generate.
func treeWithJavaKeystore(t *testing.T, links ...string) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for _, link := range links {
		if err := tree.Symlink(link, javaKeystoreTarget, vfs.Attrs{}); err != nil {
			t.Fatalf("create link %s: %v", link, err)
		}
	}
	return tree
}

// jksCertificates returns the certificate bytes of every trusted entry in a JKS
// store, in file order.
func jksCertificates(t *testing.T, store []byte) [][]byte {
	t.Helper()
	if len(store) < 12+20 {
		t.Fatalf("keystore is %d bytes, too short for a header and digest", len(store))
	}
	if magic := binary.BigEndian.Uint32(store[0:]); magic != 0xFEEDFEED {
		t.Fatalf("keystore magic is %#x", magic)
	}
	if version := binary.BigEndian.Uint32(store[4:]); version != 2 {
		t.Fatalf("keystore version is %d", version)
	}
	count := int(binary.BigEndian.Uint32(store[8:]))
	rest := store[12:]
	certificates := make([][]byte, 0, count)
	for range count {
		if len(rest) < 4 {
			t.Fatalf("keystore ends before entry tag")
		}
		tag := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if tag != 2 {
			t.Fatalf("entry tag is %d, want a trusted certificate", tag)
		}
		rest = skipUTF(t, rest) // alias
		rest = rest[8:]         // timestamp
		rest = skipUTF(t, rest) // certificate type
		size := int(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if len(rest) < size {
			t.Fatalf("certificate of %d bytes is truncated", size)
		}
		certificates = append(certificates, rest[:size])
		rest = rest[size:]
	}
	if len(rest) != sha1.Size {
		t.Fatalf("keystore has %d trailing bytes, want a %d-byte digest", len(rest), sha1.Size)
	}
	// keytool refuses to read a store whose digest does not match, so the digest is
	// checked here rather than left to the runtime, which tolerates a wrong one.
	want := jksDigest("changeit", store[:len(store)-sha1.Size])
	if !bytes.Equal(rest, want) {
		t.Fatal("keystore integrity digest does not match")
	}
	return certificates
}

// jksDigest recomputes the integrity digest the way the Java provider does.
func jksDigest(password string, body []byte) []byte {
	digest := sha1.New()
	for _, unit := range utf16BE(password) {
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], unit)
		digest.Write(encoded[:])
	}
	digest.Write([]byte("Mighty Aphrodite"))
	digest.Write(body)
	return digest.Sum(nil)
}

// utf16BE encodes a password as the JKS digest expects it.
func utf16BE(password string) []uint16 {
	units := make([]uint16, 0, len(password))
	for _, r := range password {
		units = append(units, uint16(r))
	}
	return units
}

func skipUTF(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) < 2 {
		t.Fatalf("keystore ends before UTF length")
	}
	size := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if len(data) < size {
		t.Fatalf("UTF of %d bytes is truncated", size)
	}
	return data[size:]
}

// TestCA_WritesJavaTrustStore is the defect this covers: a Java package ships its
// keystore as a link to a file the maintainer script generates, so without
// synthesis the runtime trusts no certificate at all and every TLS connection
// fails with "the trustAnchors parameter must be non-empty".
func TestCA_WritesJavaTrustStore(t *testing.T) {
	first := certificatePEM(t, "first")
	second := certificatePEM(t, "second")
	tree := treeWithJavaKeystore(t, javaKeystoreJDK9)
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem", "b.pem"),
		map[string][]byte{"a.pem": first, "b.pem": second}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	store, err := tree.Read(javaKeystoreTarget)
	if err != nil {
		t.Fatalf("java trust store: %v", err)
	}
	want := [][]byte{certificateDER(t, first), certificateDER(t, second)}
	if got := jksCertificates(t, store); !equalCertificates(got, want) {
		t.Fatalf("keystore holds %d certificates, want %d", len(got), len(want))
	}
}

// TestCA_JavaTrustStoreFollowsTheDeclaredBundle covers the reason the store is
// derived from the bundle: a CA added to the spec must reach Java too.
func TestCA_JavaTrustStoreFollowsTheDeclaredBundle(t *testing.T) {
	root := certificatePEM(t, "vapor-test-root")
	tree := treeWithJavaKeystore(t, javaKeystoreJDK9)
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeAppend, "root.pem"),
		map[string][]byte{"root.pem": root}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	store, err := tree.Read(javaKeystoreTarget)
	if err != nil {
		t.Fatalf("java trust store: %v", err)
	}
	if !equalCertificates(jksCertificates(t, store), [][]byte{certificateDER(t, root)}) {
		t.Fatalf("keystore does not hold the declared root")
	}
}

// TestCA_WritesJavaTrustStoreForEveryJVM covers the two layout depths a Java
// runtime uses: JDK 8 keeps the store under jre/, newer releases directly under lib/.
func TestCA_WritesJavaTrustStoreForEveryJVM(t *testing.T) {
	tree := treeWithJavaKeystore(t, javaKeystoreJDK8, javaKeystoreJDK9, javaKeystoreJDK25)
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": certificatePEM(t, "only")}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, err := tree.Read(javaKeystoreTarget); err != nil {
		t.Fatalf("java trust store: %v", err)
	}
}

// TestCA_JavaTrustStoreIsDeterministic keeps builds reproducible: the store must
// not carry a clock value or an unstable entry order.
func TestCA_JavaTrustStoreIsDeterministic(t *testing.T) {
	roots := map[string][]byte{
		"a.pem": certificatePEM(t, "first"),
		"b.pem": certificatePEM(t, "second"),
	}
	var previous []byte
	for range 3 {
		tree := treeWithJavaKeystore(t, javaKeystoreJDK9)
		if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem", "b.pem"), roots); err != nil {
			t.Fatalf("CA: %v", err)
		}
		store, err := tree.Read(javaKeystoreTarget)
		if err != nil {
			t.Fatalf("java trust store: %v", err)
		}
		if previous != nil && !bytes.Equal(previous, store) {
			t.Fatal("keystore differs between identical builds")
		}
		previous = store
	}
}

// TestCA_LeavesAnExistingJavaTrustStore keeps a keystore the image already ships:
// a runtime whose package provides a real file was built with trust anchors.
func TestCA_LeavesAnExistingJavaTrustStore(t *testing.T) {
	tree := treeWithJavaKeystore(t, javaKeystoreJDK9)
	shipped := []byte("a keystore the package provides")
	if err := tree.File(javaKeystoreTarget, shipped, vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": certificatePEM(t, "root")}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if got := readFile(t, tree, javaKeystoreTarget); got != string(shipped) {
		t.Fatal("synthesis replaced a keystore the image already ships")
	}
}

// TestCA_NoJavaTrustStoreWithoutJava leaves a non-Java image alone.
func TestCA_NoJavaTrustStoreWithoutJava(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": certificatePEM(t, "root")}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, exists := tree.Lookup(javaKeystoreTarget); exists {
		t.Fatal("synthesis wrote a Java trust store for an image without Java")
	}
}

// TestCA_IgnoresALinkThatIsNotAJavaKeystore checks the trigger stays narrow: only
// a link named cacerts below lib/security is a Java trust store.
func TestCA_IgnoresALinkThatIsNotAJavaKeystore(t *testing.T) {
	tree := vfs.New()
	if err := tree.Symlink("/opt/cacerts", javaKeystoreTarget, vfs.Attrs{}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	if err := synthesis.CA(tree, bundlePath, caBundle(synthesis.CAModeReplace, "a.pem"),
		map[string][]byte{"a.pem": certificatePEM(t, "root")}); err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, err := tree.Read(javaKeystoreTarget); err == nil {
		t.Fatal("synthesis wrote a keystore for an unrelated link")
	}
}

func certificateDER(t *testing.T, content []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatalf("decode certificate")
	}
	return block.Bytes
}

func equalCertificates(got, want [][]byte) bool {
	return slices.EqualFunc(got, want, bytes.Equal)
}
