package synthesis

import (
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// Java reads its trust anchors from a keystore file, not from the PEM bundle every
// other TLS client uses. Debian's Java packages ship that keystore as a symlink to
// a file their configuration step generates with `trust extract --format=java-cacerts`.
// Vapor does not run maintainer scripts, so the link dangles and the runtime trusts
// nothing: `java -version` works but every HTTPS connection fails with "the
// trustAnchors parameter must be non-empty".
//
// The store is written here from the certificates the image already trusts, so a
// declared CA takes effect in Java the same way it does everywhere else.
const (
	javaKeystoreName = "/lib/security/cacerts"
	// javaKeystorePassword is the password Debian's keystore uses and the one
	// keytool and trust assume when given no argument. Java itself reads trusted
	// entries without one; the value keeps the usual tooling working.
	javaKeystorePassword = "changeit"
)

// javaTrustStore writes a keystore at the target of every dangling Java keystore
// link in the tree. A link that resolves, or a keystore shipped as a regular file,
// is left alone: it already holds trust anchors the image was built with.
func javaTrustStore(tree *vfs.Tree, certificates [][]byte) error {
	if len(certificates) == 0 {
		return nil
	}
	targets := map[string]bool{}
	for _, entry := range tree.Entries() {
		if entry.Kind != vfs.Symlink || !strings.HasSuffix(entry.Path, javaKeystoreName) {
			continue
		}
		target := entry.Target
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(entry.Path), target)
		}
		if _, exists := tree.Lookup(target); exists {
			continue
		}
		targets[target] = true
	}
	for _, target := range slices.Sorted(maps.Keys(targets)) {
		content := encodeJKS(certificates, javaKeystorePassword)
		if err := writeFile(tree, target, content, CAOrigin); err != nil {
			return err
		}
	}
	return nil
}
