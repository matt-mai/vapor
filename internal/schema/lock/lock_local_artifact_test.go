package lock

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// A local payload is named by its path, so neither the declaration nor the record
// has a URL to compare.
func TestVerifyLockfileAcceptsALocalArtifactSource(t *testing.T) {
	t.Parallel()
	specification, lock := validMultiPlatformLock(t)
	specification.Contents.Artifacts[0].Sources[0] = contents.ArtifactSource{Platforms: []string{"linux/amd64"}, Path: "files/server-amd64", SHA256: strings.Repeat("a", 64)}
	specification.Contents.Artifacts[0].Sources[1] = contents.ArtifactSource{Platforms: []string{"linux/arm64"}, Path: "files/server-arm64", SHA256: strings.Repeat("b", 64)}
	digest, err := specification.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	lock.SpecDigest = digest
	lock.Artifacts[0].URL, lock.Artifacts[0].Path = "", "files/server-amd64"
	lock.Artifacts[1].URL, lock.Artifacts[1].Path = "", "files/server-arm64"
	if err := VerifyLockfileForProvider(specification, lock, "26.04", bindingDefaults()); err != nil {
		t.Fatalf("local artifact source refused: %v", err)
	}
}

func TestVerifyLockfileRefusesASourceThatMovesBetweenURLAndPath(t *testing.T) {
	t.Parallel()
	specification, lock := validMultiPlatformLock(t)
	specification.Contents.Artifacts[0].Sources[0] = contents.ArtifactSource{Platforms: []string{"linux/amd64"}, Path: "files/server-amd64", SHA256: strings.Repeat("a", 64)}
	digest, err := specification.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	lock.SpecDigest = digest
	if err := VerifyLockfileForProvider(specification, lock, "26.04", bindingDefaults()); err == nil ||
		!strings.Contains(err.Error(), "source identity does not match the spec") {
		t.Fatalf("error = %v", err)
	}
}
