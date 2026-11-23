package lock

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

func TestDecodeLockfile_RequiredNestedFields(t *testing.T) {
	t.Parallel()
	_, lock := validMultiPlatformLock(t)
	lock.Repositories[0].Release.Format = "release-gpg"
	lock.Repositories[0].Release.Path = "dists/resolute/Release"
	lock.Repositories[0].Release.Signature = &Content{Path: "dists/resolute/Release.gpg", SHA256: strings.Repeat("a", 64), Size: 1}
	data, err := lock.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"version", "platforms", "provider/distro", "provider/release",
		"local-inputs/0/size", "catalogues/0/archive/size", "catalogues/0/source/type",
		"repositories/0/trust/keys/0/size", "repositories/0/release/size",
		"repositories/0/release/signature/size", "repositories/0/indexes/0/size",
		"packages/0/content/size", "slices/0/content/size",
		"slices/0/selected", "slices/0/closure", "artifacts/0/size", "artifacts/0/uid",
		"artifacts/0/gid", "artifacts/0/unpack", "artifacts/0/sbom/version",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(path, "/")
			removeLockField(t, document, parts)
			input, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeLockfile(input)
			if decoded != nil || err == nil || !strings.Contains(err.Error(), `required field "`+parts[len(parts)-1]+`"`) {
				t.Fatalf("missing %s: lock=%v err=%v", path, decoded, err)
			}
		})
	}
}

func removeLockField(t *testing.T, document any, path []string) {
	t.Helper()
	for _, segment := range path[:len(path)-1] {
		switch node := document.(type) {
		case map[string]any:
			document = node[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil {
				t.Fatal(err)
			}
			document = node[index]
		default:
			t.Fatalf("unexpected document node %T", node)
		}
	}
	delete(document.(map[string]any), path[len(path)-1])
}

func TestDecodeLockfile_ExplicitZeroFields(t *testing.T) {
	t.Parallel()
	_, lock := validMultiPlatformLock(t)
	lock.Artifacts[0].Size = 0
	decoded, err := decodeLockfile(mustCanonicalYAML(t, lock))
	if err != nil {
		t.Fatal(err)
	}
	artifact := decoded.Artifacts[0]
	if artifact.Size != 0 || artifact.UID != 0 || artifact.GID != 0 || artifact.Unpack == nil || *artifact.Unpack != contents.ArtifactUnpackStandalone {
		t.Fatalf("explicit zero fields lost: %+v", artifact)
	}
}
