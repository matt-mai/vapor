package contents_test

import (
	"strings"
	"testing"
)

// Two artifacts that publish one identity with different CPEs would put a claim under
// whichever name was read first, so the specification is refused.
func TestLoadSpec_RefusesArtifactsThatDisagreeOnOneIdentity(t *testing.T) {
	t.Parallel()
	const one = `    - name: server
      dest: /usr/bin/server
      unpack: false
      sources:
        - platforms: [linux/amd64]
          url: https://example.com/server-amd64
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        - platforms: [linux/arm64]
          url: https://example.com/server-arm64
          sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      sbom: {name: server, version: "1.0"}
`
	two := strings.Replace(one, "name: server\n      dest", "name: server-asan\n      dest", 1)
	two = strings.Replace(two, `sbom: {name: server, version: "1.0"}`,
		`sbom: {name: server, version: "1.0", cpe: "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"}`, 1)
	if _, err := loadText(t, strings.Replace(contentsFixture, one, one+two, 1)); err == nil ||
		!strings.Contains(err.Error(), "different CPEs for one identity") {
		t.Fatalf("error = %v, want a conflicting-identity refusal", err)
	}
}
