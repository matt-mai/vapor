package starter

import (
	"fmt"
	"strconv"
)

// The template is written out rather than marshaled, because a full Spec marshal
// emits nulls that strict source decoding rejects. The contents block differs by
// distribution, so each one supplies its own. These literals are the only model a
// starter has: Generate decodes and validates exactly the bytes written here.
const starterYAML = `version: 1
name: %s
image: %s
distro: %s
release: %s
platforms:
  - linux/amd64
contents:
%scontainer:
  user: "65532:65532"
`

// distributions the templates cover.
const (
	debianDistro = "debian"
	ubuntuDistro = "ubuntu"
)

// debianContents names whole packages only. Debian's reviewed archives are the
// provider's own, so a specification does not restate their endpoints, suites or
// keys, and no catalogue is involved.
const debianContents = `  packages:
    - base-files
    - ca-certificates
`

// ubuntuContents declares the public archive and binds its catalogue, which is what
// an Ubuntu image needs before it locks: the published catalogue carries archives
// that only a subscription serves.
const ubuntuContents = `  repositories:
    - name: ubuntu
      platforms:
        - linux/amd64
      endpoints:
        - platforms:
            - linux/amd64
          url: https://archive.ubuntu.com/ubuntu
      suites:
        - resolute
        - resolute-security
        - resolute-updates
      components:
        - main
        - universe
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
      archives:
        ubuntu: ubuntu
  slices:
    - package: base-files
      slice: release-info
`

func renderYAML(options Options, release string) []byte {
	contents := debianContents
	if options.Distro == ubuntuDistro {
		contents = ubuntuContents
	}
	return fmt.Appendf(nil, starterYAML, strconv.Quote(options.Name),
		strconv.Quote("ghcr.io/example/"+options.Name), options.Distro, strconv.Quote(release), contents)
}
