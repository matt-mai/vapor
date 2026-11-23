package spec

const contentsFixture = minimalSpec + `platforms: [linux/amd64, linux/arm64]
contents:
  packages:
    - name: openssl
      version: "= 3.0-1"
  catalogues:
    - name: custom
      url: https://example.com/catalogue
      branch: ubuntu-26.04
      archives: {ubuntu: main}
  slices:
    - package: base-files
      slice: release-info
  repositories:
    - name: main
      suites: [resolute, resolute-updates]
      components: [main, universe]
      endpoints:
        - platforms: [linux/amd64]
          url: https://example.com/ubuntu
        - platforms: [linux/arm64]
          url: http://ports.example.com/ubuntu-ports
      trust:
        keys:
          - path: keys/repo.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
  artifacts:
    - name: server
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

const filesystemFixture = minimalSpec + `filesystem:
  paths:
    - path: /app/data
      type: directory
      uid: 65532
      gid: 65532
      mode: "0750"
    - path: /app/current
      type: symlink
      target: data
    - path: /app/ready
      type: file
  accounts:
    groups:
      - name: app
        gid: 65532
    users:
      - name: app
        uid: 65532
        gid: 65532
  timezone: Europe/Berlin
  ca:
    mode: append
    sources: [certificates/company.pem]
  os-release:
    PRETTY_NAME: Example application image
`

const policiesFixture = minimalSpec + `hardening:
  strip-docs: false
  strip-shells: false
  strip-apt-dpkg: false
  remove-suid-sgid: false
contents:
  slices-engine:
    max-steps: 250000
`

const attestationFixture = `platforms: [linux/arm64, linux/amd64]
sbom: {enabled: false}
vex:
  inputs: [nonexistent/review.json]
  assertions:
    - vulnerability: CVE-2099-12345
      package: example-library
      status: not_affected
      justification: vulnerable_code_not_present
      statement: Reviewed omitted code; not automatic proof.
      absent-paths: [/usr/bin/example]
    - vulnerability: GHSA-example
      artifact: server
      status: affected
      statement: Needs an update.
`
