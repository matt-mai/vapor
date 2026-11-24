---
layout: default
title: Contents
---

# Contents

The `contents` mapping says what goes into the image. Use any combination of
packages, slices and artifacts; an image can also use none of them, as long as it
needs no packages.

- How to choose between them: [add software](../guides/add-software.md) and
  [add your own files](../guides/add-your-own-files.md).

## Fields

```yaml
contents:
  packages: []       # whole packages
  slices: []         # named file groups from a catalogue
  catalogues: []     # where slice definitions come from
  repositories: []   # where packages come from
  artifacts: []      # your own files
  slices-engine:
    max-steps: 100000
```

Every field is optional, and an empty `contents: {}` is accepted. That does not
promise a usable image: an image with no files has nothing to run.

## packages

```yaml
contents:
  packages:
    - openssl
    - name: curl
      version: "~> 8.5"
```

| Field     | Rules                                                  |
| --------- | ------------------------------------------------------ |
| `name`    | Required. Lowercase letters, digits, `+`, `.` and `-`. |
| `version` | Optional version expression, see [versions](#versions). |
| `cpe`     | Optional CPE 2.3 name, see [vendor packages](#naming-a-vendor-package-for-a-scanner). |

An unpinned package needs only its name, written as a plain string. The mapping
form stays for a pinned package, because the pin needs a place to go. The string
form takes no other keys, so `- curl: "8.5.0"` is refused rather than read as a
name and a version.

## versions

A `version` is a constraint, not just one build. An operator is always required,
so a bare `version: "1.4.1"` is refused with a suggestion to write `= 1.4.1`.
Several expressions separated by commas or spaces must all hold.

| Expression        | Matches                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `= 1.4.1`         | Any build of 1.4.1, such as `1.4.1-1ubuntu2` or `1.4.1+b1`, but not `1.4.10`. |
| `= 1.4.1-1ubuntu2` | Exactly that one build.                                                |
| `= 2024a`         | `2024a` and any rebuild of it, but not `2024b`.                          |
| `!= 1.4.1`        | Everything but 1.4.1.                                                  |
| `>= 1.4.1`        | That version and newer.                                                |
| `> 1.4.1`         | Strictly newer.                                                        |
| `< 2.0`, `<= 2.0` | Older than the version, or up to and including it.                     |
| `~> 3.0`          | `3.0` and later `3.x` releases, but not `4.0`.                          |
| `>= 1.4, < 1.5`   | Both must hold.                                                        |

`~>` allows the newer releases of the level it names: `~> 3` allows `3.x`,
`~> 3.0` allows `3.x` up to `4.0`, and `~> 3.0.13` allows `3.0.x` up to `3.1`.
It needs a plain numeric version such as `3.0` or `2024.1`, so `~> 2024a` and a
version with a Debian revision are refused.

Three rules decide what `=` means. A version with a Debian revision names one
build. A plain numeric version covers every build of that version, so the Debian
revision never decides. Any other version compares the upstream version alone.

Comparisons follow Debian ordering, where `1.4.1~rc1` is older than `1.4.1`. They
ignore the Debian revision unless it is part of the expression, so `>= 1.4.1`
accepts `1.4.1-1ubuntu2`.

When several requests name one package, their expressions apply together. A
combination nothing satisfies fails at lock time and names the package and the
expressions that clashed.

An architecture suffix such as `openssl:arm64` is not supported; the platform
list decides the architecture. A request also cannot name the repository it comes
from, see [repositories](#repositories). A package cannot be requested twice, and it
cannot be requested both whole and through a slice.

```text
vaporize: operation failed: load spec "image.yaml": validate spec: whole-package/slice overlap is not allowed
```

A whole package is recorded in `/var/lib/dpkg/status` as `install ok installed` with
its dependency relations intact, and the image can install further packages if it
keeps the tooling to do so. This is the difference from a slice, which is recorded as
`unpacked` without relations. See
[configure the system](../guides/configure-the-system.md#package-tooling).

## slices

```yaml
contents:
  slices:
    - package: base-files
      slice: release-info
    - package: tzdata
      slice: eurasia
      version: "= 2024a"
      catalogue: ubuntu
```

| Field       | Rules                                                                   |
| ----------- | ----------------------------------------------------------------------- |
| `package`   | Required package name.                                                  |
| `slice`     | Required slice name, at least three characters, such as `release-info`. |
| `version`   | Optional version expression, as for packages above.                     |
| `catalogue` | Catalogue name. Optional when the specification declares one catalogue. |
| `cpe`       | Optional CPE 2.3 name, as for packages above.                           |

A package and slice pair can be selected only once. Two slices of one package are
fine, and their version expressions apply together, see [versions](#versions).
Slices the catalogue does not define are refused at lock time.

A package in the catalogue may name the archive it comes from. Vapor then takes
that package only from that archive, and a build refuses a lock that says otherwise.

## catalogues

A catalogue is a directory of slice definitions. Every slice needs one.

```yaml
contents:
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
    - name: internal
      path: catalogues/internal
      archives:
        ubuntu: mirror
```

| Field                     | Rules                                                          |
| ------------------------- | -------------------------------------------------------------- |
| `name`                    | Required, unique. Lowercase letters, digits, `_`, `.` and `-`. |
| `url`                     | Remote catalogue. HTTPS only.                                  |
| `branch`, `tag`, `commit` | Exactly one selector for a remote catalogue.                   |
| `path`                    | Local catalogue directory, relative to the specification file. |
| `archives`                | Upstream archive names mapped to repository names.             |

A remote catalogue needs a `url` and exactly one of `branch`, `tag` or `commit`.
A local catalogue needs `path` and no remote field. The path is written without a
leading `./` and without a trailing slash: `catalogues/internal` works,
`./catalogues/internal` and `/srv/catalogues` do not.

The catalogue must use Chisel format `v3`. Older formats are refused rather than
converted.

`lock` clones the catalogue with `git` on your machine, resolves the selector to a
commit and stores that commit in the lock. Annotated tags are resolved to their
commit. Later builds use the saved copy and never contact GitHub.

`archives` binds a catalogue archive to a repository in the same specification.
Bindings are per catalogue. An archive named after the distribution (`ubuntu`,
`debian`) falls back to the archive the distribution serves when it has no binding.
When two catalogues share a repository, platform and suite, they must list the
same components in the same order. If an image uses slices, each package can be
defined in only one of its catalogues, even if no slice from that package is selected.

An unbound paid archive is skipped only for a distribution that sells one, which is
what keeps Ubuntu Pro off until you ask for it; Debian has none, so a catalogue that
names a paid archive for Debian is refused instead of having it silently dropped. Any
other unbound archive is an error:

```text
vaporize: operation failed: catalogue "custom": catalogue archive "internal" requires an explicit repository binding
```

## repositories

A repository says where packages come from and which keys to trust.

```yaml
contents:
  repositories:
    - name: ubuntu
      endpoints:
        - platforms: [linux/amd64]
          url: https://archive.ubuntu.com/ubuntu
        - platforms: [linux/arm64]
          url: https://ports.ubuntu.com/ubuntu-ports
      suites: [resolute, resolute-security, resolute-updates]
      components: [main, universe]
      trust:
        keys:
          - path: keys/archive.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
      by-hash: prefer
      freshness:
        valid-until: if-present
```

| Field         | Rules                                                          |
| ------------- | -------------------------------------------------------------- |
| `name`        | Required, unique.                                              |
| `platforms`   | Optional subset of the image platforms. Default: all of them.  |
| `endpoints`   | Required. One `url` per platform, covering the whole scope.    |
| `suites`      | Required, ordered, unique.                                     |
| `suite-match` | Optional: `codename`. Default: use the distribution's rule.    |
| `identity`    | Optional: `own`. The vendor signs its own release identity.     |
| `packages`    | Optional, with `identity: own`: the names this archive may supply.|
| `components`  | Required, ordered, unique.                                     |
| `trust`       | Optional. Leaving it out uses the distribution's key for that archive when its name matches one, or all of the distribution's keys otherwise. |
| `by-hash`     | `prefer` (default), `require` or `disable`.                     |
| `freshness`   | `valid-until`: `if-present` (default) or `require`.             |

For whole packages, each image platform uses only the repositories that list it.
Together, those repositories must supply the packages selected for that platform.

Declaring a repository chooses its own endpoint, suites and keys, but not which
suites belong to the image's release. A Debian image for `trixie` reads `trixie`,
`trixie-updates` and `trixie-security` and nothing else, so a correctly signed
`bookworm` repository you declare is refused rather than locked. Ubuntu leaves the
suites to the declaration, because its releases are not related that way.

Ubuntu normally checks each entry in `suites` against the repository's signed
`Suite`; Debian checks the signed `Codename`. Set `suite-match: codename` on a
repository that signs a label such as `Suite: stable` and the release name as
`Codename: resolute`. Keep `suites: [resolute]`: that still selects the metadata
under `dists/resolute/`. A missing or different codename fails verification.

A vendor repository that signs an identity of its own sets `identity: own`. The
distribution's release rules then no longer judge its suites and codename, because
nothing in that repository describes the distribution's release: the keys you list
authenticate it. Such a repository must list its keys and its `packages` scope, and
its archive may only supply the names in that scope. The scope is also how you choose
which repository a package comes from: a package request cannot name one, because a
second way to say the same thing would have to agree with the first. The architecture,
components and expiry of the metadata are still checked.

Leaving `repositories` out altogether is allowed when the distribution publishes
archives of its own. A Debian image that names only packages then reads `trixie` and
`trixie-updates` from `deb.debian.org`, and `trixie-security` from
`security.debian.org`, each with the `main` component and its own key. A specification
that declares any repository is read as choosing its own
sources, so the default archives are not added beside them. Ubuntu leaves
`repositories` out and gets nothing, because it names no archive Vapor can pick for
you.

`trust.keys` lists local key files and their full fingerprints. Fingerprints are
40 or 64 hex characters; short key IDs are refused. Declaring `trust` replaces the
default keys for that repository instead of adding to them. Every listed key file
must contain every listed fingerprint, and private key material is refused.

A key `path` is relative to the specification file like a `ca.sources` entry, so it
may climb above it: `path: ../../keys/archive.asc` lets several images share one key
file.

`by-hash: require` fails the lock when the server does not offer by-hash
downloads. `freshness.valid-until: require` fails the lock when the metadata has
no expiry date, while `if-present` checks the date only when one is supplied.

A suite whose signed metadata carries no expiry date, such as Debian's main archive,
satisfies the default and fails `require`. The policy belongs to the repository you
declare, not to the distribution.

URLs accept HTTP and HTTPS and need a hostname. They cannot contain credentials,
a query string or a fragment; a redirect target may carry a query. The downloader
follows exactly one thing: the network path the server names. Redirect targets
are never written to the lock or the log. Catalogue URLs must be HTTPS.

## artifacts

```yaml
contents:
  artifacts:
    - name: server
      dest: /usr/local/bin/server
      unpack: false
      mode: "0755"
      uid: 0
      gid: 0
      platforms: [linux/amd64, linux/arm64]
      sources:
        - platforms: [linux/amd64]
          url: https://example.com/server-amd64
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        - platforms: [linux/arm64]
          url: https://example.com/server-arm64
          sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      sbom: {name: server, version: "1.0"}
```

| Field        | Rules                                                                             |
| ------------ | --------------------------------------------------------------------------------- |
| `name`       | Required, unique.                                                                 |
| `platforms`  | Optional subset of the image platforms. Default: all of them.                     |
| `dest`       | Required absolute path inside the image. Not used with `unpack: package`.          |
| `unpack`     | Required. `false` copies one file, `true` extracts an archive, `package` installs a DEB. |
| `mode`       | Octal string such as `"0755"`. Default `"0644"`. Not allowed with `true` or `package`. |
| `uid`, `gid` | Numeric owner. Default `0`.                                                       |
| `sources`    | Required. One entry per platform, each with `url` or `path` plus `sha256`.      |
| `sbom`       | Required `name` and `version` of the upstream component; optional `cpe`.          |

`sha256` is 64 lowercase hex digits without a prefix. Every declared platform
needs a source, and the sources must cover each platform exactly once. One source
can cover several platforms with the same bytes.

A source names its payload one way. `url` downloads it. `path` reads a file
relative to the specification's directory: the file must be a regular file inside
that directory, and a path that climbs out of it — including `../` — is refused,
because a payload becomes image content. A local payload is still copied into the cache at
lock time, so a later build needs neither the file nor the network.

```yaml
      sources:
        - platforms: [linux/amd64]
          path: files/server-amd64
          sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

`sbom` names the upstream component and version the artifact is reported under in the
generated SPDX document and in a VEX statement, so it should describe the payload rather
than the place it was downloaded from.

An artifact that is not a Debian package can only be described as `pkg:generic`, which
no vulnerability database indexes. Declare a CPE as well and scans can find advisories
about it:

```yaml
      sbom:
        name: python
        version: "3.15.2"
        cpe: cpe:2.3:a:python_software_foundation:python:3.15.2:*:*:*:*:*:*:*
```

The CPE has to be a CPE 2.3 name: thirteen colon-separated fields starting
`cpe:2.3:`, with `a`, `o` or `h` as the part and a vendor and product that are not
wildcards. Leave it out when the payload is a package, because a package's name,
version and distribution are enough.

### Naming a vendor package for a scanner

A package from a vendor archive is published as that vendor's package, so a scanner
looks for advisories under the vendor rather than the distribution. A vendor that files
none leaves the package unmatched, and `cpe` on the request names it in a database that
does:

```yaml
    - catalogue: ubuntu
      package: nodejs
      version: "~> 26.0"
      slice: runtime
      cpe: cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*
```

A `*` version inherits the locked version, which keeps one declaration correct as the
package moves, and a CPE that names a version is used as written. The field is allowed
on a whole `packages` entry and on a `slices` entry; every request for one package has
to declare the same CPE, because a package is one element in the document.

Scanners other than trivy only consult a CPE for a Debian package when they are told
to. For grype that is `match.dpkg.using-cpes: true`, and it applies to every package in
the image, so a CPE is only worth declaring where a purl genuinely reaches nothing.

With that switch on, grype compares the CPE against the version the purl carries, using
the distribution's version rules. A vendor's Debian revision then reads as newer than
the upstream release it was built from, which is why a current package reports nothing
and an out-of-date one still does. Declare `*` as the CPE's version rather than typing
the release number, so the comparison always sees the version that was actually
installed.

### Installing a local package

`unpack: package` installs a Debian package file. Point it at a `.deb` with a
`path` source and pin its `sha256`, and the package becomes part of the image the
same way a package from a repository does: its files are placed where the package
puts them, it appears in the package database, and it is reported in the SPDX
document.

```yaml
      unpack: package
      sbom: {name: myapp, version: "1.0"}
      sources:
        - platforms: [linux/amd64]
          path: dist/myapp_1.0_amd64.deb
          sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
```

A package artifact declares no `dest`, `uid`, `gid` or `mode`: the package decides
those. Its `sbom` name and version must match the package inside the file. The
package's own dependencies are not installed for it, so every dependency it names
must already be provided by the packages and artifacts the specification selects.
`vaporize lock` checks this and names the missing one:

```text
vaporize: operation failed: lock failed
vaporize: operation failed: local package "myapp" depends on "libssl3", which no selected
package provides; add it to contents.packages
```

Archives may be gzip, Zstandard or XZ compressed, and the format is detected from
the contents rather than the file name. Extraction is confined to `dest`:
traversal, escaping links and overlapping paths are refused.

## slices-engine

```yaml
contents:
  slices-engine:
    max-steps: 100000
```

`max-steps` caps how many steps one slice's mutation script may run. The default
is 100000, and it must be a positive integer. It is a step budget, not a memory or
time limit; the sandbox applies those separately. See [policies](policies.md).

## Validation

`vaporize lock` reads the specification, fetches nothing that the schema rejects,
and records the result. `vaporize inspect` shows what was recorded. Most mistakes
in this file produce an error before any download starts:

```text
vaporize: operation failed: load spec "image.yaml": validate spec: contents.catalogues[0]: local path must be nonempty, clean, relative and slash-separated (relative to the spec directory)
```
