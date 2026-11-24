---
title: Lock schema
---

# Lock schema

A lockfile is a complete, offline answer to "what will this build produce". This
page is the data contract for version 1: every record, every required key, the
canonical encoding, and the digest vectors that fix the derived identities.

It is a reference, not a tutorial. The code that writes and consumes locks is
described in [lock assembly](locking.md), and the reasoning behind locking at all is
in [architecture](architecture.md).

## On this page

- [Status and scope](#status-and-scope)
- [Common forms](#common-forms)
- [Strict decoding and canonical encoding](#strict-decoding-and-canonical-encoding)
- [Atomic publication](#atomic-publication)
- [Records](#records)
- [Identity digest encodings](#identity-digest-encodings)
- [Offline evidence ownership](#offline-evidence-ownership)
- [Stores](#stores)
- [Examples](#examples)

## Status and scope

This reference fixes the serialized version-1 lock records and the rules that link
them together, including the byte encodings and vectors for repository IDs,
catalogue trees and selected-definition closures.

Three things it deliberately does not claim:

- It is not an authentication claim. A structurally valid lock says nothing about
  whether its bytes were authenticated; that is what offline evidence verification
  does.
- It does not describe a migration path. Version 1 has no reader for older or newer
  versions, and unknown or duplicate fields are errors.
- It does not cover stores. See [stores](#stores) for why there are no fields at all.

The types, the `LoadLockfile` reader, the canonical encoders, the atomic
`PublishLockfile` writer and the structural `VerifyLockfileForProvider` verifier live
in `internal/schema/lock`. [The lockfile contract](../image-spec-and-lockfile.md#lockfile-and-cache)
describes behaviour; this page fixes keys, required evidence and examples.

## Common forms

The conventions below apply to every record, so they are stated once.

- Records are mappings with exactly the keys listed. Null is never a value; optional
  fields are omitted instead. Root collections are always present and use `[]` when
  empty.
- Content hashes are plain `sha256` fields: exactly 64 lowercase hex digits with no
  prefix. They hash the exact cached bytes.
- Derived identities (`spec`, repository `id`, catalogue `tree`, slice
  `definition-digest`) use the form `sha256:<64 lowercase hex>`.
- `size` is a nonnegative decimal byte count of the exact hashed bytes. Every content
  hash has its size; a digest and size pair is never partial. Zero is valid, for
  example for empty cached bytes or an empty file in a tree.
- Full OpenPGP fingerprints are 40 or 64 hex digits, keep their configured spelling,
  and match case-insensitively. Short key IDs are invalid.
- `platform` is an OCI platform string such as `linux/amd64`. `architecture` is the
  native package architecture such as `amd64`. An `all` package keeps
  `architecture: all` in every platform record.
- Package and slice versions in a lock are exact Debian version strings. A request's
  version expression is not repeated there; verification asks the expression whether
  it allows the recorded version. Names, suite and component names, and catalogue
  archive names keep their declared spelling.
- Local input and local catalogue paths keep the exact clean relative spelling from
  the specification. Repository, index and package `path` values are clean,
  repository-relative POSIX paths with no `..`, no backslash and no leading slash.
  An artifact `dest` stays an absolute in-image path.
- URLs are the declared, credential-free HTTP(S) URLs. Catalogue URLs are HTTPS.
  Redirect targets are never recorded: a signed target carries its signature in the
  query, and a target is never part of what the lock names.
- Nothing records credentials, private keys, absolute host paths, wall-clock
  timestamps, warnings, or progress and timing state.

### Canonical ordering

Set-like collections are written in a fixed order. Canonical encoders sort them;
decoders reject duplicates but accept any input order, so a hand-edited lock is not
rejected for being unsorted.

| Collection | Order |
| --- | --- |
| `platforms` | specification platform order |
| `local-inputs` | `(role, path)` byte order |
| `catalogues` | `name` byte order |
| `repositories` | `id` byte order |
| `repositories[].indexes` | `component` byte order |
| `repositories[].trust.keys` | lowercase `fingerprint` byte order, then `path` |
| `repositories[].release.signers` | lowercase fingerprint byte order |
| `packages` | `(platform, name)` byte order |
| `slices` | `(platform, package)` byte order |
| `artifacts` | `(platform, name)` byte order |

Two collections are sequences rather than sets and keep their order:
`slices[].selected` (the specification's request order for that package) and
`slices[].closure` (dependency-first order of that package's included slices). The build derives the full dependency order from the verified catalogues
and the spec requests for each platform. It checks each package's part of that
sequence against its locked `closure` and uses the full order for content and
mutation. Reordering the outer `slices` records does not change the build.

Mapping key order is not part of the logical record; the canonical writer emits
keys in the order documented here.

## Strict decoding and canonical encoding

`LoadLockfile` reads exactly one YAML mapping from immutable bytes, using the same
strict preflight as the specification reader: duplicate or
unknown fields, anchors and aliases, custom tags, malformed scalar types, invalid
UTF-8, NUL and interpolation are all errors. Alternative field and record orders are
accepted, because order is an encoding detail and not a claim. Repeated set-like
records and missing required fields at any depth are rejected. Only keys marked
optional may be omitted; explicit zero sizes, ownership fields and false flags are
retained rather than defaulted.

The encoded size limit is **4 MiB (4,194,304 bytes)**, counted before YAML parsing
and including whitespace, comments and trailing content. `LoadLockfile` reads at most
the limit plus one byte, and loading rejects oversized input early. Canonical encoders reject output over the same limit, so publication
cannot produce a lock that the reader refuses. The point of the ceiling is to bound
parser allocation; the duplicate checks themselves are linear-time sets.

Decoding verifies neither the specification nor the evidence. Call
`lock.VerifyLockfileForProvider` before consuming a decoded record.

`CanonicalJSON` and `CanonicalYAML` sort the set-like collections using the table
above, keep sequences in order, emit empty root collections as `[]`, omit optional
fields and never emit null. Canonical JSON is compact. Canonical YAML uses two-space
indentation and a trailing newline. The minimal canonical encodings are pinned as:

```json
{"version":1,"spec":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider":{"distro":"ubuntu","release":"26.04"},"platforms":["linux/amd64"],"local-inputs":[],"catalogues":[],"repositories":[],"packages":[],"slices":[],"artifacts":[]}
```

```yaml
version: 1
spec: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
provider:
  distro: ubuntu
  release: "26.04"
platforms:
  - linux/amd64
local-inputs: []
catalogues: []
repositories: []
packages: []
slices: []
artifacts: []
```

## Atomic publication

`PublishLockfile` encodes canonical YAML and writes it through a `.vapor-lock-*`
temporary file in the destination directory, created with mode `0600`. The file is
written, synced and closed before it is renamed over the destination, so the previous
lock stays intact until the rename and any earlier failure removes the temporary
file.

Encoding happens before the destination is touched, so a lock that cannot be encoded
never replaces a good one, and publishing the same lock twice produces identical
bytes. The writer does not verify the lock against a specification, so callers run
`lock.VerifyLockfileForProvider` first.

## Records

### Root record

```yaml
version: 1
spec: sha256:<64 hex>
provider:
  distro: ubuntu
  release: "26.04"
platforms:
  - linux/amd64
local-inputs: []
catalogues: []
repositories: []
packages: []
slices: []
artifacts: []
```

| Key | Requirement |
| --- | --- |
| `version` | Integer `1`; no other value is accepted. |
| `spec` | The specification's `SpecDigest()` value. Change the spec and the lock must be regenerated. |
| `provider.distro`, `provider.release` | The exact specification distribution identifier and release string, as provider identity evidence, not as a fallback. |
| `platforms` | Every specification platform exactly once, in specification order; nonempty. |
| `local-inputs` | File inputs declared by the specification; may be empty. |
| `catalogues` | Every declared catalogue source; may be empty. |
| `repositories` | Repository indexes consulted to resolve the locked packages and slices; may be empty. |
| `packages` | Resolved whole packages per platform; may be empty. |
| `slices` | Resolved sliced packages per platform; may be empty. |
| `artifacts` | Resolved artifact payloads per platform; may be empty. |

The provider's architecture mapping is not stored separately. Repository, package and
slice records each carry the native architecture they resolved to, because that is
where the value is used.

### Local inputs

One record per declared file input: the trust-key files, CA sources and VEX inputs
from the specification. A custom catalogue directory is identified once in its
`catalogues` record by its tree digest rather than duplicated here.

```yaml
local-inputs:
  - role: trust-key
    path: keys/archive.asc
    sha256: "<64 hex>"
    size: 1234
```

| Key | Requirement |
| --- | --- |
| `role` | `trust-key`, `ca` or `vex`, matching the specification declaration family. |
| `path` | Exact specification-relative, clean declaration spelling; no host resolution. |
| `sha256`, `size` | Hash and byte size of the snapshot consumed offline. |

`(role, path)` is unique. The same path may appear under different roles only when
the specification declares it in both families, because the role is part of what was
trusted.

### Catalogue sources

Every declared catalogue appears once, with the selector as declared and the resolved
immutable source identity. A remote source:

```yaml
catalogues:
  - name: ubuntu
    source:
      type: remote
      url: https://github.com/canonical/chisel-releases
      selector:
        branch: ubuntu-26.04
      commit: 5500a569c5cf448afda69b25079230d4049fb530
    tree: sha256:<64 hex>
    manifest:
      - path: chisel.yaml
        kind: file
        sha256: "<64 hex>"
        size: 321
      - path: slices
        kind: dir
    archive:
      sha256: "<64 hex>"
      size: 123456
```

A local source:

```yaml
catalogues:
  - name: custom
    source:
      type: local
      path: catalogues/custom
    tree: sha256:<64 hex>
    manifest:
      - path: chisel.yaml
        kind: file
        sha256: "<64 hex>"
        size: 321
      - path: slices
        kind: dir
```

| Key | Requirement |
| --- | --- |
| `name` | Unique specification catalogue name. |
| `source.type` | `remote` or `local`, matching the declaration; mixed fields are invalid. |
| `source.url`, `source.selector` | Required for remote. The selector contains exactly one of `branch`, `tag` or `commit`, preserving the declared string. |
| `source.commit` | Required for remote: the resolved full lowercase object ID after tag peeling. A declared full commit is its own resolved commit. |
| `source.path` | Required for local: the exact specification-relative declaration spelling. |
| `tree` | Canonical tree digest of the complete catalogue content, including entry kinds, executable bits and link targets. See [identity digest encodings](#identity-digest-encodings). |
| `manifest` | Canonical path-sorted tree entries: `path` and `kind`, plus file `sha256`, `size` and `executable`, or symlink `target`. Reconstructing the tree from the manifest must reproduce `tree`. Audit reads every file blob, so a local catalogue is replayable without its source directory. |
| `archive` | Required for remote: hash and size of the exact acquired archive bytes. Forbidden for local sources. |

Two digests exist here because they answer two questions. The archive digest
identifies the acquisition bytes; the tree digest identifies the content resolution
used. Neither authenticates the publisher, and a remote reference is never
re-resolved during a build.

### Repositories

One record per consumed repository suite on a platform, grouping the components whose
indexes were used. A suite that was only a competing candidate and contributed to no
locked package or slice is not retained, because a record nothing refers to is noise
in a file people read.

```yaml
repositories:
  - id: sha256:<64 hex>
    name: mirror
    platform: linux/amd64
    architecture: amd64
    url: https://archive.example.com/ubuntu
    suite: resolute
    trust:
      keys:
        - fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"
          path: keys/archive.asc
          sha256: "<64 hex>"
          size: 1234
    release:
      format: inrelease
      path: dists/resolute/InRelease
      sha256: "<64 hex>"
      size: 4096
      valid-until: "Thu, 01 May 2026 00:00:00 UTC"
      signers:
        - "0123456789ABCDEF0123456789ABCDEF01234567"
    indexes:
      - component: main
        path: main/binary-amd64/Packages.xz
        sha256: "<64 hex>"
        size: 8192
```

| Key | Requirement |
| --- | --- |
| `id` | Repository ID digest of the specification repository `name`, `platform`, native `architecture`, endpoint `url` and `suite`; components are excluded. Payload, domain and vectors are in [identity digest encodings](#identity-digest-encodings). |
| `name` | Specification repository name. |
| `platform`, `architecture` | Platform and native index architecture. |
| `url` | The declared endpoint for that repository and platform, never a redirected or credentialed URL. |
| `suite` | One declared specification suite for the repository. |
| `identity` | Present only as `own` for a repository that authenticates its own release identity, matching the specification's `identity`. Such a repository publishes packages the distribution never built, so their package URLs carry its name and suite as the vendor and release. |
| `trust.keys` | Every configured trust anchor for the suite, plus each provider-default anchor whose signature was accepted. Fingerprints are unique and `release.signers` is a subset. |
| `trust.keys[].fingerprint` | The full fingerprint that was trusted for this suite. |
| `trust.keys[].path` | Present only for a specification-declared key file, and it must match a `trust-key` local input with the same hash and size. |
| `trust.keys[].sha256`, `size` | Exact public key snapshot bytes used to verify the signed metadata. |
| `release.format` | `inrelease` or `release-gpg`. |
| `release.path`, `sha256`, `size` | Exact signed metadata bytes. `path` is the canonical `dists/<suite>/...` location. |
| `release.valid-until` | Optional exact authenticated `Valid-Until` string, omitted when absent or not supplied. Freshness is decided when the lock is created, against the configured policy; replay does not reapply the current expiry. |
| `release.signers` | Nonempty unique fingerprints from `trust.keys` whose trusted signature was accepted. A release signed by several keys records the first acceptable one in packet order, and replay verifies that fingerprint. |
| `release.signature` | Required only for `release-gpg`, with repository-relative `path`, `sha256` and `size` of the detached signature. Forbidden for `inrelease`. |
| `indexes` | Nonempty list of consumed compressed indexes. Each `component` is a declared specification component and unique within the record. |

Index `sha256` and `size` describe the compressed bytes before decompression. By-hash
acquisition records the canonical index path, because the bytes are identical either
way, and does not retain the temporary by-hash URL.

`(name, platform, suite)` is unique, as is `id`. A package or slice repository
reference resolves to exactly one record on the same platform, and the referenced
package architecture is either `all` or that record's native architecture.

### Per-platform packages

```yaml
packages:
  - platform: linux/amd64
    name: libssl3t64
    version: "3.0.0-1ubuntu1"
    architecture: amd64
    source: openssl
    repository: sha256:<64 hex>
    content:
      path: pool/main/o/openssl/openssl_3.0.0-1ubuntu1_amd64.deb
      sha256: "<64 hex>"
      size: 1048576
```

| Key | Requirement |
| --- | --- |
| `platform` | Requested OCI platform. |
| `name`, `version`, `architecture` | Resolved binary package identity; the version is the exact index version. |
| `source` | Source package the archive was built from, from its `Source` field; absent when the archive name is the source name. |
| `repository` | Consumed repository record ID. |
| `cpe` | CPE 2.3 name the specification declared for the package, which a scanner matches advisories against when the package's own index files none under it. Absent when none was declared; must equal the specification's. |
| `content.path`, `sha256`, `size` | Advertised archive path relative to that repository URL, and the exact archive bytes. |

`(platform, name)` is unique, and package names are disjoint from slice package names
on the same platform. A whole package that the specification requests directly
appears on every specification platform, and its version satisfies any explicit
specification pin.

### Per-platform slices

One record per package contributing any slice to a selected closure on a platform.
Essential dependencies may cross packages: a package reached only through another
package has `selected: []` but still carries its full archive and content record and
its own included slice names. Cross-package edges stay in the locked catalogue
definitions, and each record's closure names plus whole-file digest bind the
definitions it used.

```yaml
slices:
  - platform: linux/amd64
    package: base-files
    version: "13ubuntu10"
    architecture: amd64
    catalogue: ubuntu
    archive: ubuntu
    repository: sha256:<64 hex>
    content:
      path: pool/main/b/base-files/base-files_13ubuntu10_amd64.deb
      sha256: "<64 hex>"
      size: 51200
    selected:
      - release-info
    closure:
      - copyright
      - etc
      - lib
      - release-info
    definition-digest: sha256:<64 hex>
```

| Key | Requirement |
| --- | --- |
| `platform`, `package`, `version`, `architecture` | Resolved package identity. |
| `catalogue` | Declared catalogue name used for the slice definitions. |
| `archive` | Selected upstream catalogue archive name. Store origins are absent; see [stores](#stores). |
| `source` | Source package the archive was built from; absent when it is the package's own name. |
| `repository` | Consumed repository record ID for the package archive. |
| `cpe` | CPE 2.3 name the specification declared for the package. Absent when none was declared; must equal the specification's. |
| `content.path`, `sha256`, `size` | Exact package archive bytes and advertised path. |
| `selected` | Unique upstream slice names directly requested by the specification for this package, in request order; empty for a package reached only transitively. |
| `closure` | Nonempty unique slice names of this package in dependency-first order; contains every `selected` name. |
| `definition-digest` | Selected-definition closure digest of this package's definition file and included slice names. See [identity digest encodings](#identity-digest-encodings). |

`(platform, package)` is unique. Every directly requested slice appears in its
package's `selected`, every record has a nonempty `closure` containing `selected`, and
versions satisfy explicit specification pins. The definition digest is conservative:
it covers unselected slices inside the same file, because that is what "this
definition was used" means.

### Artifacts

One record per resolved artifact payload.

```yaml
artifacts:
  - name: server
    platform: linux/amd64
    url: https://example.com/server-amd64
    sha256: "<64 hex>"
    size: 2048000
    dest: /usr/bin/server
    unpack: false
    uid: 0
    gid: 0
    mode: "0755"
    sbom:
      name: server
      version: "1.0"
```

| Key | Requirement |
| --- | --- |
| `name`, `platform` | Specification artifact name and payload platform; the pair is unique. |
| `url` / `path` | Declared artifact origin, exactly one of the two: a URL the downloader fetched, or a specification-relative path the snapshot read. Neither is a redirect target. |
| `sha256`, `size` | Exact payload bytes; the digest must equal the matching specification source hash. |
| `dest`, `unpack`, `uid`, `gid` | Effective extraction and placement metadata. `dest`, `uid` and `gid` are absent for `unpack: package`. |
| `mode` | Required quoted octal string for `unpack: false`; forbidden for `unpack: true`, where archive modes are preserved, and for `unpack: package`, where the package carries modes. |
| `sbom.name`, `sbom.version` | Declared SBOM identity. |

Records cover exactly the artifact's intended platforms. An artifact deliberately
restricted to one platform needs records only for its declared scope, but a missing
payload inside an intended scope is invalid.

The origin a record names is the one the specification declared, so a lock cannot
swap a local payload for a download or the reverse: both fields are compared with the
declaration and exactly one of them has to be set.

### References, uniqueness and coverage

| Record | Unique key | References |
| --- | --- | --- |
| `local-inputs` | `(role, path)` | specification-declared key, CA or VEX path |
| `catalogues` | `name` | specification catalogue source and selector |
| `repositories` | `id` and `(name, platform, suite)` | specification repository, endpoint, suite, component; local key inputs |
| `packages` | `(platform, name)` | `repositories[].id`; specification whole-package requests |
| `slices` | `(platform, package)` | `catalogues[].name`, `repositories[].id`; specification slice requests |
| `artifacts` | `(name, platform)` | specification artifact and platform source |

Structural verification checks, in the order the code applies them:

- `version`, the recomputed specification digest, provider distribution and release,
  and the platform set.
- Every duplicate and every dangling reference. Every repository record is referenced
  by at least one package or slice, and every reference resolves with a matching
  platform and architecture. This is why collection records only the suites a package
  or slice actually came from: all declared suites are candidates while resolving
  versions, but an unused one would be an unreferenced record.
- Complete digest and size pairs, digest syntax, and valid sizes. Repository IDs must
  match their payloads. Catalogue tree and selected-definition digests are checked
  only for form, because their payload bytes and definition inputs are not stored in
  the lock.
- Local inputs and catalogues match the specification: exactly the declared key, CA
  and VEX files and sources, declared selectors, suites, components, endpoints and
  catalogue archive bindings. An archive the catalogue leaves unbound is valid only
  when it is the provider's own repository.
- A slice's repository is the one its archive was bound to, read from the verified
  catalogue: the same name, and a suite and components the archive declares. The
  package being present in that repository's authenticated index says where it came
  from, not that the catalogue allowed that source, so the binding is compared on its
  own. This also covers the implicit provider archive, which has no declaration to
  match against a repository name.
- Where the specification declares repository trust, every configured fingerprint is
  present, and release signers are members of `trust.keys`. Provider-default signers
  are recorded as evidence but cannot be checked against a specification declaration.
- Direct package and slice request coverage, and version expressions satisfied by the
recorded version on every platform.
  A specification with no slice requests has no slice records.
- Artifact platform coverage and declared hashes.
- Selected and closure consistency, and whole-package and sliced-package name
  disjointness.

All of this is structural. It does not validate signatures, key material, freshness,
resolved closure semantics or cached bytes; those belong to evidence verification and
the provider and resolver steps. The architecture checks here only ensure a reference
resolves to a compatible repository record. See [acquisition](acquisition.md) for the
offline replay that does authenticate.

## Identity digest encodings

Repository IDs, catalogue trees and selected-definition closures are derived
identities rather than plain content hashes. Each is SHA-256 over an ASCII domain
label, one `0x00` byte, and a canonical JSON payload:

```text
identity = "sha256:" + hex(SHA256(label_bytes || 0x00 || canonical_json(payload)))
```

| Identity | Domain label |
| --- | --- |
| Repository ID | `vapor.lock.repository.v1` |
| Catalogue tree | `vapor.lock.catalogue-tree.v1` |
| Selected-definition closure | `vapor.lock.slice-definitions.v1` |

The domain label exists so one identity can never be reused as another: a payload
without its label is not accepted. The label is ASCII with no trailing slash or NUL,
and the encoded bytes are exactly the label bytes, `0x00`, then the payload bytes.

Canonical JSON here means what it means for the specification digest: UTF-8 without a
BOM, object keys sorted recursively by UTF-8 bytes, compact Go `encoding/json`
spelling including HTML escaping of `<`, `>`, `&` and escaping of U+2028 and U+2029,
decimal integers, and no indentation or trailing newline. Arrays keep the order stated
for each identity. A payload has exactly the fields listed; nothing is defaulted, no
provider values or unknown fields are added, and nulls never appear. Strings must be
valid UTF-8, and the path rules reject NUL and ambiguous spelling on top of that.

### Repository ID

The payload has exactly these keys:

| Key | Value |
| --- | --- |
| `architecture` | Native package architecture for the platform, such as `amd64`. |
| `name` | Specification repository name. |
| `platform` | OCI platform string. |
| `suite` | One declared suite. |
| `url` | Declared endpoint URL. |

Components, trust anchors, release metadata and indexes are evidence about a suite,
not identity inputs, so consuming an extra component does not change the ID. Values
use the exact configured or declared spelling with no URL, case or default-port
normalization. The ID is unique and rendered as `sha256:<64 lowercase hex>`.

Canonical payload for the amd64 repository in the multi-platform example:

```json
{"architecture":"amd64","name":"mirror","platform":"linux/amd64","suite":"resolute","url":"https://archive.example.com/ubuntu"}
```

Digest:

```text
sha256:7a61186f27a8e2b419587158089216c97ff0b4c233b46f93d11f5fabba4e1f34
```

Canonical payload for the arm64 repository:

```json
{"architecture":"arm64","name":"mirror","platform":"linux/arm64","suite":"resolute","url":"https://ports.example.com/ubuntu-ports"}
```

Digest:

```text
sha256:1ff4af8ce4a765006fd8944ece387824c9a7471d30ea43bc7ed3270ef9f7eb08
```

### Catalogue tree

The payload is `{"entries": [...]}`. Entries are sorted by `path` UTF-8 bytes, not by
kind or host enumeration order. Each path is a clean, relative, slash-separated UTF-8
path: nonempty, without a leading or trailing slash, without a backslash or NUL, and
without `.` or `..` segments. The root is never an entry. Every directory except the
root has an explicit `dir` entry, including parent directories the archive omitted;
empty directories are retained. A path's parent directories must be `dir` entries, so
a symlink cannot be an ancestor.

| Entry kind | Fields |
| --- | --- |
| `dir` | `kind`, `path` |
| `file` | `kind`, `path`, `executable`, `sha256`, `size` |
| `symlink` | `kind`, `path`, `target` |

For a regular file, `sha256` is the bare lowercase SHA-256 of its exact bytes, `size`
is its nonnegative byte count, and `executable` is true exactly when any execute bit
is set; other permission bits are not part of the tree identity. For a symlink,
`target` is its exact UTF-8 target string without NUL and is not followed or
normalized. Duplicate paths and any other entry kind (hardlink, device, socket, FIFO,
submodule) are invalid; an archive must be materialized into files, directories and
symlinks before computing the tree digest. The digest is independent of archive
compression, entry order, timestamps and ownership.

The empty tree canonicalizes to `{"entries":[]}` and has digest
`sha256:c338023bbf847fbe40c47eb5edef75f54618867cc9925ebe655dee07e78e9d88`.

Base vector:

```json
{"entries":[{"kind":"dir","path":"bin"},{"executable":true,"kind":"file","path":"bin/tool","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":5},{"kind":"symlink","path":"latest","target":"slices/base-files.yaml"},{"kind":"dir","path":"slices"},{"executable":false,"kind":"file","path":"slices/base-files.yaml","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":120}]}
```

Digest:

```text
sha256:7bac2edcea6f86c9ffa94891ff7c7dce121ad2e5d0cf154a23e2fbb8ce6c7439
```

Enumerating the same entries in the source order `slices`,
`slices/base-files.yaml`, `latest`, `bin/tool`, `bin` produces the same canonical
payload and digest. Changing only the symlink target changes the payload to:

```json
{"entries":[{"kind":"dir","path":"bin"},{"executable":true,"kind":"file","path":"bin/tool","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":5},{"kind":"symlink","path":"latest","target":"slices/other.yaml"},{"kind":"dir","path":"slices"},{"executable":false,"kind":"file","path":"slices/base-files.yaml","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":120}]}
```

Digest:

```text
sha256:272bdff880e9e426273b3538b9f286236c277ce218336548694c391c426d408e
```

Changing only `bin/tool` from executable to non-executable changes the payload to:

```json
{"entries":[{"kind":"dir","path":"bin"},{"executable":false,"kind":"file","path":"bin/tool","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":5},{"kind":"symlink","path":"latest","target":"slices/base-files.yaml"},{"kind":"dir","path":"slices"},{"executable":false,"kind":"file","path":"slices/base-files.yaml","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":120}]}
```

Digest:

```text
sha256:b8e72517efe41936563169c284fbc5746e16d97c8ab8685f82a5ce7eb74359e9
```

### Selected-definition closure

Each slice record's `definition-digest` has exactly this payload:

| Key | Value |
| --- | --- |
| `path` | Catalogue-relative path of the package's definition file. |
| `sha256` | Bare lowercase SHA-256 of the exact definition file bytes. |
| `size` | Definition file byte count. |
| `slices` | This package's included slice names in dependency-first order. |

The definition file contains the package, archive and package-level essential
metadata and all its slice definitions, so hashing the whole file binds them.
Cross-package closure is represented by the other package records, each with its own
definition digest. A file for a package outside the closure is omitted, so adding or
changing an unused definition does not change this digest, although it can change the
catalogue tree digest. Because the whole used file is hashed, changing an unselected
slice inside a used file does change the digest: this is deliberately conservative
closure evidence, not a claim that every slice in the file was selected.

Base vector:

```json
{"path":"slices/base-files.yaml","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":120,"slices":["copyright","etc","lib","release-info"]}
```

Digest:

```text
sha256:5418709558c1bbf7d5be441a9bbac1ea5439ed9a0c62454d23ffd2b892e33557
```

Changing the used definition bytes while keeping the same closure changes the payload
to:

```json
{"path":"slices/base-files.yaml","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":120,"slices":["copyright","etc","lib","release-info"]}
```

Digest:

```text
sha256:09e69e1b9a63e060d2e19d6ac2a7355e1da8a208a2350b6854d21a644fbe6010
```

Removing `release-info` from the closure changes the payload to:

```json
{"path":"slices/base-files.yaml","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":120,"slices":["copyright","etc","lib"]}
```

Digest:

```text
sha256:1f84c517245957d5d4bc515ecb63c99cb75ca70d258dd71da33d844e71c6d7c8
```

### Catalogue archive

`catalogues[].archive.sha256` is a plain content hash, not a derived identity: SHA-256
over the exact acquired archive bytes, with no domain label, canonical JSON or
decompression. `archive.size` is the same byte count. Vector for the bytes
`catalogue-archive\n`:

```text
sha256:8e552c6f4894868cd6614a3ddb5e481f2d2c3865656ffef6bbe280979920dd5a
```

The archive digest identifies acquisition bytes while the tree digest identifies the
normalized content. Neither authenticates the publisher.

The vectors above are normative for these encodings, and an implementation must
reproduce them before consuming locks. Other hashes in this page are synthetic shapes,
not vectors.

## Offline evidence ownership

Evidence is not duplicated into a separate blob list. Each record owns the hashes of
the bytes it consumes: keys in repository trust records and specification key paths in
local inputs, signed metadata and signatures in `release`, compressed indexes in
`indexes`, package archives in `content`, catalogue archives and trees in
`catalogues`, and artifact payloads in `artifacts`.

The cache stores those bytes under their SHA-256; the lock stores identity and size
only. Consumers reverify the bytes they read and never treat a path as proof. The
reason for this shape is that a separate blob manifest would be a second place to
forget to add an entry, while "the record that uses the bytes names the bytes" cannot
drift.

## Stores

Version 1 has no store origin, store revision or store-success evidence fields, and no
placeholder for them. A selection that requires a store-backed package fails locking,
and package and slice content is always a repository archive in this contract.

This is a refusal by name rather than a partial implementation. Upstream parses store
metadata and cannot fetch store packages either, so a Vapor lock with invented store
evidence would be a compatibility claim nobody could verify. Store support needs a
reviewed protocol and a contract revision with known fields first.

## Examples

Both examples are synthetic; only their shapes are contractual.

### Minimal example

One package from one repository, one platform, provider-default trust and no
specification key path.

```yaml
version: 1
spec: sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
provider:
  distro: ubuntu
  release: "26.04"
platforms:
  - linux/amd64
local-inputs: []
catalogues: []
repositories:
  - id: sha256:1111111111111111111111111111111111111111111111111111111111111111
    name: archive
    platform: linux/amd64
    architecture: amd64
    url: https://archive.ubuntu.com/ubuntu
    suite: resolute
    trust:
      keys:
        - fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"
          sha256: "2222222222222222222222222222222222222222222222222222222222222222"
          size: 1234
    release:
      format: inrelease
      path: dists/resolute/InRelease
      sha256: "3333333333333333333333333333333333333333333333333333333333333333"
      size: 4096
      valid-until: "Thu, 01 May 2026 00:00:00 UTC"
      signers:
        - "0123456789ABCDEF0123456789ABCDEF01234567"
    indexes:
      - component: main
        path: main/binary-amd64/Packages.xz
        sha256: "4444444444444444444444444444444444444444444444444444444444444444"
        size: 8192
packages:
  - platform: linux/amd64
    name: openssl
    version: "3.0.0-1ubuntu1"
    architecture: amd64
    source:
      name: openssl
      version: "3.0.0-1ubuntu1"
    repository: sha256:1111111111111111111111111111111111111111111111111111111111111111
    content:
      path: pool/main/o/openssl/openssl_3.0.0-1ubuntu1_amd64.deb
      sha256: "5555555555555555555555555555555555555555555555555555555555555555"
      size: 1048576
slices: []
artifacts: []
```

### Multi-platform example

A remote catalogue, an explicit trust-key snapshot, two platform endpoints, one sliced
package per platform and one artifact with two payloads.

```yaml
version: 1
spec: sha256:6f5e4d3c2b1a09182736455463728190a9b8c7d6e5f40312233445566778899a
provider:
  distro: ubuntu
  release: "26.04"
platforms:
  - linux/amd64
  - linux/arm64
local-inputs:
  - role: trust-key
    path: keys/archive.asc
    sha256: "2222222222222222222222222222222222222222222222222222222222222222"
    size: 1234
catalogues:
  - name: ubuntu
    source:
      type: remote
      url: https://github.com/canonical/chisel-releases
      selector:
        branch: ubuntu-26.04
      commit: 5500a569c5cf448afda69b25079230d4049fb530
    tree: sha256:6666666666666666666666666666666666666666666666666666666666666666
    archive:
      sha256: "7777777777777777777777777777777777777777777777777777777777777777"
      size: 45678
repositories:
  - id: sha256:8888888888888888888888888888888888888888888888888888888888888888
    name: mirror
    platform: linux/amd64
    architecture: amd64
    url: https://archive.example.com/ubuntu
    suite: resolute
    trust:
      keys:
        - fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"
          path: keys/archive.asc
          sha256: "2222222222222222222222222222222222222222222222222222222222222222"
          size: 1234
    release:
      format: inrelease
      path: dists/resolute/InRelease
      sha256: "3333333333333333333333333333333333333333333333333333333333333333"
      size: 4096
      valid-until: "Thu, 01 May 2026 00:00:00 UTC"
      signers:
        - "0123456789ABCDEF0123456789ABCDEF01234567"
    indexes:
      - component: main
        path: main/binary-amd64/Packages.xz
        sha256: "4444444444444444444444444444444444444444444444444444444444444444"
        size: 8192
  - id: sha256:9999999999999999999999999999999999999999999999999999999999999999
    name: mirror
    platform: linux/arm64
    architecture: arm64
    url: https://ports.example.com/ubuntu-ports
    suite: resolute
    trust:
      keys:
        - fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"
          path: keys/archive.asc
          sha256: "2222222222222222222222222222222222222222222222222222222222222222"
          size: 1234
    release:
      format: inrelease
      path: dists/resolute/InRelease
      sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      size: 4096
      valid-until: "Thu, 01 May 2026 00:00:00 UTC"
      signers:
        - "0123456789ABCDEF0123456789ABCDEF01234567"
    indexes:
      - component: main
        path: main/binary-arm64/Packages.xz
        sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        size: 8192
packages: []
slices:
  - platform: linux/amd64
    package: base-files
    version: "13ubuntu10"
    architecture: amd64
    catalogue: ubuntu
    archive: ubuntu
    repository: sha256:8888888888888888888888888888888888888888888888888888888888888888
    content:
      path: pool/main/b/base-files/base-files_13ubuntu10_amd64.deb
      sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      size: 51200
    selected:
      - release-info
    closure:
      - copyright
      - etc
      - lib
      - release-info
    definition-digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  - platform: linux/arm64
    package: base-files
    version: "13ubuntu10"
    architecture: arm64
    catalogue: ubuntu
    archive: ubuntu
    repository: sha256:9999999999999999999999999999999999999999999999999999999999999999
    content:
      path: pool/main/b/base-files/base-files_13ubuntu10_arm64.deb
      sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      size: 51200
    selected:
      - release-info
    closure:
      - copyright
      - etc
      - lib
      - release-info
    definition-digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
artifacts:
  - name: server
    platform: linux/amd64
    url: https://example.com/server-amd64
    sha256: "1212121212121212121212121212121212121212121212121212121212121212"
    size: 2048000
    dest: /usr/bin/server
    unpack: false
    uid: 0
    gid: 0
    mode: "0755"
    sbom:
      name: server
      version: "1.0"
  - name: server
    platform: linux/arm64
    url: https://example.com/server-arm64
    sha256: "3434343434343434343434343434343434343434343434343434343434343434"
    size: 2048000
    dest: /usr/bin/server
    unpack: false
    uid: 0
    gid: 0
    mode: "0755"
    sbom:
      name: server
      version: "1.0"
```

## Working on this contract

- Adding a key is a format change. It needs a strict decode rule, a structural check,
  an audit or replay path, and vectors where the value is derived.
- Never reuse a domain label. A new derived identity gets a new `vapor.lock.*.v1`
  label, so a payload from one domain can never satisfy another.
- Keep evidence and conclusions apart. A record stores bytes and hashes; it does not
  store "this was fine".
- Run the lock schema tests after any edit to this page. The tree vectors are read
  from this file, so the documentation and the code cannot drift apart silently.
