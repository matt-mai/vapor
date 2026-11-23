# Vapor Image Specification and Lockfile Contract

## Scope

This document fixes the specification and lockfile contracts: field groups,
validation and default rules, the canonical spec digest, and the version-1 lock
layout, reference/uniqueness rules and examples. For what the implementation
currently does, read the [status reference](user/reference/status.md); the exact
implemented types and defaults are in the [core loader
reference](user/reference/spec.md), [contents reference](user/reference/contents.md),
[filesystem reference](user/reference/filesystem.md) and [policy
reference](user/reference/policies.md). `(*Spec).SpecDigest()` provides the frozen
[canonical identity contract/vectors](developer/schema.md#the-specification-digest).
Typed lock records, strict lock reads, canonical JSON/YAML encoders, atomic lock
publication and structural `VerifyLockfileForProvider` checks live in
`internal/schema/lock`; evidence authentication does not. The lock schema
reference is [here](developer/lock-schema.md).

The initial target is **Ubuntu 26.04 (Resolute)**, with Canonical's upstream Chisel
**format v3**. Debian follows with custom catalogues in the same format, not an
assumed upstream Debian catalogue. One independent `version: 1` spec defines one
image. No variants, variable interpolation, implicit builder inheritance, legacy
readers, or migrations are supported.

## Image specification

### Minimal target starter

This is the intended Ubuntu starter shape. It does not contain invented keys,
artifact hashes, or Markdown links masquerading as URL values.

```yaml
version: 1
name: ubuntu-minimal
image: ghcr.io/example/ubuntu-minimal
distro: ubuntu
release: "26.04"
platforms:
  - linux/amd64
contents:
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
  slices:
    - package: base-files
      slice: release-info
container:
  user: "65532:65532"
```

The starter verifies the selected slice against its pinned reference
fixture before emitting it. Release identity is the quoted Ubuntu version string
`"26.04"`; the selected catalogue or explicit repository configuration supplies
`resolute` suites, while the provider handles architecture-specific archive
locations. Unsupported distro providers error; any other numeric release of an
implemented distro warns as untested and attempts locking, without requiring a
new hardcoded codename entry. Repository authentication/identity and catalogue
compatibility remain mandatory. Provider selection and release warnings are
implemented in `internal/distro`. Do not substitute the moving alias `latest` or
`stable`.
A numeric YAML release value is not the specified string form.

### Field groups

| Group                                           | Target behavior                                                                                                                                                                                               |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`, `name`, `image`, `distro`, `release` | Required identity; version is 1. Ubuntu is first supported provider.                                                                                                                                          |
| `tags`, `annotations`                           | Image tags and OCI annotations, not catalogue source selectors.                                                                                                                                               |
| `platforms`                                     | Defaults to `[linux/amd64]`; initial supported values are `linux/amd64` and `linux/arm64`, without duplicates.                                                                                                |
| `contents.repositories`                         | Explicit package sources, suites/components, architecture scope, trusted key material/full fingerprints, by-hash and freshness policy. Ubuntu defaults must establish reviewed trust, not trust-on-first-use. |
| `contents.catalogues`                           | Named upstream-v3 catalogue sources; remote selectors or local snapshots as described below.                                                                                                                  |
| `contents.packages`                             | Whole-package requests (`name`, optional `version` expression); dependency closure follows the package policy below.                                                                                        |
| `contents.slices`                               | Package/slice selections (`package`, `slice`, optional package `version` expression), resolving the Chisel essential closure.                                                                                |
| `contents.artifacts`                            | Named logical artifacts with grouped platform-scoped URL/SHA256 payloads, explicit `unpack`, absolute `dest`, ownership/mode and SBOM identity.                                                               |
| `contents.slices-engine`                        | Positive per-mutation-script `max-steps`, default 100000; required v3 mutation/copyright/collision semantics are not optional.                                                                                |
| `container`                                     | User, entrypoint, command, workdir, ports, stop signal, and environment. Command argument order is significant.                                                                                               |
| `filesystem`                                    | Paths, accounts, timezone, CA inputs and OS-release overrides; no maintainer-script execution.                                                                                                                |
| `hardening`                                     | Four strict boolean flags, all default true: strip-docs, strip-shells, strip-apt-dpkg, remove-suid-sgid; license/metadata safeguards and explicit-path deletion conflict errors.                              |
| `sbom`, `vex`                                   | SBOM controls and explicit VEX assertions; no live CVE lookup.                                                                                                                                                |

Exact core types, allowed values and defaults are now defined in the
[core reference](user/reference/spec.md): `image` is a fully qualified repository **without
an embedded tag/digest**, `distro` is a syntactic identifier, `release` is a numeric
version string, and container fields remain unset unless specified. Provider
availability is checked later, not inferred from successful schema decoding.
Optional `tags` are unique case-sensitive ASCII tokens, 1–128 characters, without
an implicit `latest`. Optional `annotations` are a string map with nonblank keys;
there is no fixed namespace allowlist. Metadata is preserved without defaults or
normalization; OCI placement and generated-annotation collision rules are deferred
to the output step. See the core reference for the exact grammar and YAML rules.
Exact contents types/defaults and examples are in the [contents reference](user/reference/contents.md),
including grouped repository endpoints, complete artifact coverage, archive bindings,
explicit trust replacement and lock-time freshness policy (`if-present` default).

Filesystem fields and defaults are specified in the filesystem reference: explicit
entry types, non-truncating regular files, root-confined lexical symlink targets,
explicit account IDs, mandatory append/replace CA mode, and preservation/fill-missing
OS-state policy. No referenced certificate or zoneinfo bytes are read by the loader.

Policy types/defaults are in the policy reference. Maintainer scripts are never
executed. All four hardening flags
default true. An enabled deletion pass conflicting with an explicit filesystem
entry must fail with guidance, as the
[hardening contract](developer/hardening.md) specifies. The nested
slice engine exposes only positive max-steps, not switches disabling v3 behavior;
step counting is not the mutation memory-safety boundary.

[Attestation status](user/reference/status.md) records SBOM enabled by
default, VEX local inputs and four-status package/artifact assertions. VEX absence
checking defaults on: not-affected claims require explicit paths, never guessed
paths or automatic proof. The
specification declares nothing that runs: a build never starts a container.

Each field's exact type, default, allowed values and mutual exclusions belong in
these tables. Unknown future fields remain errors; the loader must not silently
accept data it cannot validate.
Catalogue archive/store selection belongs to the upstream model; explicit
repository overrides/custom archive bindings must not silently change its meaning.

### Catalogue selection

A remote source has `name`, `url`, and exactly one of:

```yaml
# Moving upstream release branch
branch: ubuntu-26.04
```

```yaml
# A publisher's actual tag, when one exists (not a fabricated default)
tag: release-tag
```

```yaml
# Full commit, not an abbreviated hash
commit: 5500a569c5cf448afda69b25079230d4049fb530
```

These are selector fragments, not complete catalogue records. A source with
`path` instead of `url` is a local custom catalogue; it has no remote selector.
Reject mixed local/remote source fields. Locking snapshots local bytes; building
must not reread a mutable source directory as if it were verified content.

For remote sources the lock records the declared selector, resolved full commit,
archive digest, and canonical tree digest. Peel annotated tags. A direct commit
is not reinterpreted as a branch name. Build never contacts Git hosting or
re-resolves a selector. Lock refresh/check may discover changed branches/tags;
report ref movement independently of changes in the selected slice closure.

`format: v3` lives in the catalogue's root **`chisel.yaml`**, not in each slice
file. Reject v1/v2/v4 roots. Package and slice `essential` values use v3 maps with
optional architecture filters. Parse maintenance dates, hints, archives/keys,
stores and bin slices as upstream defines them. See the
[compatibility boundary](architecture-and-expansion.md#chisel-v3-compatibility-boundary)
for the full target and the pinned research references. The
[source inventory](developer/chisel-v3-compatibility.md#storebin-boundary-do-not-invent-an-upstream-protocol)
records a concrete limitation: this pin parses/selects store metadata but cannot
acquire store packages. Store-success lock evidence remains blocked on an explicitly
reviewed upstream baseline or extension contract, not an invented download protocol.

The Ubuntu starter written by `vaporize init` declares the Canonical source above;
the schema does not inject a distro-specific source. Debian has no upstream
catalogue default: sliced Debian specs must supply custom sources and explicit Debian
archive bindings in that same format. Whole-package-only specs need no catalogue.

### Validation and default rules

- Decode exactly one YAML document using recursive known-field checks. Reject
  unknown fields, duplicate mapping keys, additional documents, and `${...}`
  placeholders anywhere in string values.
- Require nonempty identity fields, supported version/platforms, valid image
  references, unique named sources/inputs, and explicit non-moving release identity.
- Validate repository architecture scopes against requested platforms. `all` is
  a package architecture, not an OCI platform.
- Require valid artifact digests and safe absolute destinations. `unpack: false`
  means place a standalone file; `true` means safe archive extraction. Explicit
  false must not be lost through zero-value defaulting.
- Artifacts must cover their intended target platforms explicitly. Do not silently
  build an arm64 image without an otherwise required amd64-only runtime artifact.
- Whole and sliced requests for the same package are rejected. VFS collisions,
  archive path traversal, and link escapes must never become implicit overwrites.
- EOL and unstable maintenance states warn rather than reject. This is independent
  of repository signature, digest and lock-time freshness validation.

For implemented fields, defaults are fixed by the core, contents, filesystem and
policy references, not YAML decoding. Further security-sensitive defaults must be
documented before they are implemented; do not silently choose behavior from Go
zero values or from an illustrative example.

### Dependency policy

Whole packages resolve `Pre-Depends` and `Depends`, not `Recommends`/`Suggests`,
using Debian version comparison, constraints, ordered alternatives, versioned
virtual providers, `Conflicts` and `Breaks`. Candidate ranking is source priority,
newest version, then stable source identity. Backtrack when the first alternative
cannot satisfy the graph. Support target-native and `all` packages. A relation
qualified for another architecture is never satisfied, since the image holds no
candidates for it, but it only removes that one alternative: a dependency whose
every alternative is foreign fails explicitly instead of being guessed. Do not add
an implicit base system.

Slices resolve only the upstream package/slice essential graph and its architecture
conditions. Do not expand the sliced package's DEB dependencies. Package version
expressions are a Vapor locking extension, not a claim that the upstream Chisel CLI pins
versions. ELF runtime verification later fails on missing loaders/libraries rather
than silently installing whole packages. Never execute maintainer scripts.

### Spec digest

`(*Spec).SpecDigest()` returns `sha256:<lowercase hex>` over compact JSON with
recursively sorted object keys. It checks strings, copies the typed spec, applies
defaults and validates before projection, without caller mutation or input I/O.
The [exact contract and pinned byte/hash vectors](developer/schema.md#the-specification-digest) are
implemented before any lockfile consumer.

**Every list is ordered**, even when its consumer treats membership as a set.
Optional nil/empty maps and slices become `{}`/`[]` after validation/defaulting;
invalid empties remain errors. Absent non-defaulted pointers become null; explicit
false and empty output versus unchecked output remain distinct. Strings retain
spelling and Unicode without semantic normalization. All current schema JSON
fields are included; object/YAML key order alone never changes identity.

Catalogue/key/CA/VEX host input declarations must be clean relative slash-separated
paths; hash their exact spellings, not resolved host paths or input bytes. In-image
absolute paths and literal argv/env/annotation strings remain included. Do not add
current time or warnings. Future locking resolves inputs against the spec directory
and records/verifies their independent bytes/tree/signer evidence, even when this
declaration digest is unchanged.

## Lockfile and cache

### Lock content

`vaporize lock -f image.yaml` targets the sibling `image.lock.yaml` unless an
explicit output path is provided. The lock is version 1 and covers all requested
platforms. It is not a substitute for an independent trust policy or a publisher
signature. Exact serialized keys, reference rules, ordering and minimal/
multi-platform examples are in the [lock schema reference](developer/lock-schema.md).
Records carry inline SHA256/size evidence; large bytes belong in the cache rather
than duplicated in the lock. Digest encodings for repository/tree/closure
identities are in the [lock schema reference](developer/lock-schema.md#identity-digest-encodings).

Required records:

| Record               | Required evidence/identity                                                                                                                            |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spec/provider        | Spec digest, distribution identity and explicit release.                                                                                              |
| Local inputs         | Role, logical spec-relative identity, SHA256 and size for key/CA/VEX files; custom catalogue trees are identified in the catalogue record.            |
| Repository           | Stable source ID, URL/suite/component/architecture, authenticated Release evidence, trusted full key identity, compressed index filename/SHA256/size. |
| Catalogue            | Name, local/remote source identity, declared tag/branch/commit where applicable, resolved commit, archive digest and canonical tree digest.           |
| Per-platform package | Name/version/native architecture, source package name, repository ID, archive path and SHA256/size.                                                    |
| Per-platform slice   | Package identity and its source package name, selected/transitive slices, definition digest, archive origin and content identity; store evidence is reserved. |
| Artifact input       | Resolved source identity, platform scope, content SHA256/size, extraction metadata and SBOM identity.                                                 |
| Offline evidence     | Digests/identities of signed Release/key/index/catalogue snapshots needed to re-verify the consumed bytes; store evidence is reserved.                |

No credentials, signing private keys, host absolute paths or generated wall-clock
timestamps belong in the lock. Persist signature evidence and content identities;
cache their bytes under digest keys rather than duplicating large binary payloads
inside YAML. Credential redaction is defined by the acquisition code; authenticated
store evidence remains undefined because store acquisition is unsupported.

### Lock verification and atomic persistence

`VerifyLockfileForProvider(spec, lock, release, provider)` checks schema version, spec digest, provider/platform
identity, complete references, duplicates, consistent selected closures, and
complete digest/size records, as detailed in the
[lock schema reference](developer/lock-schema.md#references-uniqueness-and-coverage).
Evidence verification additionally checks the cryptographic chain and the consumed
cache bytes. A syntax-valid lock alone is not proof that its blobs were
authenticated.

Canonical lock encoders normalize only defined set-like records and emit record
fields in the order specified by the schema reference; semantic sequences keep
their order. Identity-digest payloads, unlike lock records, recursively sort object
keys. Repository IDs and tree/definition-closure digests use the exact
domain-separated encodings and test vectors in the
[lock schema reference](developer/lock-schema.md#identity-digest-encodings).
Tree digests include path, entry kind, executable metadata, link target, and
content, not the host filesystem's enumeration order or timestamps.

Writes use a 0600 temporary file in the target directory, sync/close, then atomic
rename. Clean up failures and do not truncate an existing lock before the new
content is ready. Cache writes use the same atomic-publication principle under
`<cache-dir>/sha256/<first two hex digits>/<hash>`; see the
[cache design](developer/acquisition.md#the-cache). Concurrent readers must never see partial
blobs. Check SHA256 **and byte size** before accepting or consuming cached content.

### Offline build contract

Successful locking populates every input required for assembly, including package
archives, catalogue snapshots, artifacts, store content, and local auxiliary files.
`build` reads spec/lock and cached immutable snapshots; no input downloads, Git
lookups or mutable-source rereads. Missing/corrupt inputs fail with instructions
to reacquire them through locking. Explicit `--push` permits only the output sink.

At lock/refresh time, validate current configured repository freshness and trust.
At build time, re-verify the retained evidence without treating today's expiry
as a reason to reject a previously valid locked snapshot. Report stale/EOL status
as warnings without including it in image bytes, provenance payloads or digests.
Offline reproducibility is not a promise that old package versions remain secure.

`lock --check` and `lock --diff` are non-writing comparisons. Both acquire and
verify current inputs. `--check` exits 0 with no drift, 1 with drift, and 1 for an
operational failure such as a missing or invalid lock. `--diff` exits 0 after
printing drift (or `no drift`) and 1 for an operational failure. Conflicting
`--check --diff` is a usage error and exits 2. Acquisition may populate the cache;
neither mode writes the lock. Moved refs are compared only during these
acquisition operations, never by build. A changed source commit and changed used
slice content are different facts and are reported separately.
