---
title: Attestations
---

# Attestations

An attestation is metadata about an image rather than the image: what it contains, who
built it, and which known vulnerabilities do not apply to it. Vapor generates three
kinds, SPDX for the contents, SLSA provenance for the build, and OpenVEX for
vulnerability statements. None of them looks up a vulnerability database, and none of
them is trusted without the image it describes.

This page fixes the parts everything else depends on: what an attestation is attached
to, how a payload's bytes and identity are computed, and what may not reach a payload.
The formats themselves are described in [SPDX documents](attest-spdx.md),
[Provenance statements](attest-provenance.md) and [VEX claims](attest-vex.md).
Wrapping a payload in a signature is described in [Signing statements](attest-signing.md).

## On this page

- [Attachment topology](#attachment-topology)
- [Payload bytes and identity](#payload-bytes-and-identity)
- [Element identities](#element-identities)
- [Platform to subject](#platform-to-subject)
- [How a build attaches them](#how-a-build-attaches-them)
- [What a payload may not contain](#what-a-payload-may-not-contain)
- [Deterministic content and signatures](#deterministic-content-and-signatures)
- [Signing](#signing)
- [Working on this package](#working-on-this-package)

## Attachment topology

An attestation is a separate OCI manifest whose `subject` is the image manifest it
describes. It is not a layer of that image, and it never mentions the index. A build
writes one attachment per format and platform, so a two-platform image with SPDX,
provenance and a VEX claim carries six of them.

```text
image index (linux/amd64, linux/arm64)
  ├─ manifest linux/amd64  ← subject of the amd64 attestations
  ├─ manifest linux/arm64  ← subject of the arm64 attestations
  ├─ attestation manifest (amd64 SPDX, provenance, VEX)
  └─ attestation manifest (arm64 SPDX, provenance, VEX)
```

Two rules follow, and both exist to keep the reference graph computable:

- **The subject is a platform manifest.** `oci.Subject.Validate` refuses an index or a
  config, because an attachment that named the index would change the index digest
  when it was added, which would change what it claims to describe.
- **An attestation never describes itself.** No subject is derived from the index and
  no payload records its own digest, so there is no recursion and no fixed point to
  search for.

The subject value is exactly the platform manifest's media type, digest and size, so a
reader that fetches a subject can verify the bytes it got.

## Payload bytes and identity

Two different questions, two different values.

**Blob identity** is `sha256:` plus lowercase hex over the exact stored bytes. It is
what an OCI descriptor points at, so it has no domain label: a reader that fetches the
blob recomputes it and expects the same value. `attest.Digest` computes it.

**Canonical bytes** are the bytes that identity covers. `attest.Encode` produces them:

- JSON, compact, no indentation, no trailing newline;
- object keys sorted recursively by UTF-8 bytes, which is `encoding/json` for a
  struct;
- arrays keep their order, because a slice closure or a list of packages is ordered
  data, not a set;
- no nulls: a field that would be empty is omitted, and an empty list is `[]`;
- UTF-8 without a BOM.

Encoding never consults the clock, the environment or the host. `encoding/json` escapes
control characters, so a license text with a newline or a tab is still valid JSON and
needs no separate text check.

## Element identities

An element is one package, sliced package or artifact inside a payload. Folding
elements into one document needs a name for each that survives a change of mirror,
catalogue order or declaration order, so element identity is a domain-separated hash
in the same shape the lock already uses:

```text
element = "sha256:" + hex(SHA256(domain_label || 0x00 || canonical_json(payload)))
```

| Element | Domain label | Payload keys |
| --- | --- | --- |
| Whole package | `vapor.attest.package.v1` | `platform`, `name`, `version`, `architecture`, `sha256`, `size` |
| Sliced package | `vapor.attest.slices.v1` | `platform`, `package`, `version`, `architecture`, `definition`, `sha256`, `size`, `slices` |
| Artifact | `vapor.attest.artifact.v1` | `platform`, `name`, `identity`, `sha256`, `size` |
| Vendored module | `vapor.attest.module.v1` | `kind`, `namespace`, `name`, `version` |

The vendored module payload names no platform, image or path: a module is the same package
wherever it was installed, so one image's `glob 10.5.0` and another's are one element and an
advisory matches both.

`sha256` is the bare lowercase content hash of the locked payload bytes and `size` is
its byte count, matching the lock's own spelling. A sliced package is one element for
the whole package rather than one per slice, because an advisory is filed under the
package: one element per slice would report the same finding several times.
`definition` is the locked `definition-digest`, so two builds that slice the same
archive through different definition files are different elements. `slices` is the
dependency-first closure in lock order, never re-sorted, so the element changes when
the package is cut differently. `identity` is the artifact's declared `sbom` name and
version, because an artifact payload has no package metadata of its own.

Three consequences are intended:

- A mirror or endpoint change does not create a new element. The repository identity
  is not part of the payload; provenance records where bytes came from.
- A version change is a different element even when the bytes are identical, because
  the document reports a version.
- A platform change is a different element, so an element never spans platforms. That
  is why attribution is per platform: an amd64 attestation names only amd64 elements.

The encoding with a label is the lock's domain-separated one, so `canonical_json` here
means the same bytes: compact Go `encoding/json` on the payload struct, with `<`, `>`
and `&` escaped as `\u003c`, `\u003e` and `\u0026`. Do not reuse a label: a new element
kind gets a new `vapor.attest.*.v1` label. `internal/attest/attest_vectors_test.go`
reads the vectors below from this page, so the page and the code cannot drift.

Whole package, base vector:

```json
{"architecture":"amd64","name":"base-files","platform":"linux/amd64","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1234,"version":"26.04"}
```

Digest:

```text
sha256:284d61d74275cb3cc656d2c3987dcec24eec65ff6ac722b9604ce3a58716f8a7
```

Changing only the platform to `linux/arm64` and the architecture to `arm64` gives
`sha256:b1dad4dbc1b9c3f7fc24943ff1197f9f8cc06fc3a97f3b86c99dcf2170739f77`; changing only
the version to `26.04.1` gives
`sha256:7141bcf01b8da6deab32a210e5fffea4e8954431dcd169fd79a6e6163e55ebc0`.

The same payload hashed under `vapor.attest.slices.v1` gives
`sha256:0891bfa6ca0ae285db1125a5997d22a1b1bfd844acc155fa7203683ebc734420`, which no
domain accepts as a whole package.

Sliced package, base vector:

```json
{"architecture":"all","definition":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","package":"libc6","platform":"linux/arm64","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":5678,"slices":["core","libs"],"version":"2.41-1"}
```

Digest:

```text
sha256:d37e2c3301a74c8d5d3703bc7a0754581a31529536f2751afbdc18f982c2bf0e
```

Adding `tools` to the closure gives
`sha256:8ba752404e2f2aa255dd4af555f405cc9780875ff81c4d6d6adf76ccb99d8576`; reordering
the same closure to `["libs","core"]` gives
`sha256:b6c32d44fe59c1aa690628086a72e8a1ce6a41430e03f443220f29a5a90501c7`, which is a
different element on purpose: the closure is ordered. Slicing the same archive through a
different definition gives
`sha256:c27a073f8e85216c81fffdbb5f29dc29cc9b2a4dcc408b08ea1e07cf72a26a30`, so which
slices an image was cut from is part of what the element is.

Artifact, base vector:

```json
{"identity":{"name":"server","version":"1.0"},"name":"server-cert","platform":"linux/amd64","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":9012}
```

Digest:

```text
sha256:e3f4df4510b3846da2eb99165a713268a143d4740c5a153f42721122e7c96190
```

Changing only the declared identity version to `1.1` gives
`sha256:431d487d703bea7e64c89d08abd055a9afe943f3ab3167b636285fa882f578a9`. The payload
has no `url` key, so two builds that fetched the same bytes from different endpoints
produce the same artifact element.

## Platform to subject

`oci.Image.SubjectOf` turns each finished platform image into the subject its
attestations attach to. Generation keeps one record per platform:

| Platform | Manifest digest | Manifest size | Payloads |
| --- | --- | --- | --- |
| `linux/amd64` | `sha256:…` | bytes | SPDX, provenance, VEX |
| `linux/arm64` | `sha256:…` | bytes | SPDX, provenance, VEX |

A payload never lists a platform that the image index does not contain, and an
attestation for one platform never mentions another platform's digest. The index
digest is deliberately absent from every payload, so attaching attestations to a build
cannot change what they say about it.

## How a build attaches them

`vaporize build` renders the statements after every platform image exists and before
anything is exported, so a statement never describes an image that failed to build.

Each statement is an OCI manifest with an empty config (`application/vnd.oci.empty.v1+json`,
the two bytes `{}`), one layer holding the payload, `artifactType` set to the payload's
media type and `subject` set to the platform manifest:

| Format | `artifactType` and layer media type | `predicateType` inside |
| --- | --- | --- |
| SPDX | `application/vnd.in-toto+json`, or the DSSE media type when signed | `https://spdx.dev/Document` |
| Provenance | `application/vnd.in-toto+json`, or the DSSE media type when signed | `https://slsa.dev/provenance/v1` |
| VEX | `application/vnd.in-toto+json`, or the DSSE media type when signed | `https://openvex.dev/ns/v0.2.0` |

The media type describes the bytes in the layer, not the format they carry. An unsigned
statement is in-toto; a signed one is a DSSE envelope
(`application/vnd.dsse.envelope.v1+json`) that wraps the same statement, and both
descriptors say so, so a reader that selects by media type finds and parses it. With
`--sign-key` every statement is signed, so every attachment is labelled as an envelope;
see [Signing statements](attest-signing.md).

The statements go three places. The two attachment destinations carry the same bytes;
the directory carries the document they wrap, because a file is read by a scanner:

- **`--attestations-dir`** writes `<image>-<platform>-<format>.json` per document — the
  SPDX document, the SLSA predicate or the OpenVEX document, without the in-toto
  wrapper — with `0o600` files in a `0o750` directory. `--sign-key` does not change
  these files: a signature covers the attachment, and wrapping a document a scanner
  reads would defeat the purpose of the plain output. A file is written beside its
  destination and renamed into place, so a rerun replaces the previous document instead
  of truncating it, and a symlink at the destination is replaced rather than followed.
- **`--oci-dir`** writes each statement as a blob and lists its manifest as an extra
  descriptor in `index.json`. The build index blob is unchanged. The loadable archive
  from `--tarball` does not include statements.
- **`--push`** uploads the image and statements by digest before writing any image
  tags. **`--push --image-only`** skips registry attestations without changing local output.

A registry that implements the Referrers API indexes the statements under their
subject. A build does not use previously attached statements as input.

If the registry lacks the Referrers API, an attested push returns
`ErrReferrersUnsupported` before writing any image tags. Vapor disables the
fallback that rewrites a shared `sha256-<digest>` tag. Concurrent pushes could
otherwise overwrite each other's entries.

## What a payload may not contain

These are refusals, not preferences. The payloads that follow in this milestone must
satisfy them, and each one is checked where it can first go wrong.

- **Host paths.** A payload names catalogue-relative and image-absolute paths only. A
  `/home/...` or `/tmp/...` prefix would leak the build machine.
- **The current time or a build duration.** A timestamp exists only where a format
  requires one, and then it is the Unix epoch (`1970-01-01T00:00:00Z`). Nothing in a
  payload measures how long a build took.
- **Credentials and signing material.** No token, password, header, private key or
  key path reaches a payload, and no error message from an authentication step is
  copied into one.
- **Warnings, progress and exit status.** A release-status warning is a diagnostic for
  the person running the build, not a claim about the image.
- **Mirror hosts and endpoint lists** as element identity. They are provenance input
  at most, never an element name, so moving a mirror does not change the SBOM.
- **A misleading base subject.** The subject is the manifest Vapor built. There is no
  field for an upstream base image digest, because Vapor composes images from packages
  rather than inheriting one.

## Deterministic content and signatures

Unsigned payloads are deterministic, and that promise is separate from any signature
over them. The same inputs produce the same payload bytes and the same subject.

## Signing

Signing is optional and adds a wrapper; it never rewrites the payload. The payload
bytes inside the envelope are exactly the bytes an unsigned run writes, and the
envelope's `payloadType` is signed along with them, so a document cannot be relabelled.

Signatures use Ed25519, which is deterministic, so a signed statement is reproducible
too. Signing changes nothing about the payload's digest, its subject or its claims.
[Signing statements](attest-signing.md) describes the envelope, the key file and what
is refused.

## Working on this package

- Add a payload field and you change bytes, so a field needs a reason that survives
  the question "would a rebuild say anything different". Nothing derived from the
  clock, the host or the network qualifies.
- Add an element kind and you add a new `vapor.attest.*.v1` label. Never widen a
  label to cover a second payload shape.
- Keep generation free of `internal/builder` and `internal/oci` imports beyond the
  subject value a caller passes in, so the payloads can be produced and tested without
  an image.
