---
title: Provenance statements
---

# Provenance statements

A provenance statement answers one question: which inputs produced this image, and
what ran the build. It is an [in-toto statement](https://in-toto.io/) whose predicate
is SLSA provenance v1. The shared rules are in
[Attestations](attest.md#attachment-topology); this page covers what Vapor puts in the
statement.

## On this page

- [Shape](#shape)
- [Subject](#subject)
- [Build type and parameters](#build-type-and-parameters)
- [Resolved dependencies](#resolved-dependencies)
- [Builder](#builder)
- [What is deliberately absent](#what-is-deliberately-absent)
- [Disabling it](#disabling-it)
- [Working on this package](#working-on-this-package)

## Shape

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "my-image linux/amd64", "digest": {"sha256": "…"}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://mattnet.de/vapor/build/v1",
      "externalParameters": {"spec": "sha256:…"},
      "resolvedDependencies": [{"name": "package/coreutils", "digest": {"sha256": "…"}}]
    },
    "runDetails": {"builder": {"id": "https://mattnet.de/vapor", "version": {"vaporize": "1.2.3"}}}
  }
}
```

One statement covers one platform. Two platforms produce two statements with different
subjects and different dependency lists.

## Subject

The subject is the platform manifest, by digest and size, named `<image> <platform>`.
It is never the index: an attachment to the index would change the index digest, which
would change what the statement claims to describe.

## Build type and parameters

`buildType` is `https://mattnet.de/vapor/build/v1`. It says how to read the rest of the
statement: the parameters are a Vapor specification and a lock, and the build replays
the lock offline.

`externalParameters` carries one value, `spec`, the specification digest. The
specification text is not copied into the statement because the digest already names
it, and a reader with the same specification can check it.

## Resolved dependencies

Every locked input of the platform is listed once, named by what it is rather than by
where it was fetched:

| Name | Digest |
| --- | --- |
| `lock` | the canonical lock bytes |
| `catalogue/<catalogue>` | the catalogue tree, or the archive for a remote catalogue |
| `input/<role>/<path>` | a snapshotted trust key, CA bundle or VEX file |
| `repository/<id>` | the signed release evidence that authenticated the suite |
| `package/<name>` | the `.deb` that was replayed |
| `slice/<package>` | the `.deb` a slice was cut from |
| `artifact/<name>` | the artifact payload |

Catalogues and local inputs belong to every platform, so they appear in each
statement. Repositories, packages, slices and artifacts appear only in the statement
for their own platform.

The first entry is the lock itself, as canonical JSON. Everything else is only
trustworthy through it, and a reader who holds the lock can compare the digest instead
of trusting the statement's word for what was used.

Two inputs with the same name are an error rather than a merge, because a merged entry
would claim one digest for two different things.

## Builder

`builder.id` is `https://mattnet.de/vapor`, and `builder.version` maps the tool name to
its version, both passed in by the caller rather than read from the running binary.
Naming the tool is not a claim about trust: there is no signature yet, so the builder
field says what produced the statement and not who vouches for it.

## What is deliberately absent

- **No timestamps.** SLSA treats `startedOn` and `finishedOn` as optional, and a build
  did not start at the Unix epoch. Leaving both out is honest and keeps the bytes
  stable.
- **No invocation ID.** A locally generated unique value would make every rebuild
  differ without telling a reader anything it could check.
- **No byproducts.** Vapor writes no build log that a statement could point at.
- **No mirror URLs.** A dependency is named by its identity, so moving a mirror does
  not change the statement.
- **No host paths, credentials or warning text.** These are the same refusals every
  payload keeps; see [Attestations](attest.md#what-a-payload-may-not-contain).
- **No base image.** Vapor composes an image from packages. There is no upstream base
  digest, and a field implying one would be misleading.

## Disabling it

There is no switch. Provenance is generated with the other payloads and is unaffected
by `sbom.enabled`, which covers the SPDX document only.

## Attachment

An SLSA statement already is an in-toto statement, so the build attaches it unchanged:
no second wrapper is added around `buildDefinition`/`runDetails`. Its subject is the
platform manifest. The predicate on its own is the provenance document:
`--attestations-dir` writes that to `<image>-<platform>-provenance.json`, and
`--sign-key` wraps the attached statement in a signed DSSE envelope. See
[attachment](attest.md#attachment-topology).

## Working on this package

- **The field set is checked.** SLSA publishes a specification and an informative CUE
  summary, not a JSON Schema, so `provenance_test.go` compares every object's keys
  against the published field set. A field that the specification does not define is a
  test failure, because a consumer would ignore it.
- **Coverage is checked.** A test asserts that every locked input of the platform
  appears exactly once and that another platform's inputs do not.
- **Adding a dependency kind** means adding it to `ProvenanceInput.sources` with a name
  prefix, not to the statement shape.
