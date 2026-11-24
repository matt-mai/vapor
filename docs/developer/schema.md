---
title: Specification loading
---

# Specification loading

`internal/schema/spec` turns YAML text into a value the rest of the program can
trust. It answers three questions in order: is this a document we can read at all,
does it have every field it needs, and does it make sense together. It also computes
the specification digest that identifies the image.

Nothing in this package touches the network, the filesystem or the process exit
code. Loading is a pure function of the input bytes, which is what makes the
digest stable and the tests cheap.

## On this page

- [Why loading is strict](#why-loading-is-strict)
- [The two passes](#the-two-passes)
- [Defaults](#defaults)
- [Validation and who owns it](#validation-and-who-owns-it)
- [The specification digest](#the-specification-digest)
- [Package layout](#package-layout)
- [Working on this package](#working-on-this-package)

## Why loading is strict

A specification is the only place a human says what they want. Every place where
the format is ambiguous is a place where a developer can be surprised by an image
that quietly differs from the file they wrote.

So the reader refuses anything it does not understand rather than ignoring it. An
unknown field is an error, a duplicate key is an error, a merge anchor is an error,
and an interpolated value is an error. Ignoring an unknown field is the tempting
choice, and it produces the worst outcome: the author believes the setting took
effect, the build does not apply it, and the image is wrong without anything
failing.

## The two passes

Decoding runs twice, on purpose.

**Pass one: shape.** The YAML document is walked as a node tree, without decoding it
into Go values yet. This is where duplicate keys, non-string keys, aliases, anchors,
merge keys, custom tags, interpolation sequences and NUL bytes are rejected. Doing
this on the node tree is the only way to see what a typed decode has already
silently collapsed: by the time a duplicate key reaches a map, one of the two
values is gone and there is nothing left to complain about.

**Pass two: types.** The cleaned tree is decoded with `KnownFields(true)` so an
unknown field fails the decode instead of being dropped. The result is a typed
value with no reflect tricks left in it.

`spec.LoadSpec` reads at most 4 MiB plus one byte, then decodes, applies defaults,
and validates. Both `LoadSpec` and `DecodeSpec` reject specs larger than 4 MiB
before parsing YAML.
Each step has one job, and none of them mutates its input, so the digest computed
afterwards describes exactly what was validated.

## Defaults

Defaults live next to the types they complete: in `internal/schema/spec/defaults.go`
for the top-level record, and in the `ApplyDefaults` functions of the subpackages:

- platform defaults to `linux/amd64`;
- filesystem and accounts fields are completed by `filesystem.ApplyDefaults`;
- policy defaults set the four hardening flags to true and the slice-engine step
  budget to `100000`;
- attestation declarations get their defaults.

Applying defaults is separate from decoding. That matters because the digest has to
be computed over the defaulted, validated value: two specifications that mean the
same thing but spell the same setting in different ways must produce the same
digest, and a specification that omits a setting must match one that states the
default.

`decodeSpec` stays pure. If it started filling in defaults it would be impossible
to tell, from a test, whether a difference came from the file or from the reader.

## Validation and who owns it

Validation answers "does this make sense", and the package is deliberately careful
about who is allowed to say no.

| Check | Owner | Why there |
| --- | --- | --- |
| Distribution and release are a known lowercase identifier and a numeric release string | `internal/distro` | the set of distributions is policy, not shape |
| Image name parses as a container reference and follows the grammar | `internal/schema/spec` | a name is invalid regardless of distribution |
| Tag follows `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` | `internal/schema/spec` | the OCI grammar is universal |
| By-hash policy defaults to `prefer`; freshness defaults to `if-present` | `internal/schema/spec` | these are defaults, not distribution rules |
| Script exceptions name packages only, never paths | `internal/schema/spec` | a path exception would bypass a security boundary |
| The slice-engine step budget is positive | `internal/schema/spec` | shape, not policy |

The division is the same one the rest of the architecture uses: shape and internal
consistency here, distribution policy in `internal/distro`. That is why
`vaporize lock` selects a provider after decoding rather than during it. A schema
package that knew which Ubuntu releases are supported would need a change every time
a distribution moved.

Validation errors are wrapped in a safe `inputError` that says what is wrong with
the specification. The raw YAML library cause is not echoed, because it can quote
fragments of the document into a terminal or a CI log.

## The specification digest

The digest is how the lock and the build agree that they are talking about the same
image. It has one contract and a few rules that follow from it.

**Contract.** The digest is `sha256:` plus lowercase hex, over the compact canonical
JSON encoding of the specification. Nothing else.

The projection rules:

- Keys are sorted recursively, so field order in the source never matters.
- Lists keep their order, because a list of commands or alternatives has meaning.
- `nil` and empty are the same thing after defaults, so a missing list and an empty
  list produce the same bytes.
- Encoding is compact: no spaces, no newlines.
- There is no domain-label prefix. The value is a plain hash of the payload.
- The root `version` field participates like any other field.

**Relative paths only.** Some fields point at files next to the specification:
`contents.catalogues[].path`, `contents.repositories[].trust.keys[].path`,
`filesystem.ca.sources[]` and `vex.inputs[]`. These must be relative paths. A
specification that could name `/etc/shadow` or an absolute host path would be a way
to make a build read things it should never read. Resolution happens later, relative
to the specification's directory, and the referenced bytes are snapshotted so the
digest is not the only thing that has to stay stable. A trust key, CA source or VEX
input may climb above the specification's directory (`../ca/ca.pem`) so images can
share one file; an artifact path may not.

**Existing digest inputs are frozen.** New opt-in fields can use the `omitzero`
JSON tag option so the projection includes them only when set. A change that
alters the projection of an existing spec needs a new digest version. Tests compare
the vectors in `internal/schema/testdata/spec-digest/` byte for byte.

**What the digest does not cover.** It hashes the specification, not the inputs it
references. Two specifications can produce the same digest while pointing at
catalogue trees that later change; that difference is captured by the catalogue
identity in the lock, not here. Keeping those two identities separate is what lets
the lock record where the spec came from and what it resolved to without mixing the
two claims.

## Package layout

| Path | Contents |
| --- | --- |
| `internal/schema/base` | scalar rules shared by specifications and locks |
| `internal/schema/contents` | package, slice, artifact and repository declarations |
| `internal/schema/filesystem` | paths, accounts, CA sources |
| `internal/schema/policy` | hardening flags, slice-engine budget |
| `internal/schema/attestation` | attestation declarations |
| `internal/schema/lock` | the lockfile types (see [lock schema](lock-schema.md)) |
| `internal/schema/container` | runtime user, entrypoint and environment |
| `internal/schema/spec` | the top-level specification record and its loader |

The split exists so a change to, say, filesystem declarations cannot accidentally
alter how locks are decoded. Tests live next to the package they cover, and
`internal/schema/testdata` holds the digest vectors.

## Working on this package

- Add a field to the type, to its defaults, to its validation and to the digest
  projection in the same change. A field that skips one of the four is a bug that
  shows up months later as a lock that does not match its spec.
- Add the failure, then the acceptance test. Strictness rules are only real if a
  test feeds the bad document and expects the error.
- Do not reach for policy. If a check needs to know about a distribution, it belongs
  in `internal/distro`, and the check moves with a reason in the commit message.
- Update the vectors when the projection changes and say so in the change
  description. A digest change is a compatibility event, not a refactor.
