---
title: VEX claims
---

# VEX claims

A VEX statement says which known vulnerabilities do not apply to an image, and why.
Vapor never looks a vulnerability up: a claim comes either from the specification's
`vex.assertions` or from a local OpenVEX document the specification imports. This page
covers how such a claim is read, which content it ends up naming, and what the finished
statement contains. The shared rules are in [Attestations](attest.md#attachment-topology).

## On this page

- [Two sources, one claim shape](#two-sources-one-claim-shape)
- [Imported documents](#imported-documents)
- [Products](#products)
- [Merging claims](#merging-claims)
- [Evidence before publication](#evidence-before-publication)
- [The statement](#the-statement)
- [What is refused](#what-is-refused)
- [Writing statements](#writing-statements)
- [Working on this package](#working-on-this-package)

## Two sources, one claim shape

Both sources resolve into the same `attest.Claim`: a vulnerability, a status, a
justification when the status is `not_affected`, the claim's own sentence, the image
paths a claim says are absent, and the package URLs the claim is about on one platform.
Generation only sees claims in that shape, so it never needs to know where one came
from.

Inline claims are resolved with `attest.CompileClaims`, imported statements with
`attest.ImportClaims`. Both take an `attest.VEXInput` holding one platform and that
platform's locked packages, slices and artifacts. A claim is resolved per platform, so
an amd64 statement never names an arm64 product.

## Imported documents

Only OpenVEX v0.2.0 is read. A document with another `@context` is refused rather than
reinterpreted as v0.2.0, because the two versions do not mean the same thing.

Vapor keeps the fields it can check or has to publish and discards the rest. Author,
role, tooling and timestamps never reach an image, and a document cannot name its own
products through a supplier or a subcomponent: only `products` decides what a statement
is about. What a statement says in its own words — its `action_statement` or
`impact_statement` — is passed on, because that is the part a reader acts on, and its
`status_notes` stays as the note on the published claim. Every imported statement has to
name its own products; a statement without them is refused instead of inheriting the
document's subject.

Decoding is bounded and strict:

| Limit | Value | Why |
| --- | --- | --- |
| Document size | 4 MiB | A document is read into memory before decoding |
| Statements | 1000 | Each one becomes output |
| Unknown fields | refused | A field Vapor ignores could be the one that qualifies the claim |
| Documents per input | one | Two concatenated documents would silently drop one |

The bytes handed to `attest.DecodeVEXDocument` come from the snapshotted `vex.inputs`
files, which the lock records with their digests. A document that is not the locked one
is therefore already refused before decoding, and Vapor does not accept a document from
any other place.

The 4 MiB limit is applied twice, and neither check allocates for the document it
refuses. `vaporize vex` compares the `size` the lock recorded against
`attest.MaxVEXDocumentSize` before the blob is opened, and the cache read stops at the
recorded size, so a cache entry that grew after locking is refused rather than read
whole. `DecodeVEXDocument` repeats the check on the bytes it is given, for callers that
did not read them itself.

The bytes handed to the decoder are the bytes the cache verified, not a second read of a
file that was checked earlier: `cache.Read` hashes what it returns, so a blob rewritten
in place cannot reach the decoder.

## Products

A product is a package URL, the same string the SPDX document writes for that element,
so a reader can match the two payloads without translating names. When the lock records a
CPE for that element, the product states it beside the URL as an additional identifier, so
an advisory database entry that has no match for the purl can still be reached. The CPE is
resolved against the locked version, so a `*` version field names the version the image
holds rather than an all-versions identifier.

- A package resolves to `pkg:deb/<distro>/<name>@<version>?arch=<arch>&distro=<distro>-<release>&upstream=<source>`,
  whether the lock holds it whole or as slices. The claim is about the package, and
  that is the name an SBOM carries. `upstream` is the source package the lock recorded,
  omitted when it is the package's own name; a claim only matches a lock entry whose
  source agrees.
- An artifact resolves to `pkg:generic/<sbom.name>@<sbom.version>`, the identity its
  specification declares rather than the local name it is locked under.
- Both are the locators the SPDX document carries, one per element, so every product a
  claim names can be joined to the SBOM by purl alone.
- An imported product may state a CPE beside its purl. The CPE is the document's own
  identity for the product and replaces the lock's rather than being compared, because a
  document naming an entry the lock does not hold is the source of that name. The claim
  carries it, so the payload publishes the name the document stated even when the lock
  states another or none.
- An imported product may name its content as loosely as the purl grammar allows. Type,
  name and version have to match a locked record exactly. A qualifier the document states
  has to match; a qualifier it omits constrains nothing, because a document written
  against a bare package URL says nothing about architecture or distribution.
- `arch=all` matches an architecture-independent package. Any other architecture that is
  not the image's own is refused, as is a distribution the lock does not hold: both mean
  the document is about a different image.

An imported statement is accepted only when every product it names is locked on that
platform. A statement about a package the image does not contain is an error, not a
skip, because a claim that quietly disappears looks like a claim that covers nothing.

## Merging claims

Merging happens in `attest.Coalesce`, after both sources are resolved:

- Claims that state the same thing about different products become one claim listing
  all of them. The payload does not repeat itself.
- Two claims that state different things about the same vulnerability and product stop
  the build. Preferring one of them, or letting the later one win, would be an invented
  decision about a security claim.
- A claim naming no product on this platform claims nothing, so it disappears at
  generation time rather than being asserted about the whole image.

The image paths a claim names are not part of what it says, so they never decide whether
claims match. An imported statement carries no paths at all, and it states the same
thing as an inline claim about the same product that names them. The two become one
claim whose paths are all the paths either of them named.

Evidence belongs to the product the claim named it for, not to the merged statement. An
imported statement can name several products, and each of them is checked on its own: a
product that only the import covers has no path to show for itself and is refused, even
though a product merged into the same statement has one. Merging never lends one product
the evidence given for another. Two claims for one product cannot disagree about what is
absent by naming different paths — both paths are checked, and a claim naming a path the
image holds still fails.

Notes merge the same way paths do. A note belongs to the claim that stated it, so every
claim about any product of the merged statement keeps its note, whichever source was
read first. That is what carries an imported statement's `status_notes` onto the
published claim, and it means the order the sources appear in never changes the bytes.

Products and notes are ordered, so the same inputs always produce the same claim order
and the same bytes.

## Evidence before publication

Nothing is published until the claims match the finished filesystem. A `not_affected`
claim is the one status Vapor can check from the image itself, so it is held to what the
tree shows:

- The check runs once the claims have been merged, and it runs once per product of a
  merged claim: evidence named by any source counts for that product, and a product no
  source gave evidence for is refused rather than passing on another product's paths.
- Every path the claim names as absent is resolved and then looked up. A claim whose
  path is in the image fails, and so does one that reaches it through a symlink, because
  a link is not a missing file.
- A path that cannot be resolved fails the claim. "Could not check" never becomes
  "not there".
- With the `vex.check-absent-paths` switch on, a `not_affected` claim that names no path
  fails, which is the default and is described in [VEX in the specification](../user/reference/spec.md).
- With the switch off, the claim is published with the note "The absent paths of this
  claim were not checked against the image", so the waiver is visible in the payload
  rather than implied.
- A path on any other status is refused. Absence only means something for a claim about
  content that is not there, and a reader would take a path on a `fixed` claim for a
  check.

Absence is evidence about these files and nothing more. It does not prove that no
vulnerable code exists, and the payload does not claim that it does.

## The statement

The payload is an OpenVEX v0.2.0 document with one statement per merged claim:

| Field | Value |
| --- | --- |
| `@context` | `https://openvex.dev/ns/v0.2.0` |
| `@id` | `https://mattnet.de/vapor/vex/<image>/<platform>/<subject hex>` |
| `author` | `vaporize` |
| `timestamp` | `1970-01-01T00:00:00Z`, the stand-in the SPDX document uses |
| `version` | `1` |
| `statements[].vulnerability.name` | the identifier the claim names |
| `statements[].products[].@id` | the package URL, nothing else |
| `statements[].status` | the status, unchanged |
| `statements[].justification` | only for `not_affected` |
| `statements[].status_notes` | every note the merged claims carried, and the waiver note when the absence check was off |
| `statements[].action_statement` | the claim's `statement` text, when the status is `affected` |
| `statements[].impact_statement` | the claim's `statement` text, for every other status |

The text a claim is required to write in the specification is not decoration: OpenVEX
wants an `affected` statement to say what a reader has to do, so that text becomes
`action_statement`. The other statuses carry it as `impact_statement`. An imported
document passes its own `action_statement` or `impact_statement` through unchanged, and
its `status_notes` is kept.

The document needs an author and a timestamp, and a rebuild has to produce the same
bytes, so both are fixed rather than taken from the machine that ran the build. A
claim that names no product on one platform is dropped from that platform's document
and keeps its place in the other: it is about content only one image contains.

Statements are ordered by vulnerability, status, justification and product, so the
order a specification or a document happened to list them in never reaches the bytes.

## What is refused

These are refusals, not preferences, and each is checked where it can first go wrong:

- Another OpenVEX version, another document format, or a second document in one input.
- A product identified by anything other than a package URL or the CPE stated beside
  one: a hash, a subcomponent, a `@id` that is not a `pkg:` URL, an identifier name
  Vapor does not recognise, or a `@id` that disagrees with the purl.
- Vulnerability aliases. A statement that fills in `vulnerability.aliases` is refused,
  not merged, because Vapor publishes one identifier per claim: a document naming the
  same issue as both `CVE-…` and its `GHSA-…` alias would otherwise produce two claims
  that nothing can tell are one vulnerability, and the duplicate check could not see it.
- A `not_affected` statement without a justification or an impact statement, and an
  `affected` statement without an action statement. The published schema expresses these
  as conditions; a reader that skipped them would accept a claim nobody can act on.
- A product from another platform, another architecture or another distribution.
- Any claim whose selector the lock does not hold on that platform.

Rendering a document adds the evidence rules:

- An absent path the image holds, one that cannot be resolved, and one on a status that
  cannot mean absence.
- A `not_affected` claim without any absent path while checking is on.
- A missing image name, platform, subject digest or finished tree: a document without
  them would identify nothing.

## Attachment

`vaporize build` puts the OpenVEX document inside an in-toto statement with
`predicateType` `https://openvex.dev/ns/v0.2.0` and attaches it to the platform
manifest, which is how vexctl publishes a claim set that a cosign-style verifier can
find. A platform no claim applies to gets no VEX attachment, because an OpenVEX
document has to state something.

`--attestations-dir` writes the OpenVEX document itself to
`<image>-<platform>-vex.json`, without the wrapper. `--sign-key` wraps the attached
statement in a signed DSSE envelope, so the attachment's payload type becomes
`application/vnd.in-toto+json` and the OpenVEX document is the signed predicate.

## Writing statements

`vaporize vex` is a thin shell around this package. It assembles every declared platform
from the verified cache, hands the finished tree to `attest.VEX` and writes the result,
so the evidence rules above are the same ones a future `build` call will use. It reads
nothing but the specification, the lock and the cache, which is why a statement about a
platform always matches the image the same lock produces. Each file is written beside
its destination and renamed into place, so a rerun replaces a previous statement
atomically and never follows a symlink planted at that path.

With `--sign-key` the same payload is written inside a DSSE envelope, described in
[Signing statements](attest-signing.md). The document inside is identical, so a signature
adds proof of authorship without changing a single claim.

Assembly is repeated rather than read back from an exported layout: a tree carries the
origin of every file, and the evidence and the SPDX attribution both depend on it. An
exported layout holds bytes and no provenance of what shipped them.

## Working on this package

- Add a status or justification label and you add it in
  `internal/schema/attestation` first: the specification and the reader share those
  constants, and both are tested from there.
- Anything that needs the finished filesystem belongs to generation, not to resolution.
  Resolution only answers "which products is this claim about".
- A new imported format needs its own decoder and its own page. Do not widen the OpenVEX
  reader to accept a second format.
