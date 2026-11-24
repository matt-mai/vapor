---
title: SPDX documents
---

# SPDX documents

An SPDX document says what is inside one platform image: which packages it was built
from, which of their files survived, and where the license text of each package is.
Vapor writes one document per platform, in SPDX 2.3 JSON. The
[attachment rules](attest.md#attachment-topology) decide where the document is stored;
this page describes its content.

`attest.SPDX` builds a document from a finished tree plus the lock records for the same
platform. Nothing else is consulted: no catalogue, no archive, no network.

## What decides the content

- **The finished tree decides what exists.** A package, slice or artifact appears in
  the document only if a file in the image still came from it. A package that
  hardening removed completely is not claimed, because a document that names content
  the image does not have is wrong in the direction a scanner cannot notice.
- **The lock decides what each element is.** Version, architecture, archive checksum
  and the pointer to the license text come from the locked records. Files are hashed
  from the bytes in the image, so a file a slice script rewrote is reported with the
  content the image really holds.
- **A record the document cannot vouch for is refused.** A contributor with no name, no
  version or a digest that is not SHA-256 stops generation instead of being published.
  The document repeats the lock as a claim about the image, so it reports a broken
  record rather than passing it to a reader as if it had been checked.
- **Attribution is per platform.** The input names one platform, and records for
  another platform are ignored rather than merged.

## Elements

Each contributor becomes an SPDX package, named by the
[element identity](attest.md#element-identities) the payload contracts share, with the
colon of `sha256:` written as `-`:

| Element | Identifier | Example |
| --- | --- | --- |
| Whole package | `SPDXRef-sha256-<identity hex>` | `SPDXRef-sha256-284d61d7…` |
| Sliced package | `SPDXRef-sha256-<identity hex>` | `SPDXRef-sha256-4057b1c6…` |
| Artifact | `SPDXRef-sha256-<identity hex>` | `SPDXRef-sha256-e3f4df45…` |
| Vendored module | `SPDXRef-sha256-<identity hex>` | `SPDXRef-sha256-9b1c2f80…` |
| File | `SPDXRef-File-<path>` | `SPDXRef-File--usr-bin-coreutils` |

An element's identifier therefore changes whenever the element does: a version, a
content digest, a slice definition or an artifact identity that differs is a different
identifier, and a reader can tell two elements apart without trusting a display name.
Two slices of one package share a purl, because the purl names the package, but they are
two elements with two identifiers.
The identity payload already names the platform, so two platforms never collide.

Files are the exception, because a file has no identity of its own: its path becomes
the identifier. Characters an identifier may not contain become `-`, so
`/usr/bin/tool` starts with a doubled dash. Two contributors that would end up with the
same identifier are an error, never merged.

Identifiers cannot keep image paths apart on their own: `/a-b` and `/a_b` both become
`SPDXRef-File--a-b`, and a document that used that string twice would describe one
element for two files. File identifiers are therefore assigned in tree order, and a
path whose identifier is taken gets a `-<n>` suffix (`SPDXRef-File--a-b-2`). Only the
identifier changes; `fileName`, the checksums and the relationships still name both
files. The suffix keeps the grammar the SPDX schema enforces.

A package element reports its locked version and architecture, the SHA-256 of the
archive it was read from, the archive file name, and a
[purl](https://github.com/package-url/purl-spec) a scanner can match against
vulnerability data:

```text
pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?arch=amd64&distro=ubuntu-24.04&upstream=openssl
```

The `upstream` qualifier names the source package the archive was built from, which the
lock records from the archive's `Source` field and leaves out when the archive's own
name is the source name. Distribution advisories are published per source package, so
a scanner that only sees the binary name under-reports: `libssl3t64` is fixed in
`openssl`, and without the qualifier the two cannot be joined.

The namespace and the `distro` qualifier name the vendor that built the package, which
is the distribution only for the distribution's own archive. A repository that
authenticates its own release identity publishes packages the distribution never built,
so a `nodejs` from a vendor suite becomes
`pkg:deb/nodesource/nodejs@26.13.1-1nodesource1?arch=amd64&distro=nodesource-nodistro`
rather than an `ubuntu` package. The distinction decides which advisory data a scanner
applies, and Ubuntu's records for a name it no longer maintains carry no version range
at all: every version matches them, so an `ubuntu` purl for a vendor build reports the
distribution's whole history against it and none of the vendor's own fixes.

`fileName` in the file section is a path relative to the image root, as SPDX 2.3
section 8.1 requires: `/usr/bin/coreutils` is written `usr/bin/coreutils`. Lines and
relationships still address the file by its absolute path, because that is what the
image's own tree uses.

A sliced package is one element for the whole package, named after the package rather
than after any slice: an advisory is filed under the package, so an element per slice
would make a scanner report the same finding once per slice. The comment lists the
slices the image actually holds, because only the image knows that. The tree names a
slice as `<package>_<slice>`, so the slice a file came from is checked against the locked
closure; a file whose origin names a slice the record does not hold stops generation,
because the document would otherwise describe a slice the lock never wrote. It has no
archive checksum, because a slice is not an archive: only the package it was cut from has
one. Its purl is that package's purl, which is the product a VEX claim about the sliced
package resolves to, so a scanner joining the two payloads finds the package under the
same name in both.

An artifact element carries `pkg:generic/<declared name>@<declared version>` and reports
the name and version its specification declared for the artifact, not its fetch URL, so
the same bytes fetched from two endpoints produce the same element. When the
specification declares a CPE it is written beside the purl as a `SECURITY`/`cpe23Type`
reference, because no advisory database indexes a `pkg:generic` URL: without the CPE a
payload that is not a package is invisible to a scan.

A package element takes a declared CPE the same way. A vendor build is published under
the vendor's own package URL, which routes a scanner to the vendor's advisories and, for
a vendor that files none, to no advisories at all. The CPE names the package in a
database that does index it, so a package whose own index is silent can still be
matched. One element carries both references, and a scanner that consults CPEs reads
them together rather than choosing between them.

The two references have to agree on the version. The purl carries the vendor's version
including its Debian revision (`26.13.1-1nodesource1`), and an ecosystem-aware scanner
compares a CPE against it with the distribution's version rules, so the revision is read
as newer than the upstream `26.13.1` and a fixed release reports nothing. A version
typed out in the CPE itself is not rewritten: declare `*` and let the lock's version
supply it.

### Vendored modules

A payload can carry packages of its own: the npm tree inside a Node.js deb, the wheel
metadata beside a Python build. The lock names the payload and nothing inside it, so
these are found in the finished tree instead, by reading the manifest each ecosystem
publishes its identity in:

| Ecosystem | Manifest | purl |
| --- | --- | --- |
| npm | `package.json` | `pkg:npm/<scope>/<name>@<version>` |
| Python | `METADATA`, `PKG-INFO` | `pkg:pypi/<name>@<version>` |
| NuGet | `*.nuspec` | `pkg:nuget/<name>@<version>` |
| Go | `vendor/modules.txt` | `pkg:golang/<path>@<version>` |
| Maven | `pom.properties` | `pkg:maven/<group>/<name>@<version>` |
| RubyGems | `*.gemspec` | `pkg:gem/<name>@<version>` |

A module element states no checksum, because it has no payload of its own: its files are
the payload's. It is not given one by hashing the manifest either, because a manifest is
not what a scanner checks an advisory against.

A vendored module and the payload carrying it both `CONTAINS` the same file. The payload
really does hold those bytes and the module really is a package, so neither claim is
dropped: a reader that asks what a deb installed still gets an answer, and a scanner that
asks which packages the image holds sees both.

Two versions of one module installed at two paths stay two elements, because they are two
versions an advisory can differ on. A manifest that states no version — an application's
own `package.json`, a `go.mod` naming a main module — is a build input rather than an
installed module, so it is skipped instead of reported under a version the image does not
hold.

Every element therefore has a purl, and each one is a product a VEX claim can name.

Download locations are `NOASSERTION` everywhere. Vapor reads packages from a mirror it
does not own, so it cannot claim where they came from; that is provenance's job.

## Files and relationships

Every file in the image appears with a SHA-1 and a SHA-256 of its final bytes. SPDX 2.3
§8.4 makes exactly one SHA-1 mandatory for a file, which is why it is there even though
it is the weaker digest; the SHA-256 beside it is the one a container reader can check
without rehashing. Both come from one pass over the file content. A file that a slice
script or a declared path rewrote carries a note saying it was modified during
assembly, so the difference from its package's original content is not read as damage.

```text
SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-coreutils
SPDXRef-Package-coreutils CONTAINS SPDXRef-File--usr-bin-coreutils
SPDXRef-DOCUMENT CONTAINS SPDXRef-File--etc-os-release
```

- The document `DESCRIBES` every element it names.
- An element `CONTAINS` each file it contributed.
- The document `CONTAINS` the files no locked record contributed: declared
  `filesystem.paths` entries and the state Vapor generates itself, such as
  `/etc/os-release` or the package database.

A sliced package is described by the document rather than contained by its package,
because the image holds a part of that package and not the whole of it.

## Licenses

License text reaches the image through `/usr/share/doc/<package>/copyright`, which
hardening keeps even when it removes the rest of the documentation. When that file is
in the image, the package's comment points at it:

```text
This package is included whole. The license text is /usr/share/doc/coreutils/copyright.
```

When the file is not in the image, the sentence is absent rather than replaced by a
guess. Vapor does not read a `License:` field out of package metadata and does not
translate one into an SPDX license identifier: a wrong identifier is worse than none,
and the copyright file is the authoritative text.

## Document header

| Field | Value |
| --- | --- |
| `spdxVersion` | `SPDX-2.3` |
| `dataLicense` | `CC0-1.0` |
| `SPDXID` | `SPDXRef-DOCUMENT` |
| `name` | image name and platform, for example `my-image linux/amd64` |
| `documentNamespace` | `https://mattnet.de/vapor/spdx/<image>/<platform>/<subject hex>` |
| `creationInfo.created` | `1970-01-01T00:00:00Z` |
| `creationInfo.creators` | `Tool: vaporize` |

The namespace contains the digest of the manifest the document describes. Two builds
of different images therefore cannot claim the same namespace, and a rebuild of the
same image does.

The creation time is the Unix epoch, not the build time, so an unchanged image
produces identical document bytes. The [epoch rule](attest.md#what-a-payload-may-not-contain)
explains why.

## Disabling it

An image specification may set `sbom.enabled: false`, which produces no document. That
switch covers SPDX only: provenance and VEX statements are separate attachments and
are not affected, and licenses stay in the image either way. See
[attachment](#attachment) for where the document ends up.

## Attachment

`vaporize build` wraps the document in an in-toto statement with
`predicateType` `https://spdx.dev/Document` — the value cosign uses, so existing
tools read it — and attaches it to the platform manifest. The wrapper names the image
and the manifest digest as the subject:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "example.invalid/app", "digest": {"sha256": "…"}}],
  "predicateType": "https://spdx.dev/Document",
  "predicate": {"spdxVersion": "SPDX-2.3", "…": "…"}
}
```

`--attestations-dir` writes the SPDX document itself to a file named
`<image>-<platform>-spdx.json`, without the wrapper, so a scanner can read the file
directly. The attachment is still the statement, and with `--sign-key` that statement
is wrapped in a signed DSSE envelope; the SPDX document inside is byte-identical to the
one in the directory either way. The
[attachment page](attest.md#attachment-topology) explains why an attachment describes
the platform manifest and not the index.

## Working on this package

- **Ordering.** Files follow tree order, elements and relationships are sorted by
  identifier, and the bytes come from the shared canonical encoder, so no map
  iteration reaches the payload.
- **Schema.** `internal/attest/testdata/spdx-2.3.1.schema.json` is the published SPDX
  2.3.1 schema. `schema_test.go` checks every payload against it with a small offline
  validator, and it fails when the schema starts using a keyword the validator does
  not implement. A new field that the schema does not allow is a test failure, not a
  surprise for a consumer.
- **Adding a field.** A field belongs in the payload only if the lock or the tree
  already knows it. Do not add a lookup, a clock read or a catalogue query to fill one.
- **Adding an element kind.** Give it its own identifier prefix and a test that the
  document describes it. Do not make two kinds share a prefix.
