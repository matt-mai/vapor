---
layout: default
title: What works today
---

# What works today

Vapor builds Ubuntu and Debian images today. Some features are declared in the
specification and recorded in the lock, but are not used yet. This page separates the two
so you know what to expect.

## Works

- `vaporize init` writes a starter specification for Debian 13 (`trixie`) or
  Ubuntu 26.04.
- `vaporize lock` fetches catalogues over git, verifies signed repository metadata,
  downloads packages and artifacts, and writes a lock.
- `vaporize lock --check` and `--diff` report drift, and `vaporize outdated` reports
  packages a repository now offers a newer version of without downloading payloads.
- `vaporize lock` warns, without failing, when the catalogue is past its end-of-life date
  or past standard support. The warning is not recorded in the lock and does not change
  the image.
- `vaporize build` assembles `linux/amd64` and `linux/arm64` images from cached inputs,
  offline.
- Slices, whole packages and artifacts, including multi-platform artifacts, archives and
  a digest-pinned local `.deb` installed as a package.
- Slice mutation scripts, run inside a Linux sandbox.
- `filesystem` paths, accounts, timezone, certificates and `os-release` overrides.
- Hardening passes and the dynamic library check.
- `/var/lib/dpkg/status` and the per-package file lists under `/var/lib/dpkg/info/`, so
  a scanner can inventory the image. A record carries `install ok installed` in an
  image of whole packages; an image that holds a slice records no status field, so a
  package manager does not read the database as broken. APT sources and repository
  keys are written only on request (`hardening.keep-package-sources`), for an image
  that installs packages at run time.
- Export as an OCI layout or an OCI archive.
- Push to a registry with the tags in the specification, and upload the attached
  statements beside the image they describe.
- An SPDX document, a provenance statement and any VEX claim, attached to every platform
  image they describe, optionally signed.
- Annotations declared in the specification, written onto every platform manifest.
- Vendor repositories that sign an identity of their own, scoped to the package names
  the specification lists for them.
- `vaporize cache bundle` and `cache unbundle`, which move a locked build's inputs to
  another machine as one verified file.
- `vaporize inspect` and the `slices` subcommands.

## Not yet

| Feature                        | State                                                                                               |
| ------------------------------ | --------------------------------------------------------------------------------------------------- |
| Verifying statements           | A statement is written and attached, but nothing checks one before or after a build.                 |
| Reading statements back        | Nothing in Vapor fetches a statement from a registry or a layout.                                    |
| Maintainer-script auditing     | Not implemented. Scripts are never executed, and a spec that declares `scripts` is refused.         |
| Other distributions            | Refused. Ubuntu and Debian are the only providers.                                                  |
| Debian catalogues              | None is bundled. Slices on Debian need a catalogue you write and host yourself.                     |

A build attaches an SPDX document and a provenance statement to every platform image, and
a VEX statement only when the specification makes a claim that applies to that platform.
Every statement is readable from a registry that supports the Referrers API and from an
exported layout. `--attestations-dir` writes the document each statement wraps, as a
plain file a scanner reads. A registry without that
API is refused rather than served a half-working fallback. Vapor itself never reads a
statement back and never verifies a signature.

Vapor never runs a container: building an image needs no container engine, and no
command runs anything inside a built image. Checking that an image starts is done with
the engine you deploy it with, outside Vapor.

## Refused on purpose

These are not gaps in the way the table above is. Each was decided, and the error
names the rule rather than building something slightly different:

- A file two packages both claim. Debian would let one package `Replaces` the other;
  Vapor stops and names both. See [build a Debian image](../guides/build-debian-images.md#files-two-packages-both-claim).
- A repository with only a detached `Release.gpg`, or architecture-independent
  packages in a separate `binary-all` index. See
  [third-party repositories](../guides/add-third-party-repositories.md#what-a-repository-must-look-like).
- A package request that names a repository. A vendor archive declares the names it
  may supply instead; see [contents](../reference/contents.md#packages).
- A lock that is expected to prove its own selection. It records what a build used;
  it does not recheck dependency closure. See [lock file](../reference/lock-file.md#what-a-lock-does-not-prove).
- A named hardening profile. The individual fields are the whole answer. See
  [policies](../reference/policies.md#hardening).

## Debian releases

Debian 13 (`trixie`) is the tested release and Debian 12 (`bookworm`) works with a
warning. Both of a reviewed release's archives are used without setup: ordinary
packages come from Debian's main archive and security fixes from its security
archive, each checked with its own key. See
[build a Debian image](../guides/build-debian-images.md).

Upstream Chisel publishes catalogues for Ubuntu only, so Debian images can use whole
packages out of the box and need their own catalogue for slices.

## Ubuntu releases

Ubuntu 26.04 is the tested release. Another release only works when the catalogue matches
it, because a catalogue archive carries the release it belongs to:

```text
warning: ubuntu release "25.10" is not a tested baseline; resolution will be attempted
vaporize: operation failed: catalogue "ubuntu": catalogue archive "ubuntu" version "26.04" does not match provider release "25.10"
```

With a catalogue built for that release, lock and build proceed. That is not a promise:
nothing has been checked against another release.

## Relying on a planned feature

The "Not yet" table is the list of things not to count on. Anything not in it is either in
the "Works" list or not part of Vapor. Annotations moved to "Works" because they are
written onto every manifest; statements moved there because the build attaches them and
`build --push` uploads them. The rows that remain are the honest boundary.
