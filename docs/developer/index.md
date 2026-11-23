---
title: Vapor developer documentation
---

# Vapor developer documentation

Vapor turns a description of an image into an OCI image without a container
daemon and without root. It is a Go program in the module `github.com/matt-mai/vapor`.

Vapor does the work in two stages, and the split is the most important idea in
the code.

`vaporize lock` reads `image.yaml`, works out what the image asks for, downloads
the inputs, and checks each one against signed repository metadata. It writes
`image.lock.yaml`. This stage may use the network.

`vaporize build` reads the same specification and the lock, and assembles the
image from bytes the verified cache already holds. It has no fetcher, so a build
that would need a download fails instead. An offline build is a property of the
code, not a promise in the documentation.

Nothing in Vapor executes a maintainer script on the host, writes outside the
image tree, or needs privileges to assemble an image.

## Where to start

| If you want to | Read |
| --- | --- |
| Set up a checkout and make a first change | [Quickstart](quickstart.md) |
| Understand how the packages fit together | [Architecture](architecture.md) |
| Change how a specification is read | [Specification loading](schema.md) |
| Change catalogue or slice behaviour | [Catalogues](catalogue.md) |
| Change distribution, trust or package resolution | [Distribution](distribution.md) |
| Change download, cache or offline replay | [Acquisition](acquisition.md) |
| Change what a lock contains or how it is written | [Lock assembly](locking.md) and [lock schema](lock-schema.md) |
| Change the in-memory filesystem or artifact placement | [Filesystem](filesystem.md) |
| Change how slice scripts run | [Mutation sandbox](mutation-sandbox.md) |
| Change build order or generated system state | [Builder](builder.md) |
| Change what gets removed or checked in the final tree | [Hardening](hardening.md) |
| Change the image bytes or how they are published | [OCI output](oci.md) |
| Generate SBOMs, provenance or VEX statements | [Attestations](attest.md) |
| Change what an SPDX document contains | [SPDX documents](attest-spdx.md) |
| Change what a provenance statement contains | [Provenance statements](attest-provenance.md) |
| Change which content a VEX claim names | [VEX claims](attest-vex.md) |
| Change how statements are signed | [Signing statements](attest-signing.md) |
| Change where statements are attached or exported | [Attestations](attest.md#how-a-build-attaches-them) |
| Change commands, exit codes or progress output | [Command line](cli.md) |
| Add or run tests | [Testing](testing.md) |
| Check what upstream Chisel v3 does | [Chisel v3 compatibility](chisel-v3-compatibility.md) |

## Table of contents

### Specification

- [Quickstart](quickstart.md): build, test and run the project, then make a first change.
- [Architecture](architecture.md): the pipeline, the packages, and the import rules between them.
- [Specification loading](schema.md): strict decoding, defaults, validation ownership and the spec digest.

### Catalogues and selection

- [Catalogues](catalogue.md): catalogue trees, slice definitions, selection rules and content declarations.

### Trust and acquisition

- [Distribution](distribution.md): the provider contract, Ubuntu policy, repository trust and whole-package resolution.
- [Acquisition](acquisition.md): verified downloads, the content-addressed cache, credential handling and offline evidence replay.

### Lock

- [Lock assembly](locking.md): how a lock is put together, audited and compared.
- [Lock schema](lock-schema.md): every lockfile record, the canonical encoding and the digest vectors.

### Assembly

- [Filesystem](filesystem.md): the in-memory tree, collision rules and artifact placement.
- [Mutation sandbox](mutation-sandbox.md): the confined worker that runs slice scripts.
- [Builder](builder.md): offline build order and the system state Vapor synthesizes itself.
- [Hardening](hardening.md): the removal passes and the static ELF closure check.

### Output

- [OCI output](oci.md): deterministic tar layers, images, indexes, layout export and registry push.
- [Attestations](attest.md): what an attestation attaches to, how a payload's bytes and identity are computed.
- [SPDX documents](attest-spdx.md): the elements, relationships, license pointers and header of the SPDX payload.
- [Provenance statements](attest-provenance.md): the subject, build definition, locked inputs and builder of a SLSA statement.
- [VEX claims](attest-vex.md): how inline and imported vulnerability claims are resolved, merged and refused.
- [Signing statements](attest-signing.md): the DSSE envelope, the key file and why signing is a wrapper.

### Working on the code

- [Command line](cli.md): the command tree, exit codes, the starter generator and progress reporting.
- [Testing](testing.md): test layout, fixtures, external oracles and the evidence rules.
- [Releases](releases.md): what a release publishes, how a tag builds it, and how it is verified.

### Reference

- [Chisel v3 compatibility](chisel-v3-compatibility.md): what upstream does, what Vapor does differently, and why.
- [Conformance matrix](conformance-matrix.md): every compatibility row mapped to the test that exercises it.

## How these pages are organised

Pages in the same stage follow the same shape: what the stage is for, why its
boundaries sit where they are, how the pieces fit, and what a change must not
break. Where a page states a rule the code enforces, it names the package and
function that enforce it, so you can read the rule and the code together.

Three pages are parsed by Go tests: [the conformance matrix](conformance-matrix.md),
[the Chisel v3 inventory](chisel-v3-compatibility.md) and the vectors in
[the lock schema](lock-schema.md). [Testing](testing.md#tests-that-read-the-documentation)
explains what that means before you edit them.
