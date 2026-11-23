# Vapor Architecture and Distribution Boundaries

## Status and scope

`vaporize lock` validates the [image specification](developer/schema.md), resolves
packages and slices through the distribution provider, acquires and verifies inputs,
and publishes a lock. `vaporize build` uses that lock and the local cache to assemble
an image. It reports maintainer scripts without executing them, applies slice
mutations, synthesizes system state, hardens the image, and generates attestations.
Nothing it does needs a container engine. See the
[CLI reference](user/reference/cli.md) for available commands.

**Ubuntu 26.04 (Resolute) is first.** Ubuntu consumes Canonical's upstream Chisel
catalogues, accepting only **format v3**. Debian uses custom catalogues in the same
upstream v3 format, because there is no upstream Debian catalogue.
Alpine is future work, not a promised feature of the initial implementation.

One independent `image.yaml` and its lock define one image, potentially for
`linux/amd64` and `linux/arm64`. Builder images are separate specifications.
No container daemon or root privileges are needed for locking or assembly.
Podman or Docker are needed only to check that a finished image starts, which is done
outside Vapor. They are also how a defining tool such as dpkg is consulted for a
conformance comparison, without adding it to the host or the module; see
[external oracles](developer/testing.md#external-oracles).

## Pipeline and network boundary

```text
image.yaml → strict schema + defaulted spec digest
    │
    └─ lock (input acquisition permitted)
         ├─ resolve catalogue tag / branch / commit; snapshot local inputs
         ├─ authenticate repository Release → compressed index → package bytes
         ├─ resolve whole-package and slice dependency graphs
         ├─ verify artifacts and store content
         └─ canonical image.lock.yaml + complete content-addressed cache

spec + lock + verified cached inputs → build (no input network access)
    ├─ verify spec identity, evidence, digests, sizes, and platform coverage
    ├─ extract packages / slices / artifacts / store content into VFS
    ├─ run sandboxed upstream slice mutations; clean temporary content
    ├─ synthesize system state; apply hardening; check ELF closure
    ├─ serialize deterministic tar → compress → OCI images/index
    └─ attestations + local output, optional explicit registry push
```

A missing or corrupt build input is an error, not permission to fetch it.
`--push` authorizes a network output only.
Smoke tests can invoke a runtime and are outside the pure assembly boundary.

## Package responsibilities

| Package                        | Responsibility                                                                                                                                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/vaporize`                 | CLI dispatch, flags, presentation, exit codes (0 success, 1 operational/validation error, 2 invocation error).                                                                                                            |
| `internal/schema`              | Directory of strict schema packages: `spec` for the top-level record and its loader, plus `base`, `contents`, `filesystem`, `policy`, `attestation`, `container` and `lock`; defaults, validation, canonical encodings and digests; no process exits. |
| `internal/cache`               | Atomic content-addressed blobs, verified SHA256/size, safe concurrent access.                                                                                                                                             |
| `internal/certbundle`          | Shared streaming reader for PEM certificate bundles: one pass, no per-line allocation, only public certificate blocks.                                                                                                    |
| `internal/acquire`             | Verified acquisition of fixed package and artifact payloads; no selection, fetching of unselected inputs or extraction.                                                                                                   |
| `internal/snapshot`            | Snapshot declared local trust keys, CAs, VEX inputs and local catalogues as verified cached bytes; reject private-key material.                                                                                           |
| `internal/verify`              | Offline replay of locked repository evidence against cached key, release and index bytes; no network, resolution or freshness policy.                                                                                     |
| `internal/lockinput`           | Lock-time catalogue, repository, package and artifact acquisition; returns evidence without writing a lock.                                                                                                               |
| `internal/locking`             | Lock-header assembly with canonical release identity, cache audit and offline replay; no resolution or fetching.                                                                                                          |
| `internal/catalogue`           | Canonical catalogue trees, local/remote Git snapshots, link confinement and offline file-byte caching; no SDF parsing.                                                                                                    |
| `internal/distro`              | Provider contracts and shared distribution-facing records.                                                                                                                                                                |
| `internal/distro/deb`          | Shared APT/OpenPGP/index/DEB mechanics; no Ubuntu default policy.                                                                                                                             |
| `internal/distro/ubuntu`       | Ubuntu release, suite, architecture, trust and archive policy; first provider.                                                                                                                                            |
| `internal/distro/debian`       | Debian codename selection, reviewed main and security archives with their own keys, and codename release matching.                                                                                                       |
| `internal/distro/ubuntu/pro`   | Selected Pro archive authentication from APT credential files; no selection, persistence or unauthenticated fallback.                                                                                                     |
| `internal/distro/slices`       | Shared upstream-v3 parsing, catalogue resolution, slice graph, content rules and Chisel manifest/store integration; no process isolation.                                                                                 |
| `internal/mutation`            | Sandboxed mutation of a committed VFS: resource bounds, worker isolation, bounded transactions and the adversarial gate; no slice parsing or selection.                                                                   |
| `internal/distro/deb/resolver` | Debian whole-package resolution: ranked candidates, transitive solving and backtracking.                                                                                                                                  |
| `internal/artifact`            | Placement of verified artifact payloads: standalone files and re-rooted unpacked trees with destination-confined links; no fetching or verification.                                                                      |
| `internal/synthesis`           | Image state no package supplies: accounts, timezone, release identity, CA bundles and the dpkg status database. No script execution and no host reads.                                                                    |
| `internal/vfs`                 | In-memory filesystem with entry/ownership/mode rules, deterministic traversal, confined link resolution and bounded archive import; later synthesis/hardening and ELF checks.                                             |
| `internal/hardening`           | The four post-synthesis passes over the committed tree: frozen shell/tool/documentation inventories, protected copyright and package metadata, and nondestructive conflict checks. No script execution and no host reads. |
| `internal/closure`             | Static ELF closure over the hardened tree: platform class/machine, `PT_INTERP`, `DT_NEEDED` search order and `$ORIGIN`; no execution, no host reads and no package installation.                                          |
| `internal/oci`                 | Deterministic tar/compression, OCI construction and local/registry export.                                                                                                                          |
| `internal/attest`              | SPDX, SLSA, OpenVEX and optional DSSE. No live CVE database lookup.                                                                                                                                                       |
| `internal/builder`             | Offline orchestration of verified inputs, VFS, output and attestations; no fetcher, Git runner or HTTP client ([input replay](developer/builder.md)).                                                                     |

Define narrow contracts when their first real caller exists. The required roles
are `Provider` (distribution policy/finalization), `RepositoryProvider`
(authenticated metadata) and `PackageAuthenticator` (verified package bytes).
`ArchiveExtractor` (safe extraction into VFS) is now a concrete function,
`deb.Extract`, which returns a standalone tree for the caller to merge. These are
responsibilities, not prewritten signatures: the provider contract defines exact
methods with tests.
Candidate/catalogue data should be concrete records unless there is a real reason
for an interface.

Distribution-specific release/key/package-database policy belongs inside
`internal/distro`, never as Ubuntu/Debian conditionals in schema, VFS, builder,
or OCI. Shared low-level packages must not import the builder or resolver.
Schema and VFS do not depend on provider implementations. Keep import direction
acyclic when defining provider/VFS integration.

Provider-selection policy: unsupported/unimplemented distro
identifiers fail; newer/unknown numeric releases of an implemented distro warn as
untested and attempt locking. Ubuntu 26.04 is a tested baseline, not a release
allowlist. Suites come from the selected catalogue or explicit repository
configuration, without requiring a hardcoded codename for each new release.
Missing repository data, incompatible catalogues and failed trust/freshness or
repository identity checks still fail. Release-status warnings are diagnostics,
not lock/image/attestation bytes or digest inputs. `internal/distro` implements
this selection and diagnostics; the core schema loader does not apply it, and
`vaporize lock` calls it after decoding.

## Authentication and immutable inputs

The repository chain is:

```text
configured trusted full key fingerprint
  → verified InRelease (or Release + Release.gpg)
  → verified compressed index SHA256 AND byte size
  → decompression and index parsing
  → verified package SHA256 AND byte size
  → extraction
```

Never parse an index or extract a package before its verification step. Treat
catalogue keys as proposed trust material, not automatically trusted because
an untrusted catalogue included them; a short OpenPGP key ID is not a full
fingerprint trust policy. The Ubuntu starter has a reviewed embedded archive
key snapshot as its default; explicit overrides replace it and are never merged.

`lock` retains signed repository metadata and key identity plus the selected
index evidence, snapshots local keys/CAs/VEX/catalogues, and caches all required
archives/artifacts/store blobs. Consumers re-verify cached bytes. Reading a path
once for verification and again later for consumption is not sufficient.
Git commit pinning gives source identity, not proof that a publisher is trusted;
content digests detect corruption but are not publisher signatures.

New locks and refreshes enforce configured repository freshness checks. Offline
builds verify the locked evidence chain without rejecting an old snapshot merely
because today's date has advanced. No credentials enter locks, cache metadata,
image layers, logs, or provenance.

## Chisel v3 compatibility boundary

Authoritative starting references:

- [Canonical chisel.yaml reference](https://ubuntu.com/chisel/docs/latest/reference/chisel-releases/chisel.yaml/)
- [Canonical slice-definition reference](https://ubuntu.com/chisel/docs/latest/reference/chisel-releases/slice-definitions/)
- [Canonical Chisel implementation](https://github.com/canonical/chisel)
- [Canonical release catalogues](https://github.com/canonical/chisel-releases)

Research baseline resolved during this documentation step:

- Chisel implementation commit: `0a817bd22133d928ff8c3f3fcd5241ca877cbe06`.
- `ubuntu-26.04` catalogue commit: `5500a569c5cf448afda69b25079230d4049fb530`.

These are research/conformance references, not hidden pins for every user build.
Users select their sources; locks record the exact commits they consume. Before
implementing catalogue-related schema contracts, use the source/test inventory and
[feature-to-test checklist](developer/chisel-v3-compatibility.md), whose rows are
tracked in the [conformance matrix](developer/conformance-matrix.md). The matrix is
machine-checked: it fails when a row names a test that does not exist or when the
inventory grows a row it does not cover. Native-v3 reference results are still
missing, so every row proves Vapor's own behavior and none proves a match.
The documentation's compatibility matrix lists v3 support from Chisel v1.4.0;
individual documentation examples can show older formats. Do not copy older
`essential` lists into a v3 fixture.

Full compatibility includes root `chisel.yaml`, maintenance metadata/defaults,
archives/priority/override/key declarations, package and slice essential maps
with architecture filters, hints, all content operations and glob rules,
`prefer` chains, mutation ordering and mutable-path rules, temporary content
lifetime, and generated Chisel manifests. The researched upstream catalogue also
has `stores`; the implementation reads `bin-slices/` for v3. Include these in the
inventory and implement their actual upstream semantics, not a guessed DEB-only
subset. Selected Pro archive authentication is part of this work; unselected
restricted sources must not cause gratuitous credential failures.

The pinned implementation parses/selects store metadata but explicitly cannot
fetch store packages (`internal/slicer/slicer.go:517–519`); the pinned release has
no bin SDFs. There is no implemented upstream store acquisition protocol at this
baseline. Preserve metadata compatibility and explicit failure, and keep the
planned successful store acquisition/extraction goal blocked until a newer baseline
or a separate extension contract is explicitly reviewed. Do not invent protocol,
lock evidence or success fixtures and call them upstream-compatible.

Only v3 catalogues are accepted. During incremental development, selected but
unimplemented features fail clearly. That is a temporary boundary, not completion
of the user's full-compatibility requirement. New upstream changes require an
explicit baseline review and regression fixtures; `latest` must not silently
change the compatibility claim.

Intentional Vapor policies differ from the Chisel CLI: immutable locking,
offline assembly, pinned package versions, normalized OCI outputs, and warnings
rather than rejection for EOL/unstable maintenance state. Required upstream
maintenance dates are accepted despite the absence of date fields in Vapor's
own image spec. Time-based warnings never affect image content/digests.
Starlark has an initial 100,000-step execution budget, but step limits alone do
not prevent a single operation from allocating enormous strings. Mutation therefore
runs in a worker process with heap and CPU limits plus a parent-side wall clock, and
the content API counts bytes inside it. The frozen bounds, the Linux-only platform
requirement and the adversarial cases are in the
[mutation sandbox contract](developer/mutation-sandbox.md). Post-allocation checks
and Go's soft memory limit are not security boundaries. Resource failures must
leave the original tree unchanged. Document platform/resource boundaries in
compatibility claims rather than pretending every arbitrarily large script is
guaranteed.

Hardening is a Vapor policy with no upstream counterpart: upstream v3 has no
post-mutation stripping passes. The four flags therefore remove only the finite
inventories frozen in the [hardening contract](developer/hardening.md), and a
pass that would delete a declared or synthesized path fails the build instead of
silently winning. Hardening never claims that an image has no interpreter.

Closure checking is static analysis of the hardened tree, frozen in the
[ELF closure contract](developer/hardening.md#the-static-elf-check): every dynamic object must reach its
`PT_INTERP` and each `DT_NEEDED` library inside the image, resolved in glibc's order
minus the runtime-only sources. Nothing is executed and a gap is never repaired by
installing a package.

## Dependency and collision policy

Whole packages expand `Pre-Depends` and `Depends`, using Debian version ordering,
version constraints, alternatives, virtual/versioned providers, conflicts and
breaks. Rank candidates deterministically by configured source priority, newest
version, then source identity. Try alternatives in declaration order and backtrack
when constraints conflict. Select one version per native package architecture;
include architecture-independent `all` packages. Do not include `Recommends` or
`Suggests`, install an implicit base system, or guess foreign-architecture behavior.
A relation qualified for another architecture is never satisfied — it only removes
that alternative — so a request whose only alternatives are foreign fails
explicitly.

Sliced packages follow Chisel's package/slice essential graph and archive/store
selection semantics, not their DEB `Depends`. This preserves the purpose of
slicing. Whole/sliced overlap for the same package is an error. Runtime ELF
[closure checks](developer/hardening.md#the-static-elf-check) catch missing interpreters and libraries
later; they never silently widen a slice into a whole package. Whole-package
`Replaces` is not a blanket overwrite permission; selected slice conflicts follow
upstream `prefer` semantics. Generic VFS collisions and artifact overlaps need
explicit rules and tests.

## Determinism and output

VFS serialization emits uncompressed tar and computes DiffID ([layer
contract](developer/oci.md)). OCI compression
produces the compressed blob digest separately. Sort traversals and metadata;
normalize tar, config/history and generated attestation timestamps to the Unix
epoch. Preserve semantically ordered collections such as commands and source
alternatives. Never include host paths, current time, credentials or transient
warnings in digest inputs.

Signed DSSE envelopes may depend on the chosen signature algorithm's randomness;
deterministic unsigned payloads and subject digests remain separate promises.
Attestation subject/index relationships must avoid self-referential digests.

## Distribution expansion

1. **Ubuntu 26.04:** first complete pipeline, Canonical v3 catalogues, standard
   archives plus selected authenticated upstream sources as required for full compatibility.
2. **Debian:** implemented. Shared DEB machinery with Debian trust and release policy,
   custom v3 catalogues, an implicit main archive and a separately bound security
   archive. Never reinterpret an Ubuntu archive as Debian just because both use DEB
   packages.
3. **Alpine:** future provider work outside the current implementation plan.
   Its package format/trust model is not implemented by adding conditionals to VFS.
