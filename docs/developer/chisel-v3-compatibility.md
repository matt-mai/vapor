---
title: Chisel v3 compatibility
---

# Chisel v3 compatibility

Vapor implements a subset of Canonical's Chisel v3: it reads the same catalogue
format, selects slices the same way, and applies the same path declarations. This page
records what that means precisely, which upstream commit the claim is measured against,
and where Vapor deliberately differs.

The rule behind the whole page: **parsing a document is not conformance.** Reading a
catalogue without error, reading upstream's source, or passing one of upstream's own
tests are three different things, and none of them proves that Vapor produces the same
image. Only a side-by-side comparison of outputs does.

## On this page

- Immutable baselines and source navigation
- Root definition, archives, maintenance and trust
- SDF syntax and dependency semantics
- Path operations, conflicts and temporary content
- Mutation lifecycle and generated manifest
- Store/bin boundary: do not invent an upstream protocol
- Intentional Vapor policies versus upstream behavior
- Fixture seed and feature-to-test checklist

## Immutable baselines and source navigation

Two upstream repositories are pinned. A pin is a reviewed commit, not a moving branch,
because a compatibility claim that drifts with upstream's main branch is not a claim
about anything.

| Repository | Reviewed commit | Role |
| --- | --- | --- |
| [canonical/chisel](https://github.com/canonical/chisel/tree/0a817bd22133d928ff8c3f3fcd5241ca877cbe06) | `0a817bd22133d928ff8c3f3fcd5241ca877cbe06` | Implementation and test oracle, limited to v3 behavior. This commit also carries v1, v2 and v4 support. |
| [canonical/chisel-releases](https://github.com/canonical/chisel-releases/tree/5500a569c5cf448afda69b25079230d4049fb530) | `5500a569c5cf448afda69b25079230d4049fb530` | The `ubuntu-26.04` catalogue snapshot. |

File paths and line numbers on this page are relative to canonical/chisel at that
commit, unless they are labelled as release records. Source archives were downloaded
for read-only inspection; the observed SHA256 values are recorded in fixture
provenance and are not treated as signed attestations. Updating a pin is a review
event, not a routine bump.

The implementation areas and the upstream tests that cover them:

| Area | Implementation | Upstream test anchor |
| --- | --- | --- |
| Root/SDF decoding | `internal/setup/yaml.go:28-229`, `internal/setup/yaml.go:249-678` | `internal/setup/setup_test.go:4566`, `TestParseRelease` |
| Validation and selection | `internal/setup/setup.go:215-386`, `internal/setup/setup.go:473-628` | `internal/setup/setup_test.go:2584-2985`, preference cases |
| Archive selection | `internal/slicer/slicer.go:493-555` | `internal/slicer/slicer_test.go:782-1105`, `TestRun` priority cases |
| Archive trust and indexes | `internal/archive/archive.go:311-557` | `internal/archive/archive_test.go:692-736`, `TestVerifyArchiveRelease`; by-hash cases at `internal/archive/archive_test.go:799-1095` |
| Extraction and globs | `internal/tarball/extract.go:98-286`, `internal/strdist/strdist.go:107-153` | `internal/tarball/extract_test.go:491`, `TestExtract` |
| Mutation | `internal/scripts/scripts.go:18-33`, `internal/scripts/scripts.go:140-220` | `internal/scripts/scripts_test.go:313`, `TestScripts` |
| Assembly lifecycle | `internal/slicer/slicer.go:78-429` | `internal/slicer/slicer_test.go:1999`, `TestRun` |
| Manifest | `internal/manifestutil/manifestutil.go:33-145`, `public/manifest/manifest.go:12-43` | `internal/manifestutil/manifestutil_test.go:542`, `TestGenerateManifests`; `internal/manifestutil/manifestutil_test.go:651`, `TestManifestValidate` |

These tests were **read, not executed**. One detail matters for planning: `TestParseRelease`
converts applicable older cases to v3 (`internal/setup/setup_test.go:4612-4652`), while
`TestRun` has no equivalent native-v3 assembly conversion. Vapor's assembly therefore
needs its own native-v3 tests; parser coverage does not imply assembly fidelity.

## Root definition, archives, maintenance and trust

`format: v3` belongs in the root `chisel.yaml` and never in a slice definition. The
root fields are `format`, `maintenance`, `archives`, `public-keys` and `stores`.

Upstream still decodes a legacy `v2-archives` field and rejects nonempty values in v3.
Vapor rejects the field's presence, including `null`, and has no legacy reader at all:
a silent upgrade path is a second code path that nobody tests.

### Archives and ordering

An archive has `version`, `suites`, `components`, `priority`, `pro` and `public-keys`.
`version` and the suite, component and key lists must be nonempty, and a catalogue
needs at least one archive even when it is store-oriented. There is no mirror URL
field in the root schema: endpoints belong to Vapor's provider mapping.

- An explicit priority is an integer in **[-1000, 1000]**, never 0. If any archive has
  one, all retained archives must. Priorities are unique.
- One archive may omit priority and is then treated as 0. Several archives may not.
- `default: true` is obsolete in v3; upstream accepts `false` as equivalent to absent.
- Automatic lookup skips negative priorities and picks the highest-priority archive
  that has the package. It does **not** compare versions across archives.
- A package's SDF `archive:` pin selects exactly that archive, including a negative
  priority one, with no fallback.
- Inside one archive the greatest Debian version wins. Equal versions keep the first
  one encountered across the ordered suites and components, so those lists are
  ordered data and must not be sorted.
- Recognized `pro` values are `esm-apps`, `esm-infra`, `fips`, `fips-updates`. Upstream
  logs and skips unknown values instead of failing. Vapor refuses unknown values
  rather than inventing an accepted service.

Evidence: `internal/setup/yaml.go:304-394`, `internal/setup/setup.go:304-326`,
`internal/slicer/slicer.go:493-555`; within-archive ordering at
`internal/archive/archive.go:121-207` and `internal/archive/archive_test.go:378-426`,
`TestFetchSecurityPackage`.

### Maintenance and public keys

Maintenance fields are ISO dates: `standard` and `end-of-life` are required, `expanded`
and `legacy` are optional. Upstream fills defaults when the whole block is empty and the
archive named `ubuntu` has a known version; it does not fill partial blocks and does not
check chronological order (`internal/setup/yaml.go:773-884`).

Vapor keeps the metadata and **warns** about EOL or short support instead of failing,
because a catalogue does not become wrong when a date passes. Clock-derived warnings
never change lock, image or attestation bytes. `standard` is the release date and starts
support; standard support ends at `expanded`, or at `end-of-life` when `expanded` is
unset.

Every public key has `id` and `armor`, and an archive's `public-keys` list refers to
them by name. Upstream decodes each key, requires exactly one public-key packet and no
private-key packet, and compares `id` with the key's 64-bit ID. That is
self-consistency: a key that agrees with its own label is not a key you trust.

Vapor requires independently configured **full fingerprints** and verified key
snapshots. `internal/distro/deb.LoadTrustedKeys` parses armored or binary snapshots and
trusts only configured fingerprints; `internal/distro/ubuntu` embeds the reviewed 2018
Ubuntu archive key as the default. Private key material and short key IDs are rejected.
See `internal/pgputil/openpgp.go:13-56` and `internal/pgputil/openpgp_test.go:23-68`,
`TestDecodeArchivePubKey`.

### Resolute snapshot facts

These are facts about the pinned release repository, not authentication evidence.
From `chisel.yaml:1-35` and `chisel.yaml:143-147`:

| Record | Value |
| --- | --- |
| Maintenance | standard `2026-04-23`, expanded `2031-05-29`, legacy `2036-04-23`, end-of-life `2038-04-27` |
| `ubuntu` | priority 10, version `26.04`, suites `[resolute, resolute-security, resolute-updates]`, components `[main, universe]` |
| `ubuntu-esm-apps` | priority 16, pro `esm-apps`, suites `[resolute-apps-security, resolute-apps-updates]`, components `[main]`, version `26.04` |
| `ubuntu-esm-infra` | priority 15, pro `esm-infra`, suites `[resolute-infra-security, resolute-infra-updates]`, components `[main]`, version `26.04` |
| Store `bin` | kind `bin`, version `26.04`, default-prefix `bin-` |
| `bin-slices/` | only `.gitkeep`; no bin package definitions in this snapshot |

Key fingerprints appear in catalogue comments: archive 2018
`F6ECB3762474EDA9D21B7022871920D1991BC93C`, apps
`E8A443CE358113D187BEE0E6AB01A101DB53907B`, ESM v2
`56F7650A24C9E9ECF87C4D8D4067E40313CB4B13` (`chisel.yaml:38-41`,
`chisel.yaml:73-76`, `chisel.yaml:108-111` in the release repository). None of them was
independently authenticated here, so a comment must not be promoted to a trusted
default.

## SDF syntax and dependency semantics

A slice definition has `package`, optional `archive`, `essential` and `slices`;
store-backed definitions also have `store` and `default-track`. A slice has `hint`,
`essential`, `contents` and `mutate`. The file's basename must equal `package`, and
nested directories are allowed.

In v3 both `essential` fields are **maps**: `other_slice: null` means unconditional,
`other_slice: {arch: [amd64, arm64]}` means filtered. `arch` accepts a scalar or a list.
Legacy essential lists and the `v3-essential` field are invalid in v3.

Package-level essentials apply to every slice except the receiving slice itself, and an
explicit self-essential fails. Repeating a dependency at package and slice level fails
rather than merging filters. Missing references and cycles fail globally, and cycle
detection deliberately ignores architecture filters. Selection traverses the matching
edges and orders dependencies before dependents.

A hint is printable metadata of at most **40 bytes**. It is not a selection directive.
Path architecture values are validated against Debian architectures upstream, while
essential architecture strings are copied without the same validation. Vapor preserves
other valid catalogue architectures even though it currently builds only amd64 and
arm64.

Evidence: `internal/setup/yaml.go:475-559`, `internal/setup/yaml.go:852-945`,
`internal/setup/setup.go:334-386`; tests at `internal/setup/setup_test.go:3814-4043`
for architecture, cycles and the v3 essential forms.

The real starter slice `base-files_release-info` closes over `base-files_copyright`,
`base-files_etc`, `base-files_lib` and itself, on amd64 and arm64. Its contents include
the Debian version, origin, host, issue, LSB and OS release files, and `lib` also
supplies architecture-filtered `/lib64` and `/usr/lib64/`. See
`slices/base-files.yaml:1-82` in the release repository. The synthetic fixture is a
**reduced subset**, not the filesystem a Canonical build would really produce.

## Path operations, conflicts and temporary content

Path keys are clean and absolute, and a trailing `/` marks a directory entry. Copies,
`make`, `text`, `symlink`, `mode`, `glob` and `prefer` are applied by
[content selection](catalogue.md#applying-content). `generate` is decoded and then
refused; see the manifest section below.

| Option | Meaning and important limits |
| --- | --- |
| null/empty, `copy` | Copy the same path, or another source in the same package archive. Directory selection is not recursive. A missing explicit path or an unmatched glob fails. |
| `make` | Synthesize a directory; requires the trailing `/`. Default synthesized mode is 0755. |
| `text` | Synthesize a file; the empty string is meaningful. Default mode is 0644. |
| `symlink` | Synthesize a link with the supplied target. It is not permission to escape the image. |
| `mode` | Nonzero octal permission override. Sticky modes matter. Copied-mode forwarding is one of the ambiguities listed below. |
| `arch` | Scalar or list filter. Absent or empty applies to every architecture. |
| `mutable` | Only text or a non-directory copy. Extracted hard links cannot be mutated. |
| `until` | Only the nonempty value `mutate`. The path survives **all** mutations and is removed after them. A shared path survives if any selected declaration retains it, and only empty temporary directories are removed. |
| `prefer` | Exact-path provider preference, not an essential dependency. Cannot prefer itself, an absent provider or path, or an invalid preference graph. The most-preferred **selected** provider wins. |
| `generate` | Parsed, then refused: Vapor does not implement manifests. |

Only one active path kind is allowed per entry. Globs support `?` (one non-slash
character), `*` (zero or more non-slash characters) and `**` (including slashes). They
are not shell globs: bracket classes do nothing. Globs allow `arch` and `until` but not
`mode`, `mutable`, `text`, `copy`, `make`, `symlink` or `prefer`.

Parents are implicit, and an explicit parent entry overrides an incidental one. This is
where a subtle rule lives: an unselected parent is seeded from the source archive's own
directory metadata, so selecting `/private/token` out of an archive whose `/private` is
`0700` keeps `0700` instead of widening it to the implicit `0755`. A parent that an
earlier declaration created only incidentally is seeded the same way, so declaration
order cannot decide the mode. Only an explicit parent declaration outranks the source.
The assembled layer keeps the seeded parent's mode and ownership. The parent stays
implicit in the tree and cannot be removed as declared content.

There is no `conflicts:` field. Conflicts are derived from declarations, and
catalogue-wide validation checks exact and glob overlap before selection. Identical
synthesized content may be shared; cross-package copies can conflict even when the
eventual bytes would be equal. Preference chains are validated globally, a preference
does not select its provider, and the chain is traversed through the catalogue so an
omitted provider does not break it. Two selected paths copied from the same source inode
stay one inode, which is why mutation still refuses to write through one name of a hard
link.

References: `internal/setup/yaml.go:577-678`, `internal/setup/setup.go:215-309`,
`internal/setup/setup.go:538-628`, `internal/setup/conflict.go:67-177`. Tests:
`TestConflictTree` at `internal/setup/conflict_test.go:127`, temporary cases in `TestRun`
at `internal/slicer/slicer_test.go:1141-1355`, preference extraction at
`internal/slicer/slicer_test.go:1811`.

## Mutation lifecycle and generated manifest

Upstream extracts all selected packages, creates synthetic content, runs mutations in
essential dependency order, removes temporary entries, and generates manifests. A
script may read content selected by other slices, not only its own. Starlark allows
top-level control flow and global reassignment. The exposed object is:

- `content.read(path)`: selected content as a string;
- `content.write(path, data)`: an existing selected mutable regular file, keeping its
  mode;
- `content.list(path)`: sorted immediate names, with directory names suffixed `/`.

No Debian maintainer scripts are executed. Upstream provides no interpreter memory or
step limits, and its host-filesystem helper is not Vapor's sandbox design. Bounded
resource use and root-confined, cycle-safe traversal are Vapor policies, described in
[mutation sandbox](mutation-sandbox.md).

### Manifests: upstream behavior, not implemented

Vapor parses `generate` and refuses it by name. Selecting `base-files_chisel` fails with
`requests "manifest", which Vapor does not support` rather than producing an image that
quietly lacks the file the slice asked for.

The rest of this section records what upstream does, so a future implementation starts
from evidence instead of a guess. `/var/lib/chisel/**: {generate: manifest}` emits
`/var/lib/chisel/manifest.wall`, **zstd-compressed JSONWall**, mode 0644. A generate
path ends in `/**` with no earlier wildcards, `arch` is accepted, and content-changing
options, `until` and `prefer` are forbidden. Unknown generate kinds parse upstream and
fail at selection. Several destinations receive the same stream.

The declaration is rare: `generate` appears once in the whole chisel-releases catalogue,
in `slices/base-files.yaml`, and that `chisel` slice is not in `base-files_base`'s
essential chain. Upstream's build path never reads the manifest back; consumers are
external tools, `canonical/ssbom` in particular.

JSONWall and the manifest schema are both `1.0`. The header is
`{"jsonwall":"1.0","schema":"1.0","count":N}` where the count includes the header. The
remaining serialized JSON objects are byte-sorted, one per line:

| `kind` | Fields in the upstream public model |
| --- | --- |
| `package` | `name`, `version`, `sha256`, `arch` |
| `slice` | fully qualified `name` |
| `content` | `slice`, `path` attribution edge |
| `path` | `path`, octal-string `mode`, sorted `slices`; optional `sha256`, `final_sha256`, `size`, `link`, `inode` |

Original file hashes and mutation final hashes are both reported; cleaned temporary
content is omitted. Shared hard links use numeric inode identities, and directory paths
end in `/`. The manifest registers itself before serialization without a recursive
content hash. Evidence: `internal/slicer/slicer.go:354-395`,
`internal/manifestutil/report.go:55-129`, `public/jsonwall/jsonwall.go:90-130`.

## Store/bin boundary: do not invent an upstream protocol

A store record needs `kind`, `version` and `default-prefix`. A store-backed slice
definition refers to a known store, sets `default-track` without a `/`, and cannot also
set `archive`. Its internal package name becomes prefix plus package (for example
`bin-demo`) while the filename and real name stay unprefixed. Prefix collisions fail.
Only the store kind `bin` is recognized; unknown kinds load and then fail at selection.

A store is conceptually an alternative package source. A normal package is downloaded
as a Debian archive and sliced; a store-backed package would be fetched as a prebuilt
blob identified by kind, track and revision, then sliced with the same definitions. It
bypasses Ubuntu's packaging, not slicing.

Upstream has not defined that protocol. Acquisition is unimplemented in the pinned
baseline at `internal/slicer/slicer.go:517-519`:

```text
cannot fetch package %q from store %q: not implemented
```

`TestRun`, case `Store package is not yet implemented` at
`internal/slicer/slicer_test.go:1982-1999`, confirms the boundary. So store metadata
parsing and an explicit refusal are testable, and working store acquisition is **not
established** by this pin.

Supporting a store later would need a reviewed contract for metadata authentication,
track-to-revision identity, blob digest and size verification, cache publication,
offline replay and the lock fields to record a store origin. None of those lock fields
exist in version 1, so they must not be invented ahead of the contract. Keep the goal
blocked rather than declaring it complete or disguising it as artifact support.

v3 reads the required `slices/` tree plus an optional `bin-slices/`, recursively.
Placing store packages under `bin-slices/` is a convention, not something the loader
enforces. v4 changes the directory behavior; Vapor does not accept v4.

## Intentional Vapor policies versus upstream behavior

Each row is a deliberate deviation. A deviation is honest when it is documented and
tested, and a bug when it is accidental. The
[conformance matrix](conformance-matrix.md) names the test for each row.

| Boundary | Vapor policy, not upstream inheritance |
| --- | --- |
| Schema | v3 only; strict rejection of unknown and duplicate fields, single document, no interpolation. Upstream ignores unknown fields and decodes once. |
| Trust | Externally configured full fingerprints; compressed index SHA256 **and size before decompression**, archive SHA256 and size before extraction; cached bytes reverified. Upstream verifies decompressed indexes, prefers SHA512, accepts missing package hashes, trusts cache hits and does not enforce these size checks. |
| Freshness | Enforce configured freshness on new locks, and replay retained evidence offline without today's expiry invalidating an old snapshot. Upstream has no Valid-Until enforcement and no detached-signature fallback path. |
| Maintenance | End-of-life and short support warn only. The upstream CLI rejects an unstable release (before `standard`) and otherwise ignores the dates. |
| Credentials | Only selected inputs need credentials; upstream opens every archive and skips the ones it cannot authenticate. Secrets never enter outputs. |
| Acquisition | The lock acquires every verified input; the build never fetches or re-resolves a mutable reference. Upstream fetches during slicing. |
| Safety | Bound mutation steps, allocations, output, time and filesystem growth before dangerous allocation, or run in a constrained worker. Never execute maintainer scripts. |
| Reproducibility | Epoch timestamps; deterministic traversal, inode assignment and serialization; clock, status and UI excluded from bytes. Signing randomness is a separate boundary. |

### Static observations needing executable decisions

These came from reading upstream's source. They are ambiguities, not Vapor rules, and
each one ends in a decision rather than a silence. Do not preserve or "fix" one under a
vague compatibility claim.

- Copied mode is parsed but the slicer does not forward it to extraction:
  `internal/slicer/slicer.go:135-139` versus `internal/tarball/extract.go:184-200`.
  Vapor decides: an omitted mode forwards the extracted mode, an explicit mode replaces
  the permission bits. See [content selection](catalogue.md#applying-content).
- Essential architecture typos are not validated the way path architecture values are:
  `internal/setup/yaml.go:872-902`.
- Manifest `arch` is accepted but `FindPaths` does not filter by it:
  `internal/manifestutil/manifestutil.go:37-46`.
- Writing an exclusively temporary mutable file can reach a missing-report-entry error:
  `internal/manifestutil/report.go:114-117`.
- Synthesized shared temporary attribution differs from extracted attribution:
  `internal/slicer/slicer_test.go:1141-1186`,
  `internal/slicer/slicer_test.go:1332-1355`.
- Change-then-revert mutation can leave a stale final hash:
  `internal/manifestutil/report.go:122-128`.

## Fixture seed and feature-to-test checklist

Fixtures and their provenance live in
[the seed README](../../internal/distro/slices/testdata/chisel-v3/README.md). Every
fixture payload is original CC0 synthetic data, because upstream catalogue licensing was
not established and no upstream test literal is vendored. The test-only key is not an
Ubuntu key and not a trusted default. No runtime dependency was added for fixtures.

`TestFixtures_ProvenanceAndIntegrity` checks pin identity, provenance hashes, missing and
unlisted fixtures, and JSON well-formedness. That proves fixture stability, **not** YAML
validity and not upstream semantic conformance.

Per-row status is tracked in the [conformance matrix](conformance-matrix.md), which names
the tests and records the blockers.

| Feature and required assertions | Seed/evidence | Planned area |
| --- | --- | --- |
| v3-only root, unknown/duplicate/extra docs; legacy fields rejected | `catalogue/chisel.yaml`; parser policy above | Catalogue parsing |
| Archive priority bounds/uniqueness/mixed omission, negative pins, no fallback, version ties and ordered suites/components | `catalogue/chisel.yaml`, `fixture.yaml`; upstream priority cases | Catalogue parsing, resolution |
| Maintenance dates/defaults and warning-only EOL/unstable; warnings outside digests | Root seed; maintenance tests at `internal/setup/setup_test.go:3032-3815` | Catalogue parsing, resolution |
| Key ID/armor consistency versus independent full-fingerprint trust; selected Pro credentials only, tamper/size/freshness/cache replay | Test key and root seed; generated signing keys later | Provider trust, acquisition |
| Starter selection/closure, package-self omission, explicit-self/duplicates/missing refs/cycles; native arch filtering | `base-files.yaml`, `expectations.json`, `invalid/list-essential.yaml` | Catalogue parsing, resolution |
| Hints 40/41 bytes/nonprintable, scalar/list arch, nonmatching/invalid arch policies | `fixture.yaml`; hint cases at `internal/setup/setup_test.go:1542-1583` | Catalogue parsing, resolution |
| Path kinds/empty text/clean keys, copied source/modes, explicit/implicit parents, hard links; missing matches | `fixture.yaml`, `invalid/mixed-path.yaml` | Filesystem assembly |
| Glob ?/*/**, arch/until and forbidden options; cross-package conflict/preference chains/subset winners/cycles | `fixture.yaml`, `provider.yaml`; `TestConflictTree` | Catalogue parsing, filesystem assembly |
| Mutation read/write/list, selected cross-slice reads, order, immutable/unlisted/hard-link rejection, shared temporary cleanup | `fixture.yaml`; `TestScripts`/`TestRun` | Mutation execution |
| Escape/cycle confinement, allocation/output/VFS/time/step exhaustion, rollback and deterministic execution | No safety claim from upstream; adversarial fixtures required | Mutation execution |
| Store prefix/track/kind/collisions and bin-slices discovery; selected unsupported acquisition fails explicitly | `bin-slices/demo.yaml`, `expectations.json`; upstream store cases | Catalogue parsing, resolution; store acquisition blocked |
| Manifest JSONWall/zstd/schema/count/order, original/final hashes, self registration, hard links and post-cleanup attribution | `fixture.yaml`; `TestGenerateManifests`/`TestReport` | Manifest generation |
| Native-v3 filesystem/manifest comparison, all ambiguities resolved, deterministic permutations and explicit policy deviations | Full checklist, mock inputs; separate opt-in upstream qualification | End-to-end conformance |

Before claiming full compatibility, every applicable row needs named Vapor tests and
recorded reference results. Track the store-success blocker separately: parsing store
metadata is not store support. Ordinary tests stay offline.

Executing native v3 against the same inputs is the only evidence that upgrades a row
from "Vapor does this" to "Vapor matches upstream". That comparison needs separately
authorized acquisition of the pinned upstream inputs and an offline replay, and it is
blocked until it exists. Until then, no full-compatibility claim is made.
