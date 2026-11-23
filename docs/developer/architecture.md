---
title: Architecture
---

# Architecture

Vapor reads a description of an image, resolves it against a distribution and a
catalogue, and writes an OCI image. The interesting part is not the list of
packages. It is the line the code draws between deciding what goes into an image
and producing the image bytes.

## On this page

- [The one rule](#the-one-rule)
- [The pipeline](#the-pipeline)
- [Packages and boundaries](#packages-and-boundaries)
- [Why the boundaries sit there](#why-the-boundaries-sit-there)
- [Trust flows one way](#trust-flows-one-way)
- [Determinism](#determinism)
- [Where policy lives](#where-policy-lives)
- [Failure rules](#failure-rules)
- [Extending Vapor](#extending-vapor)

## The one rule

Work happens in two stages, and the stage decides what the process is allowed to
do.

```
image.yaml
  → lock    network allowed, no image bytes
  → image.lock.yaml + verified cache
  → build   no fetcher at all, image bytes
```

Locking is where every question about the outside world is answered and recorded.
Building is where those answers are turned into an image, using nothing but bytes
that were recorded and verified before.

This is why `internal/builder` has no HTTP client and no Git runner. Not because
it would be untidy, but because a build that needs the network must fail instead
of quietly reaching out. The absence of the code is the guarantee. A missing or
corrupt input fails the build; it never triggers a download, and `--push` is the
only flag that authorizes new network traffic, as an explicit output step.

The second consequence is that every build input has to survive as evidence. A
lock does not say "trust me, I checked". It carries the signed metadata, the key
material and the digests that let the build check the same thing again offline.

## The pipeline

```text
image.yaml
  │
  ├─ schema        strict decode → defaults → validation → spec digest
  │
  ├─ lock
  │    ├─ catalogue     resolve tag/branch/commit, snapshot the tree
  │    ├─ distribution  provider policy, archives, suites, trust keys
  │    ├─ acquisition   download and verify keys, Release, indexes, payloads
  │    ├─ resolution    whole packages and slice closure
  │    └─ locking       assemble, audit and publish image.lock.yaml
  │
  └─ build
       ├─ vfs           in-memory tree with confined links
       ├─ artifact      place verified artifact payloads
       ├─ mutation      run slice scripts in a confined worker
       ├─ synthesis     generate accounts, timezone, release, CA, dpkg state
       ├─ hardening     remove shells, tooling, docs and set-id bits
       ├─ closure       prove every ELF dependency resolves inside the image
       └─ oci           deterministic tar → image → index → layout or push
```

Each stage page opens with the question that stage answers and the failure it is
responsible for. Read them in pipeline order and the package boundaries stop
looking arbitrary.

## Packages and boundaries

| Package | Owns | Deliberately does not |
| --- | --- | --- |
| `cmd/vaporize` | command tree, flags, exit codes, progress output | domain logic |
| `internal/schema/spec` | strict decoding, defaults, semantic validation, canonical digests | policy that depends on a distribution |
| `internal/catalogue` | catalogue trees, local and Git snapshots, link confinement, byte caching | slice definition parsing |
| `internal/distro` | provider contract, shared distribution records | Ubuntu or Debian specifics |
| `internal/distro/deb` | APT, OpenPGP, index parsing, DEB decoding | any distribution's default policy |
| `internal/distro/ubuntu` | Ubuntu releases, suites, architectures, archive and trust policy | shared DEB mechanics |
| `internal/distro/ubuntu/pro` | credentials for selected Pro archives | selection, persistence, unauthenticated fallback |
| `internal/distro/slices` | v3 catalogue parsing, slice graphs, content rules, origin selection | process isolation |
| `internal/distro/deb/resolver` | whole-package dependency resolution and backtracking | catalogue slices |
| `internal/acquire` | verified download of fixed payloads | choosing what to download, extraction |
| `internal/cache` | atomic content-addressed blobs | eviction, network, verification policy |
| `internal/snapshot` | local keys, CAs and VEX inputs as verified bytes | deciding which of them matter |
| `internal/verify` | offline replay of locked repository evidence | network, resolution, freshness policy |
| `internal/lockinput` | lock-time collection of everything the lock needs | writing a lock |
| `internal/locking` | lock assembly, audit, comparison | fetching, resolving |
| `internal/vfs` | in-memory tree, ownership and mode rules, confined link resolution, bounded archive import | hardening policy, ELF knowledge |
| `internal/xzguard` | decoder memory limits for every xz payload, enforced on the container before a decoder exists | decompression, other formats |
| `internal/artifact` | placement of verified payloads, confinement of unpacked links | fetching, verification |
| `internal/mutation` | sandboxed script execution with resource bounds | slice parsing, selection |
| `internal/synthesis` | the state no package supplies | script execution, host reads |
| `internal/hardening` | four removal passes and their conflict checks | deciding what an image should contain |
| `internal/closure` | static ELF dependency check | execution, package installation |
| `internal/builder` | offline orchestration of one build | any fetcher, Git runner or HTTP client |
| `internal/oci` | deterministic serialization, images, indexes, layout, push | deciding what goes in |
| `internal/ui` | progress and diagnostics | deciding what to report |

## Why the boundaries sit there

The package list is not a taxonomy of nouns. Each boundary answers a question a
reviewer would otherwise have to hold in their head.

`internal/schema` owns shape and internal consistency, not policy. Whether a
distribution exists, whether a suite is current, or what archive to use belongs to
`internal/distro`. That is why the loader hands back a defaulted specification and
`vaporize lock` calls the provider afterwards. A schema package that knew about
Ubuntu would have to change whenever a distribution did.

Version expressions are the one place where shape needs a grammar. Schema stores
and compares the string, but parses it with `deb.ParseConstraint`, because only
`internal/distro/deb` knows that a version has an epoch, an upstream part and a
Debian revision. Parsing in schema and matching in the resolver would split one
rule across two packages, so both sides call the same parser.

`internal/distro/deb` is shared mechanics with no opinion. Index parsing, signature
verification and DEB decoding are the same for every APT-based distribution, so the
distribution packages keep only their own policy. Debian can reuse the machinery
without inheriting Ubuntu's trust decisions.

Trust material flows one way: provider default, then explicit override, and never a
merge of the two. A catalogue may propose keys, but a proposal is not trust. A short
OpenPGP key ID is never a trust policy; only a full fingerprint is.

`internal/lockinput` collects and `internal/locking` writes. Splitting them means the
expensive, network-touching half can be tested with a fake collector and the writing
half with fixed evidence. It also keeps the rule "collecting never publishes" visible
in the type signatures rather than in a comment.

`internal/verify` replays evidence and `internal/acquire` gets it. Only the second
has the network. When a build needs to know that a repository was trusted at lock
time, it calls the replay and gets an answer with no way to reach the internet.

`internal/vfs` is an in-memory filesystem, not a wrapper around the host. It exists
because determinism and confinement have to be properties of the data structure
everything writes through: sorted traversal, explicit ownership, link resolution
that cannot leave the tree, and bounded archive import.

`internal/builder` is orchestration with an empty toolbox. It receives a lock, a
provider and a blob store, and composes the other stages. Anything it might be
tempted to fetch is something the lock should have recorded instead.

## Trust flows one way

```
configured full key fingerprint
  → verified InRelease (or Release + Release.gpg)
  → verified index SHA-256 and size
  → index parsing
  → verified package SHA-256 and size
  → extraction
```

Each arrow depends on the previous one. Nothing parses an index or extracts a
package before the step that authenticates it. During a build the same chain is
replayed from cached bytes, so verification is not a ceremony performed once at
lock time and then trusted forever.

The same rule applies to local inputs. Trust keys, CA bundles, VEX documents and
local catalogues are snapshotted into the cache as bytes with recorded hashes,
rather than re-read from a path later. Reading a file once to verify it and again
to use it would leave a gap where the file can change.

What a digest proves matters too. A content digest detects corruption and change.
It is not a publisher signature, and a Git commit pin proves which source was used,
not who is allowed to publish it. The two claims are kept separate everywhere.

## Determinism

Determinism is not a final cleanup pass. It is a set of choices made in each stage:

- Catalogue and filesystem traversal is sorted, never host enumeration order.
- Tar members are written in tree order with normalized ownership and epoch
  timestamps.
- The uncompressed layer serialization produces the DiffID; compression produces a
  separate digest. Mixing the two makes reproducibility impossible to reason about.
- Generated timestamps are epoch-normalized, including image history.
- Semantically ordered collections, like commands and source alternatives, keep
  their declared order.
- Warnings are diagnostics. They never enter digest inputs, lock bytes or image
  metadata, so an untested release warning cannot change a build.

## Where policy lives

Distribution-specific decisions live in `internal/distro` and nowhere else. No
`if distro == ubuntu` in the schema, the filesystem, the builder or the OCI writer.
Adding Debian means adding a provider, not editing four packages.

Hardening and closure checking are Vapor policies with no upstream counterpart, so
they are their own packages with frozen inventories and explicit conflict failures.
They never silently win over a declared path: if a removal pass would delete
something the specification asked for, the build fails and says which flag to turn
off.

## Failure rules

A single rule explains most of the error handling: a build must never be
surprisingly permissive. Whenever a pass cannot do what it was asked, or would have
to choose between two incompatible answers, it fails with an outer error that names
the stage and the offending path. Errors report what the operator can act on, not
raw library causes that may echo configuration or credentials.

The practical consequences:

- Two entries that collide but are not identical are an error, not last-writer-wins.
- A removal pass that would delete a declared path is an error.
- A missing ELF dependency fails the build; there is no warn-only mode.
- A resolution that cannot satisfy a constraint fails instead of picking something
  close.
- Every failure is collected and reported together where that is affordable, so one
  build does not reveal problems one at a time.

## Extending Vapor

Add a distribution by implementing the provider contract in `internal/distro`.
Add a catalogue source by teaching `internal/catalogue`. Add a specification field
by extending the strict schema, its defaults, its validation and its digest
projection together. Add output by teaching `internal/oci`, never by reaching into
the builder.

The rule behind all four: put the new behaviour where its question is already
answered, and keep the builder free of the outside world.
