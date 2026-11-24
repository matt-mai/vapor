---
title: Lock assembly
---

# Lock assembly

A lock answers one question: what exactly will this specification build, and what
evidence proves it? Everything the build needs to know about the outside world is
answered here, once, and written down.

The format is a data contract and is described in [lock schema](lock-schema.md).
This page is about the code that produces and consumes it.

## On this page

- [Why locking is separate from building](#why-locking-is-separate-from-building)
- [The shape of the work](#the-shape-of-the-work)
- [Assemble](#assemble)
- [Audit](#audit)
- [Compare](#compare)
- [What lockinput collects](#what-lockinput-collects)
- [What the lock deliberately does not hold](#what-the-lock-deliberately-does-not-hold)
- [Working on this package](#working-on-this-package)

## Why locking is separate from building

If a build could fetch, then "the build is offline" would be a promise in the
documentation. Instead the fetcher is simply not part of the build. Locking is where
the network lives, so it is where every outside-world answer has to be captured well
enough to be replayed.

That produces the interesting constraint for this package: a lock must contain
evidence, not conclusions. Saying "the repository was trusted" is not evidence.
Storing the signed metadata, the key material and the digest is, because the build
can then reach the same conclusion itself.

## The shape of the work

Two packages split the job.

`internal/lockinput` collects. It resolves the catalogue, snapshots local inputs,
binds archives, fetches metadata, resolves selections and fetches payloads. It
returns evidence and writes nothing. `internal/locking` writes. It takes that
evidence, assembles the header, verifies the structure, audits the cache, and
publishes the file.

The split exists for two practical reasons. The expensive half needs a network and a
provider and can be tested against a fake collector; the writing half needs neither
and is tested against fixed evidence. And it keeps the rule "collecting never
publishes" in the type signatures, where it cannot quietly erode.

## Assemble

`locking.Assemble` takes the specification, the provider and the collected evidence,
and produces the lock record:

1. write the `version` and the `spec` digest;
2. record the provider identity as the canonical distribution and release;
3. copy the collected local inputs, catalogues, repositories, packages, slices and
   artifacts;
4. run the structural checks.

The canonical release matters more than it looks. A specification may say
`resolute` and another may say `26.04`; both resolve to the same release, so the lock
records one identity rather than two spellings of the same thing. Otherwise two
specifications that mean the same image would produce different locks, and
`--check` would report drift that does not exist.

The header write is also where the digest gets frozen. If the specification changed
after the inputs were collected, the digest no longer matches and assembly fails,
which is the wanted outcome: a lock mixing evidence from one spec with the digest of
another is worse than no lock.

## Audit

`locking.Audit` proves the lock can be built from what is in the cache, without the
network. It does this by replaying the evidence and then opening every blob the lock
references.

`locking.Blobs` lists every cache entry a lock references, and the audit reads exactly
that list: it is the single enumeration of "what this lock needs". `vaporize cache gc`
uses it too, so removing space can never disagree with what the audit checks.

For each package and slice record, the payload it names must match the candidate the
authenticated index advertised, on name, version, architecture, path, SHA-256 and
size. This is the check that catches the subtle failure where the lock points at a
real package that is simply not the one the signed index described.

The audit returns statistics rather than nothing, because a caller usually wants to
report how much was checked. A lock that audits clean is a lock whose bytes were all
present and all still verified.

An audit does not prove the selection is right and does not try to. It checks bytes and
evidence, never whether the locked package set is a complete closure for the requested
roots. Checking that would mean resolving again, and the lock is an input, not a
claim to verify: it records what a build used. A lock is therefore a faithful record
of a build, not a proof that the build is correct. Whoever accepts a lock from
somewhere else reads its package and slice list.

## Compare

`locking.Compare` answers "is this lock still what the spec would produce". It keeps
two things apart on purpose:

- a reference move, such as a branch that now points at a different commit, reported
  as a ref move;
- a content difference, such as a package version that changed.

`vaporize lock --check` compares and fails when anything drifted. `vaporize lock
--diff` reports the difference and never writes. Both exist because the two useful
questions about a lock are "is it current" and "what changed", and answering them
with the same code as "write a new one" would make it hard to be sure a check
actually checked anything.

## Outdated

Faithful is not the same as actionable. Release metadata is re-signed on a schedule
and a repository index covers a whole suite, so `Compare` reports drift long before
anything the image contains moves. `lockinput.ResolveSelection` therefore stops
after doing the resolution, before any payload is acquired, and `locking.Updates` compares package and slice versions alone,
using the distro's version ordering. A candidate must be strictly newer to count,
and an unparsable version is ignored, so an answer nobody can read never prompts a
rebuild. Artifacts are excluded: a specification pins them by digest, so they cannot
move.

## What lockinput collects

The collector is where the outside world is touched, so its order is the order of the
authentication chain:

1. snapshot local inputs: trust keys, CA sources, VEX inputs and local catalogue
   directories, as bytes in the cache;
2. resolve the catalogue source, pinning a remote selector to a commit and
   snapshotting the tree;
3. bind catalogue archives to the provider;
4. load repository key material;
5. fetch and verify `InRelease`, then indexes;
6. resolve whole packages and slice closures against the verified candidates;
7. fetch the payloads the selections need, including Pro payloads when they are
   selected.

Step 7 has a rule worth stating: a restricted archive that no selection uses is not
fetched. Credentials are only used for content the build actually contains, so an
image without Pro content never needs Pro credentials.

The collector also fetches restricted archives only when the selection needs them,
which is why a lock can succeed on a machine that lacks credentials for archives the
specification mentions but does not use.

Every request in steps 5 to 7 goes through the retry policy described in
[acquisition](acquisition.md#retries). A retried request is reissued, not resumed, and
the bytes it finally returns are verified exactly like a first-attempt response, so a
retry cannot weaken the chain: a payload is either the locked bytes or a failure.

## What the lock deliberately does not hold

- Credentials, private keys, absolute host paths, timestamps and warnings.
- Redirect targets, since a redirect URL can carry a credential or a signature in
  its query.
- Conclusions without their bytes: every claimed hash has a size, and every one of
  those byte strings is in the cache.

Warnings and diagnostics are excluded because a lock is digest input. If a warning
could change a lock, then whether an operator saw a warning could change a build.

## Working on this package

- A new record field must be collected, verified structurally, and authenticated when
  the lock is consumed, in the same change. A field that is only written is a field
  nobody checks.
- Do not resolve anything here. If a value needs the network, it belongs to the
  collector; if it needs a check, it belongs to audit.
- Adding a new identity domain means a new domain label, never reuse of an existing
  one. See [lock schema](lock-schema.md#identity-digest-encodings).
- Structural verification is not authentication. Keep the two functions separate, and
  keep the documentation saying which is which.
