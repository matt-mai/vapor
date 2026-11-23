---
layout: default
title: Keep builds reproducible
---

# Keep builds reproducible

A lock file records exactly which inputs a build used: repository metadata,
package versions, hashes and sizes. It is a recipe, not a copy of the
ingredients. The packages themselves sit in your cache.

Lock file and cache together are your build record. Keep both.

## What the lock holds

The lock records:

- The digest of the specification it was made from.
- The Ubuntu release and the platforms.
- Every catalogue, repository, key, package and artifact, with the digest and
  size that were verified.
- The commit each remote catalogue was fetched at.

Vapor writes the lock only after all of that is verified, and writes it in one
step, so a failed run never leaves a partial lock. The lock has no secrets in it.

## What the cache holds

Every verified byte Vapor downloads goes into the cache. Building reads those
bytes and checks each one against the digest and size in the lock. A file that
was changed or cut short is refused instead of used, and the build never asks an
archive what the current version is.

The default cache is `vapor` inside your user cache directory. Change it with

```bash
vaporize lock --cache-dir /srv/vapor-cache
vaporize build --cache-dir /srv/vapor-cache
```

or set `VAPOR_CACHE_DIR` once for both commands. Lock and build must use the same
cache.

## Keep the cache with the lock

A lock alone cannot rebuild an image. It records hashes, not packages, so a lost
cache means the bytes are gone.

Archives also drop old package versions over time, so a missing package may not
be downloadable even with network access.

If the cache is missing an input, lock again. That may choose newer package
versions and produce a different image. Back up the cache next to the lock file,
or rebuild both together, if you need to reproduce an old image later.

## Check for drift

```bash
vaporize lock --check
vaporize lock --diff
```

Both commands fetch and verify the current inputs and compare them with the lock
you already have. Neither writes a lock.

| Command        | Result                                         |
| -------------- | ---------------------------------------------- |
| `lock --check` | Exits with an error when anything differs.     |
| `lock --diff`  | Prints the differences and exits successfully. |

```text
changed: header spec: "sha256:8c5df91a..." -> "sha256:4f09c7cd..."
```

The two flags cannot be combined. Both may download new inputs into the cache,
because they acquire inputs exactly as a normal lock does.

A moved catalogue commit gets its own line, so it is not mixed up with changed
contents:

```text
ref moved: catalogue "ubuntu" commit 660fe6b9... -> 9f21c4a0...
```

A moved commit means the catalogue changed. That is not the same as one of your
slices changing, so read the other lines too.

## Ask whether anything needs rebuilding

The check above answers "is the lock still a faithful record of its inputs". That is
more than a build decision needs. Signed release files are re-signed about once a
week, and one index covers a whole suite, so an upload anywhere in that suite
changes it. A nightly `lock --check` therefore reports drift every night even when
the image would come out identical — and it downloads every payload to say so.

Ask the narrower question instead:

```bash
vaporize outdated
```

It reads the lock and its specification, fetches only signed metadata, and compares
what a fresh lock would select with what the lock records:

```text
linux/amd64 package curl 8.5.0-2 -> 8.6.0-1
```

No package and no artifact is downloaded, so the answer costs a few megabytes and
adds nothing to the cache except the indexes it needs. Exit `0` means nothing is
newer and a rebuild would produce the same image. Exit `1` means something moved
and a rebuild is worth doing:

```bash
if vaporize outdated; then
  echo "no rebuild needed"
else
  vaporize lock && vaporize build
fi
```

Only packages the image actually contains are compared. A newer version of
something you do not use cannot change the image, so it is not reported.

## Move a locked build to another machine

A bundle carries exactly the bytes one lock references, so a clean CI runner can
build offline without a copy of your whole cache:

```bash
# where you locked
vaporize cache bundle app.lock.yaml --output app.bundle

# on the build machine, before the build
vaporize cache unbundle app.bundle
vaporize build --lock app.lock.yaml
```

A bundle is a tar file of cache blobs. Nothing in it is trusted on arrival: every
blob is checked against its own digest before it is stored, so a bundle cannot
introduce content the lock does not name. A blob the cache already holds is counted
and skipped.

A bundle does not replace the lock file: carry both. The build reads only the cache
and never the network, so a lock without its bundle fails at the first missing
input instead of rebuilding something different.

### What replay checks

When you build from a lock you did not make, Vapor checks what it can check locally:

- The lock matches the specification, and the requested packages and slices still
  match the recorded pins.
- Every listed package is authenticated against the repository metadata the lock
  already recorded.
- Every blob in the bundle has the digest the lock names.

It does not resolve dependencies again. The locked package set is taken as given, so
a lock whose closure was incomplete when it was written stays incomplete.

That is deliberate: a lock is not a proof that a build is valid. It proves the bytes
are the ones it names, and says nothing about whether the selection they describe is
complete or the right one. Whoever made the lock made the selection; if you did not
make it, read the package and slice list before you build.

## Dates and expiry

Repository metadata carries a `Valid-Until` date. That date limits how old
metadata may be when you create a **new** lock. It does not expire an existing
one, and it is never a reason to delete cached bytes.

Signing keys can expire too. An existing lock keeps working after a key expires,
because the signature was valid when the lock was made. Revoked keys and failed
signature checks are still refused.

## Inspect a lock

```bash
vaporize inspect
vaporize inspect --lock app.lock.yaml
```

`inspect` prints the lock in a fixed order, so two locks can be compared by eye or
with `diff`. It does not contact any server, check the cache or change the lock.
See [lock file](../reference/lock-file.md) for what each section means.
