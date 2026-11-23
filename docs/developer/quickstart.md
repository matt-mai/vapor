---
title: Quickstart
---

# Quickstart

This page gets you from a fresh checkout to a passing test run and a first
change. It takes about ten minutes.

## On this page

- [What you need](#what-you-need)
- [Build and run](#build-and-run)
- [Make a first image](#make-a-first-image)
- [Run the tests](#run-the-tests)
- [Make your first change](#make-your-first-change)
- [Where things live](#where-things-live)
- [Rules that surprise people](#rules-that-surprise-people)
- [Next](#next)

## What you need

- Go 1.27.4 or newer. The module names that toolchain, so an older Go will
  refuse to build it.
- [Task](https://taskfile.dev) for the project shortcuts. Every command below
  also works if you type the underlying Go command yourself.
- Optional: `golangci-lint` for `task check`, and `podman` if you want to run
  the container end-to-end suite.

You do not need root, Docker, BuildKit or a container daemon. Nothing in the
build path requires privileges, and that is deliberate: if a change needs root,
the change is wrong.

## Build and run

```bash
task build          # writes ./bin/vaporize
./bin/vaporize --help
```

`vaporize` has five working commands: `init`, `lock`, `build`, `inspect` and
`cache`, plus `slices` for catalogue work.

## Make a first image

Start from a generated specification, then lock it:

```bash
./bin/vaporize init --distro debian --release trixie --name demo --dir demo-out
cd demo-out
../bin/vaporize lock
../bin/vaporize build --oci-dir ../dist
```

`init` writes `image.yaml` into an empty directory and refuses to overwrite
anything. `lock` uses the network: it resolves the catalogue, downloads package
and artifact payloads, verifies each one against signed repository metadata, and
writes `image.lock.yaml` next to the spec. `build` uses no network at all; it
assembles the image from bytes the cache already holds and writes an OCI image
layout into `dist/`.

The lock is the boundary. If you find yourself wanting a download during
`build`, the fix belongs in locking, not in the builder. See
[architecture](architecture.md) for why that split is the central design rule.

## Run the tests

```bash
task test           # go test -cover ./...
task check          # lint, then tests; this is the gate for every change
```

Tests are offline and deterministic. They use fixtures under
`internal/*/testdata`, in-memory trees and mock services, so they run without a
network and without root. If a test needs the network or a container engine it
belongs in `testdata/e2e`, which only runs when you ask:

```bash
task test:e2e       # needs network, podman, and several minutes
```

The end-to-end run builds every specification in `testdata/e2e/specs` from the
live Ubuntu archive, proves the result is reproducible, and boots it in a
container. It is not part of `task check`.

## Make your first change

1. Pick the package that owns the behaviour. The pipeline runs catalogues,
   distribution, acquisition, lock, filesystem, mutation, builder, hardening,
   output. [Architecture](architecture.md) maps each stage to its package, and
   each stage page explains why its boundary sits where it does.
2. Read the stage page before the code. The pages state rules the code enforces
   and name the function that enforces them, so you can check the rule and the
   implementation together.
3. Change the smallest thing that makes the behaviour right. If the change
   touches a rule another stage relies on, add the rule to that stage's page.
4. Run `task fix` and then `task check`. Both must be clean. Never weaken a test
   to get a green run; a failing test is telling you something.
5. Leave the change in the working tree. The developer commits.

## Where things live

```
cmd/vaporize/          command tree, flags, exit codes, progress output
internal/schema/       strict spec and lock decoding, defaults, validation, digests
internal/catalogue/    catalogue trees, local and Git snapshots, link confinement
internal/distro/       provider contracts, Ubuntu policy, DEB mechanics, resolution
internal/distro/ubuntu/pro/  selected Pro archive credentials
internal/acquire/      verified downloads of fixed payloads
internal/cache/        content-addressed blob store
internal/snapshot/     local trust keys, CAs and VEX inputs as verified bytes
internal/verify/       offline replay of locked repository evidence
internal/lockinput/    lock-time collection; returns evidence, writes no lock
internal/locking/      lock assembly, audit and comparison
internal/vfs/          in-memory filesystem, confined links, bounded archive import
internal/artifact/     placement of verified artifact payloads
internal/mutation/     sandboxed slice-script execution
internal/synthesis/    generated accounts, timezone, release, CA and dpkg state
internal/hardening/    the four post-synthesis removal passes
internal/closure/      static ELF closure check
internal/builder/      offline orchestration of the whole build
internal/oci/          deterministic tar, images, indexes, layout and push
internal/ui/           progress reporting
internal/starter/      `vaporize init` specification generator
internal/conformance/  the compatibility matrix, as tests only
testdata/e2e/          opt-in end-to-end runs against the live archive
```

## Rules that surprise people

- Do not commit. The developer commits when the change is reviewed.
- A new dependency needs a conversation first. The standard library and the
  existing helpers come first.
- Documentation states the rule, the reason and the consequence, and never points
  at a planning document. A reader should not have to leave the page to find out
  what is true today.
- The developer docs describe behaviour that exists. Planned behaviour is written
  up when it is implemented, so a reader never has to guess whether a paragraph is
  real.

## Next

If you are about to change the schema, start with
[specification loading](schema.md). If you are about to change a catalogue rule,
start with [catalogues](catalogue.md). If you only want the map, read
[architecture](architecture.md).
