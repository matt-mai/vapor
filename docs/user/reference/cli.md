---
layout: default
title: Commands
---

# Commands

Vapor is one command, `vaporize`, with subcommands. This page lists every command
and flag it accepts today.

## Usage

```text
vaporize <command> [flags] [file]
```

Run `vaporize --help` for the command list and `vaporize help <command>` for one
command. For a `slices` subcommand use `vaporize slices <subcommand> --help`;
`help` only knows top-level commands and stops with `unknown help command`.
Help goes to standard output and needs no flags. `vaporize slices` with no
subcommand prints its own help and succeeds.

| Command   | What it does                                        |
| --------- | --------------------------------------------------- |
| `init`    | Writes a starter `image.yaml`.                      |
| `lock`    | Fetches and verifies every input, writes the lock.  |
| `build`   | Assembles images from a lock and exports or pushes. |
| `inspect` | Prints a lock file in canonical form.               |
| `outdated` | Reports packages a repository now offers newer.     |
| `cache`   | Reports and collects the verified input cache.      |
| `slices`  | Reads a Chisel catalogue on disk.                   |
| `vex`     | Generates OpenVEX statements from a lock.            |
| `version` | Prints the release version.                         |
| `help`    | Prints help for a command.                          |

## Exit codes

| Code | Meaning                                                                        |
| ---- | ------------------------------------------------------------------------------ |
| `0`  | The command succeeded.                                                         |
| `1`  | A command failed: a bad input, a failed check, a write error.                  |
| `2`  | The command line was wrong: unknown command, missing flag, too many arguments. |

Diagnostics and progress go to standard error. Standard output carries only the
result, so you can pipe it:

```bash
vaporize build --spec app.yaml > digest.txt
```

## Watching progress

While it works, a command keeps one line at the bottom of the terminal and rewrites
it. The line names the step, and while inputs are being collected it also names the
archive being fetched and how much has come down. A step with a known size grows a
bar:

```text
⠹ [4/4] write tarball — image.tar ███████░░░░░░░░ 52% 20.4 MiB/38.8 MiB 14s
```

Each finished step leaves a line behind, so the end of a run is a record of what it
did. The count names the steps the command actually planned: a build that writes no
output takes three steps and ends at `[3/3]`, while one that also writes a tarball
ends at `[4/4]`. A step the flags did not ask for is never counted and never missing.

Assembling is the step that runs longest, so the line follows it: it names the package
archive being unpacked, then the stage that follows, such as `compress layer`, and its
bar measures the locked archives the build has read. A build that makes several images
at once counts their archives together.

When output is not a terminal — a pipe, a log file, `CI` is set, or `TERM=dumb`
— there is no animation: every step is printed as one line, and collected inputs are
named every twentieth archive rather than rewritten in place.

Two flags turn it down further. Neither changes what a command does.

| Flag            | Effect                                                                  |
| --------------- | ----------------------------------------------------------------------- |
| `--no-progress` | No spinner or bar. Each step is one line, even in a terminal.            |
| `--quiet`       | The above, and the archives being collected are not named.               |

```bash
vaporize lock --quiet            # one line per step
vaporize build --no-progress     # steps only, no animation
```

The color of the animated line follows `NO_COLOR`.

## vaporize init

```text
vaporize init --distro debian --release trixie --name demo --dir demo
```

Writes `DIR/image.yaml` and prints `Created image.yaml`.

| Flag        | Required | Meaning                                          |
| ----------- | -------- | ------------------------------------------------ |
| `--distro`  | yes      | `debian` or `ubuntu`.                            |
| `--release` | yes      | `trixie` for Debian; `26.04` or `resolute` for Ubuntu. |
| `--name`    | yes      | Image name, also used as `ghcr.io/example/NAME`. |
| `--dir`     | yes      | Directory to write into. Created when missing.   |

All four flags are required. An existing `image.yaml` is never overwritten, and
there is no force option:

```text
vaporize: operation failed: generate starter: publish image.yaml without overwrite: linkat ... image.yaml: file exists
```

Each template names the release Vapor has reviewed for its distribution and
nothing else, so the result locks without a warning. A Debian starter asks for
`base-files` and `ca-certificates`: Debian's reviewed archives are the provider's
own, so it declares no repository, key or catalogue. An Ubuntu starter binds the
public archive to Canonical's catalogue, which it needs before it locks.

Any other distribution or release has no template:

```text
vaporize: operation failed: generate starter: no starter template: use --distro debian --release trixie or --distro ubuntu --release 26.04
```

## vaporize lock

```text
vaporize lock [spec] [flags]
```

Reads the specification, fetches and verifies every input and writes the lock. It
prints the path of the lock it wrote.

| Flag             | Default         | Meaning                                                         |
| ---------------- | --------------- | --------------------------------------------------------------- |
| `--spec`         | `image.yaml`    | Specification path.                                             |
| `-o`, `--output` | derived         | Lock path to write. Default: `image.lock.yaml` beside the spec. |
| `--cache-dir`    | your user cache | Where verified bytes are stored. `vapor` inside it.             |
| `--check`        | off             | Fail when the inputs drifted.                                   |
| `--diff`         | off             | Print drift and succeed.                                        |

`--check` and `--diff` cannot be combined, and neither writes a lock. The
specification may be given as a positional argument or with `--spec`, not both.
Giving both stops with `spec path supplied twice`. Without `--output`, the lock
sits beside the specification with the extension replaced: `app.yaml` becomes
`app.lock.yaml`.

## vaporize build

```text
vaporize build [spec] [flags]
```

Reads the lock, assembles each platform and prints the image digest.

| Flag           | Default         | Meaning                                                                                   |
| -------------- | --------------- | ----------------------------------------------------------------------------------------- |
| `--spec`       | `image.yaml`    | Specification path.                                                                       |
| `--lock`       | derived         | Lock path. Default: the spec path with `.lock.yaml`, so `app.yaml` gives `app.lock.yaml`. |
| `--cache-dir`  | your user cache | Where verified bytes are stored. `vapor` inside it.                                       |
| `--oci-dir`    | none            | Write an OCI layout to this new directory.                                                |
| `--tarball`    | none            | Write an OCI archive to this file.                                                        |
| `--push`       | off             | Publish the image and its attestations under the declared repository and tags.             |
| `--image-only` | off             | Skip registry attestations. Requires `--push`; local outputs are unchanged.               |
| `-j`, `--jobs` | `0`             | Platforms built at once; `0` means all of them.                                           |
| `--attestations-dir` | none      | Write each attestation document to this directory, creating it if needed.                 |
| `--sign-key`   | none            | PEM file with a PKCS#8 Ed25519 key; signs every attached statement.                       |

Every build produces a provenance document for each platform image, and an SPDX
document unless the specification turns the SBOM off. `--oci-dir` includes the
statements, which wrap those documents. A loadable `--tarball` contains the image but
not the statements. `--attestations-dir` writes the documents themselves, without the
wrapper, as plain JSON files named `<image>-<platform>-<format>.json`.

By default, `--push` uploads the image and statements by digest before it writes any
tags. If the registry does not support the Referrers API, the command fails without
changing tags. Vapor does not use the shared fallback tag. Use `--push --image-only`
to publish without registry attestations.

Tag updates are separate requests. If one fails, the error identifies the tag whose
write could not be confirmed and lists any earlier tags confirmed on the new digest.

`--oci-dir`, `--tarball` and `--attestations-dir` may be given together, but never two
of them with the same path.
`--oci-dir` and `--tarball` need new paths. They do not replace anything, even if
another process creates the path during the build. `--attestations-dir` can replace
existing statement files. A negative `--jobs` is refused.

`--push` needs at least one tag in the specification. It requires HTTPS for the
registry, authentication servers and any redirects.

## vaporize inspect

```text
vaporize inspect [lock] [flags]
```

Prints the lock in a fixed field order. It does not contact a server, read the
cache or change the file.

| Flag     | Default           | Meaning         |
| -------- | ----------------- | --------------- |
| `--lock` | `image.lock.yaml` | Lock file path. |

The lock may be a positional argument or `--lock`, not both; giving both stops
with `lock path supplied twice`.

## vaporize outdated

```text
vaporize outdated [lock] [flags]
```

Reports locked packages and slices a repository now offers a newer version of. Only
repository metadata is fetched: no package and no artifact is downloaded, so the
command adds nothing to the cache beyond the signed indexes it needs to answer.

| Flag        | Default           | Meaning                                     |
| ----------- | ----------------- | ------------------------------------------- |
| `--lock`    | `image.lock.yaml` | Lock file path.                             |
| `--spec`    | next to the lock  | Specification path.                         |
| `--cache-dir` | your user cache | Where verified bytes are stored.            |

Output is one line per update, on standard output:

```text
linux/amd64 package curl 8.5.0-2 -> 8.6.0-1
```

It exits `0` when nothing is newer, printing `no updates`, and `1` when something is.
A lock that does not describe the specification given is refused, because the answer
would be about a different image.

## vaporize cache

```text
vaporize cache <gc|clean|bundle|unbundle> [lock...] [flags]
```

These commands manage the verified input cache — the downloaded packages, indexes,
catalogues and files that `lock` and `build` read. Nothing is ever deleted unless you
add `--apply`, so you can always see what would go first.

| Flag        | Default               | Meaning                                             |
| ----------- | --------------------- | --------------------------------------------------- |
| `--cache-dir` | the user cache directory | Cache directory to report or collect.            |
| `--apply`   | off                   | Delete instead of only reporting.                    |
| `--min-age` | `1h`                  | Leave anything newer than this alone (`gc` only).    |

`cache gc` keeps every input a lock references and deletes the rest. Locks can be named
on the command line; without arguments it keeps every `*.lock.yaml` below the current
directory and stops with an error when it finds none. A lock that references an input
the cache no longer holds is reported, not treated as an error.

If `lock` or another `cache gc` is using the same cache, `cache gc` reports that the
cache is busy. Run it again after the other command finishes. If projects share a
cache, pass every lock file you want to keep, including those in other projects.

By default, `cache gc` also leaves files written in the last hour alone. Use
`--min-age 0` to turn off this age check.

`cache clean --apply` deletes all cached blobs, including inputs your locks reference.
Before building again, restore the cache from a backup or run `vaporize lock` to fetch
inputs and write a new lock. `build` never downloads missing inputs.

```text
$ vaporize cache gc --apply
kept 384 cached blobs referenced by 2 lock files
1 referenced blob absent from the cache
deleted 28 blobs (104.2 MiB)
0 blobs kept as recent
```

Build output layers live in the same cache, so `cache gc` removes them too. They are not
recorded in a lock, and the next build writes them again.

### Moving a locked build to another machine

```text
vaporize cache bundle <lock> --output <file>
vaporize cache unbundle <file>
```

`cache bundle` writes the inputs one lock references into a single file, and
`cache unbundle` adds them back to a cache. Together they move a locked build to a
machine that has no network:

```text
wrote 48 blobs (29.9 MiB) to app.bundle
added 48 blobs to /home/you/.cache/vapor, 0 blobs already present
```

Only the blobs the lock names are written: the release metadata, keys, package indexes
and package payloads of the repositories it used, its local inputs, catalogues and
artifacts. Output layers are never included. A blob that two entries name is written
once.

Nothing in a bundle is trusted on arrival. Each entry is hashed while it is stored and
must match the digest its path names, and an entry that is not a cache path is refused.
A blob the cache already holds is counted rather than stored again.

The build that follows re-reads everything: it checks the lock against the
specification, verifies each package against the metadata the lock recorded, and
refuses a blob whose digest does not match. It does not resolve dependencies again, so
a bundle is only as trustworthy as the lock it came from.

## vaporize slices

```text
vaporize slices <subcommand> --catalogue <dir>
```

The `--catalogue` flag names a directory that contains `chisel.yaml`. The flag
belongs to `slices`, so it comes before or after the subcommand but always on the
same command line.

| Subcommand | Meaning                                             |
| ---------- | --------------------------------------------------- |
| `list`     | Print one `package/slice` per line, sorted.         |
| `show`     | Print one slice definition.                         |
| `check`    | Validate the whole catalogue, print `catalogue OK`. |

`list` accepts `--package NAME` to narrow the result, and it can be repeated.
`show` takes one `PACKAGE/SLICE` argument. `check` takes no argument.

Use this [example slice definition](../../../internal/distro/slices/testdata/chisel-v3/catalogue/slices/base-files.yaml)
as a starting point for writing your own. Name the file `slices/<package>.yaml`
under your catalogue, then run `vaporize slices check --catalogue <dir>`.

None of the `slices` commands download anything. They read the catalogue you
point them at.

## vaporize vex

```text
vaporize vex [spec] [flags]
```

Assembles every platform from the lock, checks each vulnerability claim against the
finished files, and writes one OpenVEX statement per platform. It prints the path of
every statement it wrote.

| Flag          | Default         | Meaning                                                                                   |
| ------------- | --------------- | ----------------------------------------------------------------------------------------- |
| `--spec`      | `image.yaml`    | Specification path.                                                                       |
| `--lock`      | derived         | Lock path. Default: the spec path with `.lock.yaml`, so `app.yaml` gives `app.lock.yaml`. |
| `--cache-dir` | your user cache | Where verified bytes are stored. `vapor` inside it.                                       |
| `-o`, `--output` | `.`          | Directory the statements are written to.                                                  |
| `--sign-key`  | none            | PKCS#8 Ed25519 key; wraps each statement in a signed DSSE envelope.                        |

Statements are named after the image and platform, so `example.org/app` on
`linux/amd64` becomes `example.org-app-linux-amd64.openvex.json`. A file of that name
that already exists is replaced, and the new one is moved into place in a single step,
so nobody ever reads a half-written statement.

Without `--sign-key` the file holds the OpenVEX document itself. With it, the same
document is written inside a signed DSSE envelope instead, so verifiers can check who
wrote it. A key that cannot be read stops the command and writes nothing:

```text
vaporize: operation failed: attest: signing key is not a PEM document
```

The command only reads the spec, the lock and the cache. It contacts nothing, so a
statement is always about bytes the lock already recorded.

Generation stops without writing anything when:

- A claim names content the lock does not hold on that platform.
- An absent path is in the image, or cannot be checked.
- No claim applies to any platform, because an OpenVEX document has to state
  something.

A platform that no claim applies to is skipped without an error, as long as another
platform produced a statement.

## vaporize version

```text
vaporize version
```

Prints the version of the binary and nothing else, so scripts can read it. A
release prints its tag, as in `v1.2.3`. A binary built from a checkout prints the
commit it was built from, as in `v0.0.0-20261121093922-b4c61fc3a833`. That is the
same value that build records as the builder version in provenance statements.

## Environment variables

| Variable             | Effect                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `VAPOR_CACHE_DIR`    | Default for `--cache-dir`. Without it, the cache is `vapor` in your user cache directory, usually `~/.cache/vapor`. |
| `VAPOR_PRO_USERNAME` | Ubuntu Pro login name, usually `bearer`.                                                                            |
| `VAPOR_PRO_PASSWORD` | Ubuntu Pro token.                                                                                                   |
| `VAPOR_AUTH_DIR`     | Directory of APT credential files, default `/etc/apt/auth.conf.d`.                                                  |
