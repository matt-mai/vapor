---
title: Filesystem
---

# Filesystem

Every byte of an image passes through `internal/vfs.Tree` before it becomes a tar
layer. The tree is an in-memory filesystem: a map of clean absolute paths to nodes,
where several paths can name the same node.

It is a data structure rather than a wrapper around the host filesystem, and that
choice explains most of its rules. Determinism has to hold for traversal, ownership,
permissions and link resolution, and the only reliable way to get all four is to own
the implementation.

## On this page

- [What the tree guarantees](#what-the-tree-guarantees)
- [Nodes, entries and origins](#nodes-entries-and-origins)
- [Collision rules](#collision-rules)
- [Paths](#paths)
- [Resolving links](#resolving-links)
- [Declaring a path](#declaring-a-path)
- [Importing archives](#importing-archives)
- [Merging](#merging)
- [Placing artifacts](#placing-artifacts)
- [Why this is not `os`](#why-this-is-not-os)
- [Working on this package](#working-on-this-package)

## What the tree guarantees

- **Deterministic order.** Entries are sorted by path bytes. Nothing depends on how
  the host happened to enumerate a directory or on map iteration order.
- **Explicit ownership.** A node's `Attrs` carries uid, gid and mode. There is no
  "inherit from the host" fallback, because the host is not part of the image.
- **Confined resolution.** Following a symlink can never leave the tree, and `..` is
  interpreted by the filesystem rather than lexically.
- **Identical or failing collisions.** Two entries at the same path either describe
  the same thing or the operation fails. There is no last-writer-wins.
- **Bounded import.** Reading an archive has a ceiling on every dimension, so a
  hostile package cannot exhaust memory before a rule fires.

## Nodes, entries and origins

A `node` is one inode: kind, mode, uid, gid, content or link target. An `entry` is one
path and the inputs that declared it. Hard links are several entries naming one node,
so updating the mode through either path is visible through both.

`origins` records who asked for a path. That is not bookkeeping for its own sake: the
hardening passes need to know whether a path came from a specification declaration,
from Vapor's own synthesis, or from a package, because a pass that would delete a
declared path must fail rather than win quietly. Origins are the mechanism behind
"declared beats removed".

Directory creation is implicit where it has to be. Adding `/usr/bin/env` creates `/usr`
and `/usr/bin` as implicit `0755` directories, and a later explicit declaration can
apply real metadata to them. Snapshot-safety: a node is replaced rather than mutated,
so clearing bits in a clone never changes the tree the clone came from.

## Collision rules

Two entries collide when they share a path. The tree accepts a collision only when the
entries are identical: same kind, same content or target, same metadata. Otherwise the
operation fails, and the error names the path.

The alternative, "last one wins", is tempting and produces images whose content
depends on the order a map was walked or on which package happened to extract
second. When two inputs disagree about a path, someone has to decide, and a build is
the wrong place to make that decision silently.

Origins accumulate on identical entries, so a path provided by two packages still
knows both. That is how hardening can report that a file was removed although two
inputs declared it.

## Paths

Paths are clean and absolute. `validatePath` rejects the empty path, relative paths,
`.` and `..` segments, duplicate slashes, NUL bytes and non-UTF-8. The root `/` is
never an entry: it exists as an implicit directory so lookups and listings of `/`
behave normally, and it is never serialized into a layer.

## Resolving links

`Resolve` follows a path through symlinks with rules that are stricter than the
kernel's in one respect and identical in another:

- An absolute target restarts at the root. A link to `/etc/passwd` inside the image
  resolves to the image's `/etc/passwd`, never the host's.
- `..` is applied after expansion, so a link's target determines where `..` goes.
- `..` above the root stays at the root. Clipping is the behaviour a process inside
  the image would see, and the tree models the image, not the host.
- Resolution is bounded by a step budget, so a symlink loop fails instead of spinning.

`ResolveUnclean` exists for callers that hold a path with `..` in it and want the
filesystem's interpretation rather than a lexical guess. The ELF closure check uses
it, because `$ORIGIN/../lib` in a real binary means what the loader would do.

## Declaring a path

`Declare` is the entry point for specification-declared paths:

- an absent path is created with the declared kind and metadata;
- an existing path of the same kind receives metadata only, so a declaration can
  tighten permissions on a package's file without replacing its content;
- an existing path of a different kind is a conflict;
- a symlinked ancestor is rejected, because creating through a link would put the
  file somewhere the author did not name.

That last rule is the interesting one. `filesystem.paths` is a declaration about image
layout, and a declaration that silently lands wherever a package's symlink pointed is
not a declaration at all.

## Importing archives

`ImportTar` reads package and artifact payloads into a fresh tree. Package archives
are untrusted input, so the rules are explicit:

- member names must be clean relative paths, with `./` stripped;
- special files are rejected: no devices, sockets or FIFOs;
- hard links must name a regular file that appeared earlier in the stream;
- negative uid and gid are rejected;
- links are resolved once, after the whole stream, so member order does not change
  what a link means;
- a dangling symlink is kept, since images legitimately contain them.

`Limits` bounds entries, file size, total size, path length and total decompressed
stream size. The stream bound sits beneath `tar.Reader` because PAX and GNU headers
consume work before any entry rule applies: bounding what the import keeps is not the
same as bounding what it does.

`ImportArchive` sniffs compression from the leading bytes (gzip, zstd, xz) and drains
the reader after the last entry, so a truncated or over-long stream is noticed rather
than left half-read. Dictionary size is a memory commitment the archive chooses, so
an xz payload is checked by `xzguard` first (64 MiB, enforced on every block before a
decoder exists); see `docs/developer/distribution.md`. Zstandard enforces its own
window and memory limits.

## Merging

Each package is extracted into its own tree and then merged, so extraction cannot
partially mutate shared state.

`Merge` builds a staged path table first and only swaps it in when every entry has
been checked, which makes a failed merge leave the destination untouched. Identical
entries accumulate origins. Hard-link groups are reconciled across trees: two packages
that each hard-link the same content still produce one node with the right number of
names.

`Clone` and `Replace` support the mutation stage, which stages changes and applies
them all or not at all.

## Placing artifacts

`internal/artifact.Place` puts a verified artifact payload into a tree, and it is a
different job from importing a package.

**A standalone file** (`unpack: false`) is written at its destination with the
declared mode, uid and gid. The mode is required and is not taken from anywhere else,
because a downloaded executable has no meaningful host mode. It cannot target `/`.

**An unpacked archive** (`unpack: true`) is imported and then re-rooted at the
destination. Declared ownership applies to the placed content, and directories get
`DefaultDirMode` (`0755`) rather than whatever the artifact's author had.

**A package** (`unpack: package`) is decoded rather than placed, by the builder rather
than by `artifact.Place`. `internal/distro/deb` extracts both members of the archive,
the control stanza becomes a `synthesis.PackageState` with status `installed`, and the
data tree joins the image like a fetched package's tree. The stanza decides where its
files belong and records its dependencies, so `dest`, `uid`, `gid` and `mode` are
refused.

`mode` is refused for unpacked payloads: per-file modes come from the archive, and
accepting one mode for all of them would be a lie about what the field does.

Compression is detected from the leading bytes, so an artifact does not have to
declare how it was compressed. Links inside an unpacked artifact must resolve inside
the artifact's destination. Ownership of the destination's internal parent
directories is set explicitly, so an artifact cannot inherit a package's directory
ownership by accident.

`Place` does not fetch and does not verify. It receives bytes that were already
verified and turns them into tree entries. That split is what lets the artifact path
run during a build with no network.

## Why this is not `os`

Using the host filesystem would give correct-looking images and three problems:

- permissions and ownership would depend on the host's umask and user;
- traversal order would be whatever the kernel returns;
- confinement could only be checked after the fact, by inspecting paths.

The tree costs a map and some rules. It buys a filesystem whose behaviour is the same
on every machine and can be tested without touching a disk.

## Working on this package

- Any new entry point needs the four rules applied: clean path, confined links,
  identical-or-fail collisions, and a bound on input.
- Do not read the host. A helper that stats a host path will look harmless and will
  break reproducibility on another machine.
- When you add a rule, add the failing case for it. Most of these rules exist because
  the permissive version was wrong in a specific, testable way.
- Keep serialization in `internal/oci` and tree rules here. A tree that knew about tar
  would have two reasons to change.
