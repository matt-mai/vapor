---
title: Catalogues
---

# Catalogues

A catalogue is a directory of slice definition files plus the `chisel.yaml` that
binds them to archives and keys. It is the input that decides which files an image
gets from a package.

Vapor reads catalogues in the upstream Chisel v3 format and refuses older formats.
Compatibility with upstream is a claim we have to be able to defend, so the parser
accepts exactly the v3 shape and rejects v1, v2 and v4 rather than guessing. See
[Chisel v3 compatibility](chisel-v3-compatibility.md) for what upstream does and
where Vapor deliberately differs.

## On this page

- [Why catalogues are snapshotted](#why-catalogues-are-snapshotted)
- [Getting a tree](#getting-a-tree)
- [Tree identity](#tree-identity)
- [Bounds](#bounds)
- [chisel.yaml](#chiselyaml)
- [Slice definitions](#slice-definitions)
- [Content kinds](#content-kinds)
- [Selecting slices](#selecting-slices)
- [Applying content](#applying-content)
- [Where packages come from](#where-packages-come-from)
- [Checking a catalogue](#checking-a-catalogue)
- [Working on this package](#working-on-this-package)

## Why catalogues are snapshotted

A catalogue that changes under a build is not an input, it is a moving target. Two
builds of the same specification would then produce different images with nothing in
the lock explaining why.

So the lock does not record "ubuntu-26.04". It records the tree: a canonical list of
paths, file digests and sizes, hashed into a catalogue tree digest. The build
re-digests the tree it was given and compares it with the lock. A catalogue that has
moved fails the build instead of quietly changing what "base-files" means.

## Getting a tree

Four sources, one result: a verified, read-only tree whose bytes are in the cache.

**Local directory.** `SnapshotDirectory` reads the specification's directory through
`os.Root`, so a symlink cannot lead outside it. Every file becomes a cached blob and
the tree is built from those blobs, not from the directory: a path that is read once
to verify and again to use is a path that can change in between.

**Local archive.** `SnapshotArchive` accepts an uncompressed tar or a gzip tar and
only directory, regular-file and symlink entries. Anything else is a failure, because
a device node or a hard link in a catalogue is not something a catalogue should
contain.

**Remote Git.** `ResolveRemote` pins a commit. It asks the host `git` for the
advertisement of one reference, fetches exactly that commit at depth 1, and exports
the tree with `git archive`. The bounds are 1 MiB of ref advertisement, 16 MiB of
tree inspection and 512 MiB of archive. A tag or branch is resolved here, once, and
the lock stores the commit; the build never runs `git` at all.

**Embedded in the binary.** `init` writes a starter that references a catalogue; the
lock is the thing that resolves it.

The remote path uses the host `git` binary rather than a Go Git implementation.
Vapor is a build tool that already assumes a working Unix host, and a Git client is a
large amount of protocol surface to own for one operation. The trade is explicit:
locking requires `git` when the catalogue is remote, and building never does.

## Tree identity

`Tree.Digest` is the identity of a catalogue tree:

```
payload  = {"entries": [...]}  in canonical JSON
digest   = sha256("vapor.lock.catalogue-tree.v1" + 0x00 + payload)
```

Entries are sorted by path bytes. Each path is clean, relative and slash-separated,
with no `.` or `..` segments and no leading or trailing slash. The root is never an
entry, and every directory has an explicit `dir` entry, including parents the archive
left out. A path's parents must all be directories, so a symlink cannot be an
ancestor.

A file entry carries its SHA-256, size and one bit: executable. Other permission bits
are deliberately not part of the identity, because a catalogue's job is to say which
files exist, not how the publisher's umask looked. Symlinks carry their exact target
string, unnormalized and unfollowed.

The digest is independent of compression, entry order, timestamps and ownership. That
is what makes it usable as a lock record: two acquisitions of the same tree produce
the same digest, and a changed byte produces a different one. Hardlinks, devices,
sockets, FIFOs and submodules are invalid: an archive is materialized into files,
directories and symlinks before the digest is computed, so there is nothing else to
represent.

The digest vectors, including the empty tree, are in
[lock schema](lock-schema.md#catalogue-tree), and a test compares them byte for byte.
Changing the payload shape is a lock compatibility event.

## Bounds

Catalogue input is untrusted in the sense that it comes from outside the project, so
every loop over it has a ceiling:

| Limit | Value |
| --- | --- |
| Entries in a tree | 100,000 |
| Single file | 64 MiB |
| Whole tree | 256 MiB |
| Path length | 4,096 bytes |
| Decompressed tar | 695 MiB |
| Archive headers | 100,001 |

These are not memory-safety proofs. They are the difference between failing with a
message and dying with an allocation.

## chisel.yaml

The root file must declare `format: v3`. Everything else about it is narrow on
purpose:

- `maintenance` and `archives` are read;
- `public-keys` and `stores` are read;
- `v2-archives`, `default`, and `format` values `v1`, `v2` and `v4` are rejected by
  name.

Rejecting by name is a deliberate choice over ignoring. A v2 document in a v3 field
means the catalogue author expected different semantics; silently reading it as if it
were v3 would produce an image that looks fine and is not what the catalogue said.
Recorded as unsupported, never half-built. See
[Chisel v3 compatibility](chisel-v3-compatibility.md#intentional-vapor-policies-versus-upstream-behavior)
for the inventory of these decisions.

**Maintenance dates.** A catalogue that names an `ubuntu` archive may leave its
`maintenance` dates out; the built-in Ubuntu lifecycle fills them in. Every other
catalogue must state `standard` and `end-of-life` itself, and a catalogue naming an
`ubuntu` archive cannot describe another distribution at all. A warning about dates
never changes a build, so guessing them for someone else's distribution would be a
guess that only shows up as a message.

**Archive priority.** One archive may omit its priority, which means zero. Two or
more archives must all declare one, each value must be unique, and the range is
`-1000` to `1000` excluding zero. The uniqueness rule removes a whole class of
"which one wins" questions at parse time.

**Keys.** Public keys are decoded at the packet level, not just tagged as PEM: one
primary public-key packet, no private material, no subkeys, and an armor header whose
key ID matches the packets. The full fingerprint is recorded, because a short key ID
is not a trust policy.

## Slice definitions

`ParsePackages` walks `slices/` and `bin-slices/` recursively. A file's basename must
equal the package it names, and the same package may not appear twice in the tree. The
second rule is what makes "the definition of this package" a single answer.

Each file declares the package, its archive, package-level essentials and its slices.
Slices may declare their own essentials, and those are copied onto each slice except
the slice that declared them. A reference to itself, or a duplicate reference, is
rejected at parse time. Missing references and cycles are left to `ValidatePackages`,
because they are graph properties that need the whole tree.

Hints are limited to 40 printable bytes. They end up in generated manifests and in
error messages, and an unbounded free-text field in either is not worth the risk.

## Content kinds

A slice lists content entries, and each entry names its kind. The default is `copy`.

| Kind | Effect |
| --- | --- |
| `copy` | Copy the named path from the extracted package. |
| `make` | Create a directory with mode `0755`. |
| `text` | Create a file with the given bytes and mode `0644`. |
| `symlink` | Create a link with mode `0777`. |
| `glob` | Expand a pattern inside the package. |
| `generate` | Produced by Vapor, not by the catalogue. Refused by name. |

`generate` is refused because it is Vapor's own mechanism; a catalogue that asked for
it would be asking for something the format does not mean.

Declared modes are only accepted for the kinds where they make sense. A symlink mode
is refused because link permissions are not a thing on Linux, and accepting one would
suggest they are.

`glob` follows upstream semantics rather than the shell's: no bracket character
classes, an unmatched pattern is a failure rather than an empty match, and the
expansion is sorted. Sorted expansion is what keeps two builds of the same catalogue
identical.

**Where to be careful:** Vapor lets an explicit `mode` replace the permission bits of a
copied file, while upstream ignores a declared mode on `copy`. This is one of the
deliberate divergences, recorded in the compatibility inventory and pinned by tests
(`TestApplyContent_ExplicitModeOverridesCopy`, `TestApplyContent_CopiesSpecialBits`).
It exists because a Vapor image should be able to normalize permissions, and it is
documented as a divergence rather than presented as upstream behaviour.

## Selecting slices

`SelectSlices` computes the dependency-first closure for one architecture. Roots are
sorted, so the result depends on the selection and not on the order someone typed it.
An empty architecture list means the slice applies to every architecture, which is how
a catalogue says "always".

Closure is over slice essentials, not DEB dependencies. That is the whole point of
slicing: a package's runtime dependencies are not the same thing as the files a slice
needs. Whole-package resolution is separate and is described in
[distribution](distribution.md).

## Applying content

`ApplyContent` walks the selection in dependency-first order and writes into a
`vfs.Tree`. Order matters, so it is fixed and not a map iteration. It returns the tree,
the paths marked `until: mutate` for later cleanup, and the hashes of mutable paths so a
build can prove it cleaned up what it created.

Conflicts are resolved before content is applied, not during: an exact path conflict is
detected across the whole selection first, globs second, and `prefer` chains are
resolved with an explicit rule. A winner without a preference is a failure, so no
build depends on the accident of which file was walked first.

## Where packages come from

`SelectPackageOrigins` decides which archive a package is taken from:

1. An archive pinned for the package wins, even with a negative priority, and there is
   no fallback. A pin means "exactly this", not "prefer this".
2. Otherwise the highest-priority archive wins; negative priorities are ignored.
3. Ties break on newest version, then earliest suite and component.

Store packages are rejected here, by name, with a message that says so. Upstream
cannot fetch them either; pretending otherwise would produce a lock that cannot be
built.

`DefinitionDigest` is the identity of a used slice definition: path, file SHA-256,
size and the included slice names in dependency-first order. Cross-package closure is
represented by the other package records, each with its own digest. A file for a
package that is not in the closure is omitted, so an unused definition does not change
the digest. Changing an unselected slice inside a used file does change it. That is
conservative on purpose: it is evidence that the definition was used, not a claim that
every slice in it was selected.

## Checking a catalogue

`CheckPackages` validates the whole graph after every file has parsed, so a problem
that spans two files is still found. Diagnostics are capped at 20 with a count of what
was omitted: a catalogue with two thousand problems should produce one readable message,
not two thousand lines.

## Working on this package

- Prefer a parse-time rejection to a runtime question. A rule that removes ambiguity is
  worth more than a rule that resolves it later.
- Any new loop over catalogue input needs a bound and a test for the bound.
- When you accept something upstream rejects, or reject something upstream accepts, add
  it to the [compatibility inventory](chisel-v3-compatibility.md) with the reason.
- Changing tree identity or definition identity is a lock-format change. Update the
  vectors in [lock schema](lock-schema.md) deliberately and say why.
