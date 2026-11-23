---
title: OCI output
---

# OCI output

`internal/oci` turns a finished tree into OCI content: a layer, a config, a manifest,
a multi-platform index, a layout on disk, and optionally a registry push. Nothing here
reads the host or the clock, and nothing here decides what an image contains.

The split matters for reproducibility. The builder decides what is in the image; this
package decides how those bytes are written down. If the two were mixed, a change to
tar formatting could change what people believe the image is.

## On this page

- [OCI output](#oci-output)
  - [On this page](#on-this-page)
  - [Two identities for one layer](#two-identities-for-one-layer)
  - [Serializing a layer](#serializing-a-layer)
  - [Compressing](#compressing)
  - [Config and manifest](#config-and-manifest)
  - [The index](#the-index)
  - [Writing a layout](#writing-a-layout)
  - [Pushing](#pushing)
    - [Attachment uploads](#attachment-uploads)
  - [Working on this package](#working-on-this-package)

## Two identities for one layer

Every layer has two digests, and confusing them is the most common way to break an
image:

- **DiffID** is `sha256` of the *uncompressed* tar stream. The config's
  `rootfs.diff_ids` records it.
- **Digest** is `sha256` of the *compressed* blob, which is what a manifest descriptor
  points at.

They are separate values, computed at separate steps, and the compressed digest is
never derived from the uncompressed one. `WriteLayer` produces only the DiffID;
`CompressLayer` produces both by serializing and compressing in one pass.

Separate serialization and compression is what makes the compression level a free
choice: the DiffID does not change with it, so rebuilding an image at a different
level changes the blob and manifest digests and leaves the diff IDs alone.

## Serializing a layer

`WriteLayer` walks `tree.Entries()`, which is already sorted by path bytes. Nothing
about declaration order or map iteration can reach the archive.

The rules that make the tar deterministic:

- **Names are relative** and directories carry a trailing slash. The image root is not
  a member.
- **Every member has `ModTime` at the Unix epoch.** Tar stores whole seconds, so the
  epoch is the one value that needs no fractional-second extension and no clock.
- **No user or group names.** Only numeric uid and gid, so no host account can leak in
  through a name lookup.
- **Modes are the tree's own**, converted back to the tar header's Unix form.
- **Hard links** are written as a regular file at the first name and as link entries
  for the rest, so a shared inode stores its content once and every name survives.
- **Close is part of the digest.** The end-of-archive marker is written by
  `archive.Close()`, so it belongs to the hash and the size, not to a wrapper.

Before the first member is written, the layer refuses two trees:

- **An unresolvable symlink.** The builder checks the assembled tree, but a caller can
  hand any tree to the serializer, and a link that loops or crosses a regular file
  makes the layer describe a filesystem nobody can use.
- **A name beginning with `.wh.`.** OCI readers treat such a member as a deletion
  marker, so writing a real file under that name would delete its neighbours instead
  of adding content. No distribution package ships one, so the name is refused rather
  than escaped to something a reader would ignore.

## Compressing

`CompressLayer` streams the tar directly into gzip, so a layer is never held in
memory twice. The gzip header has no modification time, file name or comment, which
is why the blob depends on the tree and the level only.

Cancellation is checked before the first byte and on every write. A canceled build
stops promptly instead of finishing a layer nobody will use.

The compression level is chosen by the caller; a build always uses the library
default. The default is stable for a given library version, but it is not a promise
that the bytes equal any explicit level, so the level is part of what you record if
you care about blob identity.

## Config and manifest

`BuildImage` renders the config and the manifest from declared metadata and layer
identities, and refuses to invent anything.

- The config's `created` field is the epoch, never the current time.
- Environment variables are sorted, so a map cannot reorder them.
- Fields that were not declared are omitted rather than defaulted. An empty value in
  the config would be a claim the specification did not make.
- JSON is encoded canonically before hashing, so the digest is a function of the
  content and not of the encoder's field order.

The manifest references the config by digest and each layer by its compressed digest
and size. `MediaType` distinguishes an image manifest from an index.

Declared `annotations` reach the manifest through `ManifestAnnotations`, which refuses
the reserved `org.opencontainers.image.ref.name` because the tag list owns it, and
returns nothing for an empty declaration rather than an empty map. The builder passes
the declared map through unchanged, so an annotation reaches every platform manifest
and nothing else: the config carries no annotations, and `ref.name` appears only on
the tag descriptors a local layout writes. Every layer is therefore unchanged by an
annotation, and only the manifest digest moves.

## The index

An image with several platforms gets an index: one descriptor per platform, sorted by
platform string. `BuildIndex` refuses four situations outright:

- a declared platform with no image;
- an image for a platform that was not declared;
- two images claiming the same platform;
- no platforms at all.

Reordering platforms in the specification does not change the index, because both
builds contain the same images and the index sorts them. That is the same rule as
everywhere else in the pipeline: declaration order is not data.

A descriptor's digest and size describe the manifest bytes, so `BuildIndex` computes
both from those bytes instead of trusting the fields beside them. A caller that leaves
the fields empty gets them filled in; a caller that sets a digest or size that
disagrees with the bytes is refused, and so is an image with no manifest bytes at all.
The index is what a reader verifies a downloaded manifest against, so a descriptor it
publishes has to name something that exists.

`SubjectOf` exists so an attestation points at one platform's manifest instead of the
index. Nothing in the index needs it: an index descriptor names a manifest, and an
attachment that named the index would change the index it describes.

## Writing a layout

`Layout.WriteDirectory` and `Layout.WriteTarball` write the same content, so a local
build and a ``docker load``-able archive cannot drift apart.

Both stage first and publish second:

- the directory form writes into a temporary directory beside the destination and
  renames it into place, so a partial layout never appears where the caller asked for
  one;
- the tarball form writes to a temporary file, syncs, closes, sets `0644`, and renames.

Staging is not ceremony. A layout written directly into the destination would leave a
half-written `index.json` that a later tool would read as a real index.

Publication is one `rename`, which is what makes it atomic: the destination is either
absent or a complete layout, never a mixture. The destination must not exist when the
export starts, and a path that appears during staging fails the export rather than
being replaced, so an export never destroys content it did not create.

Both sinks take a context and check it before every entry and once more before the
rename. A canceled export removes its staging directory or temporary file and leaves
the destination untouched, including a previous archive under the tarball's name.

`entries()` lists every file in sorted path order for both outputs. A path that two images both need is written once. That is
ordinary for an artifact-only multi-platform build: both platforms end with the same
filesystem, so the same layer digest arrives twice, and a layout that refused the
repetition could not export such a build at all. Entries are collapsed only when they
describe the same bytes; the same path with different content still fails, because the
file can only hold one of them.

Declared tags reach a local layout as descriptors in `index.json`. Each tag is an
extra descriptor pointing at the build index digest with
`org.opencontainers.image.ref.name` set, so a reader can pull the tagged image from
the directory and the digest the build reported is the digest the tag pulls. Whenever
a tag exists the layout also writes the build index as a blob, because that descriptor
names it. With neither tags nor attachments, the directory's `index.json` is the
original build index.

Attached statements are extra entries in the same layout. Each one is an artifact
manifest whose `subject` is a platform manifest, so `index.json` lists it beside the
image descriptors while the build index blob stays byte for byte the one the build
printed. See [attachment](../developer/attest.md#how-a-build-attaches-them).

The tarball's `index.json` has one descriptor pointing to the original build index
blob. That blob still lists every platform. The outer descriptor carries the first
tag, if any. The archive omits attachments and extra tags to meet the single-entry
limit of readers such as `podman load`. Use the directory export to keep them.

## Pushing

`Layout.Push` is an explicit output step. Assembly does not contact a registry.

The rules are strict because a push is hard to undo:

- every reference must be fully qualified: a registry host, a repository and a tag.
  Strict parsing is what makes this a refusal rather than an inference, because the
  lenient parser reads `app:v1` as Docker Hub and `ghcr.io/team/app` as `latest`. A
  caller that meant either can reach this API, so the sink does not guess;
- callers supply tags, not digest references; the publisher derives digests from
  the built layout;
- every reference must name the **same repository**, because one upload session writes
  one repository;
- the pushed index is compared against the built index *before* the upload, and a
  mismatch aborts.

That last check is the interesting one. Vapor serves the bytes it built to the
registry client, so if the client computes a different index digest, something between
the build and the upload is wrong. Pushing anyway would publish content described by a
digest the user was never told about.

Failures are wrapped in `PushError`, which names the repository. Credentials are never
part of the error, the layout or the index.

### Attachment uploads

For a layout with attestations, `Layout.Push` stages the image index and its platform
images by digest. It uploads each statement's layer, config and manifest by digest
before writing tags. It uses one registry pusher for all stages, with the Referrers
API fallback disabled. A layout without attestations needs no Referrers API.

Tags are written one at a time. After a tag failure, the push result lists only the
tags confirmed to point to the index. A failed request can have taken effect if the
registry did not return a response.

## Working on this package

- Never let the clock or the host environment reach these bytes. A helper that calls
  `time.Now()` here breaks reproducibility for every image at once.
- Keep the DiffID and the digest separate. Any code that "derives" one from the other
  is wrong even when it happens to produce a working image.
- Add a determinism test with the new field: build twice with shuffled inputs and
  compare bytes, not just digests.
- Publications stage and rename. Do not add an in-place writer for convenience.
