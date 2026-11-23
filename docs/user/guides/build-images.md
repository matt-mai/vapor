---
layout: default
title: Build images
---

# Build images

Vapor works in two steps. `lock` fetches and verifies every input once, while you
have network access. `build` assembles the image from those saved inputs and never
downloads anything.

```bash
vaporize lock image.yaml     # needs network access
vaporize build image.yaml    # works offline
```

Both commands read `image.yaml` and write `image.lock.yaml` beside it by default,
so the paths in these examples are optional.

## Lock the inputs

```bash
vaporize lock
vaporize lock --spec app.yaml --output app.lock.yaml
```

`lock` reads the specification, picks the packages and slices it names, downloads
the Chisel catalogue, repository metadata and package archives, verifies
signatures and digests, and writes the lock file. Remote catalogues need `git` on
your machine. Progress goes to standard error
and the lock path goes to standard output, so this works:

```bash
vaporize inspect --lock "$(vaporize lock)"
```

Use `--cache-dir` or the `VAPOR_CACHE_DIR` environment variable to choose where
the verified bytes live. The default is `vapor` inside your user cache directory.

## Build the image

```bash
vaporize build
vaporize build --spec app.yaml --lock app.lock.yaml
```

The build reports each step on standard error and prints the digest of the image
it built on standard output:

```text
sha256:4bb671d5f0e874e887fc5e68bd915bb728446418854edb3d1f35eeaa108dab4d
```

Without `--oci-dir`, `--tarball` or `--push` the build writes no files. It still
assembles everything, so it is a good way to check that a lock works.

## Export the image

```bash
vaporize build --oci-dir out/image      # a layout directory
vaporize build --tarball out/image.tar  # the same layout as one file
```

Both flags can be given together and describe the same bytes. The layout is a
standard OCI image layout, so `podman load -i` reads the tarball and `skopeo
inspect oci:DIR` reads the directory.

A local export carries the tags from the specification. `--oci-dir` writes every tag
into the layout, so `skopeo copy oci:out/image:v1 ...` names the image you just built.
`--tarball` keeps every platform under one image index and carries only the first tag.

Every build creates a provenance document for each platform image, and an SPDX
document unless the specification turns the SBOM off. The statements that describe
them are included in the directory export and when you push, but not in the loadable
tarball. Use `--attestations-dir` to write the documents as plain files, without that
wrapper:

```bash
vaporize build --oci-dir out/image --attestations-dir out/attestations
ls out/attestations   # example.invalid-app-linux-amd64-provenance.json, …-spdx.json
grype sbom:out/attestations/example.invalid-app-linux-amd64-spdx.json
```

A scanner reads these files directly. The copies inside the image are wrapped in a
statement that names the image digest, which is what a verifier needs and what a
scanner cannot read.

Vapor only writes to destinations that are free to use. It builds the output next
to the destination and moves it into place when it is complete, so a failed build
never leaves a half-written layout.

| Output      | Destination                                       | Result              |
| ----------- | ------------------------------------------------- | ------------------- |
| `--oci-dir` | A path that does not exist yet                    | Created             |
| `--oci-dir` | An existing path, including an empty directory    | Refused             |
| `--attestations-dir` | An existing path                          | Reused, files replaced |
| `--tarball` | A path that does not exist yet | Created |
| `--tarball` | A symlink, directory or other file type           | Refused             |

To export a second time, choose another path or delete the earlier layout or tarball
first. A replaced attestation file is replaced in one step, so a reader never sees a
half-written statement.

## Push to a registry

```bash
vaporize build --push
```

The image name and tags come from the specification:

```yaml
image: ghcr.io/team/app
tags: [v1, "26.04"]
```

Every tag points at the whole image, so `v1` and `26.04` pull the same digest.
`--push` needs at least one tag; without one the build stops instead of inventing
a name. The image name needs a registry host, and each tag needs a value: Vapor never
adds a registry or a `latest` tag of its own.

The same specification tags reach a local export, as described under
[Export the image](#export-the-image).

Credentials come from `docker login` or `podman login`. Vapor reads the same
credential store, so there is nothing extra to set up. You can combine `--push`
with `--oci-dir` or `--tarball` to publish and keep a local copy in one run.

A push does not fetch build inputs. If a locked input is missing from the cache,
the build stops before uploading.

By default, Vapor publishes the image and its attestations before updating any tags.
If your registry does not support the Referrers API, the build stops without updating
tags. Use `vaporize build --push --image-only` to publish without registry
attestations. You can still keep them locally with `--attestations-dir` or `--oci-dir`.

If a tag write fails, the error identifies the tag Vapor could not confirm and lists
any earlier tags Vapor confirmed on the built digest.

## Build several platforms

List the platforms in the specification:

```yaml
platforms:
  - linux/amd64
  - linux/arm64
```

`linux/amd64` and `linux/arm64` are the supported platforms. Vapor builds them at
the same time by default and combines them into one image with one digest.

```bash
vaporize build --jobs 1   # one platform after another
```

`--jobs 1` is easier to follow in a log and uses less memory. `--jobs 0`, the
default, builds everything at once. More jobs than platforms changes nothing.
The result is the same either way: the same lock always prints the same digest.

## Repeat and compare builds

A repeated build from the same lock, cache and specification produces the same
bytes. Timestamps in the image are fixed values, not the day you ran the build.

Editing the specification means locking again, because the lock records the
specification it was made from:

```text
vaporize: operation failed: build lock structure: lock spec digest does not match the spec
```

Editing a catalogue that a lock already used also fails, because the build checks
each definition against the digest recorded in the lock. Lock again and review
what changed.

## APT sources inside the image

A finished image never installs anything, so by default it keeps no source list and
no repository keys. When `hardening.keep-package-sources` is `true`, Vapor writes
`/etc/apt/sources.list.d/vapor.sources` with the locked suites and components, and
points APT at a keyring holding only the locked public keys. A source list the image
already provides is left alone.

Vapor does not install APT and does not copy login details into the image. For a
private repository such as Ubuntu Pro, supply the credentials separately inside
the image.

## Next

- [Keep builds reproducible](keep-builds-reproducible.md) explains the lock file
  and the cache in more detail.
- [Troubleshoot](troubleshoot.md) covers the messages a failed build prints.
