---
title: Releases
---

# Releases

A release is a git tag on `main`, pushed. The workflow in
`.github/workflows/release.yml` runs the tests, then GoReleaser builds the
binaries, writes the archives and checksums, and publishes them as a GitHub
release. Pull requests are gated separately by `.github/workflows/ci.yml`, which
runs the lint and race-test jobs without publishing anything.

## What a release contains

| Artifact | Contents |
| --- | --- |
| `vapor_<version>_linux_amd64.tar.gz` | `vaporize`, both licence files, `README.md` |
| `vapor_<version>_linux_arm64.tar.gz` | the same, built for `linux/arm64` |
| `checksums.txt` | SHA-256 of each archive |

Only Linux is built. The mutation sandbox relies on Linux resource limits and
refuses any other platform at runtime, so a build for another OS would only fail
later.

The pipeline stamps the tag into the binary, which is why `vaporize version`
prints `v1.2.3` and not `1.2.3`: the tag with its `v` is the form Go uses as a
module version. The same value appears as the builder version in
provenance statements, so two images built by the same release name the same
builder.

## Cutting a release

```bash
git tag v1.2.3
git push origin v1.2.3
```

The tag push is the only trigger. A tag that does not look like `vX.Y.Z` still
starts the workflow, so tag deliberately.

The workflow needs no secrets beyond the repository token it is given: it only
writes a release on the repository it runs in. Every action is pinned by commit
SHA and both tool versions are pinned outright, so a release rebuilds with the
same tools it used before.

## Installing a release

```bash
go install github.com/matt-mai/vapor/cmd/vaporize@latest
```

Go resolves the version through the module path and the tag, so `@v1.2.3` installs
exactly that release and `@latest` installs the newest tag. A tarball from the
release page installs the same binary without a Go toolchain.

## Checking a release locally

GoReleaser can build everything without publishing:

```bash
goreleaser release --snapshot --clean --skip=publish
```

The result lands in `dist/`, including `checksums.txt`. `goreleaser check`
validates `.goreleaser.yaml` without building anything.
