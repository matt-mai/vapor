---
layout: default
title: Vapor user guide
---

# Vapor user guide

Vapor builds container images from a short YAML file. You describe what the image
contains and Vapor fetches the packages, checks their signatures, records them in
a lock file, and assembles the image without Docker or root access.

You get the same image bytes every time you build from the same lock, on any
machine, with no network access.

## Quickstart

```bash
vaporize init --distro debian --release trixie --name demo --dir demo
cd demo
vaporize lock
vaporize build --tarball image.tar
podman load -i image.tar
```

[Full quickstart](quickstart.md) explains each step and how to run the result.

## What you need

- Linux. Unprivileged user namespaces are needed only for slices that carry
  Starlark scripts, which run in a sandbox built from namespaces. Whole-package
  images build without them.
- The `vaporize` command. Install the latest release with Go:

  ```bash
  go install github.com/matt-mai/vapor/cmd/vaporize@latest
  ```

  Or take a tarball from the release page. Go 1.27.4 or newer is needed to build
  it yourself:

  ```bash
  go build -o bin/vaporize ./cmd/vaporize
  ```

- Network access for `vaporize lock`. A build reads only the local cache and
  works offline. `--push` needs network access too.
- `git` only for remote catalogues: Ubuntu images and Debian images with slices.
  A Debian image made of whole packages needs neither `git` nor a catalogue.
- Podman or Docker only if you want to run the image you built.

## All pages

### Start here

- [Quickstart](quickstart.md) builds a first image in five commands.

### Guides

- [Build images](guides/build-images.md) covers locking, building, exporting and
  pushing.
- [Keep builds reproducible](guides/keep-builds-reproducible.md) explains the
  lock file, the cache and drift checks.
- [Add software](guides/add-software.md) selects packages and slices.
- [Add a third-party DEB repository](guides/add-third-party-repositories.md)
  uses nginx.org packages alongside Ubuntu's archive.
- [Add your own files](guides/add-your-own-files.md) puts binaries and archives
  into the image.
- [Configure the system](guides/configure-the-system.md) sets up directories,
  users, timezone, certificates, release information and package tooling.
- [Build a Debian image](guides/build-debian-images.md) covers Debian releases, the
  main and security archives, and Debian catalogues.
- [Use private packages](guides/use-private-packages.md) configures Ubuntu Pro
  and your own package servers.
- [Troubleshoot](guides/troubleshoot.md) lists common messages and what to do.

### Reference

- [Commands](reference/cli.md) lists every command, flag and exit code.
- [Image specification](reference/spec.md) describes every field of `image.yaml`.
- [Contents](reference/contents.md) covers packages, slices, catalogues and
  artifacts.
- [Filesystem](reference/filesystem.md) covers paths, accounts, timezone,
  certificates and release information.
- [Policies](reference/policies.md) covers hardening and script limits.
- [Lock file](reference/lock-file.md) describes what `inspect` prints.
- [What works today](reference/status.md) separates finished features from
  planned ones.

## Conventions

Field names, commands and flags appear in `backticks`. Blocks marked `text` are
what Vapor prints, so you can compare them with your own terminal. Long digests
are shortened with `...`; the value in a real message is the full hash.
