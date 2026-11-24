# Vapor

Vapor builds container images from a short YAML file.

You write down what the image should contain — packages, slices, files, users —
and Vapor does the rest: it downloads the packages, checks their signatures,
records everything in a lock file, and assembles an OCI image. No Docker daemon,
no BuildKit, no root.

```bash
vaporize init --distro debian --release trixie --name demo --dir demo
cd demo
vaporize lock          # fetch and verify the inputs, write image.lock.yaml
vaporize build --tarball image.tar
podman load -i image.tar
```

Building from the same lock always gives you the same image, on any machine,
without network access.

## Why Vapor

- **Small images.** Ask for a whole package, or just a slice — the files one
  feature needs. A slice image can ship `/etc/os-release` and certificates
  without a shell or a package manager.
- **Reproducible.** Every byte is pinned by hash in the lock file. Same lock,
  same image.
- **Rootless and daemonless.** No privileges, no container engine, no maintainer
  scripts. The output is an ordinary OCI layout, tarball or registry push.
- **Debian and Ubuntu.** Debian 13 (`trixie`) and Ubuntu 26.04, for
  `linux/amd64` and `linux/arm64`. Slice definitions come from Canonical's
  published Ubuntu catalogue, read exactly as Chisel reads it.

The bits Chisel leaves out — signing metadata checks, locking, sandboxed slice
scripts, hardening, library checks, image assembly — are what Vapor adds.
Vapor is an independent implementation, contains no Chisel code and is not
affiliated with Canonical.

## Install

```bash
go install github.com/matt-mai/vapor/cmd/vaporize@latest
```

Or take the `linux/amd64` / `linux/arm64` tarball from the release page. You need
Linux, network access for `vaporize lock`, and `git` only for Ubuntu images or
Debian slices. Podman or Docker only to run what you built.

Building from source needs Go 1.27.4 or newer:

```bash
task build          # writes bin/vaporize
```

## Learn more

- [Quickstart](docs/user/quickstart.md) — your first image, step by step.
- [User guide](docs/user/index.md) — all user documentation.
- [What works today](docs/user/reference/status.md) — finished and planned
  features.
- [Image specification](docs/user/reference/spec.md) — every field of
  `image.yaml`.
- [Developer documentation](docs/developer/index.md) — how the code is organised.
- [Architecture](docs/architecture-and-expansion.md) and
  [spec and lock contract](docs/image-spec-and-lockfile.md) — package boundaries,
  trust rules, file formats.
- [Chisel v3 compatibility](docs/developer/chisel-v3-compatibility.md) — the
  upstream commits Vapor matches and every deliberate difference.
- [Agent skill](skills/vapor-images/SKILL.md) — instructions for AI agents that
  author specs and build images with Vapor.

## Contributing

All contributions are welcome — bug reports, documentation fixes, new tests, code.
If you are unsure where something belongs, open an issue and ask first; a short
discussion beats a large rewrite that has to be thrown away.

New to the code? [Developer quickstart](docs/developer/quickstart.md) takes you
from a fresh checkout to a first change in about ten minutes.
[Developer documentation](docs/developer/index.md) then maps every part of the
pipeline — specification loading, catalogues, distribution and trust, locking,
filesystem, sandbox, builder, hardening, OCI output, attestations — to the page
that explains it.

Before you open a pull request:

```bash
task fix      # format and fix lint issues
task check    # linters and tests, must be clean
```

Tests use offline fixtures and mock services, so the ordinary suite needs no
network. The container end-to-end suite builds real images and needs an explicit
opt-in. Never weaken a test to hide a bug.

Some rules are worth knowing up front: no new dependency without discussing it
first, no root or Docker in the build path, no maintainer scripts, and behaviour
should follow Chisel v3 for the features Vapor implements.
[Testing](docs/developer/testing.md) and
[Chisel v3 compatibility](docs/developer/chisel-v3-compatibility.md) explain the
details.

## Credits

The slice catalogue format, slice definitions and Ubuntu package metadata are
[Chisel](https://github.com/canonical/chisel) and the
[Ubuntu slice catalogue](https://github.com/canonical/chisel-releases), copyright
Canonical Ltd. and contributors, AGPL-3.0. Packages come from the Ubuntu and
Debian archives and are the work of their maintainers.

## Licence

Split licensing, described in [LICENSING.md](LICENSING.md): the toolchain under
EUPL-1.2 ([LICENSE](LICENSE)), documentation and examples under CC0-1.0
([LICENSE-CC0](LICENSE-CC0)). Your specs, locks and built images are yours.
