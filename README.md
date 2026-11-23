# Vapor

Vapor builds container images from a short YAML file. You describe what the image
contains, and Vapor fetches the packages, checks their signatures, records them in
a lock file and assembles the image. No Docker daemon, no BuildKit, no root.

```bash
vaporize init --distro debian --release trixie --name demo --dir demo
cd demo
vaporize lock
vaporize build --tarball image.tar
podman load -i image.tar
```

Debian 13 (`trixie`) is the first supported release, with Ubuntu 26.04 beside it.
Images can target `linux/amd64` and `linux/arm64`.

## Packages, or just the files you need

A whole package brings every file it ships, which is what a Debian image needs by
default:

```yaml
contents:
  packages:
    - base-files
    - ca-certificates
```

That gives you the release files, the public certificate roots and the libraries
the packages depend on. No shell, no package manager, no `/bin/sh`, unless you ask
for one.

On Ubuntu you can go finer. A normal Ubuntu package installs every file it ships;
Vapor instead takes slices, groups of files that Canonical defines for each package
in a [catalogue](https://github.com/canonical/chisel-releases). Ask for one slice
and the image gets those files, the slices that one requires, and nothing else:

```yaml
contents:
  slices:
    - package: base-files
      slice: release-info
```

That slice gives you the release files (`/etc/os-release`, `/etc/issue`,
`/etc/debian_version`), a few directories and the package copyright. No shell, no
package manager, no `/bin`. Whole packages are still available when a slice is
not enough, and Debian slices work when you supply a catalogue of your own.

The catalogue format and the slice definitions come from
[Chisel](https://github.com/canonical/chisel), Canonical's tool for cutting down
Ubuntu packages. Vapor reads the same catalogue, selects slices the same way and
applies the same file rules, so you can name slices from Canonical's published
Ubuntu catalogue without converting anything. Vapor's intentional differences
from upstream are listed in
[Chisel v3 compatibility](docs/developer/chisel-v3-compatibility.md), together
with the upstream commits the comparison is measured against.

What Vapor adds around that is the rest of the job: verifying signed repository
metadata, writing the lock file, running slice scripts in a sandbox, hardening the
result, checking that every binary can find its libraries, and producing an OCI
image without a daemon or root.

Vapor is an independent implementation. It contains no Chisel code and is not
affiliated with or endorsed by Canonical.

## How it works

There are two steps:

| Step | Command | Network |
| --- | --- | --- |
| Collect and verify every input once | `vaporize lock` | yes |
| Assemble the image from those bytes | `vaporize build` | no |

The lock file records the exact package versions, catalogue commits, hashes and
sizes. A build reads only your local cache, checks each byte against the lock and
prints the image digest. The same lock gives the same image on any machine.

Vapor never runs a package maintainer script, never needs privileges, and writes
nothing outside the image it builds. The output is an OCI image: a layout
directory, a tarball, or a registry push.

## Install

Install the latest release with Go:

```bash
go install github.com/matt-mai/vapor/cmd/vaporize@latest
```

The release pages carry a `linux/amd64` and `linux/arm64` tarball with the binary,
the licence files and `checksums.txt`. Build from a checkout when you want the
newest commit:

```bash
task build          # writes bin/vaporize
# or
go build -o bin/vaporize ./cmd/vaporize
```

`vaporize version` prints the release you are running.

You need:

- Linux. Vapor needs no privileges to build, and it needs nothing from the
  container engine you deploy with.
- Go 1.27.4 or newer to build the CLI.
- Network access for `vaporize lock`, which reads the release's package archives.
- `git` only for remote catalogues, which means Ubuntu images and Debian images
  with slices. `vaporize init --distro debian` and any Debian image built from
  whole packages need no catalogue and no `git`.
- Unprivileged user namespaces only for slices that carry Starlark scripts: Vapor
  runs those in a sandbox built from namespaces. Whole-package images build
  without them.
- Podman or Docker only to run the images you build.

## Documentation

- [User guide](docs/user/index.md): every page of user documentation.
- [Quickstart](docs/user/quickstart.md): your first image in five steps.
- [Build images](docs/user/guides/build-images.md): lock, build, export, push,
  multi-platform.
- [Troubleshoot](docs/user/guides/troubleshoot.md): what each error means.
- [What works today](docs/user/reference/status.md): finished features and
  planned ones.
- [Developer documentation](docs/developer/index.md): the code, package by
  package, and where to start.
- [Chisel v3 compatibility](docs/developer/chisel-v3-compatibility.md): which
  upstream commits Vapor matches, and every deliberate difference.
- [Architecture](docs/architecture-and-expansion.md) and
  [spec and lock contract](docs/image-spec-and-lockfile.md): package boundaries,
  trust rules and the exact format of both files.
- [Agent skill](skills/vapor-images/SKILL.md): instructions for AI agents that
  author image specifications and build images with Vapor, including the
  builder/runtime split.

## Contributing

`task fix` formats and fixes lint issues, `task check` runs the linters and the
tests. Keep both clean. Tests use offline fixtures and mock services; the
container end-to-end suite needs an explicit opt-in.

## Credits

Vapor would have nothing to assemble without
[Chisel](https://github.com/canonical/chisel) and the
[Ubuntu slice catalogue](https://github.com/canonical/chisel-releases). The
catalogue format, the slice definitions and the Ubuntu package metadata are
Canonical's work, copyright Canonical Ltd. and contributors, released under
AGPL-3.0. Vapor reads catalogues in that format and shares no code with Chisel.

Packages and their files come from the Ubuntu archive and are the work of the
Debian and Ubuntu maintainers who build them.

## Licence

Split licensing, described in [LICENSE](LICENSE):

- The toolchain, CLI and Go source are under EUPL-1.2.
- Documentation, examples and templates are under CC0-1.0, see
  [LICENSE-CC0](LICENSE-CC0).
- Your specifications, lock files and the images built from them are yours, with
  no copyleft from this project.
