---
name: vapor-images
description: Build hardened, reproducible container images with Vapor (the `vaporize` CLI). Use when asked to author an image spec (image.yaml), lock and build images, choose packages/slices/artifacts, split builder vs runtime images, or fix spec/lock/build errors.
---

# Building container images with Vapor

Vapor is a rootless, daemonless CLI that turns a short YAML file (`image.yaml`)
into a reproducible OCI container image. You describe the image's end state —
packages, slices, files, users, timezone — and Vapor verifies every input into a
lock file, then assembles the image offline with no Docker and no root. Same
lock, same image bytes, on any machine.

This skill is self-contained: everything needed to author, lock and build an
image is in this directory. Read the matching reference file before writing the
part of the spec it covers:

| File | Covers |
| --- | --- |
| `reference/spec.md` | Every `image.yaml` field: container, contents, repositories, artifacts, filesystem, hardening, local paths. |
| `reference/distros.md` | Debian vs Ubuntu: releases, implicit archives, security suites, builder/runtime pairs. |
| `reference/chisel.md` | Chisel catalogues and slice files, for any distro without an upstream catalogue (Debian included). |

## Install and the basic workflow

Vapor is a Go program. Build it from a checkout:

```bash
go build -o bin/vaporize ./cmd/vaporize   # from a vapor source checkout; Go version per its go.mod
```

You need Linux, `git` only for remote catalogues, and Podman or Docker only to
*run* the images you build. Unprivileged user namespaces are needed only for
slices that carry Starlark scripts. The workflow is always:

```bash
vaporize init --distro debian --release trixie --name <name> --dir <dir>  # or --distro ubuntu --release 26.04; all four flags required
cd <dir>
vaporize lock                                                              # after EVERY spec change
vaporize build --oci-dir out                                               # offline, reads only the lock + cache
podman load -i out.tar && podman run --rm --entrypoint /app/app <image-id>  # or build --tarball image.tar
```

`--oci-dir` and `--tarball` refuse an existing path (`already exists; choose a
new path`), so remove the directory between builds. Vapor never starts a
container: check that an image runs with the engine you deploy it with.

Supported: `--distro ubuntu --release 26.04` (codename `resolute`) and
`--distro debian --release trixie` (codename for `13`; `bookworm`/`12` locks with
a warning). Platforms `linux/amd64` and `linux/arm64`. `vaporize init` writes a
starter for either: `--distro debian --release trixie` gives a Debian image built
from two whole packages and no catalogue, `--distro ubuntu --release 26.04` gives
an Ubuntu image with a slice.

## The core rule: declare end state, never procedures

Vapor **never runs Debian maintainer scripts** (`postinst` etc.). Whatever a
package's scripts would have created, you declare yourself:

- users/groups → `filesystem.accounts` (declared users get a locked `*` password)
- files, directories, symlinks (with uid/gid/mode) → `filesystem.paths`
- timezone → `filesystem.timezone` (real zones need a tzdata slice; `UTC` works without)
- certificates → `filesystem.ca`, release identity → `filesystem.os-release`
- dpkg status + file lists, the `_apt` sandbox account, and apt sources only with
  `hardening.keep-package-sources: true` → Vapor writes these itself from verified
  package metadata

Prefer slices (Canonical's Chisel format) or custom slices over whole packages:
a slice ships only the files you need and may carry its own small sandboxed
mutation script for in-image config edits.

## Spec essentials (image.yaml)

```yaml
version: 1
name: demo                      # lowercase letters, digits, _ . -
image: ghcr.io/team/app         # repository, no tag
distro: ubuntu
release: "26.04"                # quote it
platforms: [linux/amd64]        # or both linux/amd64, linux/arm64
tags: [v1]                      # pushed by --push
contents:
  repositories:                 # where packages come from (starter writes the public Ubuntu archive)
    - name: ubuntu
      platforms: [linux/amd64]
      endpoints: [{platforms: [linux/amd64], url: https://archive.ubuntu.com/ubuntu}]
      suites: [resolute, resolute-security, resolute-updates]
      components: [main, universe]
  catalogues:                   # where slice definitions come from
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
      archives: {ubuntu: ubuntu}
  slices:                       # package + slice (+ optional version constraint, catalogue)
    - {package: base-files, slice: release-info}
  packages:                     # whole packages only as a last resort; optional version constraint
    - busybox-static            # unpinned: the name alone
    - {name: curl, version: "~> 8.5"}  # pinned to the 8.x line; needs the mapping form
  artifacts: []                 # your own verified binaries, see below
  slices-engine: {max-steps: 100000}
container:
  user: "65532:65532"           # name, uid or uid:gid
  entrypoint: [/app/server]
  cmd: ["--port", "8080"]
  workdir: /app
  env: {MODE: production}
  ports: ["8080/tcp"]
  stop-signal: SIGTERM
filesystem:
  accounts:
    groups: [{name: app, gid: 65532}]
    users:  [{name: app, uid: 65532, gid: 65532, home: /app}]
  paths:
    - {path: /app/data, type: directory, uid: 65532, gid: 65532, mode: "0750"}
    - {path: /app/current, type: symlink, target: /app/server}
  timezone: UTC
hardening:                    # all four default true; runtime images keep them
  strip-docs: true
  strip-shells: true
  strip-apt-dpkg: true
  remove-suid-sgid: true
```

Rules that bite: a package cannot be requested both whole and sliced; `sha256`
is 64 lowercase hex digits without a prefix; `unpack` must be explicit; `mode`
is only allowed when `unpack: false`; spec errors fail at `lock` before any
download. `filesystem.accounts` `home` and `shell` are metadata only — a
`workdir` still has to be declared as a directory in `filesystem.paths`, and a
shell the image does not ship simply never runs. Full field rules:
`reference/spec.md`.

The one trap that silently breaks a runtime image: **hardening removes files
that slices put there, without an error.** `strip-shells` deletes `/usr/bin/sh`
and friends even though a slice asked for them, so anything needing a shell —
pip's console script, a `#!/bin/sh` wrapper an artifact ships — is dead on
arrival. Only a `filesystem.paths` declaration conflicts loudly. If the runtime
really needs a shell, say so explicitly, and keep that trade visible:

```yaml
hardening: {strip-shells: false}   # also brings /bin/sh and its siblings back
```

Otherwise run the tool through the interpreter it belongs to
(`python -m pip`, `node script.js`), and check that path by running the image
with the engine you deploy it with.

## Builder vs runtime images

Always split an application into two images:

- **Builder image**: for compiling. Runs as **root** (`container.user: "0:0"`),
  keeps the shell and package manager, carries the toolchain and build deps:

  ```yaml
  hardening: {strip-shells: false, strip-apt-dpkg: false}
  ```

- **Runtime image**: the final, minimal image. Only the runtime libraries
  (often a libc slice), the app binary, and a non-root user. Keep all hardening
  passes on (default), `container.user: "65532:65532"`, and set
  `entrypoint`/`cmd` to the app.

Typical flow: build the app inside the builder image, then place the resulting
binary in the runtime image via an artifact or declared path.

### Whole packages on a builder, slices on a runtime

The two images record their packages differently, and that decides which
content each one may use:

- A **runtime image** slices whatever the catalogue offers. Nothing installs onto
  it, so it only needs the files it runs.
- A **builder image** selects every package whole, slices included: name `apt`,
  `dpkg`, `bash`, `ca-certificates` — never `apt/apt-get` and friends.

Vapor writes a `Status:` field per record in `/var/lib/dpkg/status` only when the
image holds no slice. One slice anywhere turns it off for the whole database,
which is how a package manager is kept from reporting a phantom upgrade at a
version already present and then re-unpacking the package. The cost is that apt
can no longer see anything is installed — `apt-get install` still works, `apt-get
remove` of a present package does not, which is exactly what a builder needs. A
database that mixes the two shapes is worse: apt stops every operation with
`E: Unmet dependencies`. So a builder is all-whole or it is broken; do not add one
slice to a builder for a single helper file.

Check it on the built image: `dpkg --list <pkg>` must show `ii`, not `un`.

## Choosing content

Pick per need, not by a fixed ranking. An artifact is often the *best* choice
even before slices: if you need a version the Ubuntu archive does not carry
(e.g. a newer Python from Astral's `astral.sh/python-build-standalone`, or Go
from `go.dev/dl`), take the artifact directly instead of hunting for a package.

1. **Slices** (`contents.slices`) — the default for distro software in a
   **runtime image**. Slices are groups of files defined by Canonical's
   **Chisel** catalogue, which exists for
   Ubuntu only; for Debian whole packages are the default and a slice needs a
   catalogue you write yourself, see `reference/chisel.md`. A **builder image**
   must not slice: see
   [Whole packages on a builder](#whole-packages-on-a-builder-slices-on-a-runtime).
   Browse what exists — these commands read a catalogue already on disk and
   download nothing:
   ```bash
   git clone --depth 1 --branch ubuntu-26.04 https://github.com/canonical/chisel-releases catalogue
   vaporize slices list --catalogue catalogue [--package NAME]
   vaporize slices show <package>/<slice> --catalogue catalogue
   vaporize slices check --catalogue catalogue
   ```
2. **Artifacts** (`contents.artifacts`) — your own verified binaries, ideal when
   the archive version is too old or missing entirely. Each needs `dest`,
   `unpack` (false = copy one file, true = extract archive), per-platform
   `sources` and required `sbom: {name: ..., version: ...}`. A source is either
   `path`, a file beside `image.yaml`, or `url`, a remote download; either way it
   carries a `sha256` (compute with `sha256sum`). Prefer `path` for your own
   files, which keeps the build offline and the spec self-contained:
   ```yaml
   artifacts:
     - name: server
       dest: /usr/local/bin/server
       unpack: false
       mode: "0755"
       sources:
         - {platforms: [linux/amd64], path: files/server-amd64, sha256: <64 hex>}
       sbom: {name: server, version: "1.0"}
     - name: toolchain
       dest: /usr/local
       unpack: true
       sources:
         - {platforms: [linux/amd64], url: https://go.dev/dl/go1.27.4.linux-amd64.tar.gz, sha256: <64 hex>}
       sbom: {name: go, version: "1.27.4"}
   ```
   A `path` is relative to the directory holding `image.yaml`, uses forward
   slashes, and may not point outside that directory. A `url` may not carry
   credentials, a query string or a fragment, but redirects are followed, so a
   `github.com/<owner>/<repo>/releases/download/...` link works — its 302 target
   carries the signature in its query, and that is allowed over HTTPS.
   `unpack: true` keeps the archive's own top directory and its modes, so expose
   a versioned binary with `filesystem.paths` symlinks.
3. **Custom slices** — if no published slice fits, write `slices/<package>.yaml`
   in a local catalogue. See the [slice definition example](reference/chisel.md#slice-definition-format).
   Check it with `vaporize slices check --catalogue catalogues/local`.
   Read the `.deb` file list first: `slices check` checks the definitions, while
   `vaporize lock` checks that the package contains the declared paths.
4. **Whole packages** (`contents.packages`) — last resort, only when neither a
   slice nor a custom slice is practical. Brings the package's full file list.

## Build, export, multi-platform

```bash
vaporize lock                                  # writes image.lock.yaml beside the spec
vaporize build --tarball image.tar             # OCI archive; --oci-dir out for a layout
vaporize build --push                          # needs tags: [...] in the spec
vaporize build -j 0 --tarball image.tar        # build all platforms at once
vaporize inspect                               # show what the lock recorded
```

Every build generates provenance and an SPDX SBOM unless the spec disables the
SBOM with `sbom: {enabled: false}`. `--attestations-dir dir` writes the statements
as plain JSON. `--push` uploads attestations before updating tags. For a registry
without the Referrers API, use `--push --image-only` and keep a local copy if needed.

The lock and the cache are both needed to rebuild: the lock (`image.lock.yaml`)
records digests and versions, the cache (`--cache-dir`, default `vapor` inside
your user cache directory, or `VAPOR_CACHE_DIR`) holds the verified bytes.
`build` never downloads — a missing cache blob fails with `open cache blob ...
no such file`. Back the cache up next to the lock if you must reproduce an old
image later: archives drop old package versions, so re-locking may pick newer
ones and produce a different image.

Drift and updates: `vaporize lock --check` fails when the current inputs differ
from the lock, `vaporize lock --diff` prints the drift and succeeds; the two
cannot be combined and neither writes a lock. `vaporize outdated` lists the
packages a repository now offers newer (exit `1` when something is newer,
`no updates` and exit `0` otherwise).

## More commands, flags, environment

```bash
vaporize lock --no-progress                  # or --quiet: one line per step, no spinner
vaporize build --sign-key key.pem            # PKCS#8 Ed25519; signs every attestation
vaporize cache gc [--apply] [lock...]        # keep blobs the locks reference, delete the rest
vaporize cache clean --apply                 # delete everything, including referenced blobs
vaporize cache bundle <lock> --output app.bundle   # one lock's inputs, as one file
vaporize cache unbundle app.bundle                 # restore them into a cache
vaporize vex -o out/                         # OpenVEX statements per platform, from the lock
vaporize version                             # prints the release tag or build commit
```

- `cache bundle` + `cache unbundle` move a locked build to a machine with no
  network: unbundle there, then `build` works offline. Only blobs the lock names
  are bundled, and nothing in a bundle is trusted on arrival — every entry is
  re-hashed against its digest.
- `cache gc` without `--apply` only reports; `--min-age 1h` (default) protects
  recently written files, `--min-age 0` turns that off. Locks can be named
  positionally; without arguments it keeps every `*.lock.yaml` below the current
  directory and errors when it finds none. Pass every lock you want to keep when
  projects share a cache.
- Exit codes: `0` success, `1` the command failed (bad input, failed check),
  `2` the command line was wrong. Diagnostics and progress go to stderr; stdout
  carries only the result, so `vaporize build > digest.txt` works.
- Environment variables: `VAPOR_CACHE_DIR` (default for `--cache-dir`),
  `VAPOR_PRO_USERNAME` / `VAPOR_PRO_PASSWORD` (Ubuntu Pro login, usually `bearer`
  plus the token), `VAPOR_AUTH_DIR` (APT credential files, default
  `/etc/apt/auth.conf.d`).

## Fixing failures

Errors name their cause; fix the spec, never weaken validation:

- `lock spec digest does not match the spec` → spec changed after locking; `vaporize lock` again.
- `open cache blob ... no such file` → cache lost; re-lock with the same `--cache-dir` / `VAPOR_CACHE_DIR`.
- `catalogue definition does not match its locked digest` → on-disk catalogue changed; re-lock and review.
- `ELF closure: /usr/bin/x: interpreter ... is missing` → add the slice/package with the loader/library, or use a static binary.
- `timezone "Europe/Berlin" needs selected zoneinfo ...` → add a tzdata slice or use `UTC`.
- `user "app" requires primary gid 65532, which the image does not define` → declare the group in `filesystem.accounts.groups`.
- `hardening.strip-shells: /bin/sh is declared in filesystem.paths` → disable that pass or drop the declaration.
- `filesystem.paths /usr/bin: ... conflicts with existing directory` → declare the type that actually exists.
- `whole-package/slice overlap is not allowed` → pick one form per package.
- `no starter template: use --distro ubuntu --release 26.04 or resolute` → only Ubuntu 26.04/resolute has a starter spec; a Debian spec is hand-written.
- `workdir "/app" does not exist` → declare `/app` as a directory in `filesystem.paths`.
- `download failed: HTTP 502` → the host or a proxy refused or failed the
  transfer; retry, or fetch the file another way and use `path`.
- `download failed: timed out` → the payload stopped arriving, often because a
  proxy inspects the body before releasing it; retry, or use `path`.
- `download failed (details redacted)` → the transfer failed for a reason Vapor
  will not print, because the message would quote the request URL; check the URL
  with `curl -I` and use `path` if it stays unreachable.
- `slice <pkg> path <path> is missing from package "<pkg>"` → the slice names a
  file the package does not ship; list the `.deb` and correct the slice.
- `--oci-dir` refuses an existing path; `--push` requires at least one tag.

## Rules of thumb

- Lock after every change to `image.yaml`; build only from the lock. Builds are offline and fail on missing/corrupt cache data.
- Narrow a slice or package `version` with an operator (`=`, `!=`, `>`, `>=`, `<`, `<=`,
  `~>`) when the archive's newest is not what you want: `~> 1.27` stays on 1.27. A bare
  version is refused.
- Podman/Docker are only for running images; Vapor needs neither.
- Slices and catalogues live in `reference/chisel.md`; distro differences in
  `reference/distros.md`; every field in `reference/spec.md`.
