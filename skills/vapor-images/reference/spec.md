# Image spec reference (image.yaml)

Everything here is enforced by `vaporize lock`; a violation fails before any
download. Field names are exact, unknown keys are rejected.

## Top level

| Key | Rules |
| --- | --- |
| `version` | `1`. |
| `name` | `^[a-z0-9][a-z0-9_.-]{0,127}$`. |
| `image` | Fully qualified repository, no tag and no digest (`example.com/team/app`). |
| `tags` | Free-form tag list. |
| `annotations` | String map, copied to the image config. |
| `distro` | `ubuntu` or `debian`. |
| `release` | String, quoted. |
| `platforms` | Subset of `linux/amd64`, `linux/arm64`. |
| `container`, `contents`, `filesystem`, `hardening`, `sbom`, `vex` | Below. |

## container

```yaml
container:
  user: "65532:65532"     # name, uid, or uid:gid
  entrypoint: [/app/server]
  cmd: ["--port", "8080"]
  workdir: /app
  ports: ["8080/tcp"]
  stop-signal: SIGTERM
  env: {PATH: /usr/local/bin:/usr/bin:/bin}
```

`workdir` must be a clean absolute path **and must exist in the image**, so
declare it in `filesystem.paths` as a directory. A missing one fails the run with
`workdir "/app" does not exist`. The entrypoint may name anything; nothing checks
it exists, so `podman run` is where a wrong interpreter path surfaces.

## contents

```yaml
contents:
  repositories: [...]
  catalogues: [...]
  slices: [...]
  packages: [...]
  artifacts: [...]
  slices-engine: {max-steps: 100000}
```

`{}` is accepted. Order is irrelevant to the result.

### repositories

```yaml
repositories:
  - name: debian
    platforms: [linux/amd64]                     # defaults to the spec's platforms
    endpoints:
      - {platforms: [linux/amd64], url: https://deb.debian.org/debian}
    suites: [trixie, trixie-updates]              # ordered, unique
    components: [main]
    by-hash: prefer                               # prefer (default) | require | disable
    freshness: {valid-until: require}             # if-present (default) | require
    trust:
      keys: [{path: keys/repo.asc, fingerprints: [<40 or 64 hex>]}]
```

- Endpoints must cover every platform the repository is used on.
- Trust key paths are relative files, unique, and may sit above the spec
  (`../keys/repo.asc`). Short key IDs are refused; fingerprints are 40 or 64 hex
  characters.
- A `trust` block **replaces** the built-in trust, it never merges with it.
- Both distros have a built-in main archive, so `repositories` is often
  unnecessary. See `distros.md`.

### catalogues

```yaml
catalogues:
  - name: trixie
    path: ../../shared/slices/trixie            # local, relative to the spec
    archives: {debian: debian, debian-security: debian-security}
  - name: ubuntu
    url: https://github.com/canonical/chisel-releases
    branch: ubuntu-26.04                        # exactly one of tag/branch/commit
```

- A local `path` is relative to the directory holding `image.yaml`, must be clean
  and slash-separated, and cannot be absolute or climb out of that directory
  (`local path must be nonempty, clean, relative and slash-separated`). It is
  snapshotted with `os.OpenRoot`, so a symlink cannot escape either.
- `path` is exclusive with `url`/`tag`/`branch`/`commit`.
- A remote catalogue needs `url` plus exactly one selector; `commit` is a full 40
  or 64 lowercase hex SHA. Resolving it needs host `git` at `lock` time only.
- A **local** catalogue is locked by content (a tree digest), so editing a slice
  file changes the lock; a **remote** one is locked by commit.
- `archives:` maps a catalogue archive name to a repository name. An archive named
  after the distro falls back to the built-in archive when unbound; any other
  needs a binding (`catalogue archive "internal" requires an explicit repository
  binding`).
- With exactly one catalogue declared, `slices[].catalogue` may be omitted.

### slices and packages

```yaml
slices:
  - {package: libc6, slice: libs}
  - {catalogue: trixie, package: libc6, slice: libs, version: "= 2.41-12"}
packages:
  - busybox-static
  - {name: openssl, version: "~> 3.5"}    # the 3.x line, but not 4.0
```

- One package cannot be both whole and sliced (`whole-package/slice overlap is not
  allowed`). Two different slices of one package are fine; the same slice twice is
  not (`duplicate slice request`).
- A pinned package uses the mapping form; `- openssl: "~> 3.5"` is refused.
- `version` is a constraint, and needs an operator: `= 3.5.1-1` is one build,
  `= 3.5.1` any build of 3.5.1, `~> 3.5` the 3.x line, `>= 1.4, < 1.5` a window.
  A bare `version: "3.5.1-1"` is refused with the suggested spelling.
- Essential slices are resolved for you — never list them yourself.

### artifacts

```yaml
artifacts:
  - name: cpython
    platforms: [linux/amd64]                    # defaults to the spec's platforms
    dest: /usr/local
    unpack: true                                # must be explicit
    sources:
      - platforms: [linux/amd64]
        url: https://releases.astral.sh/github/python-build-standalone/releases/download/20261110/cpython-3.15.2%2B20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz
        sha256: ad23d1b73fac26440b0306ae06911031344c49a90ec19716c8362e7fa40cae43
    sbom: {name: cpython, version: "3.15.2"}
```

Rules that bite:

- `unpack` must be literally `true` or `false`.
- `mode` is allowed **only** with `unpack: false` (`unpacked artifacts preserve
  archive modes; mode overrides require unpack false`). A standalone artifact
  defaults to mode `0644`; set `mode: "0755"` for a program.
- `uid`/`gid` are uint32 and apply to what the artifact places.
- `dest` is a clean absolute path and may not be `/` when `unpack: false`.
- Each source has exactly one of `url` or `path`, plus a `sha256` of 64 lowercase
  hex characters. Sources must cover every platform in `platforms`.
- `sbom.name` and `sbom.version` are both required and both non-empty.
- `url` must be plain `http(s)://host/path`: no credentials, no query string, no
  fragment. Redirects are followed (up to five, each re-checked for credentials),
  so **a host that 302s to a signed URL fails**: `github.com/<owner>/<repo>/
  releases/download/...` redirects to `release-assets.githubusercontent.com` with
  a signed query and fails with `download failed (details redacted)`. Astral's
  mirror `https://releases.astral.sh/github/<owner>/<repo>/releases/download/...`
  serves a query-free 302 and works. When a project publishes no such mirror, use
  `path` with the file stored beside the spec.
- `unpack: true` re-roots the archive under `dest` and keeps the archive's own
  modes and uid/gid. Archives may be gzip, zstd or xz. Contents cannot escape
  `dest`. A tarball with a versioned top directory keeps it, so expose binaries
  with `filesystem.paths` symlinks.

## filesystem

```yaml
filesystem:
  paths:
    - {path: /app, type: directory, uid: 65532, gid: 65532, mode: "0755"}
    - {path: /usr/local/bin/uv, type: symlink, target: /usr/local/bin/uv-x86_64-unknown-linux-gnu/uv}
    - {path: /usr/local/python/lib/libpython3.so, type: file, mode: "0644"}
  accounts:
    groups: [{name: app, gid: 65532}]
    users:
      - {name: app, uid: 65532, gid: 65532, home: /app}   # shell defaults to /sbin/nologin
  timezone: UTC
  ca: {mode: append, sources: [certs/company.pem]}
  os-release: {PRETTY_NAME: Example application image}
```

### paths

| Field | Rules |
| --- | --- |
| `path` | Clean absolute POSIX path. |
| `type` | `directory`, `file` or `symlink`. |
| `mode` | Quoted octal, 4 or 5 digits. Defaults: directory `0755`, file `0644`, symlink `0777`. |
| `uid`, `gid` | Required, uint32. |
| `target` | Symlinks only, required, non-empty clean path, may not point at itself. Relative targets may not escape the image root. |

- A path may not sit below a declared file or symlink (`filesystem path has an
  explicitly declared non-directory ancestor`).
- A declared path **never truncates**. If the path already exists with the same
  kind it keeps its bytes and takes only the declared mode/uid/gid — this is how a
  package file is re-moded, and how a link-time-only library that can never load
  is taken out of the ELF closure check (declare it `type: file`). A kind
  mismatch (`vfs declared file "/x" conflicts with existing symlink`) is a real
  conflict: declare the type that actually exists.
- Declaring a path that hardening would strip fails unless that pass is off
  (`hardening.strip-shells: /usr/bin/dash is declared in filesystem.paths`).
- Declaring a path that a package also ships is a conflict — pick one owner.

### accounts

- Names match `^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`; names and IDs must be unique per
  kind.
- `home` defaults to `/` and `shell` to `/sbin/nologin`. Both are **metadata
  only**: nothing is created and nothing is checked to exist. A shell that the
  image does not ship simply never runs. `home` does not create the directory —
  declare it in `paths` if `workdir` or the entrypoint needs it.
- Passwords are always locked.
- A user's primary `gid` must be declared (`user "app" requires primary gid 65532,
  which the image does not define`).

### timezone, ca, os-release

- `timezone: UTC` works with no tzdata. Any real zone needs a tzdata slice.
- `ca.mode` is `append` or `replace`; `ca.sources` are non-empty, unique,
  relative paths to **single local files** beside the spec. They must parse as a
  PEM bundle of public certificates. A directory source is refused, so a
  distribution CA bundle (Mozilla roots packed into
  `/etc/ssl/certs/ca-certificates.crt`) is not built with `filesystem.ca` — use a
  slice with a mutation script that joins the roots, or select the distro package
  that already ships the bundle.
- `os-release` accepts only `NAME`, `PRETTY_NAME`, `VERSION`, `HOME_URL`,
  `DOCUMENTATION_URL`, `SUPPORT_URL`, `BUG_REPORT_URL`, `LOGO`; values are
  single-line. Identity fields (`ID`, `VERSION_ID`, `VERSION_CODENAME`) are
  written from the distro and refused here.

## Hardening

```yaml
hardening:
  strip-docs: true
  strip-shells: true
  strip-apt-dpkg: true
  remove-suid-sgid: true
```

All four default to `true`. Values are booleans — the quoted string `"false"` is
refused.

| Pass | Removes |
| --- | --- |
| `strip-docs` | `/usr/share/man`, `/usr/share/info`, `/usr/share/doc` except `<pkg>/copyright`. |
| `strip-shells` | ash, bash, csh, dash, fish, ksh, ksh93, mksh, pdksh, posh, rbash, sash, sh, yash, zsh from `/bin` and `/usr/bin`. |
| `strip-apt-dpkg` | `apt*` and `dpkg*` executables. |
| `remove-suid-sgid` | The suid/sgid bits. |

A builder image needs `strip-shells: false` and `strip-apt-dpkg: false`; without
them the container has no shell and no package manager.

The passes do not know who put a file there: a shell a **slice** added is deleted
just as silently as one a package installed, with no error. The practical
consequence — a `#!/bin/sh` console script an artifact ships (pip, setuptools)
dies with `exec: /bin/sh: not found` — is the hardening trap described in
SKILL.md. The same silence applies to `strip-apt-dpkg` for a hand-written `apt`
slice.

## sbom, vex

`sbom: {enabled: false}` turns SPDX generation off (on by default). `vex` declares
local inputs and explicit vulnerability claims; it is optional and rarely needed.

## Local paths, all of them

Every path a spec mentions — catalogue `path`, artifact source `path`, trust key
`path`, `ca.sources`, `vex.inputs` — is relative to the directory holding
`image.yaml`, slash-separated and clean. All are snapshotted and hashed into the
lock at `lock` time, so builds stay offline. A trust key, `ca.sources` and
`vex.inputs` may climb above the spec with `../` and stay confined to the ancestor
they climb to; an artifact source `path` and a catalogue `path` may not leave the
spec's own directory.
