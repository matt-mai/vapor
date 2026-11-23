# Distros: Debian and Ubuntu

Vapor's package, artifact, filesystem and hardening behaviour is identical across
distributions. Only the release names, the default archive and the trust keys
differ.

## What each distro gives you out of the box

| | Ubuntu | Debian |
| --- | --- | --- |
| `vaporize init` starter | yes | yes (trixie: `base-files` + `ca-certificates` as whole packages) |
| Upstream Chisel catalogue | yes (`canonical/chisel-releases`) | no; use a [local catalogue](chisel.md) only if you need slices |
| Implicit main archive | none (declare a repository) | yes: `deb.debian.org/debian` |
| Implicit suites | none | `<codename>`, `<codename>-updates` |
| Implicit component | none | `main` |
| Bundled trust keys | yes, for the archive you declare | yes, for the implicit `deb.debian.org` archive |
| Security archive | part of the declared repository | separate host, declare it yourself |
| Extra (paid) archives | Ubuntu Pro | none |

## Debian

```yaml
version: 1
name: app
image: example.com/team/app
distro: debian
release: trixie              # or "13"; both record trixie
platforms: [linux/amd64]
contents:
  packages:
    - busybox
```

Releases:

| You write | Result |
| --- | --- |
| `13`, `trixie` | `trixie`, the tested baseline. |
| `12`, `bookworm` | `bookworm`, locks with a warning. |
| another codename | accepted, warned; you must declare repositories and trust. |
| `stable`, `testing`, `unstable`, `oldstable`, `experimental` | refused — the name moves, a lock cannot pin it. |
| another number | refused — Vapor has no codename for it. |

### Both archives are implicit

A Debian image that declares only `packages` needs no `repositories:` block. For a
reviewed codename Vapor serves both archives itself: the main archive covers
`<codename>` and `<codename>-updates`, the security archive covers
`<codename>-security`, and each is checked with its own Debian key. A package can be
taken from either without declaring anything.

An unreviewed codename has no archives and no keys, so such an image declares its
repositories and trust itself:

```yaml
contents:
  repositories:
    - name: debian
      platforms: [linux/amd64]
      endpoints: [{platforms: [linux/amd64], url: https://deb.debian.org/debian}]
      suites: [trixie, trixie-updates]
      components: [main]
    - name: debian-security
      platforms: [linux/amd64]
      endpoints: [{platforms: [linux/amd64], url: https://security.debian.org/debian-security}]
      suites: [trixie-security]
      components: [main]
      trust:
        keys: [{path: keys/debian-security.asc, fingerprints: ["5E04A1E3223A19A20706E20F9904613D4CCE68C6"]}]
      freshness:
        valid-until: require
```

- The security suite publishes an expiry date, so `valid-until: require` is the
  honest setting there.
- Debian's security archive names its components `updates/main` while storing the
  files under `main`; Vapor accepts both spellings.
- Only three suites are readable per release: the codename, `-updates` and
  `-security`. Anything else belongs to another release and is refused.

### Debian os-release

Vapor writes `ID=debian`, `VERSION_ID` and `VERSION_CODENAME` itself. Debian has
no `UBUNTU_CODENAME` and no `ID_LIKE`, so content that claims one contradicts the
distribution and fails the build.

## Ubuntu

`vaporize init --distro ubuntu --release 26.04 --name app --dir app` writes a
starter with the archive declared, `base-files` sliced and user `65532:65532`.
Release `26.04` and codename `resolute` are the same release.

Suites are not implicit for Ubuntu — they come from the declaration or from the
catalogue:

```yaml
contents:
  repositories:
    - name: ubuntu
      platforms: [linux/amd64]
      endpoints: [{platforms: [linux/amd64], url: https://archive.ubuntu.com/ubuntu}]
      suites: [resolute, resolute-updates, resolute-security]
      components: [main, universe]
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
      archives: {ubuntu: ubuntu}
```

arm64 images pull from `https://ports.ubuntu.com/ubuntu-ports` instead of
`archive.ubuntu.com`; declare one endpoint per platform.

A remote catalogue locks its commit on the first `vaporize lock`, which is slow
(a few minutes for `ubuntu-26.04`, hundreds of packages). Pass a generous
timeout, and re-use the cache for later locks.

## Builder and runtime pairs

Both distros use the same split:

Runtime — minimal, non-root, all hardening on, no shell and no package manager:

```yaml
container:
  user: "65532:65532"
  entrypoint: [/usr/local/bin/app]
  workdir: /app
filesystem:
  paths:
    - {path: /app, type: directory, uid: 65532, gid: 65532, mode: "0755"}
  accounts:
    groups: [{name: app, gid: 65532}]
    users: [{name: app, uid: 65532, gid: 65532, home: /app, shell: /sbin/nologin}]
```

A hardened runtime strips every shell, so its users get the default
`/sbin/nologin`; a shell the image does not ship is harmless but pointless.

Builder — root, shell and package manager kept, toolchain present:

```yaml
container:
  user: "0:0"
  workdir: /build
hardening:
  strip-shells: false
  strip-apt-dpkg: false
```

- A builder needs `strip-shells: false` **and** `strip-apt-dpkg: false`, or the
  image has no shell and no apt.
- `strip-docs: false` is useful on a builder you will inspect.
- Name whole packages (`apt`, `dpkg`, `bash`) on a builder rather than their
  slices: a builder wants the full package including config and helpers. Do not
  mix a whole package and a slice of the same package.
- Runtime images have **no shell and no `/bin/sh`**: hardening strips every shell,
  including one a slice added, without an error. The consequence for `#!/bin/sh`
  console scripts is the hardening trap described in SKILL.md — use
  `python -m pip` and friends, or set `strip-shells: false` and add a shell slice
  (`dash` provides `/usr/bin/sh` and `/usr/bin/dash`; nothing lives at `/bin/sh`).
  A user `shell` pointing at a binary the image lacks is accepted silently — it
  simply never runs, so leave `shell` out of a hardened runtime.

## Distributions without a catalogue

The recipe is always the same:

1. Write `chisel.yaml` with the release codename, maintenance dates, one archive
   per host that serves packages, and the archive's public key (`chisel.md`).
2. Write a slice file per package you need, listing only the files you want.
   Check the real file list from the `.deb` — a wrong path fails the lock.
3. Point the spec at the catalogue with a relative `path` and bind each archive
   to a repository.
4. `vaporize lock` — this is what verifies the paths against the actual packages.
