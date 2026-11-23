---
layout: default
title: Build a Debian image
---

# Build a Debian image

Debian is the first supported release. A Debian image starts with one command:

```bash
vaporize init --distro debian --release trixie --name demo --dir demo
```

That writes a specification with the release files and the public certificate roots.
Everything else below is what you add to it. You can also write the file by hand:

```yaml
version: 1
name: demo
image: example.com/demo
distro: debian
release: trixie
platforms: [linux/amd64]
contents:
  packages:
    - busybox
```

Everything below the distribution line works the same way as for Ubuntu: packages,
artifacts, accounts, hardening and the lock file.

## What a package list has to cover

Debian lets a package leave out dependencies on the packages every system is
assumed to have. `Essential: yes` marks those; `bash`, `dpkg`, `coreutils` and a
few others carry it, and a package may therefore require a shell it never names.
APT adds that baseline for you and Vapor does not.

Vapor follows what each package declares and nothing else. It reads `Pre-Depends`
and `Depends`, and ignores `Recommends`, `Suggests` and the implicit `Essential`
set. So a package list has to name the programs the image will actually run, and
the result is smaller and easier to reason about than an APT install of the same
packages.

In practice three things are worth knowing:

- **Every runtime needs its libc and its release files.** A dynamically linked
  program needs `libc6`; the files a program expects under `/etc` and `/lib` come
  with `base-files`. Both are dependencies of almost everything, so they usually
  arrive on their own, but naming them makes the intent clear.
- **Some packages assume an `Essential` program.** A package that runs a shell in
  a maintainer script declares `Pre-Depends: bash` or similar, and Vapor follows
  that. A package that only *mentions* `awk`, `sed` or `coreutils` expects the
  baseline and does not declare it; add what you need.
- **Nothing is configured.** See
  [what a package install does](#what-a-package-install-does) below.

If you want a shell in the image, ask for it. `busybox-static` is a single binary
with its own shell and the common utilities, which is usually the smallest way:

```yaml
contents:
  packages:
    - base-files
    - busybox-static
```

A library has to be found at run time as well. Vapor checks every executable
against the libraries in the image, so a binary whose library is missing fails the
build rather than the deployment.

### Files two packages both claim

Debian lets a package take over a file from another package it `Replaces`. Vapor
refuses instead: when two packages carry the same path with different content, the
build stops:

```text
vaporize: operation failed: package "mawk": vfs file "/usr/bin/awk" conflicts with existing symlink
```

The rule is deliberate. A silent takeover is exactly the kind of change a reviewer
cannot see in a specification, and a package set that needs one is better read than
guessed at. Two packages that agree byte for byte, such as a shared copyright file,
are not a conflict.

The workaround is to ask for the package that owns the file and leave the other
out. A package that only conflicts because two versions of one name were selected
is impossible here: the resolver keeps one version of a name.

## What a package install does

A package install here means its files, and nothing more:

- The payload is extracted and every file lands where the package puts it.
- The control stanza is recorded, so `/var/lib/dpkg/status` and the file lists
  describe the package and a scanner can inventory it.
- The maintainer scripts are not executed, and the package's triggers do not run.
  Vapor never runs a script from a package, on any path.

The database entry says `install ok installed` for a whole package and `install ok
unpacked` for a sliced one, which is the honest state of each: a slice really does
not have all of the package's files.

What a script would have done is yours to declare, and Vapor writes it
deterministically:

| A script would have          | You declare                                     |
| ---------------------------- | ----------------------------------------------- |
| created a user or group      | `filesystem.accounts`                           |
| written a configuration file | `filesystem.paths`, or an artifact              |
| written the timezone         | `filesystem.timezone`                           |
| built the CA bundle          | nothing; Vapor builds it from the package       |
| registered a service         | nothing; start it from the image's entrypoint   |
| run a database migration     | nothing; Vapor does not configure software      |

That is why `ca-certificates` works here: Debian's `update-ca-certificates`
maintainer script writes `/etc/ssl/certs/ca-certificates.crt`, Vapor writes the
same file from the roots the package ships, and the order is fixed rather than
whatever the filesystem returned.

The consequence to plan for is a package that cannot work until it has been
configured. A database server, for instance, needs a data directory and a
migration that Debian runs in `postinst`. Such a package installs its files and
starts nothing. Run it configured from a base image you control, or describe the
configuration yourself and start the software from your own entrypoint.

## Releases

Write the release as a codename or a version number. Both are stored as the codename,
so `13` and `trixie` produce the same lock.

| You write             | Vapor uses | Notes                                    |
| --------------------- | ---------- | ---------------------------------------- |
| `13`, `trixie`        | `trixie`   | The tested release.                      |
| `12`, `bookworm`      | `bookworm` | Works, with a warning.                   |
| another codename      | itself     | Warned, and needs its own repositories.  |
| `stable`, `testing`   | refused    | The name moves; a lock cannot pin it.    |
| another number        | refused    | Vapor has no name for it.                |

The refusals look like this:

```text
vaporize: operation failed: load spec "image.yaml": validate spec: release has invalid syntax
vaporize: operation failed: debian release "99" is not a known version number
```

`stable` and its neighbours are refused by the specification itself, for Ubuntu and
Debian alike: no image may name a release that moves. `oldstable` and `experimental`
pass that check and are then refused for Debian by name, because no fixed suit matches
them either.

A codename Vapor has not reviewed locks anyway, with a warning, but the archive has to
serve it and Vapor has no reviewed key for it, so such a specification declares its own
repositories and trust keys.

A number is refused while an unknown codename is not, because the two say different
things. `99` claims to be a Debian version number, and Debian has none that Vapor knows,
so the specification is wrong and no warning makes it right. `forky` names a codename,
and codenames are whatever Debian decides they are: Vapor cannot have a closed list, so
it warns and lets the archive and the keys decide.

## The two archives

Debian publishes ordinary packages and security fixes in different places, signed by
different keys, so Vapor treats them as two archives.

For a release Vapor has reviewed, both are used automatically: you declare neither.
The main archive serves `trixie` and `trixie-updates`, the security archive serves
`trixie-security`, and each is checked with its own key. An image that names only
packages therefore needs nothing but its package list, and it can take a package
from either archive:

```yaml
contents:
  packages:
    - name: base-files
    - name: openssl
```

A codename Vapor has not reviewed has no bundled archives, so such a specification
declares its repositories and trust keys itself:

```yaml
contents:
  repositories:
    - name: debian
      suites: [trixie, trixie-updates]
      components: [main]
      endpoints:
        - platforms: [linux/amd64, linux/arm64]
          url: https://deb.debian.org/debian
    - name: debian-security
      suites: [trixie-security]
      components: [main]
      endpoints:
        - platforms: [linux/amd64, linux/arm64]
          url: https://security.debian.org/debian-security
```

Declaring a repository replaces the bundled keys for that repository only when you
list keys yourself. Naming a repository after one of the bundled archives, as above,
keeps that archive's reviewed key, so a mirror of the security archive is verified
with the security key and not the main one.

A catalogue names its own archives, so `debian` and `debian-security` above are names
the catalogue uses. Binding `debian` is optional when the catalogue's main archive is
the one Vapor already serves.

The security suite sends `updates/main` as its component names while storing the files
under `main`. Vapor accepts both spellings and records the plain one.

## Catalogues for Debian

Upstream Chisel publishes catalogues for Ubuntu only. A Debian image that needs slices
uses a catalogue of your own.

A Debian catalogue states the codename as the archive version and gives the maintenance
dates Debian documents for that release:

```yaml
format: v3
maintenance:
  standard: 2030-06-30
  end-of-life: 2035-06-30
archives:
  debian:
    version: trixie
    suites: [trixie, trixie-updates]
    components: [main]
    priority: 10
    public-keys: [debian]
public-keys:
  debian:
    id: "04B54C3CDCA79751B16BC6B5225629DF75B188BD"
    armor: |
      ...
```

The version has to match the canonical codename from your specification, so a
specification written as `13` still uses an archive with `version: trixie`.

## Release information

The image's `/etc/os-release` is written from the provider's knowledge and from the
release package you selected:

```text
ID=debian
VERSION_ID="13"
VERSION_CODENAME=trixie
```

A selected package claiming another codename is refused instead of overwritten:

```text
vaporize: operation failed: selected os-release VERSION_CODENAME is "resolute" but the image is "trixie"
```

A package claiming a field Debian has no such thing as, `UBUNTU_CODENAME` above all, is
refused as well, because writing it would put a lie in the image.

## What is not there

- No Debian catalogue is bundled, so slices always need one of your own.
- No catalogue is needed for whole packages. `vaporize init --distro debian` declares
  none, and the Debian archives it reads are the provider's own.
- Debian has no Pro equivalent, so nothing is skipped and no credentials are needed.

See [contents](../reference/contents.md) for repositories and trust, and
[what works today](../reference/status.md) for the current limits.
