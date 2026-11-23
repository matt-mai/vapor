---
layout: default
title: Image specification
---

# Image specification

`image.yaml` is one YAML document with one mapping at the top. This page lists
every field, what it means and what Vapor accepts. Field groups that describe
software, files and policy have their own reference pages.

## A complete example

```yaml
version: 1
name: "demo"
image: "ghcr.io/example/demo"
distro: ubuntu
release: "26.04"
platforms:
  - linux/amd64
tags: [v1]
contents:
  repositories:
    - name: ubuntu
      platforms: [linux/amd64]
      endpoints:
        - platforms: [linux/amd64]
          url: https://archive.ubuntu.com/ubuntu
      suites: [resolute, resolute-security, resolute-updates]
      components: [main, universe]
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
      archives:
        ubuntu: ubuntu
  packages:
    - busybox-static
container:
  user: "65532:65532"
  entrypoint: [/usr/bin/busybox]
  cmd: ["sh"]
```

That is what `vaporize init --distro ubuntu --release 26.04` writes, with one entrypoint
added.

## Top-level fields

| Field         | Type    | Meaning                                                            |
| ------------- | ------- | ------------------------------------------------------------------ |
| `version`     | integer | Must be `1`.                                                       |
| `name`        | string  | Name of the image, lowercase letters, digits, `_`, `.` and `-`.    |
| `image`       | string  | Registry repository, such as `ghcr.io/team/app`. No tag or digest. |
| `distro`      | string  | `ubuntu` or `debian`.                                              |
| `release`     | string  | A codename or version number for that distribution. Quote it.      |
| `platforms`   | list    | `linux/amd64`, `linux/arm64`, or both. Defaults to `linux/amd64`.  |
| `tags`        | list    | Tags pushed with `--push`, such as `v1`.                           |
| `annotations` | mapping | Public metadata, written onto every platform manifest.             |
| `contents`    | mapping | Packages, slices, catalogues, repositories and artifacts.          |
| `container`   | mapping | Runtime settings: user, entrypoint, environment and ports.         |
| `filesystem`  | mapping | Directories, accounts, timezone, certificates and release info.    |
| `hardening`   | mapping | Which content to remove from the image.                            |
| `sbom`        | mapping | Whether to generate a software bill of materials.                  |
| `vex`         | mapping | Vulnerability statements, and the files that supply them.          |

An SPDX document is attached to every platform image when `sbom` is left on, and a
provenance statement and a VEX statement whether it is on or off. VEX claims are only
published after they match the finished image. See [what works today](status.md).

## Identity fields

`name` must be 1 to 128 ASCII characters, starting with a lowercase letter or
digit and continuing with lowercase letters, digits, `_`, `.` or `-`.

`image` is a registry host plus a repository, such as `ghcr.io/team/app` or
`localhost:5000/app`. It must not contain a scheme, a tag, a digest or
credentials. Tags belong in `tags`:

```yaml
image: ghcr.io/team/app
tags: [v1, v1-amd64, "42"]
```

Tags are 1 to 128 characters, may use upper and lower case, and are unique. A tag
may not start with `.` or `-`. There is no implicit `latest` tag.

`annotations` holds public image metadata:

```yaml
annotations:
  org.opencontainers.image.description: Minimal application image
  com.example.component: api
```

Annotations are validated, recorded in the lock, and written onto the manifest of
every platform image, where `docker inspect` and registry listings show them.
Values are public metadata, so never put secrets there.
One key is reserved: `org.opencontainers.image.ref.name`, because the tag list sets
it.

## Distribution and release

`distro` accepts `ubuntu` and `debian`.

For Ubuntu, `release` accepts `26.04` or the codename `resolute`; both are written
as `26.04`. For Debian, it accepts `13` or `trixie` and `12` or `bookworm`, and both
spellings are written as the codename, `trixie` or `bookworm`. Quote the value,
because `26.04` without quotes is a number, not text.

Vapor warns for a release it has not tested and then tries anyway. The catalogue has
to match the release, so in practice a different release needs a catalogue built for
it. Debian's main and security archives are both used without any setup, each checked
with its own key; see [repositories](contents.md). A codename Vapor has not reviewed
has no such defaults, so it binds its repositories itself.

Debian's moving names (`stable`, `testing`, `unstable` and the like) are refused,
because a name that changes underneath an image cannot be pinned in a lock. A number
Vapor does not know is refused too, while an unfamiliar codename only warns: a number
claims to be a release Debian published, and a codename is whatever Debian names next.
Other distributions are refused for now.

Authoring a Debian specification is described in
[build a Debian image](../guides/build-debian-images.md).

## Platforms

```yaml
platforms:
  - linux/amd64
  - linux/arm64
```

`linux/amd64` and `linux/arm64` are supported. The default is `linux/amd64` alone.
Order is preserved and duplicates are refused. Every artifact needs a payload for
each declared platform.

## container

```yaml
container:
  user: "65532:65532"
  entrypoint: [/app/server]
  cmd: ["--port", "8080"]
  workdir: /app
  ports: ["8080/tcp"]
  stop-signal: SIGTERM
  env:
    MODE: production
```

| Field         | Rules                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------- |
| `user`        | `name`, `uid` or `uid:gid`. Names match `[A-Za-z_][A-Za-z0-9_.-]*`, ids fit an unsigned 32-bit integer.   |
| `entrypoint`  | Argument list. The first entry must not be empty.                                                         |
| `cmd`         | Argument list of default arguments.                                                                       |
| `workdir`     | Clean absolute path.                                                                                      |
| `ports`       | `number`, `number/tcp`, `/udp` or `/sctp`. Decimal 1 to 65535, no leading zeros, no duplicates.           |
| `stop-signal` | Linux signal name such as `SIGTERM`, or a decimal 1 to 64.                                                |
| `env`         | Mapping of names to values. A name starts with a letter or `_` and continues with letters, digits or `_`. |

Every field is optional, and an omitted `user` leaves the runtime default. The
values reach the OCI image config unexpanded, so `${...}` is refused like
everywhere else in the specification.

An absolute executable — the entrypoint, or `cmd` when there is no entrypoint — must
exist in the finished image, and so must the interpreter an executable script names
on its first line. Hardening removes shells by default, so this is what stops a build
that looks successful from producing an image that cannot start:

```text
vaporize: operation failed: container.entrypoint /bin/sh is not in the image; hardening may have removed it
```

A relative name is looked up on `PATH` at run time and is accepted without a check.

## YAML rules

Vapor reads YAML strictly. These are errors:

- A second document, or a top-level value that is not a mapping.
- An unknown field, or the same field twice.
- A value of the wrong type, such as `release: 26.04` instead of `"26.04"`.
- Explicit `null`.
- Anchors, aliases, merge keys and custom tags.
- `${` anywhere in a value or a key.
- A NUL character.

Write every setting out. A rejected file produces one error and no partial
specification.

```text
vaporize: operation failed: load spec "image.yaml": spec: duplicate key
vaporize: operation failed: load spec "image.yaml": spec: unknown field "bogus"
vaporize: operation failed: load spec "image.yaml": spec.release: expected a string (quote string values)
vaporize: operation failed: load spec "image.yaml": spec.contents.packages: YAML anchors and aliases are not supported
vaporize: operation failed: load spec "image.yaml": spec.container.entrypoint[2]: interpolation is not supported
```

## Related references

- [Contents](contents.md): packages, slices, catalogues, repositories, artifacts.
- [Filesystem](filesystem.md): paths, accounts, timezone, certificates,
  `os-release`.
- [Policies](policies.md): hardening, slice limits.
- [Container settings](../guides/configure-the-system.md#the-user-the-image-runs-as):
  the user-facing guide for `container`.
