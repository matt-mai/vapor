---
layout: default
title: Filesystem
---

# Filesystem

`filesystem` adds what packages do not give you: directories, accounts,
timezone, certificates and release information. All fields are optional; an
omitted `filesystem` changes nothing.

- How to use these settings: [configure the system](../guides/configure-the-system.md).

## paths

```yaml
filesystem:
  paths:
    - path: /app/data
      type: directory
      uid: 65532
      gid: 65532
      mode: "0750"
    - path: /app/ready
      type: file
    - path: /app/current
      type: symlink
      target: data
```

| Field        | Rules                                                                                                                                        |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`       | Required clean absolute path inside the image.                                                                                               |
| `type`       | Required: `directory`, `file` or `symlink`.                                                                                                  |
| `uid`, `gid` | Unsigned 32-bit integers. Default `0`.                                                                                                       |
| `mode`       | Quoted octal, four digits from `0`, or five with a special bit. Default `"0755"` for directories, `"0644"` for files, `"0777"` for symlinks. |
| `target`     | Required for symlinks and refused for other types.                                                                                           |

Paths are unique and must not contain `..` or a backslash. Root `/` is allowed
only as a directory. A path below another declared file or symlink is refused,
because a file cannot contain a child.

Behaviour on an existing entry:

| Declared    | Existing                     | Result                         |
| ----------- | ---------------------------- | ------------------------------ |
| `directory` | Missing                      | Created with your metadata     |
| `directory` | A directory                  | Metadata applied               |
| `file`      | Missing                      | Empty file created             |
| `file`      | A file                       | Metadata applied, content kept |
| `symlink`   | Missing                      | Link created                   |
| Any         | A different entry type       | Build fails                    |
| `symlink`   | A link to a different target | Build fails                    |

Vapor never truncates an existing file, never removes a directory tree, never
copies files from your host and never runs a shell. Missing parent directories are
created along with the declared path.

Symlink ownership applies to the link itself, and a link that resolves outside
the image is refused.

## accounts

```yaml
filesystem:
  accounts:
    groups:
      - name: app
        gid: 65532
    users:
      - name: app
        uid: 65532
        gid: 65532
        home: /app
        shell: /sbin/nologin
```

| Record | Fields                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------- |
| Group  | Required `name` and `gid`.                                                                          |
| User   | Required `name`, `uid`, `gid`; optional `home` (default `/`) and `shell` (default `/sbin/nologin`). |

Names match `[A-Za-z_][A-Za-z0-9_.-]{0,31}`. Names and IDs are unique within
users and within groups; a user and a group may share a name or an ID. `home` and
`shell` are absolute paths, and the shell cannot be `/`.

Vapor writes each declared account with a locked password marker, so it can never
log in with a password. If selected packages ship an account that is already
enabled with a password, the build stops instead of producing an image whose
accounts can log in.

Only a primary group is declared. The group may come from a package instead of
from `accounts.groups`; a gid the image does not define at all stops the build:

```text
vaporize: operation failed: accounts: user "app" requires primary gid 65532, which the image does not define
```

## Standard accounts

Debian and Ubuntu keep their account databases empty and fill them from
`base-passwd`'s `passwd.master` and `group.master` while the package is being
configured. Vapor does not run that step, so it copies the two master files into
`/etc/passwd` and `/etc/group` itself, and does the same for `/etc/shadow` when the
image ships one. An image therefore names `root`, `daemon`, `www-data` and the rest,
exactly as the release defines them.

An account the image already has keeps its record, so a declaration never fights the
masters. A declared group is written before the masters are merged, so a declaration
takes the name or id it asked for and a master group that would collide is the one left
out. A user whose group is not in the image is left out rather than recorded against
a group that does not exist. An image without `base-passwd` — a static binary and
nothing else — gains no account database from the masters, but still gets one when the
specification declares an account, because a declaration is not the convenience the
masters are. Comments in a master file stay in the master: the image's own database is
written only with the accounts it needs.

## timezone

```yaml
filesystem:
  timezone: Europe/Berlin
```

The zone name must exist in the image as `/usr/share/zoneinfo/<zone>`, which a
`tzdata` package or slice provides. Use `UTC` or `Etc/UTC` when the image has no
zoneinfo data, because Vapor writes those itself.

Leaving `timezone` out keeps the timezone the packages provide, falling back to
UTC. Pointing at a zone the image lacks fails the build:

```text
vaporize: operation failed: timezone: timezone "Europe/Berlin" needs selected zoneinfo at /usr/share/zoneinfo/Europe/Berlin
```

## ca

```yaml
filesystem:
  ca:
    mode: append
    sources: [certs/company.pem]
```

| Field     | Rules                                                                                 |
| --------- | ------------------------------------------------------------------------------------- |
| `mode`    | Required: `append` keeps the package roots and adds yours, `replace` uses only yours. |
| `sources` | Required nonempty list of local certificate files.                                    |

Sources are paths relative to the specification file. They may climb above it, so
several images can share one file: `sources: [../../ca/company.pem]` reads a
certificate kept beside the images rather than beside one of them. They must hold
public certificates; a file with a private key fails the lock. Duplicates are written
once, in declaration order.

`replace` with no sources is refused. Appending to an image whose packages provide
roots, but no bundle yet, keeps those roots: the bundle is written from the roots
the packages enable. An image with no roots at all still gets a bundle holding your
certificates.

### Java trust store

A Java runtime reads its trust anchors from a keystore file, not from the public
bundle. Debian's Java packages ship that keystore as a link to a file their
configuration step generates at install time. Vapor assembles the image without
running that step, so it writes the keystore itself, from the same certificates it
puts in the bundle. This needs no configuration: an image that has a Java runtime
works with HTTPS out of the box, and a certificate you add through `ca` is trusted
by Java too.

The keystore is written only when the image has a Java runtime whose keystore link
points at a file that does not exist. A keystore the packages ship as a real file is
left untouched.

A Java runtime in a built image can be checked with:

```text
$ java -version
$ keytool -list | tail -1
Your keystore contains 121 entries
```

## os-release

```yaml
filesystem:
  os-release:
    PRETTY_NAME: Example application image
    HOME_URL: https://example.com
```

Allowed keys are `NAME`, `PRETTY_NAME`, `VERSION`, `HOME_URL`,
`DOCUMENTATION_URL`, `SUPPORT_URL`, `BUG_REPORT_URL` and `LOGO`. Values are
single-line text and are written as you give them.

Identity fields such as `ID`, `ID_LIKE`, `VERSION_ID` and `VERSION_CODENAME`
cannot be overridden:

```text
vaporize: operation failed: validate spec: filesystem.os-release key is not a supported descriptive field; identity overrides are forbidden
```

An override rewrites `/usr/lib/os-release`. When `/etc/os-release` is a symlink to
it, both paths show the same values. Leaving the mapping out keeps the release
files the packages provide.

Identity fields the release does not define are refused rather than added. Debian, for
example, has no `UBUNTU_CODENAME`, so content that declares one on a Debian image fails
the build.
