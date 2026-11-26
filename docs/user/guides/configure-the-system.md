---
layout: default
title: Configure the system
---

# Configure the system

Packages bring files. They do not bring the directories your application needs,
the user it should run as, or the timezone you want. Declare those in
`filesystem` and `container`.

## Directories, files and links

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

| Field        | Meaning                                                            |
| ------------ | ------------------------------------------------------------------ |
| `path`       | Absolute path inside the image.                                    |
| `type`       | `directory`, `file` or `symlink`. Required.                        |
| `uid`, `gid` | Numeric owner. Default `0`, which is root.                         |
| `mode`       | Permissions. Default `"0755"` for directories, `"0644"` for files. |
| `target`     | Where a symlink points. Required for symlinks only.                |

A `file` entry creates an empty file if nothing is there, and never truncates
existing content. Use it for empty markers or to set permissions on a file a
package already provides.

A `directory` entry creates the directory when it is missing and applies the
metadata. Missing parent directories are created too, with default permissions.
A declaration whose parent is a file or a symlink stops the build, because a file
cannot contain a child.

## Users and groups

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

Every ID is required and numeric. Vapor writes these accounts to `/etc/passwd`
and `/etc/group` with a locked password marker, so they can never log in with a
password.

Debian and Ubuntu normally fill their account databases from `base-passwd` while the
package is configured, which a build never does. Vapor copies that package's master
files in, so an image also names `root`, `daemon`, `www-data` and the rest of the
release's standard accounts. An account you declare is never replaced by one of them,
and an image that carries no account files at all stays without an account database.

`container.user` and `filesystem.accounts` are separate. Declaring an account
does not change the user the image runs as, and a numeric `container.user` works
without an account.

If a package already ships the account, your declaration must agree with it.
Vapor checks both `/etc/passwd` and `/etc/shadow` and stops the build when a
selected package would leave a declared account with a usable password, rather
than silently producing an image whose accounts can log in.

## The user the image runs as

```yaml
container:
  user: "app"
  entrypoint: [/usr/local/bin/server]
  cmd: ["--port", "8080"]
  workdir: /app
  ports: ["8080/tcp"]
  stop-signal: SIGTERM
  env:
    MODE: production
```

| Field         | Meaning                                                                    |
| ------------- | -------------------------------------------------------------------------- |
| `user`        | `name`, `uid`, or `uid:gid`. Set it explicitly; there is no implicit user. |
| `entrypoint`  | The program to run, as a list of arguments.                                |
| `cmd`         | Default arguments, replaced when you pass your own.                        |
| `workdir`     | Working directory. Must be an absolute path.                               |
| `ports`       | Ports the image documents, such as `8080/tcp`.                             |
| `stop-signal` | Signal used to stop the container, as a name or a number.                  |
| `env`         | Environment variables baked into the image.                                |

`entrypoint` and `cmd` are argument lists, not shell commands. Vapor runs the
first entry directly, so shell features such as variables, pipes and globs do not
work there. Run a shell explicitly when you need them:

```yaml
container:
  entrypoint: [/bin/sh, -c, "exec /app/server --port $PORT"]
```

Vapor never reads your host environment and never expands `${...}` inside the
specification. A shell reads `$PORT` at container start, because the shell does
the expansion, not Vapor.

The hardening pass removes `/bin/sh` by default. An image that starts a shell
needs `hardening.strip-shells: false`, or a shell the pass does not remove.

## Timezone

```yaml
filesystem:
  timezone: Europe/Berlin
```

The zone must be available in the image. Selecting a whole `tzdata` package
provides the files, and so does a slice such as `tzdata_eurasia`:

```yaml
contents:
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
  slices:
    - package: tzdata
      slice: eurasia
```

Without the files the build stops with

```text
vaporize: operation failed: timezone: timezone "Europe/Berlin" needs selected zoneinfo at /usr/share/zoneinfo/Europe/Berlin
```

`UTC` and `Etc/UTC` always work, because Vapor writes them itself. Leaving
`timezone` out keeps whatever the packages provide, and falls back to UTC.

## Certificates

```yaml
filesystem:
  ca:
    mode: append
    sources: [certs/company.pem]
```

`append` keeps the roots the packages provide and adds your certificates.
`replace` uses only your certificates.

Sources are local files, given as paths relative to the specification file. They
must contain public certificates only; a file with a private key stops the lock.
Duplicate certificates are written once.

`mode: replace` with no certificates is refused, so there is no way to end up with
an image that trusts nothing.

## Release information

```yaml
filesystem:
  os-release:
    PRETTY_NAME: Example application image
    HOME_URL: https://example.com
```

Allowed keys are `NAME`, `PRETTY_NAME`, `VERSION`, `HOME_URL`,
`DOCUMENTATION_URL`, `SUPPORT_URL`, `BUG_REPORT_URL` and `LOGO`. Identity fields
such as `ID` and `VERSION_ID` stay as the release defines them:

```text
vaporize: operation failed: validate spec: filesystem.os-release key is not a supported descriptive field; identity overrides are forbidden
```

## Package tooling

An image made of whole packages can install more packages at run time, because
Vapor writes the two files the package manager reads.

`/var/lib/dpkg/status` lists every package the image contains. Without it `apt`
and `dpkg` believe the image holds nothing and refuse to work, even though the
files are there.

`/var/lib/dpkg/info/<package>.list` records which files each package added, so
`dpkg -L <package>` works and `dpkg --verify` can report a file that went missing.
Vapor writes it after hardening, so a package's stripped documentation is not
listed as missing.

`/etc/apt/sources.list.d/vapor.sources` says where to download from, built from the
repositories in your specification. It is only written when you ask for it:

```yaml
hardening:
  keep-package-sources: true
```

A finished image never installs anything, so by default it keeps no source list and
no repository keys. Turn this on for an image that installs packages at run time.

A list you provide yourself is not duplicated. If a slice already ships one,
Vapor leaves it alone rather than writing a second list naming the same archive,
which APT reports as configured multiple times.

A slice in the image means no record carries a status field. A package manager then
sees nothing installed: no broken package to repair, and no upgrade it cannot
perform. That is deliberate, and it is the same tradeoff Canonical's chisel images
make. A slice contains part of a package, so when package tooling is available it
would otherwise report an available update at the version already present and then
re-unpack the whole package, restoring the files the slice left out. What a slice
needs was decided when you locked, so it is already present.

The cost is that dpkg cannot tell that a package is installed either: `dpkg -l` shows
the record without a status, `dpkg -L` names no files and `dpkg --verify` checks
nothing. Scanners are unaffected.

The practical effect:

```bash
podman run --rm my-image dpkg -l
podman run --rm my-image apt-get install -y curl
```

`apt-get install` needs the shells and
package tooling that hardening normally removes, and the package sources it does not
write by default, so it only works in an image that keeps them:

```yaml
hardening:
  strip-shells: false
  strip-apt-dpkg: false
  keep-package-sources: true
```

A builder image — one that installs packages at run time — should then be built from
whole packages rather than slices. An image in which every package is whole records
`install ok installed` for each of them, and dpkg and a package manager both read it
normally. Mixing whole packages with slices does not help: one slice anywhere turns
the status field off for the whole database, so the whole packages lose their
recorded status too.

## Hardening

Vapor removes shells, package tooling and documentation from every image unless
you say otherwise:

```yaml
hardening:
  strip-docs: true
  strip-shells: true
  strip-apt-dpkg: true
  remove-suid-sgid: true
```

All four are on by default; set one to `false` to keep that content. Hardening
runs after packages and slices are applied, and it keeps each package's
`/usr/share/doc/<package>/copyright` file, so removing documentation never
removes attribution.

If hardening would delete something you declared, the build stops and names the
pass and the path:

```text
vaporize: operation failed: hardening: hardening.strip-shells: /bin/sh is declared in filesystem.paths; disable strip-shells or remove the declaration
```

Choose one of the two ways out: keep the pass off for that image, or drop the
declaration. See [reference: policies](../reference/policies.md) for the exact
lists of what each pass removes.

## Next

- [Reference: filesystem](../reference/filesystem.md) lists every field.
- [Reference: policies](../reference/policies.md) covers hardening and script
  limits.
