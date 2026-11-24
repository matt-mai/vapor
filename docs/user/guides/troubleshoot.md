---
layout: default
title: Troubleshoot
---

# Troubleshoot

Vapor prints one line per failure, prefixed with `vaporize:`. Progress lines before
it show how far the command got.

Start by finding which step failed:

| Prefix                              | Step                                          |
| ----------------------------------- | --------------------------------------------- |
| `load spec`                         | Reading `image.yaml`.                         |
| `collect inputs`                    | Fetching catalogues, keys and packages.       |
| `audit cache`                       | Checking the saved inputs.                    |
| `write lock`                        | Writing the lock file.                        |
| `compare`                           | Checking the inputs against an existing lock. |
| `verify evidence`                   | Checking the lock against the cache.          |
| `render attestations`               | Producing the SBOM and provenance statements. |

In a terminal each step animates while it runs and is replaced by a `✓` line when it
finishes, followed by one `success:` line naming what was produced. When the output is
redirected, every step is a plain line instead, which is what makes a captured build log
readable.
| `assemble image`                    | Building the filesystem.                      |
| `write OCI layout`, `write tarball` | Exporting the image.                          |
| `push image`                        | Uploading to a registry.                      |

## Specification errors

These appear before anything is downloaded, so they are quick to fix.

```text
vaporize: operation failed: load spec "image.yaml": spec: duplicate key
```

The same field appears twice. YAML keeps the last one and Vapor refuses to guess;
delete the duplicate.

```text
vaporize: operation failed: load spec "image.yaml": spec.container.entrypoint[2]: interpolation is not supported
```

`${...}` is not allowed in the specification. Write the literal value, or let a
shell expand a plain `$NAME` at container start.

```text
vaporize: operation failed: load spec "image.yaml": validate spec: filesystem.os-release key is not a supported descriptive field; identity overrides are forbidden
```

Only descriptive `os-release` keys can be set. `ID`, `VERSION_ID` and similar come
from the release.

```text
vaporize: operation failed: load spec "image.yaml": validate spec: whole-package/slice overlap is not allowed
```

Choose one. Request the whole package or the slices that contain the files you
need.

```text
vaporize: operation failed: load spec "image.yaml": validate spec: contents.catalogues[0]: local path must be nonempty, clean, relative and slash-separated (relative to the spec directory)
```

A catalogue path must be relative to the specification file and written without
leading `./`. `cat` works; `./cat` and `/home/me/cat` do not. The `--catalogue`
flag of the `slices` command is looser and accepts `./cat`.

## Lock errors

```text
vaporize: operation failed: catalogue "ubuntu": repository "ubuntu" suites do not match catalogue archive "ubuntu"
```

Your repository lists different suites or components than the catalogue archive it
is bound to. Copy the suites and components from the catalogue's `chisel.yaml`, or
from `vaporize inspect` of a lock that already worked.

```text
vaporize: operation failed: repository "ubuntu": archive request for "dists/resolute/InRelease" failed: HTTP 404
```

The repository answered, but not with the suite it was asked for. Check the suite
name against the catalogue, and that the mirror still publishes that release.

A request that fails for a passing reason — a busy mirror, a rate limit, a server
error — is retried up to five times over about a minute before this appears. A 404
is not retried: the answer will not change. When the delay is long enough for the
lock to take a while, the archive is throttling you; waiting and running `lock`
again works.

```text
vaporize: operation failed: repository "esm-apps": InRelease is not validly signed
```

The metadata did not verify against the keys you trust. Either the server is not
the one the catalogue expects, or your `trust.keys` list is wrong. A login does not
fix a signature failure.

```text
vaporize: operation failed: lock drift detected:
changed: header spec: "sha256:8c5d..." -> "sha256:4f09..."
```

The inputs changed since the lock was written. Review the differences, then lock
again when the change is expected.

```text
vaporize: operation failed: artifact "server" on linux/amd64: download failed: HTTP 502
```

An artifact download failed. `lock` retries a rate limit, a server error and a
request that times out before its headers five times over about a minute, so a 502
that survives those attempts is a refusing host, a proxy in the way or a broken
mirror. Check the URL with `curl -I` from the same machine, and use `path` with a
local copy if it stays unreachable.

```text
vaporize: operation failed: artifact "server" on linux/amd64: download failed: timed out
```

The payload stopped arriving mid-transfer. A proxy that scans a file before it
passes it on looks exactly like this: the headers arrive, then nothing until the
client gives up. `lock` allows one minute for headers and thirty for the whole
request. A stall while the body is being read is not retried: those bytes were
already handed to the caller, so a retry would restart a transfer that may be most
of the way done. Retry the command on a network that bypasses the inspector, or
declare a `path`.

```text
vaporize: operation failed: artifact "server" on linux/amd64: download failed (details redacted)
```

The download failed for a reason Vapor will not repeat, because the message would
quote the request URL and a URL can carry a credential. Unusable URLs are caught
before the request, so this is a transport failure: DNS, a refused connection,
a proxy that resets the connection, or a TLS failure. `curl -v` against the same
URL on the same machine shows which. Environment variables such as
`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are honored the way Go honors them.

```text
vaporize: operation failed: artifact "server" on linux/amd64: download failed: redirect target is not a credential-free HTTP(S) URL
```

The host redirected the download to an address that carries credentials or is not
HTTP(S), and Vapor refuses to send the request there. Use a URL that serves the
file directly, or a local `path`.

```text
vaporize: operation failed: 15 referenced blobs are absent from the cache
```

The cache was collected or cleaned and no longer holds everything the lock names. Lock
again to download the missing inputs; `vaporize cache gc --apply` keeps the inputs of
every lock it is given, so name the locks you still build from.

When the cache grows too large, `vaporize cache gc` reports what it would delete and
`vaporize cache gc --apply` deletes it. See [the command reference](../reference/cli.md)
for the flags.

## Build errors

```text
vaporize: operation failed: build lock structure: lock spec digest does not match the spec
```

`image.yaml` changed after the last `vaporize lock`. Lock again.

```text
vaporize: operation failed: repository "sha256:7686e4ba...": open key evidence failed
vaporize: operation failed: catalogue "ubuntu" trust: open catalogue root evidence failed
vaporize: operation failed: artifact "hello": open cache blob "8599a426...": open /tmp/e5/...: no such file or directory
```

The cache does not hold what the lock names. Lock again with the same cache
directory, and check that `--cache-dir` or `VAPOR_CACHE_DIR` is the same for both
commands.

```text
vaporize: operation failed: slice package "base-files": catalogue definition does not match its locked digest
```

The catalogue on disk changed after locking. Lock again and review what changed.

```text
vaporize: operation failed: ELF closure: /usr/bin/busybox: interpreter /lib64/ld-linux-x86-64.so.2 is missing
```

A program in the image needs a library or loader the image does not contain. Add
the package or slice that provides it, or use a static binary.

```text
vaporize: operation failed: package "mawk": vfs file "/usr/bin/awk" conflicts with existing symlink
```

Two packages carry the same path with different content, which Debian would settle
through `Replaces`. Vapor keeps the fail-closed rule, so the build stops. Ask for
only one of the packages, or for the one that owns the file.

```text
vaporize: operation failed: timezone: timezone "Europe/Berlin" needs selected zoneinfo at /usr/share/zoneinfo/Europe/Berlin
```

Add a `tzdata` package or slice, or use `UTC`.

```text
vaporize: operation failed: accounts: user "app" requires primary gid 65532, which the image does not define
```

Declare the group in `filesystem.accounts.groups`, or pick a gid that a selected
package already defines.

```text
vaporize: operation failed: hardening: hardening.strip-shells: /bin/sh is declared in filesystem.paths; disable strip-shells or remove the declaration
```

A hardening pass would delete something you declared. Disable that pass or drop the
declaration. The same shape appears for `strip-docs`, `strip-apt-dpkg` and
`remove-suid-sgid`.

```text
vaporize: operation failed: filesystem.paths /usr/bin: vfs declared file "/usr/bin" conflicts with existing directory
```

The path already exists as another kind of entry. Declare the type that is actually
there, or choose a different path.

## Export errors

```text
vaporize: operation failed: write OCI layout: layout destination "out" already exists; choose a new path
```

`--oci-dir` writes to a new path only. Delete the earlier output, or choose another
name.

```text
vaporize: operation failed: write tarball: tarball destination "out.tar" already exists; choose a new path
```

`--tarball` writes to a new file only. Choose another name or move the earlier archive.

```text
vaporize: operation failed: --push requires at least one tag in the specification
```

Add `tags:` to the specification.

```text
vaporize: operation failed: push to ghcr.io/team/app failed (details redacted)
```

The registry refused the upload. Check `docker login` or `podman login`, your
network, and whether you may write to that repository. Vapor does not print the
registry's message, because it can contain credentials.

## Command-line errors

Exit code 2 means the command line was wrong.

```text
vaporize: a command is required; use vaporize --help
vaporize: unknown command "buidl" for "vaporize"
vaporize: --catalogue is required
```

Check the spelling, then run `vaporize --help`. The `slices` subcommands need
`--catalogue` on the same command line.

## Running the image

A local export has no tag, so load it and use the printed image ID:

```bash
podman load -i image.tar
podman run --rm <image-id> echo hello
```

```text
Error: crun: executable file `echo` not found in $PATH: No such file or directory: OCI runtime attempted to invoke a command that was not found
```

That message means the image holds no program with that name. The starter image
only has base files, so add `busybox-static` or another package that ships the
command, or run an absolute path to a program the image does contain.

## Package tooling in the image

```text
dpkg: warning: files list file for package 'bash' missing; assuming package has no files currently installed
```

That warning means the image was built by an older Vapor. Current images write one
file list per package under `/var/lib/dpkg/info/`, next to the package list at
`/var/lib/dpkg/status`, so `dpkg -L <package>` names the files the package added and
`dpkg --verify` reports a file that went missing. Rebuild the image to get them.

```text
W: No sandbox user '_apt' on the system, can not drop privileges
```

`apt` prefers to download as an unprivileged `_apt` user and warns when that account
does not exist. Installs still work. Current images write the account whenever they
carry `apt`'s fetcher, so this warning means the image was built by an older Vapor,
or that uid 42 already belongs to another account in the image. Rebuild to get the
account; if the uid is taken, the warning stays and the download runs as root.

```text
E: Unmet dependencies. Try 'apt --fix-broken install' with no packages (or specify a solution).
```

This is what `apt` says when it reads a package database it believes is broken. It is
not something to fix with `--fix-broken` inside an ephemeral image; it means the
database does not match the files. Report it along with the image's package list,
because Vapor is expected to write a consistent database for the packages it
contains.
