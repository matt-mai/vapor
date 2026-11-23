---
layout: default
title: Policies
---

# Policies

Two settings change what Vapor does to the assembled image: which content it
removes or keeps for run time, and how long one slice script may run.

- How to use hardening: [configure the system](../guides/configure-the-system.md#hardening).

## hardening

```yaml
hardening:
  strip-docs: true
  strip-shells: true
  strip-apt-dpkg: true
  remove-suid-sgid: true
  keep-package-sources: false
```

The four `strip-*` and `remove-*` fields default to `true`; `keep-package-sources`
defaults to `false`. Change a value to switch that decision. Values must be real
booleans; `"false"` in quotes is refused.

There is no named profile such as "minimal" or "builder". These fields are the whole
answer to what hardening removes, so a reader never has to look up what a profile
turned on. A builder image turns the fields off explicitly, as the catalogue's Python
builders do. If a field would remove something the specification declares, the build
stops rather than choosing.

| Field              | Removes                                                                    |
| ------------------ | -------------------------------------------------------------------------- |
| `strip-shells`     | Named shells under `/bin` and `/usr/bin`.                                  |
| `strip-apt-dpkg`   | The `apt` and `dpkg` command-line tools.                                   |
| `strip-docs`       | Everything under `/usr/share/man`, `/usr/share/info` and `/usr/share/doc`. |
| `remove-suid-sgid` | The setuid and setgid bits on every file.                                  |

The shells removed are `ash`, `bash`, `csh`, `dash`, `fish`, `ksh`, `ksh93`,
`mksh`, `pdksh`, `posh`, `rbash`, `sash`, `sh`, `yash` and `zsh`. The package tools
removed are `apt`, `apt-cache`, `apt-cdrom`, `apt-config`, `apt-get`, `apt-key`,
`apt-mark`, `dpkg`, `dpkg-deb`, `dpkg-divert`, `dpkg-maintscript-helper`,
`dpkg-query`, `dpkg-split`, `dpkg-statoverride` and `dpkg-trigger`.

Multi-call binaries such as `busybox`, other interpreters, other package managers
and anything not on the list stay in the image.

`strip-docs` keeps one thing: each package's
`/usr/share/doc/<package>/copyright`, which holds its license. Everything else
under the three documentation directories goes, including
`/usr/share/common-licenses` when a package puts it there.

### Package sources

An image is immutable: whatever it installs, it installs when you build it. A source
list and repository keys therefore buy it nothing, and an image that keeps them can
download packages nobody reviewed and then disagree with its own lock. Vapor writes
no apt sources and no package keys unless the specification asks:

```yaml
hardening:
  keep-package-sources: true
```

Turn it on for a builder image that installs packages at run time. The list is
built from the repositories the lock was acquired against, and the keys are the ones
the lock recorded. A source list a slice already ships is left alone rather than
duplicated. The package database is written in every image either way: it is what
lets a scanner attribute what the image contains. A whole package is recorded as
installed and a sliced package as unpacked, because only its selected files are
there. The file lists are written after hardening, so they name the files the image
still has.

Only repositories that a locked package or slice came from reach the image. A
repository the specification configures but nothing is installed from is dropped
during locking, because the lock records only what it used. An image that keeps
sources therefore holds the archives its own software really came from, and no
others. If you configured a security suite but every package happened to come from
the release suite, the security suite is not in the image and `apt-get update`
cannot see it. Add one package that resolves from that suite when the image needs
to install from it at run time. That is the rule rather than an oversight: an image
that carries a source it never used would let a later download change what the lock
describes.

Hardening runs after packages, slices and `filesystem` entries are applied, so it
never changes the input of a slice script.

### Conflicts stop the build

If a pass would remove something you declared, the build stops:

```text
vaporize: operation failed: hardening: hardening.strip-shells: /bin/sh is declared in filesystem.paths; disable strip-shells or remove the declaration
```

The error names the pass, the path and the declaration. Choose one of the two ways
out. `remove-suid-sgid` applies to declared paths too, so an image that needs a
privileged binary must turn that pass off.

### The library check

After hardening, Vapor checks every dynamic executable in the image and stops when
one cannot find its program interpreter or a library it needs:

```text
vaporize: operation failed: ELF closure: /usr/bin/busybox: interpreter /lib64/ld-linux-x86-64.so.2 is missing
```

The check never modifies or downloads anything. A missing library usually means a
slice or package is missing from `contents`.

## slices-engine

```yaml
contents:
  slices-engine:
    max-steps: 100000
```

`max-steps` is the step budget for one slice's mutation script, including the
helper calls it makes. It is a positive integer; the default is 100000. Each slice
gets its own budget.

The budget is not a memory or time limit. Vapor applies those separately and you
cannot change them from the specification. A script that exceeds any limit stops
the build with no partial result.
