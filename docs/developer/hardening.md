---
title: Hardening
---

# Hardening

Hardening removes things. A package ships what its maintainer thought was complete: a
shell, the package manager that installed it, manuals, documentation, and the
occasional setuid binary. A service image needs almost none of it.

`internal/hardening` runs four passes, each switched by a flag in the specification:

| Flag | Pass name | Removes |
| --- | --- | --- |
| `strip-docs` | `strip-docs` | `/usr/share/man`, `/usr/share/info`, `/usr/share/doc` |
| `strip-shells` | `strip-shells` | the shell inventory under `/bin` and `/usr/bin` |
| `strip-apt-dpkg` | `strip-apt-dpkg` | the `apt` and `dpkg` executable inventory |
| `remove-suid-sgid` | `remove-suid-sgid` | the setuid and setgid bits on every entry |

All four default to true. This page explains the rules those passes follow, because
the interesting part of hardening is not the lists, it is the conflicts.

A fifth flag, `keep-package-sources`, defaults to false and belongs to the same block
although it removes nothing: it decides whether the runtime apt sources and keyrings
are written at all. See [the builder](builder.md#package-sources).

## On this page

- [The rule that matters: declared wins](#the-rule-that-matters-declared-wins)
- [Conflicts are errors, not warnings](#conflicts-are-errors-not-warnings)
- [How candidates are collected, then removed](#how-candidates-are-collected-then-removed)
- [The documentation pass](#the-documentation-pass)
- [The inventories](#the-inventories)
- [Setuid and setgid](#setuid-and-setgid)
- [The static ELF check](#the-static-elf-check)
- [Working on this package](#working-on-this-package)

## The rule that matters: declared wins

A path that the specification declared is never removed. The pass fails instead:

```
hardening.strip-shells: /bin/bash is declared in filesystem.paths; disable strip-shells or remove the declaration
```

There are two ways to implement "do not remove what the specification asked for":
check every candidate against the specification, or record who asked for each path
and check that. Vapor does the second, using `vfs.Origins`.

Origins answer "who put this here" for every path, including paths the user never
wrote down: a file from a package, a file a script generated, a file Vapor
synthesized. Checking the specification text would miss every one of those, and it
would pull specification knowledge into a package that should not need it.

An entry is protected when it has an origin with no package and no slice, and that
origin's path starts with `filesystem.`. That covers `filesystem.paths` and the
synthesized state (`filesystem.accounts`, `filesystem.timezone`,
`filesystem.os-release`, `filesystem.ca`, `filesystem.packages`). Package content,
slice content and artifact content are fair game. The rule is small enough to read
in `conflictOrigin`.

## Conflicts are errors, not warnings

A conflict is a specification that asks for two contradictory things: keep a shell,
and strip all shells. Vapor could pick one (keep the shell, ignore the flag, exit
zero) or refuse.

Refusing is better because both alternatives are silent surprises. Silently keeping
the file means `strip-shells` did not do what it says. Silently removing it means the
declared path is not in the image, and the user finds out in the middle of an
incident rather than at build time.

Synthesis participates in this. A specification that strips shells is not in conflict
with a generated `/etc/shells`, because the shell inventory does not list
`/etc/shells`. But a synthesized path that an inventory does name fails the build the
same way a declared one does. The prefix is the test, not the intent.

## How candidates are collected, then removed

Hardening never deletes while it decides. `collect` builds one map from path to the
pass that would remove it, and removal happens afterwards in `deepestFirst` order.

The map is keyed by path, so a merged `/usr` layout cannot make the same inode count
twice and a path claimed by two passes is removed once, credited to the first pass
that found it.

Directories need special care. `dropNonEmptyDirectories` keeps a candidate directory
when any child is not a candidate, so a directory survives exactly when something
inside it survives. Removing `/usr/share/doc/bash` while keeping
`/usr/share/doc/bash/copyright` must leave the directory in place.

The child map is built from `tree.Entries()` rather than from the tree's directory
listing, because that listing carries a display convention (a trailing slash) that
would become load-bearing if the pass depended on it. Behaviour that a presentation
detail cannot influence is one less thing to break later.

## The documentation pass

Everything under the three documentation prefixes goes, with one exception:
`/usr/share/doc/<package>/copyright`.

Copyright notices are license material. Removing them would strip the attribution a
package's license requires, which is not a size optimization anyone asked for. The
exception is exactly two path components after `/usr/share/doc` with the last named
`copyright`, so `/usr/share/doc/bash/copyright/foo` is removed with the rest.

## The inventories

`strip-shells` and `strip-apt-dpkg` share a helper. For each name in the inventory,
Vapor looks for the entry at `/bin/<name>` and `/usr/bin/<name>` and resolves only the
parent directory.

Resolving the parent matters: `/usr/bin/sh` is usually a symlink to `dash`. Following
it would remove `dash` rather than the link, changing a file the inventory did not
name. Keeping the last component unresolved means the link is removed as a link.

Implicit directories are skipped, so an inventory name that happens to be a directory
(`/usr/bin/apt` on some layouts) is left alone. Removing a directory because a file
of the same name is on the list would be a bug found only on one distribution.

The lists are deliberately explicit rather than pattern matches. A pattern like
`/bin/*sh` would eventually match something nobody considered, and hardening removing
an unlisted file is not a failure anyone can diagnose from the build output.

## Setuid and setgid

`remove-suid-sgid` is not a removal pass. It clears two mode bits on every entry in a
single pass through the tree's inodes.

Doing it per inode rather than per path is what keeps a tree with many hard-linked
privileged files linear. It also means every name of a hard link changes together,
which is the only correct outcome: the bits belong to the inode, not to a name.

## The static ELF check

`internal/closure` runs after hardening and is not a removal pass. It walks the
dynamic ELF objects in the tree and checks that each one can find its program
interpreter and every `DT_NEEDED` library. The resolved files must be ELF objects
for the target platform, with the right object type and file-backed load segments.
A linker script or a position-independent executable cannot stand in for a library.
This is a structural check, not a simulation of the runtime loader.

The check judges inherited `RPATH`/`RUNPATH` per executable: a library reached from
one root is not assumed to be reachable from another, because the chain that found it
started at the first root's directories.

It never repairs and never suppresses. It fails the build, because an image whose
binaries cannot start is not an image, and a warning would be ignored.

What it deliberately does not do:

- It does not run anything. Vapor does not execute maintainer code.
- It does not follow computed `dlopen` paths, so a target built from concatenated
  strings is invisible.
- It does not treat every file with an ELF header as an object. Only files the loader
  can reach, for the target platform, are checked. Distribution packages ship ELF test
  fixtures for other machines and deliberately malformed objects, and reporting those
  as image defects would make the check useless.
- It collects all failures before returning, in path order, so one unreadable file does
  not hide the rest.

`$ORIGIN` and `RPATH`/`RUNPATH` are expanded with the filesystem's resolution rules,
not by string joining, so an unusual layout is either resolved correctly or reported
as unresolvable. The check reads immutable file data directly. Hard links share the
same bytes, but each path keeps its own `$ORIGIN`.

An unresolved library usually means the slice set is missing something, or a package
split its libraries in an unexpected way. The fix belongs in the specification, not in
an allow list.

## Working on this package

- New removals are new passes with a test that puts a declared path in the way and
  expects a conflict. The conflict tests are the valuable ones.
- Keep passes staged. Decide first, remove second; a pass that removes while it
  decides leaves a half-hardened tree when it fails.
- Do not add repair paths to the closure check, and do not turn its failures into
  warnings.
- Keep the inventories explicit. If a new list is needed, name it and test it rather
  than generalizing the matcher.
