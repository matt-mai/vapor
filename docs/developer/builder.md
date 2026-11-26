---
title: Builder
---

# Builder

The builder is where the image happens. It takes a specification, a lock and a store
of verified bytes, and produces one image per declared platform. It has no HTTP
client, no Git runner and no fetcher of any kind. That absence is the offline
guarantee.

This page is about the build stage and about the state Vapor generates itself. The
tree rules are in [filesystem](filesystem.md), the scripts in
[mutation sandbox](mutation-sandbox.md), the removal passes in
[hardening](hardening.md), and the output in [OCI output](oci.md).

## On this page

- [Opening a build](#opening-a-build)
- [Content, and why the order is fixed](#content-and-why-the-order-is-fixed)
- [Assembly](#assembly)
- [Platforms and concurrency](#platforms-and-concurrency)
- [Generated state](#generated-state)
- [Reading the builder as a reviewer](#reading-the-builder-as-a-reviewer)
- [Working on this package](#working-on-this-package)

## Opening a build

`builder.Open` takes an `Inputs` value: the specification, the lock record, the
provider, the blob store and the reporter. It validates that the lock matches the
specification and the provider, and returns an `Input` handle.

Opening does not authenticate anything. The lock's structure is verified, not its
evidence, because a build is allowed to run long before every byte has been checked.
Evidence verification happens next, and it happens before any blob is used:

- `Input.Catalogues` rebuilds each catalogue's manifest from the store, re-digests it,
  and compares the result with the locked tree identity. The result is a read-only
  view over cached blobs, not a directory anywhere.
- `Input.Content` verifies repository evidence for the platform, then merges whole
  packages, slices and artifacts into a tree.

The distinction between "the lock is structurally right" and "the lock's bytes are
authenticated" is kept in the API for a reason: mixing them would make it possible to
use an unverified blob because a check looked done.

## Content, and why the order is fixed

`Input.Content(ctx, platform)` produces everything a platform's image needs, and the
order in which it merges the three sources is fixed:

1. whole packages;
2. sliced packages;
3. artifacts.

Whole packages before slices, because a whole package brings the complete file set and
a slice brings a subset; applying slices first would let a package silently overwrite
content the specification asked for by slice. Artifacts last, because an artifact's
declared destination is the most specific statement in the specification and should
win over anything a package provides at the same path. Any genuine conflict is still a
collision error, not an override, but the order decides which of two identical entries
records which origin.

The stage also does three checks:

- the platform must be one the lock declares, so a build cannot invent a platform;
- each package's definition digest is recomputed and compared;
- origins accumulate on every path, so later passes can tell declared content from
  package content.

A sliced package whose definition pins an archive must be locked in that archive.
The catalogue's pin, not the lock, says where the catalogue meant the package to come
from, so a lock that recorded the same valid bytes from another archive is refused
before extraction. A whole package has no pin: the specification chose it directly.

Architecture comes from the provider, never from the platform string, because only
the distribution knows what it calls its own architectures.

## Assembly

`Input.Assemble` builds one platform's tree, in a fixed order:

1. run slice scripts, including removal of `until: mutate` temporary content;
2. apply `filesystem.paths` declarations through `vfs.Declare`;
3. generate synthesized state;
4. write the dpkg package database;
5. run the hardening passes;
6. write the per-package dpkg file lists;
7. check that every symlink resolves inside the image;
8. run the static ELF closure check.

The order is a set of decisions, not an accident.

**Scripts first.** A script may generate a file that a declaration then adjusts, and
temporary content exists only for the scripts' benefit. Running scripts after
declarations would let a script overwrite what the specification just declared.

The stage is skipped only when the platform has neither a locked script nor temporary
content. A script may only assert, without declaring a mutable or temporary path, and
those assertions have to run: they are usually checkable facts about the packages, and
a skipped run turns a failing check into a passing build.

**Declarations after scripts.** A declared path with explicit metadata has to win over
whatever a package or script produced, and `Declare` does exactly that by applying
metadata without replacing content.

**Synthesis after declarations.** Generated state talks to the real image: it resolves
timezone aliases through the tree and writes into directories the packages created.
The accounts, release file and APT sources Vapor generates may add files a declaration
pointed at; declarations that came first are already in place.

**Hardening after synthesis.** The removal passes must see everything, including
Vapor's own generated files, or they would leave stale content behind. Protection by
origin is what stops a pass from deleting a generated file it did not create.

**File lists after hardening.** A dpkg file list names what a package contributed, and
`dpkg --verify` treats every listed path it cannot find as missing. Written before
hardening, a list would name the documentation the passes just removed. Writing it
afterwards means the list describes the image that is actually serialized.

**Link and closure checks last.** Both are checks, not passes: nothing after them
changes the tree, so their result describes the tree that will be serialized. Running
them earlier would leave a window where a later step could break the tree while the
check still reported success.

The link check runs here because each package is confined on its own at import, and
two payloads that are valid alone can still form a cycle or a link that passes through
a regular file once merged. A declared path can do the same to a package's file. A
link whose target does not exist is still accepted, because an image may link into a
package it does not install.

## Platforms and concurrency

`Input.Build` builds every declared platform. `Input.BuildEach` builds them with at
most one worker per platform, one coordinator collects the results, and the callback
runs as each platform finishes, so progress moves while the rest are still building.
The returned images are always in declaration order.

A failure cancels the platforms still queued and returns that failure, never a
cancellation. A sibling that was stopped says "canceled", which describes the cleanup
rather than the problem, so it must not become the error the developer has to read.
Each worker waits for the coordinator to take its result before it takes another
platform; otherwise a worker could start a new platform after a sibling had already
failed. That rule is why a busy counter alone is not enough here.

The result is independent of the worker count. That is the rule worth preserving:
parallelism is an optimization, never an order. `buildWorkerCount` clamps the requested
jobs to the platform count, so asking for eight workers on a two-platform build does
not start eight.

## Generated state

Some of an image is not provided by any package: the account database, the timezone,
the release identity, the CA bundle, APT sources and the dpkg status file.
`internal/synthesis` generates them, and the rules below are the ones that surprise
people.

### Accounts

`/etc/passwd` and `/etc/group` are `0644`, `/etc/shadow` is `0600`. A declared user
gets `*` in the shadow field, meaning "no password". An existing shadow entry is
preserved only when its password field is `*`, `!` or `!!`. A crypt hash or an empty
field fails the build: keeping a usable password in an image whose specification did
not ask for one is a security bug that would ship silently. In `passwd`, the password
field must be `x`, `*`, `!` or `!!`. The gecos field is not declarable, because it is a
comment with no security meaning and no reproducibility value.

### Package sources

The source list is derived from the lock's repository records, so it names the exact
suites, components and keys the build was acquired against. It is written only when
`hardening.keep-package-sources` is set: an image that installs nothing gains nothing
from it, and a stale list invites installing packages that the lock never reviewed.
The lock still records every repository and key, so enabling the flag changes nothing
about acquisition or verification.

### The apt sandbox account

apt's postinst creates `_apt` (uid 42, gid 65534) so the download methods can drop
privileges. Vapor never runs that script, so synthesis writes the same record when
the image carries apt's fetcher: the package is recorded in the lock and
`/usr/bin/apt` or `/usr/bin/apt-get` is a file in the tree. The second half matters
because a slice can drop the binaries and keep the record.

The account is a convenience, so it never displaces one: an image that already has a
`_apt` record, or a different account with uid 42, keeps what it had and apt falls
back to fetching as root with its warning. The group name follows the id the
distribution fixed, so an image that names gid 65534 something other than `nogroup`
joins the group it already has instead of gaining a second one with the same id.

### Standard accounts

`base-passwd` ships `/usr/share/base-passwd/{passwd,group}.master` and fills
`/etc/passwd` and `/etc/group` from them in `postinst`. Without that step a Debian
image names only what the specification declares, and anything that resolves an
account by name fails: apt's `SetupAPTPartialDirectory` cannot chown its download
directories to `root`, so it disables its own sandbox and fetches as root for the rest
of the run, and `chown root:root` reports an unknown group.

`ApplyAccounts` is one staged pass over every account an image needs, in the order that
lets each one resolve: the distribution's groups, the declared groups, the declared
users, the sandbox account, and finally the distribution's users. A declaration may name
a group only a master supplies, and a master user may need a group the declaration
supplies, so the passes cannot run as independent steps. The distribution supplies the
master locations through its provider; synthesis never hardcodes them.

Within a pass the records are read from the masters the selected release ships rather
than compiled in, so a release that changes an account changes the image, and one
disabled `/etc/shadow` line is written per added account when the image ships a shadow
file. An image without `base-passwd` gains uid 0's two records, because a container has
a superuser whether its account database names one or not; an image with no account data
at all, and no apt fetcher, gains nothing.

Like the sandbox account, a base account never displaces one the image already has: a
taken name or id keeps its record even when the other half of the pair is free, and a
master user whose primary group did not survive the merge is skipped rather than written
naming a group the image does not define. A file the merge leaves unchanged is not
rewritten at all.

### Timezone

Vapor writes `/etc/timezone` and resolves `/etc/localtime` through the image, so an
alias like `Europe/Berlin` becomes the real zoneinfo file the packages installed. The
TZif magic is required, so a truncated or text file is refused.

`UTC` is the fallback only when no timezone state exists at all. A fallback that
applied more eagerly would silently override a package's timezone, which is the kind
of difference nobody notices until a log has the wrong offset.

### Release identity

`/usr/lib/os-release` wins over `/etc/os-release`, and both are resolved and read. The
identity fields `ID`, `ID_LIKE`, `VERSION_ID`, `VERSION_CODENAME` and
`UBUNTU_CODENAME` always come from the provider when it supplies a value, because they
are facts about the distribution rather than facts about the specification. A field the
provider supplies as empty says the distribution has no such field, so a package
claiming one fails the build instead of producing an image that claims to be two
things. A field the provider says nothing about keeps the package's value.

A provider may also carry descriptive defaults such as `NAME`. They only fill a field
the released file leaves out, because the released value is more specific than a
distribution default. Descriptive fields may always be overridden.

### CA bundle

Certificates are added as PEM blocks, and DER duplicates are dropped so the same
certificate added twice does not appear twice. Only `CERTIFICATE`, `TRUSTED CERTIFICATE`
and `X509 CERTIFICATE` blocks are accepted, and each segment must begin with
`-----BEGIN `. Anything else is refused rather than skipped: a bundle is trust
material, and a block nobody understood is not a block to drop quietly.

The bundle is read once, from the bytes already in memory, without a table of its
lines. A snapshot of a local CA input and the image's bundle use the same reader
(`internal/certbundle`), so both accept exactly the same files. Around the blocks it
accepts only what a published bundle actually contains: `#` comment lines, blank
lines, and a heading underlined with repeated punctuation, as in Mozilla's
`cacert.pem`. Bytes of any other shape are refused. A bundle is small by nature, so
this is a cheap rule; the cost of the alternative is a silently narrower trust store.

### APT sources

Sources are generated as deb822 stanzas, with keyrings under `/etc/apt/keyrings/`
named by their SHA-256. There is one stanza per URI and suite, and a URI whose
keyrings conflict is omitted with a diagnostic rather than written in a form APT would
misread.

### The dpkg database

Both stages that extract payloads collect the record for each package they read — the
whole-package stage from the lock's packages, the slice stage from the locked slices —
and a payload whose control stanza did not survive decoding fails that stage rather
than being recorded without metadata.

`/var/lib/dpkg/status` gets one record per package, and the control stanza is copied
verbatim. Records are sorted by name and architecture, existing records that no
package accounts for are kept, and the file is bounded by `MaxStatusFileSize`. A
package that owns no regular file gets no record, for the reason given under the file
lists below.

### Why a sliced image has no Status fields

In an image whose packages are all whole, every record carries `Status: install ok
installed`, and both dpkg and a package manager read the database normally.

An image holding a slice writes no `Status` field in any record. This is the same
tradeoff Canonical's `chisel-wrapper --generate-dpkg-status` makes: it appends
`dpkg-deb -f` output verbatim, which carries no `Status` field either. dpkg reads a
record without one as `unknown ok not-installed`.

Why not `install ok unpacked`: a package manager compares the recorded stanza against
the archive's own to decide whether an upgrade is available. The comparison hashes
`Installed-Size`, `Depends`, `Pre-Depends`, `Conflicts`, `Breaks` and `Replaces`, and
any difference produces a second version object with the same version string, which
reads as a newer version. Dropping a slice's relations therefore makes every sliced
package appear in `apt list --upgradable` at the version it already has, and
`apt-get upgrade` then re-unpacks the whole package and puts back the files the slice
left out. Keeping the relations and claiming `install ok unpacked` instead gives a
package manager a record it cannot repair: a single `Depends` whose target is not in
the database stops every later operation with `E: Unmet dependencies`, which is worse
than the phantom upgrade.

With no `Status` field at all, a package manager sees nothing installed: no broken
package to repair, no phantom upgrade, and `apt-get install`, `remove`, `upgrade` and
`dist-upgrade` all behave. The cost is that dpkg cannot tell that a package is
installed either — `dpkg -l` lists the record as `un`, `dpkg -L` names no files, and
`dpkg --verify` checks nothing. Scanners are unaffected, because they read the record
itself.

The choice is per database, not per record. Mixing recorded statuses with statusless
records points a whole package's relations at packages the database says are absent,
and every package operation fails. One slice anywhere therefore means no `Status`
field anywhere, which is why an image that installs packages at run time should not
be assembled from slices.

### The dpkg file lists

`/var/lib/dpkg/info/<package>.list` names the paths a package contributed, one per
line. Without them every `dpkg` query warns that the files list is missing, `dpkg -L`
prints nothing and `dpkg --verify` cannot tell a complete package from one whose files
are gone. dpkg reads a list only alongside a record it accepts as installed, so in an
image that holds a slice the lists are written but inert.

The paths come from the tree's origins, not from the package archive: an entry is
listed for a package when that package's payload carried it and it is still in the
image. A path some other package overwrote is therefore listed for the package that
won, and stripped documentation disappears from the list.

dpkg qualifies the file name with the architecture only for a `Multi-Arch: same`
package (`libacl1:amd64.list`), the one kind that can be installed twice. Any other
package gets an unqualified name; a qualified one makes dpkg look for a file nothing
wrote and warn about the missing list it just skipped.

A package that owns no regular file gets neither a list nor a status record. Its
content may have been only directories and symlinks, or hardening may have removed
the last file it contributed. Either way the image holds no code the package put
there, so a record would tell a scanner the image contains a package whose
advisories cannot apply to anything it can run. The record follows the files: this
is the same test the SPDX document applies when it decides what exists.

The image's root is implicit and belongs to no package, so no list names it. Each list
is a plain text file with a fixed mode, generated from the tree, so the result is
deterministic.

### What is not generated

`/etc/ld.so.cache` is not generated. Its format is a cache, not a contract, and the
default search directories cover the layouts Vapor produces. Generating it would mean
implementing `ldconfig`'s cache writer for no gain.

## Reading the builder as a reviewer

When a change touches the builder, these are the questions worth asking:

- Does this add a way to reach the network? If yes, it belongs in locking.
- Is the new step's position in `Assemble` justified, or was it appended? Order is
  behaviour here.
- Can a failure leave a half-built tree? Every stage either works on a staged copy or
  fails before mutating.
- Does the result still not depend on worker count or iteration order?
- Is the new behaviour reported through the reporter rather than printed? A library
  that writes to stdout cannot be tested or embedded.

## Working on this package

- Keep `Assemble`'s order documented where it is defined, and change it only with a
  reason and a test that would fail under the old order.
- Add a stage by adding the package that owns the question, then calling it. Do not
  grow a stage inside the builder.
- Any new generated file needs a mode, an owner and a bound. An unbounded generated
  file is a build that fails on a large input in production only.
- Evidence verification before use, and no convenience path around it.
