---
title: Distribution
---

# Distribution

This page covers the parts of Vapor that know what a distribution is: which release
you are building for, where its packages come from, whose signatures are trusted,
and how a request for a package turns into a set of exact files.

Five packages share the work, and the split between them is the point.

| Package | Owns |
| --- | --- |
| `internal/distro` | the provider contract and the selection registry |
| `internal/distro/deb` | APT, OpenPGP, index parsing, DEB decoding |
| `internal/distro/ubuntu` | Ubuntu releases, suites, architectures, archive and trust policy |
| `internal/distro/ubuntu/pro` | credentials for selected Pro archives |
| `internal/distro/debian` | Debian releases, the two archives, and the reviewed trust snapshots |
| `internal/distro/deb/resolver` | whole-package dependency resolution |

`internal/distro/deb` has no idea that Ubuntu or Debian exist. Everything in it is true
for any APT-based distribution: signed releases, compressed indexes, DEB archives,
Debian version ordering. Each provider package adds only what is specifically its
distribution's policy. That is why there is no `if distro == "ubuntu"` anywhere below
`internal/distro`, and why Debian arrived as a package beside Ubuntu rather than a branch
inside it.

## On this page

- [The provider contract](#the-provider-contract)
- [Selecting a provider](#selecting-a-provider)
- [Archives and suites](#archives-and-suites)
- [Trust](#trust)
- [Indexes](#indexes)
- [Versions and relations](#versions-and-relations)
- [Decoding packages](#decoding-packages)
- [Maintainer scripts](#maintainer-scripts)
- [Whole-package resolution](#whole-package-resolution)
- [Pro archives](#pro-archives)
- [Adding a distribution](#adding-a-distribution)
- [Working on this package](#working-on-this-package)

## The provider contract

A provider is the policy for one distribution release. It answers the questions the
rest of the pipeline is not allowed to answer for itself:

```go
type Provider interface {
	Distro() string
	Release() string
	ReleaseWarnings() []string
	Architecture(platform string) (string, error)
	Archives() []deb.SignedArchive
	AllowedSuites() []string
	ReleaseMatching() deb.ReleaseIdentity
	DefaultTrust() []deb.KeySnapshot
	ProTrust(service string) []deb.KeySnapshot
	CABundlePath() string
	ReleaseIdentity() map[string]string
}
```

Several of these are worth explaining, because they are where policy leaks if you are
careless.

`Architecture` maps an OCI platform to a native package architecture. The schema
layer knows about `linux/amd64`; it does not know that Ubuntu calls that `amd64` and
serves it from `archive.ubuntu.com` while `linux/arm64` lives on `ports.ubuntu.com`.
That mapping is knowledge about Ubuntu, so it lives in Ubuntu.

`Archives` lists the archives the provider serves itself, each with its endpoints, its
suites, its components and its keys in one value. Debian answers two: its main archive
with the codename and updates suites, and its security archive with the security suite
on another host. Acquiring the two separately is what lets each be checked with its own
key. Ubuntu answers one archive with no suites: both of its hosts are served, and the
suites still come from the catalogue or a declared repository.

The archives are what a specification with whole packages and no repositories of its
own is resolved against: every archive is bound for it, with the suites, components and
keys it carries. A catalogue archive that matches a provider archive by name is bound to
it the same way. Ubuntu's archive has no suites, so it contributes no package source on
its own; a package-only Ubuntu image still has to declare a repository, and that is the
specification's omission rather than something to guess at.

`BindingProvider` is handed to `BindArchives`, and build-time replay runs the same
binding over the verified catalogue root before the lock is checked. That is what lets
a slice record be compared with the archive it claims, rather than only with a
repository name. The map is keyed by catalogue, archive and platform, because two
catalogues may declare the same archive name and a slice is checked on the platform it
was locked for. Every platform the image targets is bound, and a slice whose catalogue
or platform has no entry fails: a check that silently passes when nothing was rebuilt
protects nothing.

`AllowedSuites` lists every suite an image of this release may read, whichever endpoint
serves it. An archive's own suite list only says what that archive holds; `AllowedSuites`
says what the release is. That distinction matters because a declared repository
chooses its own endpoint and keys, and without this the choice would also widen the
suites: a trixie image could lock and replay bookworm packages from a correctly signed
repository it declared itself. All three paths ask the same list, so the answer cannot
differ between locking a catalogue archive, locking packages and replaying a lock.
Ubuntu returns nothing, because its suites come from the declaration.

Replay keeps the two answers apart as well. A lock repository the provider supplies is
checked against the endpoint and suites of the archive it names, while a repository the
specification declares is checked against `AllowedSuites`. Otherwise a lock could place
the security suite on the main host, where the package would never actually be served,
or verify a security record with the main archive's key.

`ReleaseMatching` carries the release matching rules that acquisition and replay both
apply. Ubuntu signs a fixed suite, so it returns nothing and the exact suite match
applies. Debian signs a moving `Suite` (`stable`) beside a fixed `Codename`, so it
compares the codename and accepts the security archive's `updates/<component>` names.

`DefaultTrust` returns every reviewed key snapshot, which is what a declared
repository that is not one of the provider's archives is checked against. Explicit
trust replaces the default; it never merges with it. A
merge would mean an image could be signed by a key nobody chose. `ProTrust` answers the
same for a paid archive, and a provider that returns nothing there makes the archive
unsupported: a catalogue cannot make a subscription source usable by adding keys to a
repository, because the provider is what says the service exists.

`CABundlePath` and `ReleaseIdentity` keep distribution paths and `os-release` facts
out of `internal/synthesis`. Synthesis needs to know where a CA bundle goes and which
release fields are authoritative, but those are answers about a distribution, so it
takes them as arguments instead of hardcoding them.

`ReleaseIdentity` answers with three kinds of entry. A value pins a field, so the image
carries it and packages cannot disagree. An empty value says the distribution has no
such field: a package claiming one fails the build, because rewriting it would invent a
fact. A missing key says nothing, so the released value stays. A descriptive default
such as `NAME` may also appear and only fills a field the release left out.

`ReleaseWarnings` returns diagnostics, not failures. An untested release warns and
still locks. Those warnings are deliberately not lock content, image metadata or
digest input: a warning changing must never change a build.

The same rule covers the catalogue's own support dates. A catalogue past its end-of-life
— or past the end of standard support, `expanded` — warns during `lock` and locks anyway;
the dates describe support, not the bytes. `distro/slices.Maintenance.Warnings` produces
the message and `lockinput` carries it to the command through `locking.Evidence.Warnings`.

## Selecting a provider

`distro.Select` looks the distribution up in an explicit registry holding `ubuntu` and
`debian`. A known distribution identifier with an unimplemented provider is a failure,
never a generic fallback: falling back would silently build something nobody asked
for.

Registry entries return `(Provider, error)` because a provider may refuse the release
outright. Ubuntu never needs to; Debian does, and a caller that received a provider
anyway could not know its policy. Selection therefore fails before any acquisition
starts, which is the only place a refusal costs nothing.

Release handling is a deliberate middle ground:

- `resolute` canonicalises to `26.04`, and Debian's `13` and `trixie` to `trixie`, so
  a suite name and a version number are the same lock identity rather than two
  different ones.
- An unknown numeric release of an implemented distribution warns that it is
  untested and still attempts to lock. Ubuntu 26.04 is a tested baseline, not an
  allowlist to maintain.
- Debian refuses moving aliases (`stable`, `testing`, `unstable` and the rest) and
  unknown version numbers, because neither can be pinned: the first changes what it
  means, the second names nothing a reviewed key set covers.
- Missing repository data, an incompatible catalogue, a trust failure or a failed
  freshness check still fails. A warning is never permission to skip a check.

## Archives and suites

`internal/distro/slices` binds the archives declared in `chisel.yaml` to the
provider:

- An explicitly bound archive must cover the platform and must match the provider's
  ordered suites and components and its release. A binding that does not match is an
  error, because a specification that names an archive for another release is almost
  always a mistake with a confusing symptom later.
- An unbound archive binds only when its name equals the provider's distribution
  identifier. That is how a catalogue written for Ubuntu keeps working without
  restating policy.
- An unbound Pro archive is optional only for a provider that has keys for the
  service. Ubuntu has them, so collection skips the archive: a specification that
  never asked for Pro content should not fail because of credentials it does not
  have. Debian has no subscription service, so a catalogue that declares one names a
  source the image cannot get from the default endpoint, and the archive is refused
  rather than quietly dropped. Silence there would ship an image missing an archive
  the catalogue says it needs.

## Trust

The Ubuntu default is a single reviewed full fingerprint,
`F6EC B376 2474 EDA9 D21B 7022 8719 20D1 991B C93C`, checked against the signed
`resolute` `InRelease`. It is a snapshot embedded in the binary, which is why Vapor
can lock without trusting whatever key happens to be installable on the host.

Debian publishes no single key that signs everything. A codename has a main archive
and a security archive, each with its own key, and only a reviewed release has keys
at all. `debian.Archives` returns each archive with the keys that sign its own suites,
taken from `ftp-master.debian.org/keys`; an unknown codename has no archives, which is
why an unnamed Debian release needs explicit trust. A record in the lock is checked
against the keys of the archive it names, so a security record signed by the main key
is refused even though both keys are reviewed.

`deb.LoadTrustedKeys` is strict on purpose:

- 1 MiB bound on the key material.
- Exactly one armor block.
- No private-key packets.
- No short fingerprints, no duplicates.

`deb.ParseKeyring` additionally requires exactly one primary key in a snapshot while
keeping its bound subkeys, because a Debian archive signs with a subkey. A snapshot
with a second primary key is refused: the shipped bytes must be the reviewed key and
nothing else. Refusing short IDs is the difference between "the publisher signed this"
and "someone with a related key signed this". Catalogue keys are proposed material,
not trust: including a key in an untrusted catalogue does not make it trusted.

The verification chain, in `internal/distro/deb`:

```
configured full fingerprint
  → InRelease, or Release + Release.gpg
  → index SHA-256 and size from the signed metadata
  → decompressed index parsing
  → package SHA-256 and size
  → extraction
```

`InRelease` is preferred. If it is present and invalid, verification fails; it never
falls back to `Release` + `Release.gpg`. Falling back on a bad signature is how
downgrade attacks work.

A release may carry several signatures, because archives rotate and overlap keys. Each
signature packet is verified on its own, and the first one in packet order that a
trusted key made and that passes the expiry policy becomes the recorded signer. Stopping
at the first packet the keyring recognises would reject a release whose first signature
comes from a key this build does not carry. A packet that does not qualify is skipped;
damaged packet data fails the release instead.

The stream is read to its end before the answer is settled. Returning as soon as one
signature is acceptable would let a well-signed release carry anything after it, so the
whole bounded stream is parsed up front and must contain nothing but signature packets.
Nothing after the accepted signature can change the signer, but malformed data must not
pass simply because it sits behind a good signature.

The signature byte limit bounds the size of that stream, not the work it causes: every
packet from a known issuer costs one hash over the whole payload, however small the
packet. A stream is therefore also capped at eight packets, which refuses a padding of
valid signatures before it can multiply the work. One hash per packet is what a real
release costs — Debian's main archives carry three.

Replay records which signer the lock chose and asks for exactly that fingerprint, so
ignoring expiry cannot swap in another signature that happens to be valid today.

A detached signature is one complete file, so its armor envelope is checked as a whole:
one opening line, well-formed headers, base64 written to strict rules, the optional
CRC24 line, then the closing line and nothing after it but whitespace. The armor
library on its own is too forgiving for this: it skips leading garbage, ends a block at
EOF when the closing line is missing, and reads no further than a block's end, so text
before or after a signature would be ignored rather than refused. A file that ends
early is refused at whatever point it was cut, which is what keeps a truncated
signature from reading as the signature of a shorter document.

Two expiry modes exist because two callers need different answers. Acquisition uses
`EnforceExpiry`: a new lock must not accept expired metadata. Build verification uses
`IgnoreExpiry`: an offline build must not fail because today's date moved past the
lock.

`VerifyOptions` carries both the policy and the clock. `Now` is the time key and
signature expiry are judged against; leaving it zero reads the system clock, which is
only right for a live acquisition. A test over pinned samples sets `Now`, so a check
that once passed does not start failing when the sample's window closes.

`CheckReleaseIdentity` binds the release identity, plus architecture and components.
By default the signed `Suite` must match exactly, because a prefix match would let a
release for one version satisfy a lock for another. Debian's archives sign a moving
`Suite` (`stable`) beside a fixed `Codename`, so a second mode compares the signed
`Codename` instead, and never falls back to `Suite` when `Codename` is missing or
wrong. Both modes still check architecture exactly.

Debian's security archive lists components as `updates/main` while index paths, slices,
bindings and locks keep the plain `main`. A prefix mode accepts that shape; it is off
for Ubuntu, and even on it accepts exactly one prefix segment.

A repository declared with `identity: own` describes a release of its own, so no
distribution rule can judge it. `ReleaseIdentity.OwnIdentity` says so, and both
acquisition and replay go through it: the signed suite name is not compared, while
architecture, components and freshness still are, and the declared keys are the only
thing that authenticates the metadata. The declared `packages` scope travels with the
catalogue binding into `resolver.Index.Scope`, so a vendor archive contributes
candidates only for the names it was declared for; an empty scope admits every name,
which is what a base archive needs. The same scope filters slice origins in
`lockinput.sliceVersions`: a slice closure reaches names the specification never
listed, so applying the list only to whole packages would leave the slice selector
free to take a dependency from a vendor that was never granted it. Replay applies it a
third time, in `checkRepositoryNameScope`, because a lock is a file on disk and an
edited one must not be able to hand a vendor a name it may not supply.

Acquisition and replay use the same `distro.RepositoryPolicy`. It starts with
`Provider.ReleaseMatching` and applies `suite-match: codename` and `identity: own`
only to the matching repository declaration, so lock audit, build and VEX replay
reach the same verdict as acquisition. The policy is derived from the spec rather
than stored in the lock; replay without a policy checks the exact `Suite`.

## Indexes

`SelectIndex` walks the candidates in a fixed order: `Packages.xz`, then `Packages.gz`,
then plain `Packages`. Each candidate has to appear in the signed metadata with a
SHA-256 and a size, and the path is the canonical
`<component>/binary-<arch>/Packages...` form.

The `by-hash` policy is `prefer` by default, `disable` or `require` on request.
`prefer` exists because by-hash paths are immutable and survive repository updates,
which makes locks more durable without requiring the repository to provide them.

Parsing is bounded: 256 MiB decompressed, and 64 MiB of dictionary for xz, enforced
by `xzguard` before a decoder is constructed. Field names are case-insensitive;
duplicate fields, invalid UTF-8 and NUL bytes are rejected.

Two repository shapes are not supported, and both are refused rather than guessed at:

- **`InRelease` is required.** A repository that publishes only `Release` and
  `Release.gpg` is refused, even though the verifier can check a detached signature
  and replay already knows how. No archive Vapor reads needs it. Detached acquisition
  would add a second fetch, a second signed-file rule and a second failure mode for a
  shape no supported repository publishes.
- **Only the native index is read.** `Architecture: all` packages are found when the
  repository lists them in `<component>/binary-<arch>/Packages`, which Debian and
  Ubuntu both do. A repository that publishes them only in a separate
  `binary-all` index would silently lose them, so such a repository is not supported.
  Add the split-index read when a repository you need is shaped that way.

## Versions and relations

`deb.ParseVersion` implements Debian version ordering: optional epoch, upstream
version, revision, with `~` sorting before everything, including the empty string.

Dependency parsing accepts `<<`, `<=`, `=`, `>=` and `>>`. It rejects `<`, `>`, `==`
and `!=`, which are not Debian syntax. `:any` is accepted, because it is a real
multi-arch qualifier; `:native` and `:all` are rejected, because Vapor does not model
those semantics and pretending to is worse than refusing.

A qualifier on a relation says which architecture the alternative needs, so the
resolution of a multi-platform image skips an alternative carrying a foreign one
instead of failing. A qualifier on a `Provides` entry says what the offering package
itself provides. `virtual:arm64` is therefore not an offer of `virtual` to a native
relation, and it matches neither that relation nor a `Conflicts` or `Breaks` on it.
Judging the entry by the relation's qualifier would hide this: an unqualified relation
has no qualifier to compare, which is exactly how a foreign provider used to satisfy a
native dependency.

## Decoding packages

`deb.DecodeArchive` reads three required `ar` members in order: `debian-binary`
(version `2.0`), `control.tar`, then `data.tar`. The tar members can use gzip, xz or
zstd. Control is bounded at 16 MiB; data is streamed with an 8 GiB ceiling. Both
bounds are on decoded output, so the decoder's own memory is bounded separately by
the xz policy below.

That 16 MiB covers the control tarball as stored, which is not the same as what
reading it costs. A sparse member declares a logical size unrelated to the bytes it
stores, and a tar reader synthesizes the holes: a 3 KiB control tarball can yield
hundreds of MiB once its members are read whole. Retained control evidence is
therefore charged against the same 16 MiB as a running budget, and each member's
declared size is checked before it is read rather than after.

A single trailing `_gpgbuilder` member is allowed for packages such as upstream
nginx. Vapor ignores its contents: trust comes from the package digest in the
verified repository index. Other extra members are rejected.

`deb.Extract` returns a standalone tree plus control evidence sorted by name, so the
caller merges rather than mutating shared state. Duplicate names like `postinst` and
`./postinst` are refused: they would give the same file two identities.

## Decoder memory

`xzguard.Check` reads an xz container and rejects any block whose LZMA2 filter
declares a dictionary larger than 64 MiB. It exists because the decoder library
does not treat its `DictCap` setting as a ceiling: a block header that asks for more
raises the value before the dictionary is allocated, so a payload chooses the
allocation no matter what the caller configured. Bounding decompressed output does
not bound that. The check walks the container from the stream footer, validates the
index, every block header, and the framing between them, and allocates nothing
proportional to the payload; nothing is decompressed. All three xz readers use it —
indexes, package members and archive artifacts — so there is one policy rather than
three copies of a constant.

The library has no fix to upgrade to: v0.6 removes the setting and derives the
window from the stream, which is worse. `TestLibraryIgnoresTheLimit` in
`internal/xzguard` fails if a future release makes `DictCap` a real ceiling, which
is the signal to delete the guard.

## Maintainer scripts

Vapor never runs a maintainer script and does not audit them. Control members such as
`postinst` stay in the extracted control evidence as data, so a later reader can
inspect them, but nothing classifies or reports them. The specification has no
field for accepting an unhandled script, so an image cannot look as if auditing
happened.

## Whole-package resolution

Slices and whole packages are different problems and get different code.

Slice content follows the catalogue's essential graph, in
[catalogues](catalogue.md). Whole packages use the DEB dependency graph, in
`internal/distro/deb/resolver`.

`NewCatalog` takes indexes with a repository name, priority, platform, architecture
and candidate packages. Ranking is total and deterministic:

1. higher priority first;
2. newer Debian version;
3. repository, then suite, then component, in byte order;
4. native architecture before `all`;
5. filename;
6. SHA-256.

A version expression narrows the candidates before ranking, and `deb.ParseConstraint`
decides what matches. The expression keeps the meaning it has in the specification:
a version with a Debian revision names one build, a plain numeric version covers
builds of that version, and anything else compares upstream versions. It never falls
back to string equality, so a differently-spelled equivalent version still satisfies
it.

`Solve` expands `Pre-Depends` and `Depends`. Roots must be real packages; a root that
only exists as a virtual provider is an error, because it means the specification
named something that does not exist. Alternatives are tried in declared order, real
packages before virtual ones. `Conflicts` and `Breaks` are checked in both directions.
One version per package name. Cycles terminate because a package already selected is
not selected again.

`Recommends`, `Suggests` and implicit `Essential` are ignored. Including them would
make an image larger than the specification asked for, and "essential" is a policy
the catalogue already expresses through slices. `Replaces` is treated as ownership
metadata, not as blanket permission to overwrite. Honouring it would mean deciding
file by file which package wins and keeping the dpkg records consistent with that
decision, so a collision stops the build with both package names instead. Add
merging only for a package set that demonstrably needs it, and only where the
takeover is unambiguous.

The search is bounded: 100,000 attempts, 10,000,000 candidate inspections and 100,000
pending requirements. Backtracking with no ceiling is a denial of service waiting for
a hostile index.

## Pro archives

`internal/distro/ubuntu/pro` handles credentials for Canonical's Pro service, and it
is written to fail closed.

`LoadCredentials` reads `.conf` files in lexical order, skips dotfiles, directories
and symlinks, and bounds the total at 1 MiB. `LoadDefaultCredentials` uses
`VAPOR_AUTH_DIR` when set, otherwise `/etc/apt/auth.conf.d`. `VAPOR_PRO_USERNAME` and
`VAPOR_PRO_PASSWORD` are also accepted; a password without a username is an error.

Matching a machine entry compares scheme, host and port, and requires the request
path to be at or below the entry's path. A missing scheme means HTTPS, and `http` never
matches. Sending a token in clear text because the entry forgot to say `https` is not
a mistake worth being compatible with.

`Fetcher` makes one archive origin available with relative, clean paths, no query or
fragment, and redirects restricted to the same scheme and host with at most five hops.
Credentials are sent as Basic auth only when they are present, and only to the matched
host.

Secrets stay in memory, formatting redacts them, and HTTP failures report the status
class only. Even a successful fetch still verifies the signature, key expiry and
`Valid-Until`: authentication is not trust, and a password does not make a repository's
signature optional.

## Adding a distribution

1. Implement `Provider` in `internal/distro/<name>`. Keep only what is specific:
   releases, suites, architectures, archive endpoints, default trust, and the
   `os-release` fields it owns.
2. Reuse `internal/distro/deb` unchanged. If you need to change it, check that the
   change is genuinely distribution-neutral.
3. Register the provider in `distro.Select` with a constructor returning
   `(Provider, error)`, so a release the provider refuses fails before acquisition. A
   distribution that is not registered fails by name; never add a fallback.
4. Bind catalogues for it in `internal/distro/slices` if its archives differ from the
   provider default.
5. Add the compatibility rows for the new distribution to the
   [matrix](conformance-matrix.md) before claiming anything about it.

## Working on this package

- Anything Ubuntu-specific belongs in `internal/distro/ubuntu`. If a change in `deb`
  reads like a policy, it is in the wrong place.
- A new verification step goes before the thing it protects, never after. Parse only
  verified bytes.
- New bounds need a test that trips them.
- If you relax a trust rule, write down the attack it reopens. Most of the strictness
  here exists because the permissive version had a known failure mode.
