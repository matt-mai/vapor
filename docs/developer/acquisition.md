---
title: Acquisition
---

# Acquisition

Acquisition is the only part of Vapor that talks to the network, and it only ever
does one thing: fetch a payload whose identity is already known, and prove the bytes
match. It does not choose what to fetch, does not extract, and does not decide
whether a repository is trusted. Those decisions belong to
[distribution](distribution.md) and [lock assembly](locking.md).

Keeping the scope this narrow is what makes the offline guarantee checkable. A build
has no fetcher to call, so "build links never download" is a property of the code
rather than a policy someone has to remember.

## On this page

- [The pieces](#the-pieces)
- [The cache](#the-cache)
- [Snapshotted local inputs](#snapshotted-local-inputs)
- [Verified downloads](#verified-downloads)
- [Retries](#retries)
- [Replaying evidence offline](#replaying-evidence-offline)
- [Credentials](#credentials)
- [Boundaries worth naming](#boundaries-worth-naming)
- [Working on this package](#working-on-this-package)

## The pieces

| Package | Job |
| --- | --- |
| `internal/acquire` | download fixed payloads and verify them |
| `internal/cache` | store verified bytes by digest, atomically |
| `internal/snapshot` | copy declared local files into the cache as verified bytes |
| `internal/verify` | replay locked repository evidence with no network |

## The cache

The cache is a directory of blobs named by their SHA-256:

```
<cache-dir>/sha256/<first two hex>/<sha256>
```

`cache.New` creates the `sha256` directory. Directories are `0700`, because the cache
is private local state and everything in it is content the build already trusted.

`Store(reader, digest, size)` writes to a staging file in the same directory with mode
`0600`, reads at most `size+1` bytes, and only renames it into place after the size,
the hash, the sync and the close all succeeded. The `size+1` read is what catches a
producer that hands over more bytes than it promised. A rename is atomic, so a reader
either sees the old inode or the new one and never a half-written blob.

`Open(digest, size)` derives the path from the digest, requires a regular file of the
recorded size, and reads the whole blob once to compare it with its digest before it
hands anything out. A corrupt blob therefore fails the open, not the last read: some
callers stream the handle straight into a registry upload session, and bytes already
sent cannot be taken back. The handle it returns hashes the bytes again as they are
read, so a blob rewritten in place after it was opened still fails instead of reaching a
caller as verified content. The blob is read twice, once to verify and once by the
caller; that is the price of never emitting a byte whose content is still unknown.

`Read(digest, size)` is the same check for callers that want the whole blob in memory at
once. It goes through `Open`, so it verifies the same way and then returns the bytes the
second pass hashed.

### Decoded indexes

A package index is stored compressed, because that is the form its signed release file
names. Nothing can use it in that form: the resolver needs the text. Decoding is
therefore repeated on every run, and it dominates the cost of asking the cheap
questions. Measured on the Ubuntu `universe` index, 16 MB compressed and 77 MB of text,
xz spends about six seconds per run. Second runs of `vaporize outdated` were slow for
that reason alone, not for network or git.

So the cache also keeps the decoded bytes, in `<digest>.decoded` beside the blob. Five
properties make that safe to do:

- **It is a pure function of a verified blob.** The name is the digest of the compressed
  input, so a decoded entry cannot be confused with a decode of something else. If the
  compressed blob is removed, `gc` removes the decoded entry with it, because both are
  keyed by the same digest.
- **The signed release names the bytes it hands out.** A release file hashes the plain
  `Packages` index as well as the compressed one, so `SelectIndex` records that digest and
  size and `ReadDerived` recomputes both before returning anything. An entry that
  describes different packages is refused even when its own header and length agree.
  This is the check that closes the gap between "a memo of these bytes" and "a memo of
  *some* bytes": `verify` can only confirm that the records the resolver selected exist
  in the signed index, never that the resolver did not omit one.
- **It can only save work.** `ReadDerived` reports failure for anything missing, short,
  longer than it declares, larger than the caller allows, or naming bytes the release does
  not, and the caller then decodes the verified compressed bytes itself. A wrong or stale
  entry costs time, never correctness: cold and warm resolution reach the same answer.
- **It carries its own length.** A truncated package index parses as a shorter index
  instead of failing, so a half-written entry would silently change the answer. The
  header holds the payload length, and an entry whose file size disagrees with it is
  refused.
- **It is never the authority.** The compressed blob stays the thing the lock names and
  the audit replays. A decoded entry is a memo of work already done on bytes that were
  already authenticated.

A release that names no plain `Packages` index leaves a decoded entry nothing to check
against, so none is written and every run decodes the verified bytes. That is the
accepted cost of the rule above.

The type that carries this is `deb.DerivedIndexStore`, an optional interface on the
index store. `cache.Cache` implements it; a test double need not, and then every call
decodes as before.

The cache has no eviction and no parent-directory fsync. Both are deliberate: the cache
is a build input, so deleting from it under a running build would be a foot-gun, and a
staging file left behind after a crash is harmless because the next `Store` of the same
digest either finishes the rename or replaces the leftover.

Reclaiming space is an explicit operation instead: `vaporize cache gc` keeps the blobs a
set of locks references and removes the rest. `gc` learns what a lock references from
`locking.Blobs`, the same walk the audit uses, so a blob kind that is added to the lock
cannot be checked without also being kept. `lock` holds a shared filesystem lock from
acquisition through publication, and `cache gc` holds it exclusively from discovery
through the sweep. A command that cannot acquire the lock returns a busy error. The
`.gc.lock` file stays in the cache directory so all processes lock the same file.

GC keeps recent unmarked blobs and refuses to sweep when it sees a recent staging
file. The age check is not a substitute for the filesystem lock: an input reused
from the cache may be old. GC still cannot preserve inputs from locks it is not given.
Build output layers are not in any lock and can be rebuilt after GC. If a lock's
blobs are already missing, GC reports them without failing.

## Snapshotted local inputs

Anything the specification points at on disk is copied into the cache before use, and
the lock records the resulting hash and size. Reading a file once to verify it and
again later to consume it leaves a window where the file can change, so Vapor does not
have that window.

`internal/snapshot.Snapshot` handles three kinds of local input:

| Role | What is accepted |
| --- | --- |
| trust key | exactly one public-key snapshot containing every configured fingerprint, no private material |
| CA | PEM public certificates; every block parsed; no private keys, no other block types; text outside a block accepted only as a `#` comment, a blank line or a heading underlined with repeated punctuation, and anything else refused |
| VEX | bytes retained as-is |

The snapshot is taken relative to the specification's directory. A path may climb above
it, because images in a repository share a key directory or a CA file, so
`../ca/ca.pem` resolves. The climb itself is the root: a leading run of `..` is applied
to the directory name and everything after it is opened through `os.Root` on that
ancestor. Only regular files are reachable, a symlink that escapes the ancestor is
rejected, and each file is bounded at 64 MiB. An artifact `path` is different: it is
image content, so it stays inside the specification's directory.

The same path used for two different roles produces two records. A file is not "the
key file"; it is "this file, in this role", and a trust decision has to know which.

An artifact source declared with `path` is the fourth kind of local input, but it is
copied by `internal/acquire` rather than by `Snapshot`: the payload is verified against
the declared `sha256` while it is streamed into the cache, exactly like a download. It
reads through `snapshot.Local`, so the same confinement applies, and the lock records
the path instead of a URL. Bounding stays at `MaxArtifactSize`, because an artifact is
an image payload and not a trust input.

## Verified downloads

`internal/acquire` takes a payload that has already been authenticated by repository
metadata and makes it available as a verified blob. It never resolves a name, never
picks a version and never fetches a file just in case a later step needs it.

That last point is a real behaviour: when a selection does not include a package from
an optional or restricted archive, the archive is not fetched at all. A build should
not need credentials for content it does not use.

## Retries

Both fetchers — the artifact downloader and the archive fetcher — retry a request
that failed for a reason that may pass. `internal/retry` holds the policy:

| Setting | Value |
| --- | --- |
| Attempts | 5, counting the first try |
| Backoff | 500 ms doubling, capped at 20 s |
| Jitter | spread over the upper half of each interval |
| Waits for | transport errors, 408, 429, 500, 502, 503, 504 |

During `lock`, each archive or artifact HTTP attempt allows one minute for the
response headers and 30 minutes for the whole request, including the body. The
longer limit leaves time to download a payload up to the 2 GiB size limit. An
attempt can be retried if it times out before the body is handed to the caller.
A timeout while reading the body fails the download without caching partial data, and
is reported as `download failed: timed out` rather than as a cache write error: the
bytes only pass through the cache writer, they do not come from it.

Jitter spreads out retries when several clients hit the same outage.

A `Retry-After` header wins over the computed delay, in either form the header allows
(seconds or an HTTP date), and is still capped by the policy's maximum. Obeying the
server's own number is what makes a rate limit work: guessing shorter lands inside the
window and gets refused again.

What is **not** retried is a conclusion rather than a hiccup: a 404 or 403, a refused
redirect, or a cancelled context. A missing file stays missing, and a redirect the
fetcher refuses would be refused again — asking twice only delays the error the user
needs to see.

A declared URL carries no query, but a redirect may: a server that signs its own
asset URLs, like GitHub's release assets, puts the signature in the query of the
302 target. So a redirect is checked for credentials, scheme and host rather than
for a query, and its target is never recorded or printed. A target that carries a
query must be HTTPS, because a signature in a plaintext URL is a published
signature: verifying the payload's digest afterwards protects the bytes, not the
proof that they were fetched.

The fetch sends no `Referer`. Go would fill one in from the previous hop on every
redirect, query included, and a signed asset URL signs itself with that query, so a
second hop to another host would hand the first signature to a third party.

The failure a user sees names the repository, the file and the status:

```
repository "ubuntu": archive request for "dists/nonexistent/InRelease" failed: HTTP 404
```

Neither the archive URL (it may carry credentials) nor the transport's own text (it
may quote them) appears in the message. An artifact download is stricter, because a
transport error quotes the request: its failure says `download failed` and adds the
reason only when Vapor composed that reason itself — a refused redirect, an HTTP
status or a timeout.

## Replaying evidence offline

`internal/verify` is what lets a build answer "was this trusted" without a network.
It takes the lock's evidence and the cache, and reproduces the chain:

1. For a repository with no explicit keys, take the provider default. A catalogue
   binding is resolved by reading the binding file from the verified cache; a Pro
   binding only accepts keys for the matching service.
2. Load each key blob and require its full fingerprint to be the configured one. A key
   that does not match is not "a different key"; it is a failure.
3. Verify `InRelease`, or `Release` plus `Release.gpg`. Replay asks only for the
   recorded signer, then requires the resulting signer set to equal the expected set
   exactly. `Valid-Until` must match the recorded value, and the suite, architecture and
   components must bind.
4. Read the package index from its canonical path
   `<component>/binary-<arch>/Packages[.xz|.gz]`, check it against the signed SHA-256
   and size, decompress within the bound, and parse candidates.
5. Match each selection on repository, name, version, architecture, path, SHA-256 and
   size. Discard the candidates before reading the next index. Replay still checks every
   index, even after all selections have matched.

Steps 3 to 5 are the same checks acquisition performed at lock time. That repetition is
the design: the lock records evidence so the build can reach the same conclusion from
cached bytes instead of trusting an earlier conclusion.

The one intentional difference is freshness. Replay takes no clock input at all, and
uses `deb.IgnoreExpiry`, so a lock that was fresh when it was written stays usable. A
build failing because a Monday moved past a `Valid-Until` would make offline builds
impossible for no security gain, since the evidence was verified when it was created.
See [distribution](distribution.md) for the two expiry modes.

## Credentials

Credentials never enter the cache, the lock, image layers or logs. They live in memory
for the duration of a fetch, they are formatted redacted, and failures report the HTTP
status class instead of the request that carried them. `internal/distro/ubuntu/pro`
holds the matching rules; see [distribution](distribution.md#pro-archives).

## Boundaries worth naming

- A missing or corrupt blob is a build failure. Nothing retries by downloading.
- A decoded index is a memo, not a source. It is named by the digest of the blob it came
  from, refused when its length disagrees with itself, and dropped with that blob. If it
  is absent or unreadable the decode is repeated, so the only thing it can ever cost is
  the time it was meant to save.
- Verification happens before parsing, always. No exception for "we already checked
  this at lock time". The bytes are hashed twice, once before they are handed out and
  once as they are read, so a caller never parses unverified content and never emits
  bytes whose content is still unknown.
- The cache trusts its own directory. Local state under `0700` is the boundary; Vapor
  does not defend the cache against someone who can already write to it.
- The specification is trusted. A trust key, CA source or VEX input may name a file above
  the specification's directory, and the ancestor it names is the confinement. An author
  who may write a specification already chooses the keys, the repositories and the
  artifact digests, so nothing here is a defence against that author. The assumption
  itself is recorded in [the schema notes](schema.md).
- Acquisition does not extract. Extraction is a separate operation with its own bounds,
  so a bug in a decoder cannot reach the network and a network bug cannot reach the
  image tree.

## Working on this package

- Add a bound with the loop, not later. Every ceiling here exists because an input is
  attacker-influenced in size.
- When a new payload type appears, decide whether it is authenticated by repository
  metadata, by a spec digest, or by nothing. If the answer is "by nothing", it does not
  belong in the cache.
- Tests use fakes and fixtures. Network access in a unit test is a sign the design has
  drifted.
