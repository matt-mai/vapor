---
title: Testing
---

# Testing

Vapor's tests are the only place where a claim about behavior becomes checkable. This
page explains how the test suite is laid out, what each kind of test is allowed to do,
how to add a test, and where the boundary is between a test that proves Vapor is
self-consistent and one that proves Vapor agrees with somebody else.

Read the rules here as one sentence: **a test must fail for a reason you can name.**

## On this page

- The three kinds of test
- Running the suite
- What a good test looks like
- Fixtures and test data
- Tests that read the documentation
- External oracles
- End-to-end images
- Quick reference

## The three kinds of test

| Kind | Runs where | Network | Proves |
| --- | --- | --- | --- |
| Unit and integration tests | `go test ./...` | never | That a package behaves as its callers expect. |
| Oracle comparisons | opt-in, one at a time | no | That a Vapor answer matches the tool that defines the answer. |
| End-to-end images | opt-in, `testdata/e2e/run.sh` | yes, at lock time | That a real specification produces an image that runs. |

`task check` runs the unit and integration tests without the race detector.
Oracle comparisons and end-to-end image tests are opt-in.

## Running the suite

```bash
task test        # go test -cover ./...
task test:race   # go test -race -cover ./...
task lint        # golangci-lint run ./...
task check       # lint + test, the fast local gate
task test:mutation # mutation tests without race instrumentation
task test:full     # test:race + test:mutation + test:e2e
```

`task fix` before `task check` formats the files, applies autofixes and runs `go fix`.
Run both before you ask for a review: a failing lint is not a finding, it is unfinished
work.

On every push to `main` and every pull request, GitHub Actions runs `golangci-lint`
and runs the tests with the race detector. CI and `task test:full` also run the
mutation tests without the race detector, whose extra memory use would otherwise
cause the sandbox memory-limit cases to skip. The end-to-end suite runs locally
before a release because it needs a container engine.
Workflow actions are pinned by commit SHA with the release in a trailing comment, so a
moved tag cannot change what CI runs. Dependabot checks the Go modules and those pins
once a week and rewrites both the SHA and the comment.

Two things the suite depends on:

- **Tests may be slow but must not be flaky.** A test that passes twice out of three
  runs is worse than no test, because it teaches people to rerun instead of read.
- **Tests must not need root or a daemon.** If a test needs either, it belongs in the
  opt-in group with a skip message that says so.

The mutation sandbox needs Linux 4.7 or newer for user namespaces. On a platform that
cannot provide that, its tests skip with the reason rather than failing. A skip is not a
pass, and CI for those tests runs on Linux.

## What a good test looks like

A test is a claim about behavior plus the reason the claim matters. In practice:

- **Name the behavior, not the mechanism.** `TestApplyContent_ExplicitModeOverridesCopy`
  tells the reader what was decided; `TestApplyContent2` does not.
- **Test the boundary you changed.** If a limit exists, test the value at the limit and
  the value past it. Off-by-one at a resource bound is a security bug in this codebase.
- **Do not assert on the shape of an error string** unless the string is part of a
  contract the conformance matrix depends on. Compare typed errors or wrapped sentinels.
- **Prefer the real thing over a mock of it.** The filesystem, the digest functions and
  the specification decoder have no I/O and can be used directly. Mocking them would
  test the mock.
- **Use `t.TempDir()`, never a fixed path.** Tests run in parallel; a shared directory
  turns a pass into an occasional failure.
- **Never weaken a check to make a test pass.** If a test cannot pass, either the code
  or the expectation is wrong. Both are findings.

Concurrency deserves a note. `BuildEach` runs platforms in parallel and produces bytes
that must not depend on the number of workers. That is tested by building with one
worker and with many and comparing digests, not by asserting on goroutine behaviour.

## Fixtures and test data

Three directories hold test data, and each has a different rule.

| Directory | Content | Rule |
| --- | --- | --- |
| `internal/schema/spec/testdata/spec-digest/` | Specification files with their canonical JSON and SHA256 | The digest vectors. Changing a projection changes these files. |
| `internal/distro/slices/testdata/chisel-v3/` | The reduced Chisel v3 fixture: catalogue, slice definitions, expectations, provenance | Synthetic CC0 payloads only, with recorded hashes. |
| `internal/distro/debian/testdata/` | Real signed `InRelease` samples for the Debian main and security archives | Reviewed Debian bytes, pinned with digests and a fixed verification time. |
| `testdata/e2e/` | Real specifications, apps and the runner | Opt-in, network, container engine. |

The slice fixture is deliberately a small subset of a real catalogue. Its
`provenance.json` records where each file came from, and
`TestFixtures_ProvenanceAndIntegrity` fails if a fixture is added, removed or edited
without updating the record. That proves the fixtures are stable, not that they are
valid: unchanged bytes of a broken document are still broken.

Fixtures that need signed data are generated inside the test. `lockinput`'s integration
test creates an OpenPGP entity, signs a synthetic repository release with it, serves it
from `httptest` and collects a lock. The key exists only for the duration of the test
and is never a trusted default. Do the same for anything else that needs credentials:
generating cheap throwaway material beats committing a key that someone later mistakes
for real.

The CLI tests share one such fixture, `newOfflineFixture` in `cmd/vaporize/workflow_test.go`,
which serves a signed repository, a catalogue, per-platform artifacts and a mutable
slice. It can be turned off — `(f *offlineFixture) offline` stops answering requests and
deletes the catalogue and key directories — so a rebuild from the same lock provably
needs only the cache. `cmd/vaporize/main_test.go` runs the sandbox worker when the test
binary is re-executed, so a slice mutation in those tests crosses a real process
boundary.

## Tests that read the documentation

Three developer pages are part of the code contract, because a Go test parses them:

| Page | Enforcing test | What fails |
| --- | --- | --- |
| [Conformance matrix](conformance-matrix.md) | `internal/conformance/matrix_test.go` | A named test that does not exist, an unknown status, a repeated ID, a checklist row with no matrix row, a missing blocker, or no Debian provider coverage at all. |
| [Chisel v3 compatibility](chisel-v3-compatibility.md) | `internal/conformance/matrix_test.go` | A missing heading, a policy table whose row count no longer matches the policy rows in the matrix. |
| [Lock schema](lock-schema.md) | `internal/schema/lock/lock_vectors_test.go` | A digest vector block that does not decode, or a recorded digest that no longer matches its example. |

This is not documentation-as-tests for its own sake. The matrix is the only place that
records which behavior is covered, blocked or refused, and a matrix that silently drifts
from reality is worse than no matrix. Wiring it to `go test` makes drift a build
failure within a minute of the change.

What that means when you edit those pages:

- Keep the exact heading text. Headings are the anchors the tests look for.
- Keep the table columns in order and one row per ID.
- Keep the digest blocks byte-identical to what the test expects. If you change a
  vector, change the code and the vector in the same change, and expect the test to
  tell you the new digest.
- Put the text the test greps for (`covered`, `blocked`, `unsupported`) in a whole
  table cell, not inside a longer sentence.

## External oracles

Some behavior Vapor implements is defined by an external tool, not by Chisel. For those,
a test that only asserts Vapor's own reading repeats the same assumption in two places.
Where the defining tool can be run, the test compares against it.

| Behaviour | Defined by | Oracle | Status |
| --- | --- | --- | --- |
| Slice and catalogue semantics | Chisel v3 | `chisel` | blocked: no upstream run yet |
| Debian version ordering | dpkg `verrevcmp` | `dpkg --compare-versions` | not yet compared |
| Deb archive decoding | dpkg-deb, ar, tar | `dpkg-deb -I`, `dpkg-deb -c` | not yet compared |
| Archive import and link rules | POSIX tar and GNU extensions | `tar` | not yet compared |
| OCI image and index layout | OCI image-spec | `skopeo`, spec JSON Schemas | not yet compared |
| SPDX payloads | the published SPDX 2.3.1 schema | checked-in schema, offline validator | covered |
| SLSA provenance statements | the published SLSA v1 specification | field allowlist, since SLSA publishes no JSON Schema | covered |
| OpenVEX claims and statements | the OpenVEX v0.2.0 specification | one case per rule, per refused input and per evidence outcome | covered |
| `vex` command output and exit codes | the command reference | end-to-end runs against the offline build fixture | covered |
| Attached statements | the OCI image-spec artifact and referrers rules, cosign's attachment shape | local registry round trips and directory layout inspection | covered |
| DSSE envelopes and signatures | the DSSE v1.0.2 protocol and envelope specifications | the specification's worked example, generated Ed25519 keys | covered |

The [conformance matrix](conformance-matrix.md) tracks the Chisel rows. The other
authorities are ordinary tests with a real oracle, not a second status table.

### Rules for oracle tests

- **An oracle is evidence, never an input.** No lock, build or assembly path may invoke
  one, and no oracle output may reach a spec, lock, cache or image.
- **Ordinary tests stay offline and deterministic.** A test that needs an oracle skips
  with a clear message when the tool is missing, so `task check` passes without it.
- **Opt in explicitly.** A missing oracle must never turn a failing check into a pass.
- **Compare outputs, not exit codes alone.** A misconfigured oracle that exits zero must
  not look like agreement.
- **Record the oracle identity** (image digest or package version) next to the
  expectation, so a later disagreement can be attributed to a version change rather than
  to Vapor.

### Running an oracle in a container

Containers keep the oracle off the host and out of the module. Rootless Podman is
enough; Vapor itself needs no daemon, root or BuildKit, and neither does this.

```bash
# Debian version ordering: ask dpkg, do not reimplement it in a test.
podman run --rm --network=none \
  --mount type=bind,src="$PWD/testdata/versions.txt",dst=/versions.txt,ro \
  docker.io/library/debian:bookworm-slim \
  sh -c 'while read -r a b want; do
           dpkg --compare-versions "$a" lt "$b" && got=-1 ||
           dpkg --compare-versions "$a" gt "$b" && got=1 || got=0
           [ "$got" = "$want" ] || echo "MISMATCH $a $b want=$want got=$got"
         done < /versions.txt'
```

Keep the case list in the repository as data. The container runs it; it does not
generate it. Mount inputs read-only and mount nothing else: no home directory, no
socket, no credentials. Record the image by digest, not by the floating tag used above.

### Dogfooding: build the oracle with Vapor

The long-term shape is that Vapor builds the container it is tested against. A
whole-package request needs no catalogue, so an oracle spec stays small:

```yaml
# oracle.yaml: a throwaway image that exists to run dpkg, nothing else.
version: 1
name: oracle-dpkg
image: localhost/oracle-dpkg
distro: ubuntu
release: "26.04"
platforms: [linux/amd64]
contents:
  packages:
    - dpkg
```

Lock it, build it, and the result is the oracle for version-ordering and
archive-decoding comparisons. Two things follow: the oracle is pinned by Vapor's own
lock, so a disagreement has one traceable cause; and a bug in Vapor's assembly then
shows up as an oracle disagreement, which is the point of dogfooding.

This path is not wired up yet. Today an oracle image comes from an upstream registry,
pinned by digest.

## End-to-end images

`testdata/e2e/run.sh` builds real images from the live Ubuntu and Debian archives,
rebuilds them to prove reproducibility, and runs them in a container. It needs `git`,
`go`, `curl`, `uv`, `python3`, `openssl` and either `podman` or `docker`, and it is
never part of `go test`.

`CONTAINER_ENGINE` picks the engine; it defaults to `podman`.

```bash
CONTAINER_ENGINE=docker testdata/e2e/run.sh runtime-packages
```

Podman reads the layout directory the build wrote. Docker cannot, so the runner imports
the build's own `image.tar` and addresses every image by the manifest digest the layout
holds for that platform. The two paths are only different in how an image is named: the
in-image checks, the hardened-image checks, the export assertions and the serving checks
run against either engine.

One image, or all of them:

```bash
testdata/e2e/run.sh runtime-slices
testdata/e2e/run.sh
```

Each spec is a template with `@name@` placeholders replaced by the SHA256 of a staged
local file, so the runner pins a hash it computed from the bytes it just handed to the
build. The staged files are copied into a `files/` directory beside each rendered spec,
because an artifact `path` may not leave the spec's own directory. The runner also
swaps the remote catalogue URL for the checked-out copy, which keeps the lock on local
bytes instead of re-fetching Git for every image.

Local paths are the normal shape, and the suite uses them for everything it generates:
application scripts, the test binaries and the throwaway certificates. One artifact is
a real download — the Go toolchain in `runtime-artifact` — so the `url` path is covered
by an actual upstream release rather than only by unit tests.

The runner asserts behaviour that unit tests cannot: the hardened runtime images contain
no shell and no package manager, a rebuilt `index.json` and its statements are
byte-identical, and each image actually serves HTTP. A second build costs as much as the
first, so reproducibility is asserted on `builder-packages` and `runtime-slices`, one image
per assembly path, rather than on every image.

Checks that need the image running are ordinary engine runs against the layout, because
the runner is also the only place a real engine meets these images. They fall in three
groups, and each is deliberately small, because the interesting failure is the image
rather than the check:

- An image that already runs a script inside the container asserts dpkg and apt there.
  `apps/build.sh` lists a package from dpkg's database and runs `apt-get check`, so an
  unreadable database or an unusable keyring fails during the run.
- A runtime image names a command, which replaces the entrypoint. That is how the
  packaged interpreter is exercised rather than the application: one run imports
  `json`, `http.server` and `ssl`, and `runtime-packages` additionally runs
  `apps/tls.py`, which has to accept a server signed by the certificate it imported and
  reject it under a context trusting an unrelated certificate.
- `runtime-artifact` runs its own binary with an unknown flag and expects exit code 2,
  which proves startup without opening a port.

Every build also passes `--attestations-dir`, so each run checks the documents a real
build writes. `testdata/e2e/attestations.py` is a single-file `uv` script: it reads the
layout, the lock and the documents directory and checks them against each other. It
unpacks every layer and expands the hardlinks multi-call packages rely on, so the file
list it compares with SPDX is the image's real content.

First the shape: one artifact manifest per platform and format, each with the right
subject, `_type`, `predicateType`, a payload that hashes to its descriptor, and files in
the directory that are exactly those payloads, without the wrapper.

Then the content, which is what makes the check worth running:

- SPDX is compared with the image. The layers are unpacked, each layer's uncompressed
  bytes are checked against the config's diff ID, and the resulting file set with its
  checksums has to equal the document's files — so a statement that names a file the
  image does not have, or carries a stale checksum, fails. Every package, slice and
  artifact must be an element the lock holds on that platform, the slices the
  dependency closure pulled in included, with matching versions and checksums. The
  document must describe every element and every file must be contained by one, and the
  namespace and name must name the subject and its platform.
- Provenance is compared with the lock. The recorded spec digest, the builder identity
  and every resolved dependency (catalogue tree or archive, local inputs, repository
  release, packages, slices, artifacts) have to match the lock for that platform; only
  the digest of the lock itself is taken on trust, because it names a file the layout
  does not carry.
- VEX is compared with the lock's products. Every product URL in the document must be a
  package or artifact the lock holds for that platform, the document id must name the
  subject, and every claim must be complete (`not_affected` with a justification,
  `affected` with an action statement).

`runtime-packages` also claims three vulnerabilities — two inline and one imported from
`specs/vex/review.json` — and the check requires all three in the attached VEX
statement.

### Why the checker needs uv

The checker is a script, not a Go test. It belongs to the e2e run, which is already
opt-in and already needs tools outside the module, so it must not grow the shipped
binary, `go.mod`, or the `task check` surface.

It does need one third-party library: the lock is YAML, and the Python standard library
cannot read it. Rather than check a `requirements.txt` or a virtual environment into the
repository, the script declares its dependency in the file itself (PEP 723) and `uv`
builds an isolated, cached environment for it:

```python
#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///
```

That keeps three things true at once: the dependency is pinned in the same file as the
code that uses it, nothing is installed into the developer's system Python, and the
first run on a new machine works without a setup step. `run.sh` checks for `uv` up front
and stops with `missing uv: this check validates the attached statements with it`, so a
missing tool is one clear message instead of an import error in the middle of a build.

The script annotates every function and passes both `mypy --strict` and `basedpyright`
with no warnings. That means no bare `Any`: each document it reads has a `TypedDict`
for the fields it uses, and every `json.loads` result is cast to one at the point it is
read. Checkers are not a runtime dependency, so they are not declared inside the
script:

```bash
uvx --with mypy --with types-PyYAML mypy --strict testdata/e2e/attestations.py
uvx --with pyyaml basedpyright testdata/e2e/attestations.py
```

To run it by hand against a layout you already built:

```bash
uv run testdata/e2e/attestations.py \
    --layout out --statements statements --lock image.lock.yaml \
    --expect spdx,provenance
```

One image is built for `amd64` and `arm64` and started under emulation, so the run also
covers a mixed-architecture index and `ports.ubuntu.com` resolution. Emulation needs qemu
registered with binfmt_misc (`qemu-user-static`); the runner checks for the emulator and
fails with a clear message instead of skipping the arm image, because a skipped image
proves nothing. It is the slowest image in the run. A run that ends without those assertions failing is the only
evidence that a real specification survives the whole pipeline.

## Quick reference

| Question | Answer |
| --- | --- |
| Which gate must pass before review? | `task fix`, then `task check`. |
| Where do I put a test for a package? | Next to the code, `package_test.go` in the same directory. |
| How do I test a network input? | `httptest`, generated signing keys, no committed secrets. |
| How do I test a bounded resource? | At the bound (passes) and one unit past it (fails). |
| How do I record a new conformance case? | Add the test, add the row in the matrix, keep the checklist row. |
| May I add a dependency for a test? | Discuss it first. Test-only dependencies still enter `go.mod`. |
| Something needs root. What now? | It does not go in `go test`. Opt-in script or a container. |
