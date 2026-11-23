# End-to-end image specs

Real specifications, built from the live Ubuntu and Debian archives and then run in a
container. The lock authenticates the archive, the build assembles the image and the
script starts it.

Run everything:

```bash
testdata/e2e/run.sh
```

A single image:

```bash
testdata/e2e/run.sh runtime-packages
```

The script needs `git`, `go`, `curl`, `uv`, `openssl`, `python3` and `podman` (or
`docker`). It is opt-in: ordinary `go test` never touches this directory or the network.

`uv` runs `attestations.py`, which reads the lock and therefore needs a YAML parser. The
script names that dependency in its own header (PEP 723), so `uv` builds a small cached
environment for it and nothing is installed into your Python installation. Without `uv`
the run stops before the first build.

## Images

| Name                 | Content  | Proves                                                                           |
| -------------------- | -------- | -------------------------------------------------------------------------------- |
| `builder-packages`   | packages | A whole-package build image installs a dependency and an apt package at runtime. |
| `runtime-packages`   | packages | A whole-package runtime image serves HTTP with no shell and no package manager, builds for `amd64` and `arm64`, and trusts a certificate authority the spec imported. |
| `builder-slices`     | slices   | The same build works from slices, including a slice that runs a mutation script. |
| `runtime-slices`     | slices   | The same runtime works from slices, including a mutated certificate bundle.      |
| `runtime-artifact`   | artifact | A static Go binary copied from a local file serves HTTP without any packages. |
| `builder-go`         | packages | The pinned upstream Go toolchain builds Vapor and runs the new binary.     |
| `debian-builder-packages` | packages | The same build works against Debian, with both archives declared.        |
| `debian-runtime-packages` | packages | A Debian runtime image serves HTTP with no shell or package manager.     |

An image is the smallest thing that can be built, locked and run, so checks share an
image rather than getting one each. `runtime-packages` carries three unrelated checks
because it is already the image built from whole packages on both architectures; a
second specification would only repeat it.

The two Debian images name both archives themselves: Debian's security updates are
published at a different address from its main archive, and Vapor has no default for
that. They use `trixie`, the release Vapor carries trust keys for.

Every image also carries attestations: an SPDX document and a SLSA provenance statement
per platform, plus a VEX statement for `runtime-packages`, which makes three
vulnerability claims — two inline and one imported from `specs/vex/review.json`.
The unsigned and signed checks both require exactly those CVE IDs on each platform.

## Smoke tests

Every spec declares `tests`, and the run calls `vaporize test` on the layout it just
built. Each test runs in its own container with no network and no host access, and its
exit status is compared with what the spec claims. The declarations are small on
purpose — the interpreter prints one line, `dpkg --list` names a package, `apt-get check`
reads the archive configuration Vapor generated — because a failure should point at the
image rather than at the test.

On an AMD64 host using Podman, `runtime-artifact` also loads the published
`image.tar` into a fresh temporary store and runs the imported server's `--help`
without pulling or using the network. This is separate from the OCI-directory
workload. Run `bash testdata/e2e/check-tarball_test.sh` to test the check with a
mock engine.

## Slice mutation

Two images select a slice that carries a mutation script, and the run checks what the
script produced from the flattened root filesystem rather than trusting that it ran.

`ca-certificates_data` declares the bundle as `text: FIXME` with `mutable: true`, reads
the individual certificates from a directory marked `until: mutate`, concatenates them
into the bundle and lets the directory be removed. So the run requires
`/etc/ssl/certs/ca-certificates.crt` to begin with a PEM header — the placeholder text
would be a one-word file — and requires the `mozilla` directory to be gone.

`builder-slices` selects `ca-certificates_data-with-certs`, which generates the same
bundle and also writes `/etc/ca-certificates.conf`. That image was already selecting the
slice before these checks existed; nothing asserted the outcome.

The runner exports and lists the filesystem once per inspected image and platform.
An `absent` check rejects both the path and anything below it. Run
`bash testdata/e2e/check-filesystem_test.sh` to test these checks without an engine.

The assertions live in the `mutations` array in `run.sh`: an entry names the image, a
path and either `starts:PREFIX` or `absent`. Adding a mutation to another spec means
adding an entry, not a new block of script.

These are real catalogue scripts from the selected upstream commit, so they exercise the
worker boundary end to end: the build re-executes `vaporize` in the sandbox, the script's
writes land in the image, and `until: mutate` cleanup happens. `internal/mutation`'s
adversarial suite covers the limits; this covers the result.

These are not just inspected for their shape. `attestations.py` unpacks the image layers
and requires the SPDX file list and its SHA-1 and SHA-256 checksums to match what the
image actually contains, compares the provenance inputs and the VEX products with the
lock, and requires each statement's subject to be the image it is attached to.

It also derives every element identifier itself, from the documented domain-separated
identity, and requires the document and the lock to agree. An identifier that a name
could produce would pass a weaker check, so the script rebuilds the identity rather than
matching a pattern. Finally it requires every package, slice and artifact to carry the
package URL that a VEX claim about it resolves to, which is what lets the two payloads be
joined by URL alone.

One image is also built twice with a throwaway Ed25519 key. The script requires the
attachment descriptors to name a DSSE envelope, verifies the signature with `openssl`
over the pre-authentication encoding, and unwraps the statement the checks above already
describe. A signed rebuild has to produce byte-identical files, and a key the loader
refuses has to fail the build without writing a layout.

`builder-go` compiles Vapor from the source artifact, then runs the new binary and
checks the spec it writes. `GOTOOLCHAIN=local` prevents Go from downloading a
replacement compiler. The build can still reach the module proxy for dependencies.

`runtime-packages` and `runtime-slices` are the images that get hardened: no
shell, no `apt`, no `dpkg` tooling. The script asserts that all three are absent
before starting the app, so a silently unhardened image fails the run.

## The imported certificate authority

The `ca` test on `runtime-packages` proves that a certificate authority arriving
through `filesystem.ca` is trusted by the image, not merely written into it. `run.sh`
creates a throwaway root and a server certificate for `127.0.0.1` with `openssl`,
passes them to the build as local artifacts, and pins the root in the rendered spec.

The test replaces the entrypoint and talks to a TLS server inside the container, so
the container needs no network. It builds one context from the image's own bundle
and requires the handshake to verify, then builds a context trusting an unrelated
root and requires that handshake to be rejected. The second half is the real
assertion: a client that skipped verification would pass the first one.

Both certificate files come through `filesystem.ca`, one of them the public bundle
pinned by hash, which is why the image trusts the public roots as well as the new
one. The private key is an artifact with declared ownership, because the test runs
as an ordinary user rather than as root.

## The arm64 image

`runtime-packages` is the only image with more than one platform. The `amd64`
packages come from `archive.ubuntu.com` and the `arm64` packages from
`ports.ubuntu.com`, so it is also the only image that proves a mixed-architecture
index and cross-architecture package resolution.

The run starts the `arm64` image under emulation. That needs qemu registered with
binfmt_misc, which `qemu-user-static` provides; without it the run stops and says
so, because a silently skipped arm image would prove nothing.

Emulation is slow: expect a minute or two extra. The image is built and locked once,
and the container checks run per platform, so the arm64 half costs what starting one
container costs rather than a whole build.

## What a run does

1. Builds `vaporize` into `.work/vaporize`.
2. Fetches the branch or tag named by `CATALOGUE_REF` (default `ubuntu-26.04`),
   prints its commit, and exports the committed files to `.work/catalogue/`.
3. Stages the local artifact files into `.work/inputs/`.
4. Locks and builds each spec into `.work/<name>/`, holding the layout and a tarball.
5. Checks the attached statements against the layout, the image layers, the lock and
   the statements directory with `attestations.py`.
6. Builds `builder-packages` and `runtime-slices` a second time into
   `.work/<name>/signed-again/` and asserts an identical digest and identical
   statements. One image per assembly path is enough, and a second build costs as much
   as the first.
7. Checks the mutation script results: the generated certificate bundle and the
   removed `until: mutate` directory.
8. Runs a command in each runtime image, which replaces its entrypoint: the
   interpreter and standard library, the trust bundle in `runtime-packages`, and
   an unknown flag for the artifact binary.
9. Starts the runtime images and checks the HTTP response, adding
   `--platform` for an image built for another architecture.
10. Runs the builder images' workload inside the container.

## The workloads

The builder images run `apps/build.sh` inside the container, which is a real
build rather than a probe:

- installs a Python dependency with pip into a virtual environment,
- installs `curl` with `apt-get` from the image's own configured archive,
- runs the app's test suite,
- starts the server and requests a page with the freshly installed `curl`,
- lists a package from dpkg's database and runs `apt-get check` over the source
  list and keyrings the build generated.

The runtime images run `apps/server.py` directly, served by the interpreter the
image carries. Because a runtime image has no shell, the runner also gives each
one a command, which replaces the entrypoint: the interpreter imports `json`,
`http.server` and `ssl`, `apps/tls.py` accepts a server signed by the imported
root and rejects it under an unrelated one, and the artifact image runs its own
binary with an unknown flag and expects exit code 2. The artifact runtime image
runs a compiled Go binary that has no interpreter and no shared library to find,
and checks an unpacked Go release that came from the network.

## Where the artifacts come from

Almost every artifact source is a local file, named by `path` relative to the
specification. `run.sh` stages the files into a `files/` directory beside each
rendered spec, because a path may not leave that directory, and stamps each
`@name@` placeholder with the hash of the staged file. Local files are what a
real specification uses for its own scripts, so this is also the shape that
most of the suite exercises.

`builder-go` also tests a remote artifact: it downloads the official Go release
from `go.dev` and unpacks it at `/usr/local/go`. The spec pins its SHA-256 digest.

GitHub release assets are not usable here: their download redirect carries a
signed query string, and Vapor refuses a URL with credentials or a query, so a
`github.com/.../releases/download/...` source would fail. `go.dev` serves the
archive directly.

## Layout

```text
testdata/e2e/
  run.sh                 the whole run
  attestations.py        checks the statements a build attached (run by `uv`)
  specs/                 one specification per image
  specs/vex/             OpenVEX documents the specs import
  apps/                  Python application and its build script
  tools/                 the Go program compiled into the artifact image
  .work/                 catalogue, rendered specs, staged files and outputs (ignored)
```

Run `bash testdata/e2e/catalogue_test.sh` to check catalogue refreshes with a local
Git repository. This check needs no network or container engine.
