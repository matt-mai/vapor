# Chisel v3 fixture seed

All YAML and JSON fixture data here was authored for Vapor and is dedicated under
**CC0-1.0** (see the repository's `LICENSE-CC0`). It is not copied upstream code,
not a complete Canonical catalogue, and not suitable for building a real image.

## Provenance and deliberate substitutions

The immutable source identities, source paths and per-fixture SHA256 values are
recorded in `provenance.json`. The matching implementation inventory is
[`docs/developer/chisel-v3-compatibility.md`](../../../../../docs/developer/chisel-v3-compatibility.md).

- `catalogue/chisel.yaml`: original micro-catalogue probing v3 root records. Release
  dates and public archive suite/component values are factual references to the
  pinned Resolute catalogue. It adds a negative-priority archive, omits ESM infra,
  and replaces **all** Canonical keys with one generated test-only public key.
- `catalogue/slices/base-files.yaml`: original reduced starter probe. It preserves
  the selected slice's name and four-slice closure, not the full upstream paths or
  behavior. Never use it as a byte-for-byte upstream regression fixture.
- `catalogue/slices/fixture.yaml` and `provider.yaml`: original path, architecture,
  mutation, preference, hint and manifest probes. No DEB archives are included yet.
- `catalogue/bin-slices/demo.yaml`: original store metadata probe. The pinned
  release contains only `.gitkeep` in `bin-slices/`; this is not a real released
  binary. The pinned implementation cannot acquire store packages.
- `invalid/`: isolated future parser rejection inputs, not part of the valid
  catalogue. Load each under the SDF filename in `expectations.json` so a
  filename-mismatch error does not mask the intended rejection.
- `expectations.json`: future semantic assertions. Closure lists are sorted sets,
  not claimed mutation/extraction execution order.

The release snapshot contains no license file and Chisel's implementation has an
AGPL-3.0 license with separately marked Apache public components. Neither grants
an assumed license to the separate release repository. No upstream source, test
literals, catalogue files or license texts are vendored here. Check permissions
before adding verbatim upstream fixtures; retain any applicable notices.

## Test key

The armor in `catalogue/chisel.yaml` was locally generated using GnuPG (RSA-2048,
creation time 2026-01-01, no expiry). Only its public key was retained; the temporary
key directory/private key was deleted. Full fingerprint:

```text
5F2B6B981ACC84B969998767F6DC226F4AAF8F29
```

Its short ID is fixture metadata, **not a production trust anchor**. Do not use it
for release authentication. Future authentication tests generate their own signing
keys and signed metadata; this fixture supplies no signatures or private key.

## Verification boundary

`go test ./internal/distro/slices` checks pins, declared license and fixture byte
integrity, including unlisted/missing files. It does **not** parse YAML, resolve
slices, execute Starlark, acquire store blobs or generate manifests. These tests
will be added in the substeps mapped by the developer checklist. No upstream test
suite or upstream CLI was executed to qualify these fixtures in substep 1.2.

To deliberately change a fixture, review its source evidence and expected behavior,
then update its SHA256 in `provenance.json`; tests never regenerate golden hashes.
Refreshing upstream pins is a separate explicit review, not a test-time download.
