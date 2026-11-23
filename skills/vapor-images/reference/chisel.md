# Chisel catalogues and slice definitions

A **catalogue** is a directory with a `chisel.yaml` plus `slices/<package>.yaml`
files. A **slice** names a subset of one package's files. Vapor reads the
upstream Chisel v3 format and refuses v1, v2 and v4 by name.

Canonical publishes catalogues for Ubuntu only
(`https://github.com/canonical/chisel-releases`, branch `ubuntu-<release>`).
Debian has no upstream catalogue. If you want to use slices in a Debian image,
write a local catalogue.

## Do you need a catalogue at all?

Only slices need one. Whole `packages` and `artifacts` do not. Write a catalogue
when you want a small image: a slice ships exactly the files you list, while a
whole package drags in its full file list.

## Layout

```text
catalogue/
├── chisel.yaml
└── slices/
    ├── libc6.yaml
    ├── base-files.yaml
    └── ca-certificates.yaml
```

`slices/` is walked recursively and the same package may not appear twice. A
file's basename must equal the `package:` it declares.

## chisel.yaml

```yaml
format: v3

maintenance:
  standard: 2028-08-09      # required for every non-Ubuntu catalogue
  end-of-life: 2030-08-09

archives:
  debian:
    priority: 10
    version: trixie
    components: [main]
    suites: [trixie, trixie-updates]
    public-keys: [debian-archive-key-13]
  debian-security:
    priority: 20
    version: trixie
    components: [main]
    suites: [trixie-security]
    public-keys: [debian-security-archive-key-13]

public-keys:
  debian-archive-key-13:
    id: "225629DF75B188BD"
    armor: |
      -----BEGIN PGP PUBLIC KEY BLOCK-----

      mQINB...
      -----END PGP PUBLIC KEY BLOCK-----
```

Rules:

- `format: v3` exactly. `v2-archives`, `default`, and formats `v1`/`v2`/`v4` are
  refused by name.
- `maintenance` needs `standard` and `end-of-life` (dates `YYYY-MM-DD`). Only a
  catalogue that names an `ubuntu` archive may leave the block out; the built-in
  Ubuntu lifecycle fills it in. `expanded` and `legacy` are optional.
- `version` is the **release codename**, so a spec written as `13` still matches
  `version: trixie`.
- `priority`: one archive may omit it (treated as zero); with two or more
  archives every one must declare a unique non-zero value in `-1000…1000`. Two
  archives sharing a priority is an error.
- `public-keys` must be non-empty for every archive, and every name must exist
  under the top-level `public-keys`.
- `public-keys.<name>.id` is exactly **16 uppercase hex characters** — the short
  form of the key ID, not the fingerprint. `armor` is the ascii-armored public
  key block. The key must be a single primary public key: private material and a
  second primary key are refused, but the **signing subkey every archive key
  carries is fine and expected**.
- The blank line straight after `-----BEGIN PGP PUBLIC KEY BLOCK-----` is part of
  the armored block. Keep it, and indent the whole block to the scalar's level
  (`armor: |` then six spaces). Dropping either detail corrupts the key.
- A catalogue archive is used only when the image binds it to a repository:
  `catalogues: [{archives: {debian: debian, debian-security: debian-security}}]`.
  An archive named after the distro falls back to the built-in archive when
  unbound.

To get an archive's key:

```bash
curl -fsSL https://ftp-master.debian.org/keys/archive-key-13.asc          # trixie main
curl -fsSL https://ftp-master.debian.org/keys/archive-key-13-security.asc # trixie security
gpg --show-keys --with-colons archive-key-13.asc
```

The last 16 characters of the primary **fingerprint** (the `fpr` record) are the
`id`. For Debian 13's archive key the fingerprint is
`04B54C3CDCA79751B16BC6B5225629DF75B188BD`, so the `id` is
`225629DF75B188BD` — which is also what `gpg` prints on the `pub` record. Use
`fpr` if the two ever disagree. Known pairs:

| Key | Primary fingerprint | `id` |
| --- | --- | --- |
| Debian 13 main | `04B54C3CDCA79751B16BC6B5225629DF75B188BD` | `225629DF75B188BD` |
| Debian 13 security | `5E04A1E3223A19A20706E20F9904613D4CCE68C6` | `9904613D4CCE68C6` |
| Debian 12 main | `B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8` | `B7C5D7D6350947F8` |
| Debian 12 security | `05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0` | `254CF3B5AEC0A8F0` |

All four expire in 2035. Re-check with `gpg --show-keys` before relying on them
for a new release.

## Slice definition format

Write `slices/libc6.yaml` in the catalogue directory. Use an archive name from
that catalogue's `chisel.yaml`.

```yaml
package: libc6
archive: debian

essential:
  libc6_copyright:                # package-level essentials: a MAP, never a list

slices:
  config:
    contents:
      /etc/ld.so.conf.d/*-linux-*.conf:

  libs:
    essential:
      base-files_lib:             # slice-level essentials
    contents:
      /usr/lib/*-linux-*/ld-linux-x86-64.so.2: {arch: [amd64]}
      /usr/lib64/ld-linux-x86-64.so.2: {arch: [amd64]}
      /usr/lib/*-linux-*/libc.so.*:
      /usr/lib/*-linux-*/librt.so.*: {mode: 0755}

  copyright:
    contents:
      /usr/share/doc/libc6/copyright:
```

Structure:

- Top level: `package`, `archive`, `store`, `default-track`, `essential`,
  `slices`.
- Slice keys: `hint`, `essential`, `contents`, `mutate`.
- Unknown keys are **errors**, not warnings. So are a second YAML document, an
  empty file, and `${...}` interpolation anywhere.
- Package names match `^[a-z0-9](?:-?[.a-z0-9+])+$`. Slice names match
  `^[a-z](?:-?[a-z0-9]){2,}$` — at least three characters, so `bins` is fine and
  `db` is not.
- `hint` is printable metadata of at most 40 bytes.

### essential

`essential` is a map of `package_slice` references, each optionally filtered by
architecture:

```yaml
essential:
  libgcc-s1_libs: {arch: [amd64, arm64]}
  ca-certificates_copyright:
```

The value may carry **only** `arch:` — anything else is an unknown field. The
architecture list comes from amd64, arm64, armhf, i386, ppc64el, riscv64, s390x.
Self-references and duplicates are refused; the closure is pulled in dependency
first, so never repeat an essential yourself.

### contents

Each entry is a path (wildcards allowed) mapped to `null` or an options map:

| Option | Meaning |
| --- | --- |
| *(empty)* or `copy:` | Copy the path, or `copy: <other path>` from the same `.deb`. Directory copies are not recursive. |
| `make: true` | Create a directory. The path **must end in `/`**. Default mode `0755`. |
| `text: "..."` | Create a file with these bytes (`""` is a real empty file). Default mode `0644`. |
| `symlink: <target>` | Create a link. Mode must be `0777`. |
| `mode:` | Octal mode override, unquoted (`0755`). |
| `mutable: true` | The path may be rewritten by a mutation script. Text and non-directory copies only. |
| `until: mutate` | Temporary content: removed after mutations run. |
| `arch:` | String or list, restricts the entry to those Debian architectures. |
| `prefer:` | Names the provider of a conflicting exact path. Not a dependency. |
| `generate:` | Refused by name — Vapor does not implement manifests. |

- Exactly one kind per entry; combining `text:` and `symlink:` on one line is
  `has conflicting kinds`.
- Wildcards: `?` = one non-slash character, `*` = zero or more non-slash
  characters, `**` = across slashes. **Bracket classes do nothing** — this is not
  shell globbing. Expansion is sorted, so builds stay reproducible.
- Glob entries accept `arch:` and `until:` only.
- There is no `conflicts:` field. Conflicts are derived: an exact path may have
  one owner, globs are checked for overlap, and `prefer:` settles a real conflict.
- **Every declared path must exist in the package.** A path or glob that matches
  nothing fails the lock with `slice <pkg> path <path> is missing from package
  "<pkg>"`. List the package's real contents first — see below.

### mutate

A slice may carry a small script for changes the package's maintainer script
would have made. This is the supported way to build a config file or dir that
`postinst` would have produced.

```yaml
  data:
    contents:
      /etc/ssl/certs/ca-certificates.crt: {text: "", mutable: true}
      /usr/share/ca-certificates/mozilla/: {until: mutate}
      /usr/share/ca-certificates/mozilla/**: {until: mutate}
    mutate: |
      roots = "/usr/share/ca-certificates/mozilla/"
      bundle = "".join([content.read(roots + name) for name in sorted(content.list(roots))])
      content.write("/etc/ssl/certs/ca-certificates.crt", bundle)
```

- The language is **Starlark** (a Python dialect), sandboxed with a step budget.
- The only API is `content.read(path)`, `content.write(path, data)` (an existing
  `mutable` regular file, mode kept) and `content.list(path)` (sorted immediate
  names, directories suffixed `/`).
- No imports, no file or network access, no shelling out. A generator expression
  inside a call is a syntax error — use a list comprehension as above.
- `contents.slices-engine.max-steps` in the image spec raises the budget
  (default 100000 steps).
- Anything a script creates outside `mutable` paths, or leaves behind after
  `until: mutate`, is a build failure.

## Finding the files a package really ships

A slice path that does not exist in the `.deb` fails the lock, so read the real
file list before writing the slice. From a `.deb`:

```bash
ar p package.deb data.tar.xz | tar -tJf -            # or data.tar.zst | tar -t --zstd
```

From a repository, download the `.deb` with plain HTTP first:

```bash
curl -fsSLO http://deb.debian.org/debian/pool/main/libc/libc6/libc6_2.41-12_amd64.deb
ar p libc6_2.41-12_amd64.deb data.tar.xz | tar -tJf - | grep -E 'ld-linux'
```

The package's own `Copyright` file is usually `/usr/share/doc/<pkg>/copyright`
— **not every package ships one** (libgcc-s1 does not). Check before writing a
`copyright` slice.

## The copyright convention

Upstream catalogue files give each package a `copyright` slice and list
`<pkg>_copyright` in the package-level `essential`, so every slice carries the
license notice. Vapor does not enforce this; it is a convention. Copy it, and
drop the pair for a package that ships no copyright file.

## Checking a catalogue

```bash
vaporize slices check --catalogue path/to/catalogue      # prints "catalogue OK"
vaporize slices list --catalogue path/to/catalogue [--package NAME]
vaporize slices show libc6/libs --catalogue path/to/catalogue
```

`check` validates the whole graph — parse errors, missing essential references,
cycles, path conflicts — and prints at most 20 diagnostics. It does **not**
download anything, so it cannot tell you a path is absent from the `.deb`; only
`vaporize lock` does that.

## Using the catalogue from an image spec

```yaml
contents:
  catalogues:
    - name: trixie
      path: ../../shared/slices/trixie          # relative to the spec directory
      archives: {debian: debian, debian-security: debian-security}
  slices:
    - {catalogue: trixie, package: libc6, slice: libs}
    - {catalogue: trixie, package: base-files, slice: base}
```

- The local `path` is relative to the directory holding `image.yaml`, cannot be
  absolute, and cannot escape that directory.
- With exactly one catalogue declared the `catalogue:` key may be omitted.
- A local catalogue is locked **by content**: edit a slice and the lock drifts,
  so `vaporize lock` again. This is deliberate — the lock records exactly which
  bytes define the image.
- Bind each catalogue archive to a repository name in `archives:`; an archive
  named after the distro falls back to the built-in one when unbound.

### A slice you can reuse: distro CA bundle

`ca-certificates` builds `/etc/ssl/certs/ca-certificates.crt` in a maintainer
script that Vapor never runs. The slice above rebuilds it from the Mozilla roots
and then deletes the roots with `until: mutate`. Measured root counts differ per
release (Debian 13: 148, Ubuntu 26.04: 120), so count once instead of guessing:

To check the count, run the image with the engine you deploy it with:

```bash
podman run --rm --entrypoint /usr/local/bin/python3 example.org/app \
    -c 'import ssl; print(len(ssl.create_default_context().get_ca_certs()))'
```

## Troubleshooting

| Message | Cause and fix |
| --- | --- |
| `catalogue public key "x" is invalid` | The armor is malformed: usually the blank line after `BEGIN` or the indentation was lost. |
| `catalogue public key "x" has invalid id` | `id` is not 16 uppercase hex characters. |
| `catalogue public key "x" has id "A", want "B"` | `id` must be the last 16 of the key's primary fingerprint. |
| `catalogue archive "x" public keys is empty` | Every archive lists at least one key. |
| `catalogue archive "x" requires an explicit repository binding` | Bind it in the spec's `archives:` map. |
| `catalogue archives "a" and "b" have the same priority` | Priorities must be unique and non-zero. |
| `essential must be a map` / `essential value must be a map` | Write `{pkg_slice:}` not `- pkg_slice`. |
| `slice def is invalid: ... field not found` / unknown key | A typo or an option that does not belong on that entry. |
| `slice <pkg> path <path> is missing from package "<pkg>"` | The path is not in the `.deb`. List the `.deb` and correct the slice. |
| `slice <pkg>_<slice> path <path> must end in / for make` | `make: true` needs a trailing slash. |
| `... has conflicting kinds: text, symlink` | One kind per entry. |
| `requests "manifest", which Vapor does not support` | Drop the `generate:` entry. |
| `got for, want ','` in a mutation | Starlark refused a generator expression; use a list comprehension. |
