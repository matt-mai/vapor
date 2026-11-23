---
layout: default
title: Use private packages
---

# Use private packages

Two cases need extra setup: packages from an Ubuntu Pro archive, and packages from
a server or mirror you run yourself.

## Ubuntu Pro archives

Ubuntu's catalogue names two paid archives, `ubuntu-esm-apps` and
`ubuntu-esm-infra`. They work like the public archive, but they need a login and
a repository of your own:

```yaml
contents:
  repositories:
    - name: esm-apps
      endpoints:
        - platforms: [linux/amd64]
          url: https://esm.ubuntu.com/apps/ubuntu/
      suites: [resolute-apps-security, resolute-apps-updates]
      components: [main]
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
      archives:
        ubuntu-esm-apps: esm-apps
```

Two things make it an opt-in: a repository that names the Pro endpoint, and the
binding under the catalogue's `archives`. An unbound paid archive is skipped, so
it costs nothing in an image that does not use it.

A slice from a Pro archive that has no binding fails, because Vapor has nowhere to
fetch that package from.

A Pro token is not a substitute for the archive's signing key. Vapor checks the
signed metadata with the service key and refuses metadata it cannot verify:

```text
vaporize: operation failed: repository "esm-apps": InRelease is not validly signed
```

### Supply the login

Either use environment variables, which suits CI:

```bash
export VAPOR_PRO_USERNAME='bearer'
export VAPOR_PRO_PASSWORD='your-pro-token'
vaporize lock
```

Or rely on the credential file Ubuntu Pro machines already have, at
`/etc/apt/auth.conf.d/`:

```text
machine https://esm.ubuntu.com/apps/ubuntu/ login bearer password your-pro-token
```

Vapor reads the same directory as APT. Set `VAPOR_AUTH_DIR` to point somewhere
else. When `VAPOR_PRO_USERNAME` is set, Vapor uses the environment and ignores the
files.

A login is only for downloading. Vapor still verifies the signed metadata against
the archive's key or the keys you configured, and a correct login cannot skip that
check. Once the inputs are in the cache, builds need no login at all.

Keep credentials out of the specification, the lock file and your catalogue.
Vapor keeps them in memory and removes them from error messages and logs.

## Your own package server

A repository declaration names one server per platform, its suites, its
components and the keys you trust:

```yaml
contents:
  repositories:
    - name: internal
      endpoints:
        - platforms: [linux/amd64]
          url: https://packages.example.com/ubuntu
        - platforms: [linux/arm64]
          url: https://packages-arm.example.com/ubuntu
      suites: [resolute, resolute-updates]
      components: [main]
      trust:
        keys:
          - path: keys/archive.asc
            fingerprints: ["0123456789ABCDEF0123456789ABCDEF01234567"]
      by-hash: prefer
      freshness:
        valid-until: if-present
```

| Field        | Meaning                                                       |
| ------------ | ------------------------------------------------------------- |
| `endpoints`  | One URL per platform. Every platform needs one.               |
| `suites`     | The distribution suites to read, in order.                    |
| `components` | The components to read, in order.                             |
| `trust.keys` | Public keys and their full fingerprints.                      |
| `by-hash`    | `prefer` (default), `require` or `disable`.                   |
| `freshness`  | `if-present` (default) or `require` for a `Valid-Until` date. |

Key files are local files, given relative to the specification directory.
Fingerprints are full 40 or 64 hex characters, not short key IDs. Vapor rejects a
key file that contains private key material, and it only trusts the fingerprints
you list.

Declaring `trust` replaces the default trust for that repository instead of adding
to it. Leave `trust` out to use the key Ubuntu publishes.

`by-hash: require` makes the lock fail when a server does not offer by-hash
downloads. `freshness.valid-until: require` makes it fail when the metadata has no
expiry date.

## Bind your own catalogue

A catalogue can name different servers for its archives:

```yaml
contents:
  catalogues:
    - name: internal
      path: catalogues/internal
      archives:
        ubuntu: internal
```

The upstream archive name stays exactly as the catalogue writes it. The value is
the name of a repository in the same specification. A binding changes where
packages come from; it does not change package versions, suites or trust.

A local catalogue is a directory next to your specification:

```yaml
contents:
  catalogues:
    - name: internal
      path: catalogues/internal
```

The path is relative to the specification file, written without a leading `./`.
An absolute path and `./catalogues/internal` are both refused:

```text
vaporize: operation failed: load spec "image.yaml": validate spec: contents.catalogues[0]: local path must be nonempty, clean, relative and slash-separated (relative to the spec directory)
```

## Next

- [Reference: contents](../reference/contents.md) has the full repository and
  catalogue reference.
- [Troubleshoot](troubleshoot.md) covers refused keys and downloads.
