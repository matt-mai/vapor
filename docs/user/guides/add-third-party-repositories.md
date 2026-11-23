---
title: Add a third-party DEB repository
---

# Add a third-party DEB repository

Use a vendor's repository to get a package the vendor publishes directly. Keep
the distribution archive in the same spec so Vapor can find system libraries and
other dependencies. This example uses nginx.org's stable packages on Ubuntu
26.04 (`resolute`) for `linux/amd64`.

## Save the vendor's public key

Save each public key you trust in a file next to the image spec or in a
subdirectory. List the full fingerprint in the spec after checking it against
the vendor's published fingerprint.

The [NGINX signing key download](https://nginx.org/en/pgp_keys.html) contains
several keys. The following commands use a temporary GPG keyring to export just
the key used by this example. Check its fingerprint against the
[NGINX installation docs](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/)
before using it. Run these commands in the directory where you'll save the spec:

```sh
(
  set -eu
  keyring=$(mktemp -d)
  trap 'rm -rf "$keyring"' EXIT
  curl -fsS https://nginx.org/keys/nginx_signing.key -o "$keyring/nginx.key"
  gpg --homedir "$keyring" --batch --import "$keyring/nginx.key"
  gpg --homedir "$keyring" --batch --armor --export \
    8540A6F18833A80E9C1653A42FD21310B49F6B46 > "$keyring/nginx.asc"
  test -s "$keyring/nginx.asc"
  mkdir -p keys
  cp "$keyring/nginx.asc" keys/nginx.asc
)
```

## List both repositories

Save this as `nginx.yaml`:

```yaml
version: 1
name: nginx
image: example.com/nginx
distro: ubuntu
release: resolute
platforms: [linux/amd64]

contents:
  packages: [base-files, nginx]
  repositories:
    - name: nginx
      endpoints:
        - platforms: [linux/amd64]
          url: https://nginx.org/packages/ubuntu
      suites: [resolute]
      identity: own
      packages: [nginx]
      components: [nginx]
      trust:
        keys:
          - path: keys/nginx.asc
            fingerprints: ["8540A6F18833A80E9C1653A42FD21310B49F6B46"]
    - name: ubuntu
      endpoints:
        - platforms: [linux/amd64]
          url: https://archive.ubuntu.com/ubuntu
      suites: [resolute, resolute-updates, resolute-security]
      components: [main, universe]
```

`identity: own` says the vendor describes its own release. NGINX signs
`Suite: stable` and `Codename: resolute`; keep `suites: [resolute]` for the URL
path and Vapor accepts whatever suite the vendor signs, because your key checks
the signature. The declared keys are required: nothing else vouches for that
identity.

`packages: [nginx]` is the scope. The vendor archive may only supply the names
listed, so a vendor that also publishes a common library cannot quietly replace
the copy the distribution ships. Without a scope list an own-identity repository
could satisfy any package name.

The Ubuntu entry keeps its usual signed `Suite` check and uses the keys Vapor
ships. The `base-files` package supplies standard paths needed by this image.

## Lock and build

```sh
vaporize lock --spec nginx.yaml
vaporize build --spec nginx.yaml --oci-dir nginx.oci
```

Check the `nginx` entry under `packages` in `nginx.lock.yaml` to confirm the
chosen package came from `nginx.org`. The scope list decides what the vendor may
supply; among the archives that may supply a name, the higher version wins. To
pin one, request a version with `contents.packages[].version`.

A repository without `identity: own` keeps the distribution's release rules: the
suite must be one the distribution serves. That is what a plain mirror needs,
and it is why a mirror of another release stays out of the image.

This builds an OCI image with the package files. Vapor does not run maintainer
scripts. Set the command, user and any writable paths you need before running
nginx as a container. See [configure the system](configure-the-system.md).

## What a repository must look like

Vapor reads the repository shapes Debian, Ubuntu and the common vendor archives
publish, and refuses anything else rather than guessing:

- An `InRelease` file is required. A repository that publishes only `Release` and a
detached `Release.gpg` is refused. No archive Vapor reads needs that shape.
- Packages are read from `<component>/binary-<arch>/Packages`. A repository that
  publishes architecture-independent packages only in a separate `binary-all` index
  is refused, because those packages would silently go missing.

A refused shape is named in the error, so you can tell it apart from a wrong suite
or a bad key.
