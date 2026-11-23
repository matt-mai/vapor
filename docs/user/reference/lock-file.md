---
layout: default
title: Lock file
---

# Lock file

The lock file records what a build used: versions, commits, hashes and sizes. It
holds no secrets and no package bytes. `vaporize lock` writes it and
`vaporize inspect` prints it in a fixed order.

- Working with locks: [keep builds reproducible](../guides/keep-builds-reproducible.md).

## Top-level fields

```yaml
version: 1
spec: sha256:51b97bc446c75558368a270875b9f9e780fec653f21bd5baaf2c53a0202c394e
provider:
  distro: ubuntu
  release: "26.04"
platforms:
  - linux/amd64
local-inputs: []
```

| Field          | Meaning                                                                                                                                 |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `version`      | Lock format version. `1` today.                                                                                                         |
| `spec`         | Digest of the specification this lock was made from.                                                                                    |
| `provider`     | Distribution and release.                                                                                                               |
| `platforms`    | Platforms the lock covers, in the declared order.                                                                                       |
| `local-inputs` | Local files the lock captured: trust keys (`trust-key`), certificates (`ca`) and VEX inputs (`vex`), each with a path, digest and size. |

A build refuses a lock whose `spec` digest does not match the specification in
front of it, so editing the specification always needs a new lock.

## catalogues

```yaml
catalogues:
  - name: ubuntu
    source:
      type: remote
      url: https://github.com/canonical/chisel-releases
      selector:
        branch: ubuntu-26.04
      commit: 660fe6b93063ce85286fb51f759cc55ddf24d9a1
    tree: sha256:fca44d418c7a7a4b3989ec8835f0a5a972db3f4201f7a6328ce2f8f948419abb
    manifest:
      - path: chisel.yaml
        kind: file
        sha256: b54d3fc743724898f21976734e1886c02dc171e17fa4adee7036649c0ccb1c8d
        size: 7069
```

| Field      | Meaning                                                                                |
| ---------- | -------------------------------------------------------------------------------------- |
| `source`   | Where the catalogue came from: `remote` with url and selector, or `local` with a path. |
| `commit`   | The commit the selector resolved to. A branch resolves once, at lock time.             |
| `tree`     | Digest of the whole catalogue directory.                                               |
| `manifest` | Every file in the catalogue with its digest and size.                                  |

The build compares each definition it uses against the digest recorded here, so a
catalogue that changes after locking is refused.

## repositories

One record for each repository, suite and platform that a selected package or
slice actually came from. A declared suite nothing was taken from is left out.

```yaml
repositories:
  - id: sha256:a673bedd66602c229734eee5...
    name: ubuntu
    platform: linux/amd64
    architecture: amd64
    url: https://archive.ubuntu.com/ubuntu
    suite: resolute-updates
    trust:
      keys:
        - fingerprint: F6ECB3762474EDA9D21B7022871920D1991BC93C
          sha256: 2a3cc57ab6b47626b496a101c29af6dfe54d54d03d613f2326b9f2a30a15c39b
          size: 1660
    release:
      format: inrelease
      path: dists/resolute-updates/InRelease
      sha256: 52c0d015365dd368d1c94962cfc93513a112a3a1d03ee86e1e46d44e126bdbbf
      size: 137401
      signers:
        - F6ECB3762474EDA9D21B7022871920D1991BC93C
    indexes:
      - component: main
        path: main/binary-amd64/Packages.xz
        sha256: 4ba87e5cf212fcf87edba67ca6f9f7fa4500248f670b1a3448ddaf3bc3df2df2
        size: 872476
```

| Field     | Meaning                                                          |
| --------- | ---------------------------------------------------------------- |
| `id`      | Digest of the repository identity.                               |
| `name`    | The name from the specification.                                 |
| `trust`   | Key fingerprints and the digests of the key files used.          |
| `release` | The signed metadata file and the keys that signed it.            |
| `indexes` | The package indexes used, per component, with digests and sizes. |

Package records point at a repository `id`, which is how the build knows where a
package came from.

## packages and slices

```yaml
slices:
  - platform: linux/amd64
    package: base-files
    version: 14ubuntu6.3
    architecture: amd64
    catalogue: ubuntu
    archive: ubuntu
    repository: sha256:a673bedd66602c229734eee5...
    content:
      path: pool/main/b/base-files/base-files_14ubuntu6.3_amd64.deb
      sha256: 2dbda984e7036988cb7e1051c88884188056bd190422b720bd5039036a8cdacb
      size: 74706
    selected:
      - release-info
    closure:
      - copyright
      - etc
      - lib
      - release-info
    definition-digest: sha256:4d046b3a661eae77fa1f64499a03163bb27ebe0d714d70b6a2acda4e7799e944
```

| Field               | Meaning                                            |
| ------------------- | -------------------------------------------------- |
| `platform`          | The platform this record is for.                   |
| `version`           | The exact package version that was selected.       |
| `content`           | The package archive, with its digest and size.     |
| `selected`          | The slices the specification asked for.            |
| `closure`           | The slices actually used, including required ones. |
| `definition-digest` | Digest of the slice definition in the catalogue.   |

A whole package record has `platform`, `name`, `version`, `architecture`,
`source`, `repository` and `content`, but no slice fields. `source` names the
Debian source package and its version, which differs from the binary version when
one source builds several packages.

## artifacts

```yaml
artifacts:
  - name: hello
    platform: linux/amd64
    url: http://example.com/hello.sh
    sha256: 8599a426f95d3384f133ff8ddb87ab360430c2f59018a9294ece513013beb404
    size: 32
    dest: /usr/local/bin/hello
    unpack: false
    uid: 0
    gid: 0
    mode: "0755"
    sbom:
      name: hello
      version: "1.0"
```

Each record names where the file came from — `url` for a download, `path` for a
file that was read from the specification's directory — the digest it was verified
against and its size. The build reads the bytes from the cache and checks them
again, so neither the original file nor the network is needed.

An artifact with `unpack: package` is a Debian package, so its record has no
`dest`, `uid`, `gid` or `mode`: the package decides those when it is installed.

## What a lock does not prove

A lock records the inputs a build used and lets a build verify them again. It does not
prove the build is right:

- It does not re-resolve dependencies. A locked package set that was incomplete when
the lock was written stays incomplete, and a build accepts it.
- It does not say whether the selection is the one you want, only which versions were
chosen from which signed metadata.

A lock you made yourself records your decision. A lock from somewhere else is a
proposal: read the package and slice list before you build from it.

## Reading a lock

- Compare two locks with `diff`, `vaporize inspect` keeps field order stable.
- Look at `packages` and `slices` to see which exact versions an image contains.
- Look at `repositories` to see which keys signed the metadata.
- If a build says the spec digest does not match, lock again.
