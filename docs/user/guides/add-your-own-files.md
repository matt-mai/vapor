---
layout: default
title: Add your own files
---

# Add your own files

An artifact is a file you supply yourself: your compiled binary, a certificate,
a static asset. Vapor reads it during `lock`, checks its SHA256 and puts it at the
path you choose.

Use an artifact when the file is not in an Ubuntu package, or when you want your
own build instead of the packaged one.

## One file

Keep the file next to `image.yaml` and name it with `path`:

```yaml
contents:
  artifacts:
    - name: server
      dest: /usr/local/bin/server
      unpack: false
      mode: "0755"
      sources:
        - platforms: [linux/amd64]
          path: files/server-1.0-linux-amd64
          sha256: 3f7c1d0a9b95a4b0f1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899
      sbom: {name: server, version: "1.0"}
container:
  entrypoint: [/usr/local/bin/server]
```

`sbom` is required. It names the upstream component and version the file comes
from, so a later software list can attribute it.

Compute the hash from the file you are going to ship:

```bash
sha256sum files/server-1.0-linux-amd64
```

`sha256` takes 64 lowercase hex digits without a `sha256:` prefix.

| Field        | Meaning                                                        |
| ------------ | -------------------------------------------------------------- |
| `name`       | A name for this artifact, unique in the specification.         |
| `dest`       | Where the file goes in the image. Must be an absolute path.    |
| `unpack`     | Required. `false` copies one file, `true` extracts an archive, `package` installs a Debian package. |
| `mode`       | Permissions for the copied file. Default `"0644"`.             |
| `uid`, `gid` | Owner of the file in the image. Default `0`, which is root.    |
| `sbom`       | Required `name` and `version` of the upstream component.       |

## One artifact, two platforms

A multi-platform image needs a payload per platform:

```yaml
contents:
  artifacts:
    - name: server
      dest: /usr/local/bin/server
      unpack: false
      mode: "0755"
      sources:
        - platforms: [linux/amd64]
          url: https://downloads.example.com/server-linux-amd64
          sha256: 1111111111111111111111111111111111111111111111111111111111111111
        - platforms: [linux/arm64]
          url: https://downloads.example.com/server-linux-arm64
          sha256: 2222222222222222222222222222222222222222222222222222222222222222
      sbom: {name: server, version: "1.0"}
```

Every platform in the specification scope needs a source. A missing payload stops
the build instead of producing an image that fails on one architecture.

If the same bytes work everywhere, one source can cover both:

```yaml
    - name: server
      dest: /usr/local/bin/server
      unpack: false
      mode: "0755"
      sbom: {name: server, version: "1.0"}
      sources:
        - platforms: [linux/amd64, linux/arm64]
          url: https://downloads.example.com/server-any
          sha256: 3333333333333333333333333333333333333333333333333333333333333333
```

## Archives

Set `unpack: true` to extract a tar archive. Gzip, Zstandard and XZ compression
are recognised from the file contents, so the file name does not matter:

```yaml
contents:
  artifacts:
    - name: tools
      dest: /
      unpack: true
      sbom: {name: tools, version: "2.1"}
      sources:
        - platforms: [linux/amd64]
          path: files/tools.tar.gz
          sha256: 4444444444444444444444444444444444444444444444444444444444444444
```

`dest` is the directory the archive is extracted into. Use `/` to unpack at the
image root.

`mode` may not be set with `unpack: true`, because the permissions stored in the
archive are kept. Extraction refuses entries that try to leave the target
directory, link outside it or overwrite an unrelated path.

## Installing a Debian package

Set `unpack: package` to install a `.deb` you built elsewhere. Vapor treats it as a
package: the files go where the package puts them, it is recorded in the package
database, and the SPDX document lists it.

```yaml
contents:
  artifacts:
    - name: myapp
      unpack: package
      sbom: {name: myapp, version: "1.0"}
      sources:
        - platforms: [linux/amd64]
          path: dist/myapp_1.0_amd64.deb
          sha256: 5555555555555555555555555555555555555555555555555555555555555555
```

No `dest`, `mode`, `uid` or `gid` here: the package carries them. Its `sbom` name
and version must match the package inside the file. Vapor does not install the
package's dependencies for it; list what it needs under `contents.packages`, and
`vaporize lock` will tell you the name of anything missing.

## Where artifacts come from

A source names its file either by `path`, a file next to `image.yaml`, or by
`url`, a remote download.

A `path` is what you normally want: the file travels with the specification and
the build stays offline. It is relative to the directory that holds `image.yaml`,
uses forward slashes, and may not point outside that directory.

A `url` is for something you do not want to vendor, such as a published upstream
release archive. It accepts HTTP or HTTPS and must have a hostname. It cannot
contain credentials, a query string or a fragment, so a GitHub release asset link
is refused; use an address that serves the file directly. HTTP is allowed because
the `sha256` value establishes what the download must contain, but it gives no
transport privacy. Put the file on an HTTPS server when that matters to you.

Either way Vapor reads the file during `lock`, checks the hash and keeps the
verified bytes in the cache. A build never reads the original file or downloads it
again, so a build works offline.

## Next

- [Reference: contents](../reference/contents.md) lists every artifact field and
  the exact validation rules.
- [Add software](add-software.md) covers packages and slices.
