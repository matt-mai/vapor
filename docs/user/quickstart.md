---
layout: default
title: Quickstart
---

# Quickstart

This page builds a small Debian image that serves a request and runs it. The lock
takes a minute or two on a normal connection, the build a few seconds.

## Before you start

You need:

- Linux. Building needs no privileges.
- The `vaporize` command. If you do not have it yet, install the latest release
  with Go:

  ```bash
  go install github.com/matt-mai/vapor/cmd/vaporize@latest
  ```

  Or build it from the repository with `go build -o bin/vaporize ./cmd/vaporize`.

- Network access for `vaporize lock`. The first lock downloads a few tens of
  megabytes.
- Podman or Docker to run the result.

You do not need `git` for this page: a Debian image made of whole packages reads
Debian's own archives and no catalogue.

## Step 1: create a project

```bash
vaporize init --distro debian --release trixie --name demo --dir demo
```

The command writes `demo/image.yaml` and prints `Created image.yaml`. The file
describes a Debian 13 (`trixie`) image for `linux/amd64` with the release files and
the public certificate roots. It refuses to overwrite an existing `image.yaml`.

## Step 2: lock the inputs

```bash
cd demo
vaporize lock
```

`lock` reads `image.yaml`, checks Debian's signed release metadata, downloads the
packages it needs and writes a lock file:

```text
image.lock.yaml
```

The verified bytes stay in your cache. Later builds read them from there and
never download anything.

A download that fails for a passing reason — a busy mirror, a rate limit, a server
error — is tried again up to five times over about a minute. A file that simply is
not there fails at once, because waiting will not make it appear.

## Step 3: add a program

The starter image holds release files and certificates, so it has no program to
run. Add Python and a small server. Write the server first:

```bash
mkdir app
```

```python
# app/server.py
import http.server


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from vapor\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


http.server.HTTPServer(("", 8080), Handler).serve_forever()
```

Then replace `image.yaml` with this. It installs the interpreter, supplies the
server as a file, declares a user to run it, and starts it:

```yaml
version: 1
name: demo
image: ghcr.io/example/demo
tags: [v1]
distro: debian
release: trixie
platforms: [linux/amd64]
contents:
  packages:
    - base-files
    - libc6
    - python3-minimal
    - python3.13-minimal
    - libpython3.13-stdlib
    - ca-certificates
  artifacts:
    - name: server
      dest: /app/server.py
      unpack: false
      mode: "0644"
      sources:
        - platforms: [linux/amd64]
          path: app/server.py
          sha256: "0000000000000000000000000000000000000000000000000000000000000000"
      sbom:
        name: demo-app
        version: "1.0.0"
filesystem:
  accounts:
    groups:
      - name: app
        gid: 65532
    users:
      - name: app
        uid: 65532
        gid: 65532
        home: /app
  paths:
    - path: /app
      type: directory
      uid: 65532
      gid: 65532
      mode: "0755"
container:
  user: "65532:65532"
  entrypoint: [/usr/bin/python3, /app/server.py]
  ports: ["8080/tcp"]
  workdir: /app
```

Fill in the checksum of the file you just wrote, and lock again because the
specification changed:

```bash
sed -i "s/^\( *\)sha256: \".*\"$/\1sha256: \"$(sha256sum app/server.py | cut -d' ' -f1)\"/" image.yaml
vaporize lock
vaporize build --tarball image.tar
```

`lock` compares the file with the checksum you declared, so a file that changed
after you locked it is refused rather than silently built.

## Step 4: run it

```bash
podman load -i image.tar
podman run --rm -p 8080:8080 localhost/v1:latest
```

In another terminal:

```bash
curl localhost:8080
```

```text
hello from vapor
```

The server runs as user `65532`, so the image starts without root and holds no
shell or package manager.

The specification declares `tags: [v1]`, so the loaded image is named
`localhost/v1:latest`. The digest `vaporize build` printed describes the whole
index, which is what the tarball carries; the engine unwraps it to the single
platform image inside.

## Step 5: build it again

```bash
vaporize build --tarball image.tar
```

The digest is the same. That is what reproducible means here: the same lock gives
the same image bytes, on any machine, offline.

A build needs the lock *and* the inputs it names, so copy both when you move it to
another machine:

```bash
vaporize cache bundle image.lock.yaml --output demo.bundle
# on the other machine
vaporize cache unbundle demo.bundle
vaporize build --tarball image.tar
```

The bundle holds only what the lock references and nothing is trusted on arrival:
every entry is checked against its own digest. See
[keep builds reproducible](guides/keep-builds-reproducible.md#move-a-locked-build-to-another-machine)
for what the build checks when it reads one.

## Where to go next

- [Build images](guides/build-images.md) exports layouts, pushes to a registry
  and builds several platforms.
- [Keep builds reproducible](guides/keep-builds-reproducible.md) covers the lock
  file, the cache and moving a locked build to a clean machine.
- [Build a Debian image](guides/build-debian-images.md) covers repositories,
  releases and what Debian images do not need.
- [Add software](guides/add-software.md) picks packages and slices.
- [Troubleshoot](guides/troubleshoot.md) helps when a command fails.
