# The Vapor image

`ghcr.io/matt-mai/vapor` is a container for running `vaporize` where Go is not
installed: a CI job, a build machine or your own laptop. It carries the binary and
the tools a build script expects — `sh`, `bash`, `git`, `curl`, `tar`, `gzip`,
`xz`, coreutils and a public root bundle. There is no package manager and no
interpreter, so it cannot install anything at runtime.

Every path it needs sits in the image, and the defaults already point at them, so
a spec in the working directory needs no flags:

| Thing   | Default                            |
|---------|------------------------------------|
| spec    | `/work/image.yaml`                 |
| lock    | next to the spec                   |
| cache   | `/work/cache` (`VAPOR_CACHE_DIR`)  |
| run as  | root, working directory `/work`    |

`lock` needs the network once; `build` is offline and only needs the inputs
`lock` left in the cache.

## Running it

Mount the directory that holds the spec at `/work` and name the subcommand:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/matt-mai/vapor:latest lock
docker run --rm -v "$PWD:/work" ghcr.io/matt-mai/vapor:latest build --lock /work/image.lock.yaml --oci-dir /work/out
```

On `podman` with SELinux, add `--security-opt label=disable`, or the container
cannot traverse the mount. Add `--user "$(id -u):$(id -g)"` to write the lock and
cache as yourself instead of root.

In a pipeline it is the image the job runs in, so the repository is already there
and only the entrypoint needs clearing: it is `vaporize`, and a runner appends the
job command to the entrypoint, which would make the script an argument to
`vaporize`. How that is spelled differs per product — `entrypoint: [""]` for
GitLab, `--entrypoint` for `docker run`, `container.command` for Azure Pipelines —
and the job then calls `vaporize` like any other tool.

## What is inside

| Path                      | Origin                                       |
|---------------------------|----------------------------------------------|
| `/usr/local/bin/vaporize` | the release binary                           |
| `/bin/sh`, `/bin/bash`    | the `dash:bins` and `bash:bins` slices       |
| `/usr/bin/git`            | the `git:bins` and `git:http-support` slices |
| `/usr/bin/curl`           | the `curl:bins` slice                        |
| `/etc/ssl/certs`          | the `ca-certificates:data` slice             |

Every file comes from an Ubuntu slice, so the trust bundle is the real one: the
`data` slice's script concatenates the certificates, which is the step the package
normally does in a maintainer script Vapor never runs. Shells are kept on purpose
— the hardening pass that strips them is turned off in `image.yaml.in`.

A job that needs another tool has nowhere to install it: build it in the job, or
add the slice to `image.yaml.in` and publish a new image.

## Publishing it

`images/vapor/build.sh` compiles the binary, stamps its hash into
`image.yaml.in`, locks the result and pushes it:

```bash
images/vapor/build.sh --version v1.2.3 --tags 1.2.3,latest --push
```

The hash is stamped at build time because a release binary's hash does not exist
until it is built, so the lock file is an output here rather than a committed
file. The push uses `--image-only`: ghcr.io answers the Referrers API with 404,
and Vapor refuses the tag fallback, so the SPDX and provenance documents stay in
the local layout instead of attached to the tag.

`.github/workflows/image.yml` runs the same script on every `v*` tag, pushing
the version tag and `latest`.
