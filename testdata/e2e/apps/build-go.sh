#!/bin/sh
# Compile Vapor with the Go release baked into the image. Module dependencies
# can still come from the proxy.
set -eu

export HOME=/tmp
export GOPATH=/tmp/go
export GOCACHE=/tmp/go-cache
export CGO_ENABLED=0
export GOTOOLCHAIN=local

cd /src

/usr/local/go/bin/go version
/usr/local/go/bin/go build -trimpath -o /tmp/vaporize ./cmd/vaporize

spec_dir=$(mktemp -d)
/tmp/vaporize init --distro ubuntu --release 26.04 --name self-build --dir "$spec_dir"
grep -Fxq 'name: "self-build"' "$spec_dir/image.yaml"

echo "== build ok"
