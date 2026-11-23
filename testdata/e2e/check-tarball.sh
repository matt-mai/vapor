#!/bin/bash
# Import a published tarball into an isolated store and run one command in it.
# Usage: check-tarball.sh ARCHIVE ENTRYPOINT EXPECTED [ARGS...]
set -euo pipefail

archive=$1
entrypoint=$2
expected=$3
shift 3
store=$(mktemp -d)
podman=(podman --root "$store/graph" --runroot "$store/run" --tmpdir "$store/tmp" --storage-driver vfs)
image=
cleanup() {
    if [ -s "$store/container" ]; then
        "${podman[@]}" rm --force --ignore --cidfile "$store/container" >/dev/null || true
    fi
    if [[ $image =~ ^(sha256:)?[a-f0-9]{64}$ ]]; then
        "${podman[@]}" image rm "$image" >/dev/null || true
    fi
    rm -rf "$store"
}
trap cleanup EXIT

"${podman[@]}" load --input "$archive"
image=$("${podman[@]}" image list --no-trunc --quiet)
if ! [[ $image =~ ^(sha256:)?[a-f0-9]{64}$ ]]; then
    echo 'expected exactly one image in the isolated archive store' >&2
    exit 1
fi
output=$("${podman[@]}" run --rm --cidfile "$store/container" --pull=never --network=none \
    --timeout 30 --platform linux/amd64 --entrypoint "$entrypoint" "$image" "$@" 2>&1) || {
    echo "$output" >&2
    exit 1
}
if ! grep -Fq "$expected" <<< "$output"; then
    echo "the imported image printed '$output', which does not contain '$expected'" >&2
    exit 1
fi
