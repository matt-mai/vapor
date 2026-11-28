#!/bin/bash
# Build the published Vapor runtime image from this directory and push it.
#
#   images/vapor/build.sh --version v1.2.3 --tags v1.2.3,latest [--push]
#
# The binary is compiled here rather than taken from a release, because the image
# is built by the same tag job that publishes that release.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
version=""
tags=""
push=false

usage() {
    sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

while (($#)); do
    case $1 in
        --version) version=${2:?--version needs a value}; shift 2 ;;
        --tags) tags=${2:?--tags needs a value}; shift 2 ;;
        --push) push=true; shift ;;
        -h | --help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || { echo "--version must be a release tag such as v1.2.3" >&2; exit 2; }
[[ -n $tags ]] || { echo "--tags must list at least one tag" >&2; exit 2; }

work="$here/.work"
rm -rf "$work"
mkdir -p "$work/files"

# Static, like the release binaries: an image with no libc carries no dynamic loader.
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$version" \
    -o "$work/files/vaporize" "$root/cmd/vaporize"
# The specification is a template, so stamping is a plain substitution rather than
# a rewrite: @vaporize@ is the hash of the bytes that go into the image.
sed -e "s|@vaporize@|$(sha256sum "$work/files/vaporize" | cut -d' ' -f1)|" \
    -e "s|@version@|${version#v}|" \
    -e "s|@tags@|$tags|" \
    "$here/image.yaml.in" >"$work/image.yaml"

vaporize lock --spec "$work/image.yaml" --cache-dir "$work/cache"
build=(vaporize build --spec "$work/image.yaml" --lock "$work/image.lock.yaml"
    --cache-dir "$work/cache" --oci-dir "$work/out" --tarball "$work/image.tar")
# --image-only: ghcr.io answers the Referrers API with 404, and Vapor refuses the tag
# fallback that would index the statements instead. The SPDX and provenance documents
# are still in the layout this leaves behind, and in the release assets.
$push && build+=(--push --image-only)
"${build[@]}"
