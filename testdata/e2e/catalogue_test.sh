#!/bin/bash
# Check catalogue selection without the network, a container engine, or a Go build.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ALLOW_PROTOCOL=file
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.file://$tmp/upstream.insteadOf"
export GIT_CONFIG_VALUE_0=https://github.com/canonical/chisel-releases
export GIT_AUTHOR_NAME=Fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=$GIT_AUTHOR_NAME GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL

upstream="$tmp/upstream"
git init --quiet --initial-branch=first "$upstream"
commit_catalogue() {
    printf '%s\n' "$1" > "$upstream/chisel.yaml"
    git -C "$upstream" add chisel.yaml
    git -C "$upstream" commit --quiet -m "$1"
}
commit_catalogue first

mkdir -p "$tmp/bin" "$tmp/testdata/e2e"
cp "$here/run.sh" "$tmp/testdata/e2e/run.sh"
for command in go podman uv; do
    printf '#!/bin/bash\nexit 0\n' > "$tmp/bin/$command"
done
# Stop the real runner immediately after it reports the checkout.
printf '#!/bin/bash\nexit 71\n' > "$tmp/bin/openssl"
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH" CONTAINER_ENGINE=podman

check_catalogue() {
    local ref=$1 contents=$2 status=0 output expected
    expected=$(git -C "$upstream" rev-parse "$ref")
    output=$(CATALOGUE_REF="$ref" bash "$tmp/testdata/e2e/run.sh" 2>&1) || status=$?
    if [ "$status" != 71 ] || ! grep -Fxq "catalogue commit $expected" <<< "$output"; then
        printf 'expected checkout of %s at %s, got exit %s:\n%s\n' "$ref" "$expected" "$status" "$output" >&2
        exit 1
    fi
    local catalogue="$tmp/testdata/e2e/.work/catalogue"
    if [ "$(<"$catalogue/chisel.yaml")" != "$contents" ] || [ -e "$catalogue/.git" ] || [ -e "$catalogue/stale.yaml" ]; then
        printf 'wrong catalogue contents for %s\n' "$ref" >&2
        exit 1
    fi
}

check_catalogue first first
touch "$tmp/testdata/e2e/.work/catalogue/stale.yaml"
git -C "$upstream" checkout --quiet -b second
commit_catalogue second
check_catalogue second second
commit_catalogue updated
check_catalogue second updated

status=0
output=$(CATALOGUE_REF=missing bash "$tmp/testdata/e2e/run.sh" 2>&1) || status=$?
if [ "$status" = 0 ] || [ "$status" = 71 ] || grep -q '^catalogue commit ' <<< "$output"; then
    printf 'expected the missing ref to stop the runner, got exit %s:\n%s\n' "$status" "$output" >&2
    exit 1
fi
