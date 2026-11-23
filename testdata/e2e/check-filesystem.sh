#!/bin/bash
set -euo pipefail

engine=$1 image=$2 platform=$3 mode=$4 forbidden=$5
shift 5

fail() { echo "$*" >&2; exit 1; }

# Every engine call is bounded, so a wedged engine fails the run instead of hanging it.
command -v timeout >/dev/null 2>&1 || fail "missing timeout: every engine call is bounded with it"
limit=(timeout "${E2E_RUN_TIMEOUT:-120}")

tmp=$(mktemp -d)
container=
trap 'if [ -n "$container" ]; then "${limit[@]}" "$engine" rm -f "$container" >/dev/null || true; fi; rm -rf "$tmp"' EXIT
container=$("${limit[@]}" "$engine" create --platform "$platform" "$image")
"${limit[@]}" "$engine" export "$container" > "$tmp/root.tar" || fail "cannot export the image filesystem"
"${limit[@]}" "$engine" rm -f "$container" >/dev/null
container=
tar -tf "$tmp/root.tar" > "$tmp/members" || fail "cannot list the image filesystem"
sed -E 's@^(\./)+@@; s@^/+@@; s@/+$@@' "$tmp/members" > "$tmp/paths"

for check in "$@"; do
    read -r path expectation <<< "$check"
    member=${path#/}
    case "$expectation" in
        absent)
            found=$(awk -v p="$member" '$0 == p || index($0, p "/") == 1 { print; exit }' "$tmp/paths")
            [ -z "$found" ] || fail "$path survived the mutation script"
            echo "removed: $path"
            ;;
        starts:*)
            prefix=${expectation#starts:}
            original=$(awk -v p="$member" 'FNR == NR { orig[FNR] = $0; next } $0 == p { print orig[FNR]; exit }' \
                "$tmp/members" "$tmp/paths")
            [ -n "$original" ] || fail "$path is missing from the image"
            tar -xOf "$tmp/root.tar" -- "$original" > "$tmp/content" || fail "cannot read $path from the image"
            actual=$(sed -n 1p "$tmp/content")
            [[ $actual == "$prefix"* ]] || fail "$path starts with '${actual:0:40}', want '$prefix...'"
            echo "written: $path"
            ;;
        *) fail "unknown filesystem expectation: $expectation" ;;
    esac
done

if [ "$mode" = serve ]; then
    found=$(awk -v pattern="^($forbidden)$" '$0 ~ pattern { print; exit }' "$tmp/paths")
    [ -z "$found" ] || fail "a shell or package manager is present in a hardened runtime image: $found"
    echo "no shell, no package manager"
fi
