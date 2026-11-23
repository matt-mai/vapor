#!/bin/bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export ARCHIVE="$tmp/root.tar"
mkdir -p "$tmp/root/etc/removed" "$tmp/root/usr/bin"
printf 'expected bundle\n' > "$tmp/root/etc/bundle"
touch "$tmp/root/etc/removed/child" "$tmp/root/usr/bin/sh"
cat > "$tmp/engine" <<'SH'
#!/bin/bash
case "$1" in
    create) echo fake-container ;;
    rm) ;;
    export) cat "$ARCHIVE" ;;
    *) exit 1 ;;
esac
SH
chmod +x "$tmp/engine"

check() {
    bash "$here/check-filesystem.sh" "$tmp/engine" image linux/amd64 "$1" 'usr/bin/sh' "${@:2}" > "$tmp/output" 2>&1
}
reject() {
    local want=$1
    shift
    if check "$@" || ! grep -Fq "$want" "$tmp/output"; then
        echo "expected failure: $want" >&2
        cat "$tmp/output" >&2
        exit 1
    fi
}

reject 'cannot export' build '/etc/removed absent'
printf 'not a tar' > "$ARCHIVE"
reject 'cannot list' build '/etc/removed absent'
tar -cf "$ARCHIVE" -C "$tmp/root" ./etc/bundle
check serve '/etc/removed absent' '/etc/bundle starts:expected'
tar -cf "$ARCHIVE" -C "$tmp/root" ./etc/removed
reject 'survived' build '/etc/removed absent'
tar -cf "$ARCHIVE" -C "$tmp/root" ./etc/removed/child ./usr/bin/sh
reject 'survived' build '/etc/removed absent'
reject 'present in a hardened runtime image' serve
