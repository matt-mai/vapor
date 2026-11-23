#!/bin/bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export ARCHIVE="$tmp/image.tar"
export PATH="$tmp:$PATH"
cat > "$tmp/podman" <<'SH'
#!/bin/bash
set -euo pipefail
[[ $1 == --root && $3 == --runroot && $5 == --tmpdir && $7 == --storage-driver && $8 == vfs ]]
root=$2
shift 8
case "$1 $2" in
    'load --input')
        [[ $3 == "$ARCHIVE" && ! -e "$root" && -f $3 ]]
        mkdir "$root"
        ;;
    'image list')
        [[ -d $root ]]
        printf '%064d\n' 1
        ;;
    'run --rm')
        [[ -d $root && " $* " == *' --pull=never '* && " $* " == *' --help ' ]]
        printf '%s\n' "${HELP_OUTPUT:-port to listen on}"
        ;;
    'image rm')
        [[ -d $root ]]
        ;;
    *) exit 1 ;;
esac
SH
chmod +x "$tmp/podman"
if bash "$here/check-tarball.sh" "$ARCHIVE" /usr/bin/server 'port to listen on' --help; then
    echo 'missing archive unexpectedly passed' >&2
    exit 1
fi
touch "$ARCHIVE"
if HELP_OUTPUT='wrong binary' bash "$here/check-tarball.sh" "$ARCHIVE" /usr/bin/server 'port to listen on' --help 2> "$tmp/error" ||
    ! grep -Fq "which does not contain 'port to listen on'" "$tmp/error"; then
    echo 'wrong server output unexpectedly passed' >&2
    exit 1
fi
bash "$here/check-tarball.sh" "$ARCHIVE" /usr/bin/server 'port to listen on' --help
