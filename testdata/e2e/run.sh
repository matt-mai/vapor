#!/bin/bash
# Build every image in specs/ from the live Ubuntu archive, prove the result is
# reproducible, and run the workloads in a container.
#
# Usage: testdata/e2e/run.sh [name...]
#
# This is an opt-in end-to-end check: it needs the network, a container engine
# and roughly twenty minutes for every image. Ordinary unit tests never run it.
#
# Every step is logged with a "=== " line before it runs, so a run that looks
# stuck shows the step it is in. Naming images runs only those, which is what a
# targeted check wants; the global preparation still happens, because each image
# locks against the same catalogue, keys and rendered inputs.
#
#   testdata/e2e/run.sh                       every image
#   testdata/e2e/run.sh runtime-packages      one image
#   testdata/e2e/run.sh debian-runtime-packages runtime-slices   a few
#
# Progress goes to the terminal and, when E2E_LOG names a file, to that file as
# well, so a long run can be watched from another shell. Set E2E_KEEP_CONTAINERS=1
# to leave a failed container in place for inspection.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
work="$here/.work"
catalogue="$work/catalogue"
catalogue_url=https://github.com/canonical/chisel-releases
catalogue_ref="${CATALOGUE_REF:-ubuntu-26.04}"
ca_bundle_url="${CA_BUNDLE_URL:-https://curl.se/ca/cacert.pem}"

# Both engines are wired up. Podman runs an OCI layout directory directly; Docker
# cannot, so the run imports the layout's own archive and addresses each platform by
# its content digest. The running section below handles both cases.
engine="${CONTAINER_ENGINE:-podman}"
command -v "$engine" >/dev/null 2>&1 || {
    echo "missing $engine: this check runs the built images in a container" >&2
    exit 1
}
case "$engine" in
    podman | docker) ;;
    *)
        echo "unsupported CONTAINER_ENGINE=$engine: use podman or docker" >&2
        exit 1
        ;;
esac
# The statement checker is a single-file uv script: uv fetches its one dependency
# into a throwaway environment instead of the runner's Python.
command -v uv >/dev/null 2>&1 || {
    echo "missing uv: this check validates the attached statements with it" >&2
    exit 1
}

# Every engine call is bounded. A wedged engine, or a server that never answers,
# has to fail the run rather than leave it hanging until something else kills it.
command -v timeout >/dev/null 2>&1 || {
    echo "missing timeout: this check bounds every container call with it" >&2
    exit 1
}
run_limit=(timeout "${E2E_RUN_TIMEOUT:-120}")
image_limit=(timeout "${E2E_IMAGE_TIMEOUT:-600}")

log() {
    printf '\n=== %s (%s)\n' "$*" "$(date +%H:%M:%S)" | tee -a "${E2E_LOG:-/dev/null}"
}
fail() {
    printf 'FAIL: %s (%s)\n' "$*" "$(date +%H:%M:%S)" | tee -a "${E2E_LOG:-/dev/null}" >&2
    exit 1
}

# A container left behind by a failed run holds its name for the next attempt, so
# failure and interruption clean up unless the run is being inspected.
running_containers=()
cleanup() {
    [ "${E2E_KEEP_CONTAINERS:-0}" = 1 ] && return 0
    ((${#running_containers[@]})) || return 0
    "$engine" rm -f "${running_containers[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- preparation -----------------------------------------------------------

log "building vaporize"
mkdir -p "$work"
(cd "$root" && go build -o "$work/vaporize" ./cmd/vaporize)
vaporize="$work/vaporize"

log "fetching the catalogue at $catalogue_ref"
catalogue_stage=$(mktemp -d "$work/catalogue.XXXXXXXX")
# Staging replaces the trap that removes a container, which is safe here because no
# container exists yet. The cleanup trap is put back once staging is done, so the rest
# of the run still removes what it starts.
trap 'rm -rf "$catalogue_stage"' EXIT
git clone --quiet --depth 1 --no-checkout --branch "$catalogue_ref" -- "$catalogue_url" "$catalogue_stage/repo"
catalogue_commit=$(git -C "$catalogue_stage/repo" rev-parse --verify 'HEAD^{commit}')
# Only the committed files belong in the catalogue tree recorded by the lock.
mkdir "$catalogue_stage/tree"
git -C "$catalogue_stage/repo" archive "$catalogue_commit" | tar -xf - -C "$catalogue_stage/tree"
rm -rf "$catalogue"
mv "$catalogue_stage/tree" "$catalogue"
rm -rf "$catalogue_stage"
trap cleanup EXIT
echo "catalogue commit $catalogue_commit"

# A throwaway Ed25519 key. Signatures over the same payload are deterministic, so a
# signed rebuild has to produce the same envelope bytes, and the key never leaves the
# work directory.
log "creating a signing key"
openssl genpkey -algorithm ed25519 -out "$work/signing.pem" 2>/dev/null
openssl pkey -in "$work/signing.pem" -pubout -out "$work/signing.pub.pem"

log "compiling the artifact binary"
mkdir -p "$work/tools"
(cd "$here/tools" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-buildid=" -o "$work/tools/server-amd64" .)

# The Go builder compiles the sources in the image, so the sources travel as an
# artifact. Only the module files and Go source are packed: no build output, no
# vendor directory, and the same bytes every run.
log "packing the Vapor sources"
(cd "$root" && tar --create --gzip --owner=0 --group=0 --numeric-owner --mtime=@0 \
    --sort=name --file "$work/tools/vapor-src.tar.gz" \
    go.mod go.sum cmd internal)

# A throwaway certificate authority for the CA image. Nothing here outlives the work
# directory, and the images built from it are the only place it is trusted.
log "creating a test certificate authority"
ca_dir="$work/ca"
rm -rf "$ca_dir"
mkdir -p "$ca_dir"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -keyout "$ca_dir/ca.key" -out "$ca_dir/e2e-ca.pem" \
    -subj "/CN=Vapor e2e CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null || fail "could not create the test CA"
# A second, unrelated root. The check trusts it explicitly and requires the server
# to be rejected, so a client that skipped verification cannot pass.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -keyout "$ca_dir/untrusted.key" -out "$ca_dir/untrusted.pem" \
    -subj "/CN=Unrelated e2e CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null || fail "could not create the unrelated root"
# The server certificate names the loopback address, which is the only address the
# in-image check can reach: the container has no network.
openssl req -newkey rsa:2048 -nodes -sha256 -keyout "$ca_dir/server.key" \
    -out "$ca_dir/server.csr" -subj "/CN=127.0.0.1" 2>/dev/null || fail "could not create a server key"
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid,issuer\n' \
    > "$ca_dir/server.ext"
openssl x509 -req -in "$ca_dir/server.csr" -CA "$ca_dir/e2e-ca.pem" -CAkey "$ca_dir/ca.key" \
    -CAcreateserial -days 3650 -sha256 -extfile "$ca_dir/server.ext" \
    -out "$ca_dir/server.pem" 2>/dev/null || fail "could not sign the server certificate"
# The image needs the certificate chain only; the private keys never leave the host.
chmod 0644 "$ca_dir/e2e-ca.pem" "$ca_dir/server.pem" "$ca_dir/untrusted.pem"
chmod 0600 "$ca_dir/server.key"

# Every local artifact lives beside the spec that names it, in a `files/` directory: the
# loader refuses a path that leaves the spec's own directory, so each rendered spec gets
# its own copy. Staging once keeps the specs free of a listening port and makes a path
# source read the same bytes the hash was computed from.
log "staging the local inputs"
files="$work/inputs"
rm -rf "$files"
mkdir -p "$files"
cp "$here"/apps/* "$files/"
cp "$ca_dir/server.pem" "$ca_dir/server.key" "$ca_dir/untrusted.pem" "$files/"
cp "$work/tools/server-amd64" "$files/server-amd64"
cp "$work/tools/vapor-src.tar.gz" "$files/vapor-src.tar.gz"

# Each rendered spec binds the same local catalogue instead of fetching Git again.
sed_catalogue() {
    sed -e "s|url: $catalogue_url|path: ../catalogue|" \
        -e "/^      branch: /d"
}

# Nothing is served over HTTP: a source either names a file beside the spec, which is
# what a user writes, or fetches a genuine upstream release by url.
render() {
    local template=$1 target=$2 directory
    directory=$(dirname "$target")
    cp "$template" "$target"
    cp -r "$files" "$directory/files"
    # Documents a spec imports, such as OpenVEX inputs, travel beside it so the
    # spec names them as ordinary relative local paths.
    if [ -d "$here/specs/vex" ]; then
        cp "$here"/specs/vex/* "$directory/"
    fi
    if grep -q 'certs/cacert.pem' "$target"; then
        mkdir -p "$directory/certs"
        curl -sfL --max-time 60 "$ca_bundle_url" -o "$directory/certs/cacert.pem" ||
            fail "could not download the CA bundle from $ca_bundle_url"
        cp "$ca_dir/e2e-ca.pem" "$directory/certs/e2e-ca.pem"
    fi
    stamp "$target"
}

# Replace each @name@ placeholder with the SHA256 of the staged file of that name.
stamp() {
    local target=$1
    for token in $(grep -o '@[a-zA-Z0-9._-]*@' "$target" | sort -u); do
        local file="$files/${token#@}"
        file=${file%@}
        [ -f "$file" ] || fail "placeholder $token has no input at $file"
        sed -i "s|$token|$(sha256sum "$file" | cut -d' ' -f1)|g" "$target"
    done
    sed_catalogue < "$target" > "$target.tmp" && mv "$target.tmp" "$target"
}

# --- the images ------------------------------------------------------------
#
# Each entry is: name mode [platform]
#   mode      "build" runs apps/build.sh inside, "serve" checks the HTTP response
#
# platform selects the image the engine runs. It defaults to linux/amd64 and may
# name several platforms, comma-separated; running one that differs from the host
# needs an emulator, and the run fails rather than skipping it, because a skipped
# arm image proves nothing.
images=(
    "builder-packages build"
    "builder-slices build"
    "builder-go build"
    "runtime-packages serve linux/amd64,linux/arm64"
    "runtime-slices serve"
    "runtime-artifact serve"
    "debian-builder-packages build"
    "debian-runtime-packages serve"
)

# A full second build is the only assertion that a rebuild is byte-identical, and it
# costs as much as the first one. Each assembly path is covered once on Ubuntu and once
# on Debian, because the two distros differ in which archives they read.
rebuilds="builder-packages runtime-slices debian-builder-packages debian-runtime-packages"

selected=("$@")
if [ ${#selected[@]} -gt 0 ]; then
    filtered=()
    for entry in "${images[@]}"; do
        for want in "${selected[@]}"; do
            [ "${entry%% *}" = "$want" ] && filtered+=("$entry")
        done
    done
    [ ${#filtered[@]} -gt 0 ] || fail "no image matches: ${selected[*]}"
    images=("${filtered[@]}")
fi

# Every spec tags its index "v1".
tag=v1

declare -A platforms statements claims

for entry in "${images[@]}"; do
    read -r name mode platform <<< "$entry"
    # SPDX and provenance are attached to every image; only a spec that makes a
    # vulnerability claim gets a VEX statement.
    statements[$name]=spdx,provenance
    if [ "$name" = runtime-packages ]; then
        statements[$name]=spdx,provenance,vex
        # The vulnerabilities that statement has to mention: two inline claims and
        # one from the imported document.
        claims[$name]=CVE-2026-0001,CVE-2026-0002,CVE-2026-0003
    fi
    platforms[$name]=${platform:-linux/amd64}

    log "$name: render, lock, build"
    rm -rf "$work/$name"
    mkdir -p "$work/$name"
    render "$here/specs/$name.yaml.in" "$work/$name/image.yaml"

    "$vaporize" lock --spec "$work/$name/image.yaml" \
        --cache-dir "$work/cache" >/dev/null
    digest=$("$vaporize" build --spec "$work/$name/image.yaml" \
        --lock "$work/$name/image.lock.yaml" --cache-dir "$work/cache" \
        --oci-dir "$work/$name/out" --tarball "$work/$name/image.tar" \
        --attestations-dir "$work/$name/statements")
    echo "$digest" > "$work/$name/digest"
    echo "index $digest"

    # The statements the build attached: an in-toto statement per platform for
    # every format the spec asks for, written to the layout, with the document each
    # wraps written to the directory.
    log "$name: check the attached statements"
    uv run --quiet "$here/attestations.py" --layout "$work/$name/out" \
        --statements "$work/$name/statements" \
        --lock "$work/$name/image.lock.yaml" \
        --expect "${statements[$name]}" --claims "${claims[$name]:-}"

    log "$name: build again from the same lock"
    case " $rebuilds " in
        *" $name "*) ;;
        *)
            echo "skipped: $name is not one of the images that rebuild"
            continue
            ;;
    esac
    "$vaporize" build --spec "$work/$name/image.yaml" \
        --lock "$work/$name/image.lock.yaml" --cache-dir "$work/cache" \
        --oci-dir "$work/$name/again" \
        --attestations-dir "$work/$name/again-statements" >/dev/null
    cmp -s "$work/$name/out/index.json" "$work/$name/again/index.json" ||
        fail "$name: a rebuild changed index.json"
    diff -r "$work/$name/statements" "$work/$name/again-statements" >/dev/null ||
        fail "$name: a rebuild changed the attached statements"
done

# --- signing ---------------------------------------------------------------

# --sign-key wraps every statement in a DSSE envelope, and the attachment has to say so
# in both descriptors. The checker verifies each signature against the public key and
# validates the statement inside the envelope.
# Sign the image that carries all three formats when it was selected, so a signed VEX
# document is checked too; otherwise sign whichever image was asked for.
name=${images[0]%% *}
for entry in "${images[@]}"; do
    [ "${entry%% *}" = runtime-packages ] && name=runtime-packages
done
log "$name: signing the statements"
"$vaporize" build --spec "$work/$name/image.yaml" \
    --lock "$work/$name/image.lock.yaml" --cache-dir "$work/cache" \
    --oci-dir "$work/$name/signed" --attestations-dir "$work/$name/signed-statements" \
    --sign-key "$work/signing.pem" >/dev/null
uv run --quiet "$here/attestations.py" --layout "$work/$name/signed" \
    --statements "$work/$name/signed-statements" \
    --lock "$work/$name/image.lock.yaml" \
    --expect "${statements[$name]}" --claims "${claims[$name]:-}" --signed "$work/signing.pub.pem"

# A signature is deterministic, so a signed rebuild is byte-identical.
log "$name: sign again from the same lock"
"$vaporize" build --spec "$work/$name/image.yaml" \
    --lock "$work/$name/image.lock.yaml" --cache-dir "$work/cache" \
    --oci-dir "$work/$name/signed-again" \
    --attestations-dir "$work/$name/signed-again-statements" \
    --sign-key "$work/signing.pem" >/dev/null
diff -r "$work/$name/signed-statements" "$work/$name/signed-again-statements" >/dev/null \
    || fail "$name: a signed rebuild changed the attached statements"

# A key the loader refuses stops the build instead of writing an unsigned statement.
log "$name: a broken key fails the build"
if "$vaporize" build --spec "$work/$name/image.yaml" \
    --lock "$work/$name/image.lock.yaml" --cache-dir "$work/cache" \
    --oci-dir "$work/$name/broken" --sign-key /dev/null >/dev/null 2>&1; then
    fail "$name: an empty signing key was accepted"
fi
[ -e "$work/$name/broken" ] && fail "$name: a refused key still wrote a layout"

echo "signed statements verified"

# --- running ---------------------------------------------------------------

# An image built for another architecture runs through binfmt_misc and qemu. Ask
# for it once, up front, so a missing emulator is reported as such instead of as
# a broken image. The two engines spell the host architecture differently and only
# Podman answers to .Host.Arch, so the value is normalized to OCI spelling here.
host_arch=$(
    if [ "$engine" = podman ]; then
        "${run_limit[@]}" "$engine" info --format '{{.Host.Arch}}'
    else
        "${run_limit[@]}" "$engine" info --format '{{.Architecture}}'
    fi
) || fail "cannot read the host architecture"
case "$host_arch" in
    x86_64 | x86-64) host_arch=amd64 ;;
    aarch64) host_arch=arm64 ;;
esac
emulation() {
    local image=$1 wanted=$2 arch=${2#linux/} emulator
    [ "$arch" = "$host_arch" ] && return 0
    # binfmt names the emulator after the CPU, not after the OCI architecture.
    case "$arch" in
        amd64) emulator=qemu-x86_64 ;;
        arm64) emulator=qemu-aarch64 ;;
        *) emulator="qemu-$arch" ;;
    esac
    [ -e "/proc/sys/fs/binfmt_misc/$emulator" ] ||
        fail "$image: running $wanted needs $emulator through binfmt_misc; install qemu-user-static"
}

# An image with more than one platform is checked on each of them, so a spec that
# declares two architectures cannot pass on the cheaper one alone.
run_platforms() {
    local image=$1 want=${2//,/ }
    for wanted in $want; do
        emulation "$image" "$wanted"
        "$3" "$image" "$wanted"
    done
}

# Published ports start well above the usual range, so two consecutive runs do not collide.
port=9099

# The runtime images that carry an interpreter, which the in-image checks use.
python_images="runtime-packages runtime-slices debian-runtime-packages"

# The runtime images are inspected from the flattened root filesystem rather than
# from inside: an artifact image carries no tool that could list its own files.
forbidden="bin/sh|bin/bash|bin/dash|usr/bin/sh|usr/bin/bash|usr/bin/dash|usr/bin/apt-get|usr/bin/apt|usr/bin/dpkg|usr/sbin/dpkg|usr/bin/pip|usr/bin/pip3"

# A slice that carries a mutation script states what the script must achieve. Only
# the presence of an effect is checked here, not how it was produced: the bundle has
# to hold real certificates and the directory it was built from has to be gone.
# entry: name path expectation, where expectation is "starts:PREFIX" or "absent".
mutations=(
    "runtime-slices /etc/ssl/certs/ca-certificates.crt starts:-----BEGIN CERTIFICATE-----"
    "runtime-slices /usr/share/ca-certificates/mozilla absent"
    "builder-slices /etc/ca-certificates.conf starts:mozilla/"
    "builder-slices /etc/ssl/certs/ca-certificates.crt starts:-----BEGIN CERTIFICATE-----"
    "debian-runtime-packages /etc/ssl/certs/ca-certificates.crt starts:-----BEGIN CERTIFICATE-----"
)

# docker_image prints the digest a layout holds for one platform, importing the
# build's own tarball first when the daemon does not have it yet. A digest is the only
# reference that names the bytes the build wrote; a tag would be resolved against a
# registry.
docker_image() {
    local layout=$1 platform=$2 digest
    digest=$(
        python3 - "$layout/index.json" "$platform" <<'PY'
import json, sys
index, wanted = sys.argv[1], sys.argv[2]
for manifest in json.load(open(index))["manifests"]:
    platform = manifest.get("platform") or {}
    if manifest.get("artifactType") or not platform:
        continue
    if f"{platform['os']}/{platform['architecture']}" == wanted:
        print(manifest["digest"])
        break
PY
    )
    [ -n "$digest" ] || fail "$layout: no image for $platform"
    if ! "${run_limit[@]}" "$engine" image inspect "$digest" >/dev/null 2>&1; then
        "${image_limit[@]}" "$engine" load --input "$(dirname "$layout")/image.tar" >/dev/null ||
            fail "$layout: the engine could not import $(dirname "$layout")/image.tar"
    fi
    echo "$digest"
}

# Everything below is per platform, because an image with two platforms is two
# images as far as the engine is concerned.
check_image() {
    local name=$1 platform=$2 image
    # A check that hangs says nothing, so every container run is bounded. A server
    # image appends its own arguments to the entrypoint, which is exactly the failure
    # mode a missing --entrypoint produces, and it would never return on its own.
    if [ "$engine" = docker ]; then
        image=$(docker_image "$work/$name/out" "$platform")
    else
        # The layout carries one tag, and an index with a tag has to be addressed by
        # it: the engine refuses to choose an image on its own.
        image="oci:$work/$name/out:$tag"
    fi

    local -a checks=()
    local check
    for check in "${mutations[@]}"; do
        [[ $check == "$name "* ]] && checks+=("${check#* }")
    done
    if [[ $mode == serve ]] || ((${#checks[@]})); then
        bash "$here/check-filesystem.sh" "$engine" "$image" "$platform" "$mode" "$forbidden" "${checks[@]}" ||
            fail "$name: filesystem checks failed ($platform)"
    fi

    # A runtime image carries no shell, so the only check it can make about itself is
    # the interpreter it ships. A trailing command is appended to the entrypoint, so
    # --entrypoint is what makes this about the packaged interpreter rather than the
    # application.
    if [ "$mode" = serve ]; then
        if [[ " $python_images " == *" $name "* ]]; then
            log "$name: interpreter and standard library ($platform)"
            local out
            out=$(
                "${run_limit[@]}" "$engine" run --rm --platform "$platform" \
                    --entrypoint /usr/bin/python3 "$image" \
                    -c 'import json, http.server, ssl; print("python ok")'
            ) || fail "$name: the packaged interpreter did not run ($platform)"
            [ "$out" = "python ok" ] ||
                fail "$name: the interpreter printed '$out', want 'python ok' ($platform)"
            # A declared user is a claim about the config; this is the process. The
            # runner starts every container without --user, so the uid printed here is
            # the one the image itself asks for.
            log "$name: runs as a non-root user ($platform)"
            out=$("${run_limit[@]}" "$engine" run --rm --platform "$platform" \
                --entrypoint /usr/bin/python3 "$image" -c 'import os; print(os.getuid())') ||
                fail "$name: the non-root check did not run ($platform)"
            case "$out" in
                '' | 0 | *[!0-9]*) fail "$name: the image ran as uid '$out', want a non-root user ($platform)" ;;
            esac
        fi
        if [ "$name" = runtime-packages ]; then
            # The handshake proves the imported root reached the bundle the image
            # actually loads: the context is built from /etc/ssl/certs/ca-certificates.crt
            # and has to verify a server that root signed, while a context trusting an
            # unrelated certificate has to reject the same server.
            log "$name: trust bundle ($platform)"
            out=$("${run_limit[@]}" "$engine" run --rm --platform "$platform" \
                --entrypoint /usr/bin/python3 "$image" /app/tls.py) ||
                fail "$name: the trust bundle check failed ($platform)"
            [ "$out" = "tls ok" ] || fail "$name: the trust bundle check printed '$out' ($platform)"
        fi
        if [ "$name" = debian-runtime-packages ]; then
            # This image declares no bundle, so the roots come from the package Vapor
            # read. A client that loads the bundle by default has to find many real
            # roots in it, which one placeholder certificate would not satisfy.
            log "$name: default trust bundle ($platform)"
            out=$("${run_limit[@]}" "$engine" run --rm --platform "$platform" \
                --entrypoint /usr/bin/python3 "$image" \
                -c 'import ssl; print(len(ssl.create_default_context().get_ca_certs()))') ||
                fail "$name: the default trust bundle check failed ($platform)"
            [ "${out:-0}" -ge 100 ] || fail "$name: the default bundle holds '$out' roots, want at least 100 ($platform)"
        fi
        if [ "$name" = runtime-artifact ]; then
            # An unknown flag verifies startup without opening a port.
            log "$name: startup ($platform)"
            local code=0
            "${run_limit[@]}" "$engine" run --rm --platform "$platform" \
                --entrypoint /usr/bin/server "$image" --not-a-flag || code=$?
            [ "$code" = 2 ] || fail "$name: an unknown flag exited $code, want 2 ($platform)"
        fi
    fi

    case "$mode" in
        serve)

            log "$name: serving on 127.0.0.1:$port ($platform)"
            port=$((port + 1))
            running_containers+=("vapor-e2e-$name")
            "${run_limit[@]}" "$engine" run -d --rm --name "vapor-e2e-$name" --platform "$platform" \
                -p "127.0.0.1:$port:8080" "$image" >/dev/null
            response=
            for _ in $(seq 1 100); do
                if response=$(curl --silent --fail --max-time 2 "http://127.0.0.1:$port/health" 2>/dev/null); then
                    break
                fi
                sleep 0.2
            done
            if [ "$response" != "ok" ]; then
                "${run_limit[@]}" "$engine" logs "vapor-e2e-$name" 2>&1 | tail -20 || true
                "$engine" rm -f "vapor-e2e-$name" >/dev/null 2>&1 || true
                fail "$name: the server did not answer on port $port"
            fi
            page=$(curl --silent --fail --max-time 5 "http://127.0.0.1:$port/")
            "$engine" rm -f "vapor-e2e-$name" >/dev/null 2>&1 || true
            case "$page" in
                *"hello from vapor"*) echo "response: $page" ;;
                *) fail "$name: unexpected response: $page" ;;
            esac
            ;;
        build)
            log "$name: running the build inside the container ($platform)"
            "${run_limit[@]}" "$engine" run --rm --platform "$platform" "$image"
            ;;
    esac
}

for entry in "${images[@]}"; do
    read -r name mode platform <<< "$entry"
    log "$name: check the image (${platforms[$name]})"
    run_platforms "$name" "${platforms[$name]}" check_image
    # A tarball is the shared output, so the images that carry a command get one
    # imported into a store that has never seen them and asked to answer for itself.
    if [[ $engine == podman && $host_arch == amd64 ]]; then
        case "$name" in
            runtime-artifact)
                log "$name: loading the published tarball in a fresh Podman store"
                bash "$here/check-tarball.sh" "$work/$name/image.tar" /usr/bin/server 'port to listen on' --help
                ;;
            runtime-packages | debian-runtime-packages)
                log "$name: loading the published tarball in a fresh Podman store"
                bash "$here/check-tarball.sh" "$work/$name/image.tar" /usr/bin/python3 'python ok' \
                    -c 'import json, http.server, ssl; print("python ok")'
                ;;
        esac
    fi
done

log "every image built, reproduced and ran"
