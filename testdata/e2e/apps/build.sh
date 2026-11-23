#!/bin/sh
# The build a builder image performs inside the container, using only what the
# image carries: the shipped interpreter, the package manager, and the network.
#
# It fails on the first error, so a broken image cannot pass by accident.
set -eu

cd /app

echo "== python: $(/usr/bin/python3 --version)"
/usr/bin/python3 -m venv /tmp/venv
/tmp/venv/bin/python -m pip install --quiet --no-cache-dir --no-input --retries 5 --timeout 60 packaging
/tmp/venv/bin/python -c 'import packaging; print("== pip install ok:", packaging.__version__)'

# Vapor never runs maintainer scripts, so dpkg's database is only as good as the files
# it unpacked. Listing a package it recorded proves the database is readable and holds
# what the build put there.
echo "== dpkg database"
/usr/bin/dpkg --list base-files

# apt reads the source list Vapor generated and both keyrings without touching the
# network: an unusable keyring fails here rather than in a later build.
echo "== apt sources"
/usr/bin/apt-get check

echo "== apt-get install curl"
apt-get update -qq
apt-get install -y -qq curl
echo "== curl: $(curl --version | head -1)"

echo "== unit tests"
/tmp/venv/bin/python -m unittest discover -s /app -t /app -v

echo "== serving"
PORT=8081 /usr/bin/python3 /app/server.py &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
    if page=$(curl --silent --fail --max-time 2 http://127.0.0.1:8081/ 2>/dev/null); then
        echo "== response: $page"
        break
    fi
    kill -0 "$server" 2>/dev/null || { echo "server died" >&2; exit 1; }
    sleep 0.2
done

case "$page" in
    "hello from vapor"*) echo "== build ok" ;;
    *) echo "unexpected response: ${page:-none}" >&2; exit 1 ;;
esac
