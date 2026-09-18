#!/bin/sh
# End-to-end: Arti bootstraps Tor through lyrebird-rs as a managed transport.
# Uses Tor Browser's signed built-in bridges (tools/arti-e2e/bridges.sh).
# Usage: tools/arti-e2e/run.sh [obfs4|snowflake|webtunnel] [extra docker run args...]
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
transport="${1:-obfs4}"
[ $# -gt 0 ] && shift
bridges="$root/tools/arti-e2e/bridges-$transport.txt"
[ -s "$bridges" ] || "$root/tools/arti-e2e/bridges.sh" "$transport" > "$bridges"
docker build -t lyrebird-rs-arti-e2e -f "$root/tools/arti-e2e/Dockerfile" "$root"
docker run --rm -e TRANSPORT="$transport" -e BRIDGES="$(cat "$bridges")" "$@" lyrebird-rs-arti-e2e
