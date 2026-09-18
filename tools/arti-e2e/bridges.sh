#!/bin/sh
# Prints Tor Browser's built-in bridge lines for one transport from the newest
# stable, signed Tor Expert Bundle (signature from the Tor Browser Developers key).
# Usage: tools/arti-e2e/bridges.sh [transport] [tor-browser-version]
# webtunnel: the bundle carries no webtunnel lines; Tor Browser gets those
# from the Moat service, so they are read from its circumvention defaults.
set -eu
TRANSPORT="${1:-obfs4}"
KEY=EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
if [ "$TRANSPORT" = webtunnel ]; then
  echo "# bridges.torproject.org/moat/circumvention/defaults, webtunnel" >&2
  curl -fsS -X POST -H 'Content-Type: application/vnd.api+json' \
    https://bridges.torproject.org/moat/circumvention/defaults \
    | python3 -c 'import json,sys
for s in json.load(sys.stdin)["settings"]:
    if s["bridges"]["type"] == "webtunnel":
        print("\n".join(s["bridges"]["bridge_strings"]))'
  exit 0
fi
ver="${2:-$(curl -fsS https://dist.torproject.org/torbrowser/ \
  | sed -n 's#.*href="\([0-9][0-9.]*\)/".*#\1#p' | sort -V | tail -1)}"
echo "# Tor Browser $ver, $TRANSPORT" >&2
docker run --rm -e VER="$ver" -e KEY="$KEY" -e TRANSPORT="$TRANSPORT" debian:bookworm-slim bash -euo pipefail -c '
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends curl gnupg dirmngr ca-certificates jq >/dev/null 2>&1
  f="tor-expert-bundle-linux-x86_64-$VER.tar.gz"
  cd /tmp
  curl -fsSO "https://dist.torproject.org/torbrowser/$VER/$f"
  curl -fsSO "https://dist.torproject.org/torbrowser/$VER/$f.asc"
  gpg -q --auto-key-locate nodefault,wkd --locate-keys torbrowser@torproject.org >/dev/null 2>&1
  gpg -q --status-fd 1 --verify "$f.asc" "$f" 2>/dev/null | grep -Eq "VALIDSIG .* $KEY\$" \
    || { echo "signature check FAILED" >&2; exit 1; }
  echo "# signature OK ($KEY)" >&2
  tar -xzf "$f" tor/pluggable_transports/pt_config.json
  jq -r ".bridges.\"$TRANSPORT\"[]" tor/pluggable_transports/pt_config.json
'
