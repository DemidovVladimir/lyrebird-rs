#!/bin/sh
# Starts Arti with lyrebird-rs as a managed pluggable transport, waits for
# Tor, then asks check.torproject.org through Arti's SOCKS port.
# Env: TRANSPORT (obfs4 | snowflake | webtunnel, default obfs4),
#      BRIDGES (newline-separated bridge lines for that transport),
#      TIMEOUT (seconds, default 180),
#      IAT (optional, obfs4: force iat-mode=<n> on every line).
set -eu
: "${TRANSPORT:=obfs4}"
: "${TIMEOUT:=180}"
state=/var/lib/arti
cfg="$state/arti.toml"
[ -n "${BRIDGES:-}" ] || { echo "BRIDGES is empty" >&2; exit 2; }

{
  echo '[proxy]'
  echo 'socks_listen = "127.0.0.1:9150"'
  echo 'dns_listen = 0'
  echo '[bridges]'
  echo 'enabled = true'
  echo 'bridges = ['
  printf '%s\n' "$BRIDGES" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ -n "${IAT:-}" ]; then
      line=$(printf '%s' "$line" | sed "s/iat-mode=[0-9]/iat-mode=$IAT/")
    fi
    printf '  "%s",\n' "$line"
  done
  echo ']'
  echo '[[bridges.transports]]'
  echo "protocols = [\"$TRANSPORT\"]"
  echo 'path = "/usr/local/bin/lyrebird"'
  echo 'arguments = ["-enableLogging", "-logLevel", "INFO"]'
  echo 'run_on_startup = true'
  echo '[storage]'
  echo "cache_dir = \"$state/cache\""
  echo "state_dir = \"$state/state\""
  echo '[logging]'
  echo 'console = "info"'
} > "$cfg"

arti proxy -c "$cfg" > "$state/arti.log" 2>&1 &
arti_pid=$!
trap 'kill $arti_pid 2>/dev/null || true' EXIT

start=$(date +%s)
while :; do
  if ! kill -0 "$arti_pid" 2>/dev/null; then
    echo "arti exited:" >&2
    cat "$state/arti.log" >&2
    exit 1
  fi
  out=$(curl -fsS --max-time 30 --socks5-hostname 127.0.0.1:9150 \
        https://check.torproject.org/api/ip 2>/dev/null || true)
  if printf '%s' "$out" | grep -q '"IsTor":true'; then
    elapsed=$(( $(date +%s) - start ))
    echo "--- pluggable transport log (key lines) ---"
    find "$state" -name lyrebird.log -exec grep -hE 'NAT Type|OnOpen|OnClose|stale|Closing|failure|error|Error' {} \; | head -30
    echo "--- arti log (transport events, first 30) ---"
    grep -F '[pt ' "$state/arti.log" | head -30
    echo "--- arti log (guard/bootstrap lines) ---"
    grep -iE 'guard|bootstrap' "$state/arti.log" | tail -12
    echo "RESULT: OK after ${elapsed}s: $out"
    exit 0
  fi
  if [ $(( $(date +%s) - start )) -ge "$TIMEOUT" ]; then
    tail -40 "$state/arti.log"
    find "$state" -name lyrebird.log -exec sh -c 'echo "--- $1 ---"; tail -30 "$1"' _ {} \;
    echo "RESULT: FAILED, no Tor connectivity after ${TIMEOUT}s (last: $out)"
    exit 1
  fi
  sleep 3
done
