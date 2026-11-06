#!/usr/bin/env bash
# Test for docker/tor/entrypoint.sh (D-12). Needs only docker.
#
#   tests/tor/test_entrypoint.sh [image]      (default: darkweb-scanner-tor)
#
# 1. The image holds no torrc and no password hash.
# 2. The file rendered at start has a SOCKS port, no control port and no hash.
# 3. Tor listens on the SOCKS port and on nothing else; it does not run as root.
# 4. TOR_SOCKS_PORT moves the SOCKS port.
set -uo pipefail

IMAGE="${1:-darkweb-scanner-tor}"
C="tor-test-$$"
FAILED=0

ok()   { echo "  ok    $*"; }
fail() { echo "  FAIL  $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (expected '$3', got '$2')"; fi; }

# shellcheck disable=SC2329  # called by the trap
cleanup() { docker rm -f "$C" >/dev/null 2>&1; }
trap cleanup EXIT

# start [docker run options]: no network is needed, Tor opens its listeners before it bootstraps.
start() {
  docker rm -f "$C" >/dev/null 2>&1
  docker run -d --name "$C" --network none "$@" "$IMAGE" >/dev/null || return 1
  local port="${TEST_PORT:-9050}" waited=0
  while [[ $waited -lt 30 ]]; do
    docker exec "$C" nc -z 127.0.0.1 "$port" 2>/dev/null && return 0
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}
in_c() { docker exec "$C" sh -c "$1" 2>/dev/null; }

echo "1. Image"
check "no torrc in the image" "$(docker run --rm --network none --entrypoint sh "$IMAGE" -c 'ls /etc/tor/torrc 2>/dev/null | wc -l')" "0"
check "no password hash in the image" "$(docker run --rm --network none --entrypoint sh "$IMAGE" -c 'grep -rl "16:[0-9A-F]\{58\}" /etc/tor /usr/local/bin 2>/dev/null | wc -l')" "0"

echo "2. Rendered configuration"
if start; then ok "tor started and listens on 9050"; else fail "tor did not start"; docker logs "$C" 2>&1 | tail -20; fi
check "SocksPort rendered" "$(in_c 'grep -c "^SocksPort 0.0.0.0:9050$" /etc/tor/torrc')" "1"
check "no ControlPort, HashedControlPassword or CookieAuthentication" "$(in_c 'grep -ciE "^(ControlPort|ControlSocket|HashedControlPassword|CookieAuthentication)" /etc/tor/torrc')" "0"
check "not an exit or relay" "$(in_c 'grep -cE "^(ExitRelay 0|ExitPolicy reject \*:\*)$" /etc/tor/torrc')" "2"
check "torrc readable by its owner only" "$(in_c 'stat -c %a /etc/tor/torrc')" "600"

echo "3. Listeners and user"
check "nothing listens on the old control port" "$(in_c 'nc -z 127.0.0.1 9051 && echo open || echo closed')" "closed"
check "tor does not run as root" "$(in_c 'id -un')" "debian-tor"
check "tor is the main process" "$(in_c 'cat /proc/1/comm')" "tor"

echo "4. TOR_SOCKS_PORT"
if TEST_PORT=9150 start -e TOR_SOCKS_PORT=9150; then ok "tor listens on 9150"; else fail "tor did not listen on 9150"; fi
check "default port is closed" "$(in_c 'nc -z 127.0.0.1 9050 && echo open || echo closed')" "closed"

echo ""
if [[ $FAILED -eq 0 ]]; then echo "tor entrypoint: all checks passed"; else echo "tor entrypoint: FAILED"; fi
exit "$FAILED"
