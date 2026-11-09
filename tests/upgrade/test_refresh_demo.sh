#!/usr/bin/env bash
# refresh_demo of upgrade.sh, cut out and run with docker replaced by a stub.
# usage: tests/upgrade/test_refresh_demo.sh
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0
ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }

FUNCS="$WORK/funcs.sh"
grep -E '^(in_list|demo_running)\(\) \{' "$REPO/upgrade.sh" > "$FUNCS"
sed -n '/^refresh_demo() {/,/^}/p' "$REPO/upgrade.sh" >> "$FUNCS"
check "found the functions in upgrade.sh" "$(grep -cE '^(in_list|demo_running|refresh_demo)\(\) \{' "$FUNCS")" "3"

# run <was-running> [SERVICES]: prints what docker was asked to do
run() {
  ( cd "$WORK" && : > calls && FUNCS="$FUNCS" SERVICES="${2:-}" FAIL_UP="${FAIL_UP:-}" bash -c '
      set -euo pipefail
      info() { :; }; success() { echo "OK $*" >> calls; }; warn() { echo "WARN $*" >> calls; }
      wait_healthy() { echo "wait $1 profiles=${COMPOSE_PROFILES:-}" >> calls; }
      docker() { echo "docker $*" >> calls; [[ -z "$FAIL_UP" || "$*" != *"$FAIL_UP"* ]]; }
      source "$FUNCS"
      refresh_demo "$1"
    ' _ "$1" ) || echo "exit-nonzero" >> "$WORK/calls"
  cat "$WORK/calls"
}

check "not running: nothing happens" "$(run 0)" ""
out="$(run 1)"
[[ "$out" == *"up -d --no-build demo-postgres"* ]] && ok "starts the demo database" || fail "no demo-postgres: $out"
[[ "$out" == *"up -d --no-deps --no-build demo-dashboard"* ]] && ok "recreates the demo dashboard without building" || fail "no demo-dashboard: $out"
[[ "$out" == *"wait demo-dashboard profiles=demo"* ]] && ok "waits with the profile on" || fail "wait: $out"
[[ "$out" != *" build"*"demo"* || "$out" == *"--no-build"* ]] && ok "never builds" || fail "built: $out"
check "SERVICES without the dashboard: nothing happens" "$(run 1 'tor nginx')" ""
[[ "$(run 1 'tor dashboard')" == *"demo-dashboard"* ]] && ok "SERVICES with the dashboard: demo moves too" || fail "SERVICES with dashboard"
out="$(FAIL_UP=demo-dashboard run 1)"
[[ "$out" == *"WARN"* && "$out" != *"exit-nonzero"* ]] && ok "a demo failure warns and does not fail the upgrade" || fail "failure handling: $out"

exit "$FAILED"
