#!/usr/bin/env bash
# OPS-8: deploy.sh generates each secret once. Running it again must keep the
# database password, DATABASE_URL, the session secret and the setup token, and
# it must refuse to invent a new database password when a database volume exists.
#
# The test runs the ".env" block of deploy.sh on its own, in a temp directory,
# with docker replaced by a stub. Needs bash, openssl, sed, grep. No containers.
#
# usage: tests/deploy/test_env_secrets.sh
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0
ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }

# The block under test, cut out of the real script.
BLOCK="$WORK/block.sh"
sed -n '/^# ── Patch \.env/,/^# Set domain and SSL email if provided/p' "$REPO/deploy.sh" > "$BLOCK"
grep -q 'POSTGRES_PASSWORD' "$BLOCK" || { echo "FAIL - could not find the .env block in deploy.sh"; exit 1; }

# run <dir> <volume-exists: yes|no>  -> exit status of the block; output in <dir>/out
run() {
  ( cd "$1" && VOLUME_EXISTS="$2" bash -c '
      set -euo pipefail
      info() { echo "[INFO] $*"; }; error() { echo "[ERROR] $*"; exit 1; }
      docker() { [[ "$1 $2" == "volume inspect" && "$VOLUME_EXISTS" == "yes" ]]; }
      source "$0"' "$BLOCK" > out 2>&1 )
}
val() { grep -m1 "^$2=" "$1/.env" | cut -d= -f2-; }

# 1. First run on the example file: every secret is generated.
A="$WORK/a"; mkdir "$A"; cp "$REPO/.env.example" "$A/.env"
run "$A" no; check "first run succeeds" "$?" "0"
check "session secret is 64 hex characters" "$(val "$A" DASHBOARD_SECRET_KEY | grep -cE '^[0-9a-f]{64}$')" "1"
check "database password is 48 hex characters" "$(val "$A" POSTGRES_PASSWORD | grep -cE '^[0-9a-f]{48}$')" "1"
check "DATABASE_URL holds that password and the driver name" \
  "$(val "$A" DATABASE_URL)" "postgresql+psycopg2://scanner:$(val "$A" POSTGRES_PASSWORD)@postgres:5432/darkweb_scanner"
check "setup token is 48 hex characters" "$(val "$A" SETUP_TOKEN | grep -cE '^[0-9a-f]{48}$')" "1"
check "no secret value is printed" "$(grep -cE '[0-9a-f]{40,}' "$A/out")" "0"
check "each setting appears once" "$(grep -cE '^(DASHBOARD_SECRET_KEY|POSTGRES_PASSWORD|DATABASE_URL|SETUP_TOKEN)=' "$A/.env")" "4"

# 2. Second run, now with a database volume: nothing changes.
cp "$A/.env" "$A/.env.first"
run "$A" yes; check "second run succeeds" "$?" "0"
check "second run changes nothing in .env" "$(cmp -s "$A/.env" "$A/.env.first" && echo same || echo changed)" "same"
check "second run says it kept the values" "$(grep -c 'Keeping' "$A/out")" "2"

# 3. Placeholder password but a database volume exists: stop, change nothing.
B="$WORK/b"; mkdir "$B"; cp "$REPO/.env.example" "$B/.env"
sed -i.bak 's/^DASHBOARD_SECRET_KEY=.*/DASHBOARD_SECRET_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/' "$B/.env"; rm -f "$B/.env.bak"
cp "$B/.env" "$B/.env.first"
run "$B" yes; check "placeholder password with an existing volume stops the script" "$?" "1"
check "it says why" "$(grep -c 'database volume darkweb-scanner_pg_data already exists' "$B/out")" "1"
check "and leaves .env alone" "$(cmp -s "$B/.env" "$B/.env.first" && echo same || echo changed)" "same"

# 4. A hand-set password with characters sed treats specially is kept as it is.
C="$WORK/c"; mkdir "$C"; cp "$REPO/.env.example" "$C/.env"
sed -i.bak 's|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=p\&ss/w0rd|' "$C/.env"; rm -f "$C/.env.bak"
before="$(val "$C" POSTGRES_PASSWORD)"
run "$C" yes; check "hand-set password: run succeeds" "$?" "0"
# Compared, never printed: the old script wrote a generated value here.
check "hand-set password is kept" "$([[ "$(val "$C" POSTGRES_PASSWORD)" == "$before" ]] && echo kept || echo replaced)" "kept"

# 5. An .env without a SETUP_TOKEN line gets one.
D="$WORK/d"; mkdir "$D"; grep -v '^SETUP_TOKEN=' "$REPO/.env.example" > "$D/.env"
run "$D" no; check "missing SETUP_TOKEN line is added" "$(val "$D" SETUP_TOKEN | grep -cE '^[0-9a-f]{48}$')" "1"

if [[ "$FAILED" == "0" ]]; then echo "all checks passed"; else echo "SOME CHECKS FAILED"; exit 1; fi
