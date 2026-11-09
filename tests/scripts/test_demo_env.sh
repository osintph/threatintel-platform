#!/usr/bin/env bash
# scripts/demo-env.sh: own secrets kept across runs, lookup keys copied, nothing that sends.
# usage: tests/scripts/test_demo_env.sh
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0
ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }
val() { grep -m1 "^$1=" "$WORK/out" | cut -d= -f2-; }

cat > "$WORK/prod" <<'EOF'
DASHBOARD_SECRET_KEY=prod-secret
POSTGRES_PASSWORD=prod-db-password
DATABASE_URL=postgresql+psycopg2://scanner:prod-db-password@postgres:5432/darkweb_scanner
SETUP_TOKEN=prod-token
VIRUSTOTAL_API_KEY=vt-key
HIBP_API_KEY=hibp-key
SMTP_HOST=smtp.prod.example
SMTP_PASSWORD=prod-smtp
ALERT_WEBHOOK_URL=https://hooks.prod.example/x
MAILGUN_API_KEY=prod-mailgun
TELEGRAM_API_ID=12345
TELEGRAM_API_HASH=prod-telegram
SOME_NEW_SETTING=prod-new
EOF

run() { SOURCE="$WORK/prod" OUT="$WORK/out" bash "$REPO/scripts/demo-env.sh" >/dev/null; }
run || fail "script failed"

check "lookup key copied" "$(val VIRUSTOTAL_API_KEY)" "vt-key"
check "missing lookup key is blank" "$(val OTX_API_KEY)" ""
for name in SMTP_HOST SMTP_PASSWORD ALERT_WEBHOOK_URL MAILGUN_API_KEY TELEGRAM_API_ID TELEGRAM_API_HASH; do
  check "$name is blank" "$(val "$name")" ""
done
if grep -q 'prod-' "$WORK/out"; then fail "a production value reached the demo env file"; else ok "no production secret in the file"; fi
check "setting not on the allow list is absent" "$(grep -c '^SOME_NEW_SETTING=' "$WORK/out")" "0"
check "database is the demo one" "$(val DATABASE_URL | sed 's#//[^@]*@#//#')" "postgresql+psycopg2://demo-postgres:5432/darkweb_scanner_demo"
[[ "$(val DATABASE_URL)" == *":$(val POSTGRES_PASSWORD)@"* ]] && ok "URL carries the demo password" || fail "URL does not carry the demo password"
check "session secret is long enough" "$([[ $(val DASHBOARD_SECRET_KEY | wc -c) -gt 32 ]] && echo yes)" "yes"
check "mode 600" "$(stat -f %Lp "$WORK/out" 2>/dev/null || stat -c %a "$WORK/out")" "600"

before="$(val POSTGRES_PASSWORD)/$(val DASHBOARD_SECRET_KEY)/$(val SETUP_TOKEN)"
echo "VIRUSTOTAL_API_KEY=vt-key-2" > "$WORK/prod.new"; grep -v '^VIRUSTOTAL' "$WORK/prod" >> "$WORK/prod.new"; mv "$WORK/prod.new" "$WORK/prod"
run || fail "second run failed"
check "secrets kept on a second run" "$(val POSTGRES_PASSWORD)/$(val DASHBOARD_SECRET_KEY)/$(val SETUP_TOKEN)" "$before"
check "lookup key refreshed on a second run" "$(val VIRUSTOTAL_API_KEY)" "vt-key-2"

exit "$FAILED"
