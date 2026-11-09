#!/usr/bin/env bash
# Write .env.demo, the environment of the demo instance (docker compose --profile demo).
#
# Built from an allow list, not by copying .env: anything not named here does not
# reach the demo. The secrets are generated once and kept on later runs, because a
# new database password would not match the existing demo volume. The lookup keys
# are read from .env again on every run. Values are never printed.
#
# usage (from the install directory): make demo-env
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SOURCE="${SOURCE:-.env}"
OUT="${OUT:-.env.demo}"
LOOKUP_KEYS=(
  RANSOMWARE_LIVE_API_KEY THREATFOX_API_KEY OTX_API_KEY WHITEINTEL_API_KEY
  VIRUSTOTAL_API_KEY ABUSEIPDB_API_KEY DNSDUMPSTER_API_KEY HIBP_API_KEY
)
BLANK_KEYS=(
  SMTP_HOST SMTP_USER SMTP_PASSWORD ALERT_EMAIL_FROM ALERT_EMAIL_TO ALERT_WEBHOOK_URL
  MAILGUN_API_KEY MAILGUN_DOMAIN MAILGUN_FROM
  TELEGRAM_API_ID TELEGRAM_API_HASH TELEGRAM_PHONE TELEGRAM_CHANNELS
)

[[ -f "$SOURCE" ]] || { echo "demo-env: $SOURCE not found" >&2; exit 1; }

value() { grep -m1 "^$1=" "$2" 2>/dev/null | cut -d= -f2- || true; }

kept_or_new() { # name bytes
  local current=""
  [[ -f "$OUT" ]] && current="$(value "$1" "$OUT")"
  if [[ -n "$current" ]]; then printf '%s' "$current"; else openssl rand -hex "$2"; fi
}

secret_key="$(kept_or_new DASHBOARD_SECRET_KEY 32)"
db_password="$(kept_or_new POSTGRES_PASSWORD 24)"
setup_token="$(kept_or_new SETUP_TOKEN 24)"

umask 077
tmp="$(mktemp "$OUT.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
{
  echo "# Written by scripts/demo-env.sh. Run 'make demo-env' again instead of editing."
  echo "DASHBOARD_SECRET_KEY=$secret_key"
  echo "POSTGRES_PASSWORD=$db_password"
  echo "DATABASE_URL=postgresql+psycopg2://scanner_demo:$db_password@demo-postgres:5432/darkweb_scanner_demo"
  echo "SETUP_TOKEN=$setup_token"
  echo "LOG_LEVEL=INFO"
  for key in "${LOOKUP_KEYS[@]}"; do echo "$key=$(value "$key" "$SOURCE")"; done
  for key in "${BLANK_KEYS[@]}"; do echo "$key="; done
} > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$OUT"
trap - EXIT
echo "demo-env: wrote $OUT (mode 600)."
