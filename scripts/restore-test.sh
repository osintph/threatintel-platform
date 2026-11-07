#!/usr/bin/env bash
# =============================================================================
#  Restore test — prove that a database dump can be restored.
#
#  The dump is restored into a throwaway PostgreSQL container that has no
#  network and keeps its data in memory. The live database is not touched, and
#  the container is removed at the end. Only table names and row counts are
#  printed, never data.
#
#  Usage:
#    scripts/restore-test.sh backups/pre-upgrade-<time>.dump     a pg_dump -Fc file, plain or gzipped
#    scripts/restore-test.sh - < some.dump.gz                    the same from standard input
#    COMPARE=1 scripts/restore-test.sh <dump>                    also print the live row counts next to
#                                                                the restored ones (run it in the install
#                                                                directory, with the stack up)
#  Optional env:
#    IMAGE=postgres:16-alpine    image to restore into (default: the one docker-compose.yml names)
#
#  Exit status: 0 when the dump restored without an error and holds at least
#  one table; 1 otherwise. See docs/runbook.md, "Backups and restore test".
# =============================================================================
set -euo pipefail

SRC="${1:-}"
[[ -n "$SRC" ]] || { echo "usage: $0 <dump file | ->   (see the header of this script)" >&2; exit 1; }
[[ "$SRC" == "-" || -s "$SRC" ]] || { echo "restore-test: $SRC is missing or empty" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${IMAGE:-}" ]]; then
  IMAGE="$(sed -nE 's/^[[:space:]]*image:[[:space:]]*(postgres:[^[:space:]]+).*/\1/p' "$HERE/docker-compose.yml" 2>/dev/null | head -1)"
  IMAGE="${IMAGE:-postgres:16-alpine}"
fi
NAME="restore-test-$$-$RANDOM"
DB_NAME="${DB_NAME:-darkweb_scanner}"
DB_USER="${DB_USER:-scanner}"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "restore-test: starting a throwaway PostgreSQL ($NAME, no network, data in memory)"
# The password is never used: every command below goes through the socket inside the container.
docker run -d --rm --name "$NAME" --network none \
  --tmpfs /var/lib/postgresql/data --tmpfs /tmp \
  -e POSTGRES_PASSWORD="unused-$RANDOM$RANDOM$RANDOM" "$IMAGE" >/dev/null

# The image starts a temporary server first; wait for the real one.
waited=0
until docker logs "$NAME" 2>&1 | grep -q 'PostgreSQL init process complete' \
  && docker exec "$NAME" psql -U postgres -Atqc 'select 1' >/dev/null 2>&1; do
  waited=$((waited + 1))
  [[ $waited -le 90 ]] || { echo "restore-test: PostgreSQL did not start" >&2; docker logs --tail 20 "$NAME" >&2 || true; exit 1; }
  sleep 1
done

# Copy the dump in (memory only) and unpack it if it is gzipped.
if [[ "$SRC" == "-" ]]; then
  docker exec -i "$NAME" sh -c 'cat > /tmp/in'
else
  docker exec -i "$NAME" sh -c 'cat > /tmp/in' < "$SRC"
fi
docker exec "$NAME" sh -c '
  [ -s /tmp/in ] || { echo "restore-test: the dump is empty" >&2; exit 1; }
  if [ "$(head -c 2 /tmp/in | od -An -tx1 | tr -d " \n")" = "1f8b" ]; then
    gunzip -c /tmp/in > /tmp/db.dump && rm /tmp/in
  else
    mv /tmp/in /tmp/db.dump
  fi'

echo "restore-test: restoring ($(docker exec "$NAME" sh -c 'wc -c < /tmp/db.dump' | tr -d ' ') bytes unpacked)"
docker exec "$NAME" sh -c 'createdb -U postgres restored &&
  pg_restore -U postgres --no-owner --no-privileges --exit-on-error -d restored /tmp/db.dump' \
  || { echo "restore-test: FAILED — pg_restore reported an error" >&2; exit 1; }

count_tables() { # prints "table rows" per line; reads psql command from "$@"
  local t
  "$@" -Atqc "select tablename from pg_tables where schemaname = 'public' order by 1" | while read -r t; do
    [[ -n "$t" ]] && printf '%s %s\n' "$t" "$("$@" -Atqc "select count(*) from \"$t\"")"
  done
}
restored() { docker exec "$NAME" psql -U postgres -d restored "$@"; }
live() { (cd "$HERE" && docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" "$@" </dev/null); }

R="$(count_tables restored)"
TABLES="$(grep -c . <<<"$R" || true)"
ROWS="$(awk '{n += $2} END {print n + 0}' <<<"$R")"
[[ "$TABLES" -gt 0 ]] || { echo "restore-test: FAILED — the restored database has no tables" >&2; exit 1; }

echo
if [[ "${COMPARE:-}" == "1" ]]; then
  L="$(count_tables live)"
  printf '%-28s %10s %10s\n' "table" "restored" "live now"
  join -a 1 -a 2 -e - -o 0,1.2,2.2 <(sort <<<"$R") <(sort <<<"$L") | while read -r t a b; do
    printf '%-28s %10s %10s%s\n' "$t" "$a" "$b" "$([[ "$a" == "$b" ]] || echo '   <- differs (rows added or removed since the dump)')"
  done
else
  printf '%-28s %10s\n' "table" "rows"
  while read -r t a; do printf '%-28s %10s\n' "$t" "$a"; done <<<"$R"
fi
echo
if grep -q '^alembic_version ' <<<"$R"; then
  echo "schema revision in the dump: $(restored -Atqc 'select version_num from alembic_version')"
else
  echo "schema revision in the dump: none (a dump from release 1.2.0 or older)"
fi
if grep -q '^users ' <<<"$R"; then
  echo "accounts in the dump: $(restored -Atqc 'select count(*) from users') ($(restored -Atqc 'select count(*) from users where is_admin') administrator)"
fi
echo "restore-test: PASSED — $TABLES tables, $ROWS rows restored without an error; the container is removed now"
