#!/usr/bin/env bash
# OPS-7: scripts/restore-test.sh restores a dump into a throwaway PostgreSQL and
# reports row counts; a damaged dump fails; nothing is left behind.
#
# Makes its own small database in a throwaway container (no network), dumps it,
# and runs the script on that dump as a file, gzipped, and from standard input.
#
# usage: tests/scripts/test_restore_test.sh            (needs docker)
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; SRC="restore-src-$$"
cleanup() { docker rm -f "$SRC" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT
FAILED=0
ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }

IMAGE="${IMAGE:-$(sed -nE 's/^[[:space:]]*image:[[:space:]]*(postgres:[^[:space:]]+).*/\1/p' "$REPO/docker-compose.yml" | head -1)}"
export IMAGE

# A source database with two tables, a schema revision and one administrator.
docker run -d --rm --name "$SRC" --network none --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_PASSWORD="unused-$RANDOM$RANDOM" "$IMAGE" >/dev/null
n=0
until docker logs "$SRC" 2>&1 | grep -q 'PostgreSQL init process complete' && docker exec "$SRC" psql -U postgres -Atqc 'select 1' >/dev/null 2>&1; do
  n=$((n + 1)); [[ $n -le 90 ]] || { echo "FAIL - source PostgreSQL did not start"; exit 1; }; sleep 1
done
# One statement per -c: CREATE DATABASE cannot run in a batch with others.
docker exec "$SRC" psql -U postgres -q -v ON_ERROR_STOP=1 -c "create role scanner" -c "create database src owner scanner" >/dev/null
docker exec "$SRC" psql -U postgres -d src -q -v ON_ERROR_STOP=1 -c "
  create table users (id serial primary key, username text, is_admin boolean);
  insert into users (username, is_admin) values ('boss', true), ('analyst', false), ('second', false);
  create table keyword_hits (id serial primary key, keyword text);
  insert into keyword_hits (keyword) select 'k' || g from generate_series(1, 40) g;
  create table alembic_version (version_num varchar(32) not null);
  insert into alembic_version values ('0002');
  alter table users owner to scanner;" >/dev/null
docker exec "$SRC" pg_dump -U postgres -Fc src > "$WORK/good.dump"
gzip -c "$WORK/good.dump" > "$WORK/good.dump.gz"
head -c 600 "$WORK/good.dump" > "$WORK/cut.dump"
: > "$WORK/empty.dump"
check "the test dump was made" "$([[ -s "$WORK/good.dump" ]] && echo yes)" "yes"

T="$REPO/scripts/restore-test.sh"

"$T" "$WORK/good.dump" > "$WORK/plain.out" 2>&1; check "plain dump: exit status" "$?" "0"
check "plain dump: reports success with the right totals" "$(grep -c 'PASSED — 3 tables, 44 rows' "$WORK/plain.out")" "1"
check "plain dump: row count per table" "$(awk '$1 == "keyword_hits" {print $2}' "$WORK/plain.out")" "40"
check "plain dump: schema revision" "$(grep -c 'schema revision in the dump: 0002' "$WORK/plain.out")" "1"
check "plain dump: accounts are counted, not listed" "$(grep -c 'accounts in the dump: 3 (1 administrator)' "$WORK/plain.out"):$(grep -c 'boss\|analyst' "$WORK/plain.out")" "1:0"

"$T" "$WORK/good.dump.gz" > "$WORK/gz.out" 2>&1; check "gzipped dump: exit status" "$?" "0"
check "gzipped dump: same totals" "$(grep -c 'PASSED — 3 tables, 44 rows' "$WORK/gz.out")" "1"

"$T" - < "$WORK/good.dump.gz" > "$WORK/stdin.out" 2>&1; check "from standard input: exit status" "$?" "0"
check "from standard input: same totals" "$(grep -c 'PASSED — 3 tables, 44 rows' "$WORK/stdin.out")" "1"

"$T" "$WORK/cut.dump" > "$WORK/cut.out" 2>&1; check "a cut-off dump fails" "$?" "1"
check "a cut-off dump is not reported as passed" "$(grep -c PASSED "$WORK/cut.out")" "0"

"$T" "$WORK/empty.dump" > "$WORK/empty.out" 2>&1; check "an empty file fails" "$?" "1"
"$T" > "$WORK/noarg.out" 2>&1; check "no argument fails with the usage line" "$?:$(grep -c usage "$WORK/noarg.out")" "1:1"

check "no restore container is left behind" "$(docker ps -a --format '{{.Names}}' | grep -c '^restore-test-' || true)" "0"

if [[ "$FAILED" == "0" ]]; then echo "all checks passed"; else echo "SOME CHECKS FAILED"; exit 1; fi
