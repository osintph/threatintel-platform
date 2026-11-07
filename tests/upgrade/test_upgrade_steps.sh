#!/usr/bin/env bash
# Two steps of upgrade.sh, run on their own with docker, git and crontab replaced
# by stubs (no containers, no real crontab is touched):
#
#   remove_paste_cron   D-10: the paste monitor's cron job goes, everything else in
#                       root's crontab stays, and a copy of the old crontab is kept.
#   schema_step_back    REL-7: before moving to a release with an older database
#                       schema, the dashboard is stopped and the schema is taken back.
#
# usage: tests/upgrade/test_upgrade_steps.sh
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0
ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }

# The functions under test, cut out of the real script.
FUNCS="$WORK/funcs.sh"
grep '^app_cli() {' "$REPO/upgrade.sh" > "$FUNCS"   # a one-line function
for f in schema_step_back remove_paste_cron; do
  sed -n "/^$f() {/,/^}/p" "$REPO/upgrade.sh" >> "$FUNCS"
done
check "found the three functions in upgrade.sh" "$(grep -cE '^(app_cli|schema_step_back|remove_paste_cron)\(\) \{' "$FUNCS")" "3"

# run <dir> <function> [args]: status of the function; its output in <dir>/out, calls in <dir>/calls
run() {
  local dir=$1; shift
  ( cd "$dir" && : > calls && FUNCS="$FUNCS" bash -c '
      set -euo pipefail
      info() { echo "[INFO] $*"; }; success() { echo "[OK] $*"; }; warn() { echo "[WARN] $*"; }
      error() { echo "[ERROR] $*"; exit 1; }
      crontab() {
        if [[ "$1" == "-l" ]]; then [[ -f crontab.txt ]] && cat crontab.txt; else cat > crontab.txt; echo "crontab-written" >> calls; fi
      }
      docker() {
        echo "docker $*" >> calls
        case "$*" in
          "compose ps --status running --services") [[ "${PG:-up}" == "up" ]] && echo postgres; return 0 ;;
          *"db-status --quiet") echo "2026-01-01 [INFO] darkweb_scanner.storage: Database schema ready"; echo "${DB_REV:-}"; return 0 ;;
          *"db-downgrade"*) return "${DOWNGRADE_STATUS:-0}" ;;
          "compose stop dashboard") return 0 ;;
        esac
      }
      git() {
        case "$1" in
          show-ref) return 1 ;;                       # the ref is a tag or a commit, not a branch
          rev-parse) [[ "${KNOWN_REF:-yes}" == "yes" ]] && echo 0123abc ;;
          ls-tree) for r in ${TARGET_REVS:-}; do echo "src/darkweb_scanner/migrations/versions/${r}_x.py"; done ;;
        esac
      }
      source "$FUNCS"
      "$@"' _ "$@" > out 2>&1 )
}
calls() { grep -c -- "$2" "$1/calls" || true; }

PASTE='*/5 * * * * cd /root/darkweb-scanner && docker compose exec -T dashboard python3 -c "from darkweb_scanner.paste_monitor import run_paste_monitor" >> /var/log/paste_monitor.log 2>&1'
OTHER1='# nightly'
OTHER2='15 3 * * * /opt/backup/run.sh'

# ── remove_paste_cron ──────────────────────────────────────────────────────────
A="$WORK/a"; mkdir "$A"; printf '%s\n' "$PASTE" > "$A/crontab.txt"
run "$A" remove_paste_cron; check "only line is the paste job: step succeeds" "$?" "0"
check "the crontab is empty afterwards" "$(grep -c . "$A/crontab.txt" || true)" "0"
check "a copy of the old crontab is kept" "$(cat "$A"/backups/root-crontab-before-* | grep -c paste_monitor)" "1"
check "the copy is private" "$(stat -c %a "$A"/backups/root-crontab-before-* 2>/dev/null || stat -f %Lp "$A"/backups/root-crontab-before-*)" "600"
check "it says what it did" "$(grep -c 'Removed the paste monitor job' "$A/out")" "1"

B="$WORK/b"; mkdir "$B"; printf '%s\n' "$OTHER1" "$PASTE" "$OTHER2" > "$B/crontab.txt"
run "$B" remove_paste_cron; check "paste job among others: step succeeds" "$?" "0"
check "the other lines stay, in order" "$(cat "$B/crontab.txt")" "$(printf '%s\n' "$OTHER1" "$OTHER2")"

C="$WORK/c"; mkdir "$C"; printf '%s\n' "$OTHER1" "$OTHER2" > "$C/crontab.txt"
run "$C" remove_paste_cron; check "no paste job: step succeeds" "$?" "0"
check "no paste job: the crontab is not rewritten" "$(calls "$C" crontab-written)" "0"
check "no paste job: no copy is made" "$([[ -e "$C/backups" ]] && echo made || echo none)" "none"

D="$WORK/d"; mkdir "$D"
run "$D" remove_paste_cron; check "no crontab at all: step succeeds and writes nothing" "$?:$(calls "$D" crontab-written)" "0:0"

# ── schema_step_back ───────────────────────────────────────────────────────────
E="$WORK/e"; mkdir "$E"
DB_REV=0002 TARGET_REVS="" run "$E" schema_step_back v1.2.0
check "1.3.0 database, target 1.2.0 (no revisions): step succeeds" "$?" "0"
check "the dashboard is stopped first" "$(grep -n 'compose stop dashboard\|db-downgrade' "$E/calls" | head -1 | grep -c 'stop dashboard')" "1"
check "the schema is taken back to the baseline" "$(calls "$E" 'db-downgrade 0001 --yes')" "1"

F="$WORK/f"; mkdir "$F"
DB_REV=0002 TARGET_REVS="0001 0002" run "$F" schema_step_back v1.3.1
check "target knows the database's revision: nothing is done" "$?:$(calls "$F" 'stop dashboard'):$(calls "$F" db-downgrade)" "0:0:0"

G="$WORK/g"; mkdir "$G"
DB_REV=0003 TARGET_REVS="0001 0002" run "$G" schema_step_back v1.3.0
check "one revision too new: taken back to the target's newest" "$?:$(calls "$G" 'db-downgrade 0002 --yes')" "0:1"

H="$WORK/h"; mkdir "$H"
DB_REV="" TARGET_REVS="" run "$H" schema_step_back v1.1.1
check "installed release has no revisions (1.2.0 or older): nothing is done" "$?:$(calls "$H" db-downgrade)" "0:0"

I="$WORK/i"; mkdir "$I"
DB_REV=0002 TARGET_REVS="" SKIP_BACKUP=1 run "$I" schema_step_back v1.2.0
check "no step back without the database dump (SKIP_BACKUP=1)" "$?:$(calls "$I" db-downgrade):$(calls "$I" 'stop dashboard')" "1:0:0"
check "it says to run without SKIP_BACKUP" "$(grep -c 'without SKIP_BACKUP=1' "$I/out")" "1"

J="$WORK/j"; mkdir "$J"
PG=down DB_REV=0002 TARGET_REVS="" run "$J" schema_step_back v1.2.0
check "postgres not running: nothing is done" "$?:$(calls "$J" db-downgrade)" "0:0"

K="$WORK/k"; mkdir "$K"
DB_REV=0002 TARGET_REVS="" DOWNGRADE_STATUS=1 run "$K" schema_step_back v1.2.0
check "a failed step back stops the upgrade" "$?" "1"
check "and says how to start the dashboard again" "$(grep -c 'docker compose up -d dashboard' "$K/out")" "1"

L="$WORK/l"; mkdir "$L"
KNOWN_REF=no DB_REV=0002 run "$L" schema_step_back no-such-ref
check "an unknown ref is left for the checkout step to report" "$?:$(calls "$L" db-downgrade)" "0:0"

if [[ "$FAILED" == "0" ]]; then echo "all checks passed"; else echo "SOME CHECKS FAILED"; exit 1; fi
