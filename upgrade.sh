#!/usr/bin/env bash
# =============================================================================
#  threatintel-platform — upgrade an existing install
#  Repo: https://github.com/osintph/threatintel-platform
#
#  Usage (as root, from the install directory):
#    sudo ./upgrade.sh              # move to the tip of main
#    sudo ./upgrade.sh v1.2.0       # move to a release tag, a branch or a commit
#
#  Optional env:
#    SERVICES="tor dashboard"   rebuild and recreate only these services
#    SKIP_BACKUP=1              skip the pre-upgrade database dump
#    SKIP_FETCH=1               use the refs already in the local clone
#    SITE_URLS="https://a/ https://b/"
#                               public URLs that must answer 200 at the end
#                               (default: built from DOMAIN and WWW_DOMAIN in .env)
#    ORIGIN_LOCK=1              install the Cloudflare origin lock if it is not there yet
#    UPDATE_WWW=1               also move the www submodule to the recorded commit
#
#  What it does, in order: pre-flight checks, database dump, git checkout,
#  .env fixes, origin lock update, image build, containers recreated one by one
#  (postgres, tor, dashboard, nginx), health checks, public URL checks.
#  It never touches SSH, ufw or volumes. See docs/runbook.md for rollback.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

DB_NAME=darkweb_scanner
DB_USER=scanner

# Read one non-secret value from .env.
env_value() { grep -m1 "^$1=" .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'"'[:space:]'; }

wait_healthy() { # service seconds
  local svc=$1 limit=$2 waited=0 cid state
  while :; do
    cid="$(docker compose ps -q "$svc" 2>/dev/null | head -1)"
    state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo missing)"
    case "$state" in healthy | running) return 0 ;; esac
    [[ $waited -ge $limit ]] && return 1
    sleep 3
    waited=$((waited + 3))
  done
}

in_list() { local x=$1; shift; local y; for y in "$@"; do [[ "$x" == "$y" ]] && return 0; done; return 1; }

preflight() {
  [[ $EUID -eq 0 ]] || error "Please run as root:  sudo ./upgrade.sh"
  [[ -f docker-compose.yml && -d .git ]] || error "Run this from the install directory (the git checkout with docker-compose.yml)."
  [[ -f .env ]] || error ".env is missing. This script upgrades an existing install; use deploy.sh for a new one."
  docker compose version >/dev/null 2>&1 || error "docker compose plugin not found."

  local marker
  for marker in CHERRY_PICK_HEAD MERGE_HEAD REVERT_HEAD rebase-merge rebase-apply; do
    [[ -e ".git/$marker" ]] && error "A git operation is unfinished (.git/$marker). Finish or abort it first, for example: git cherry-pick --abort"
  done
  local dirty
  dirty="$(git status --porcelain --untracked-files=no --ignore-submodules=all)"
  if [[ -n "$dirty" ]]; then
    echo "$dirty" >&2
    error "Tracked files have local changes. Commit, stash or discard them first. Untracked files are left alone."
  fi
  success "Pre-flight checks passed."
}

backup_database() {
  if [[ "${SKIP_BACKUP:-}" == "1" ]]; then warn "SKIP_BACKUP=1 — no pre-upgrade database dump."; return 0; fi
  if ! docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
    warn "postgres is not running — no pre-upgrade database dump."
    return 0
  fi
  local out objects
  mkdir -p backups && chmod 700 backups
  out="backups/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ).dump"
  info "Dumping the database to $out ..."
  # Local socket inside the container: no password on any command line.
  docker compose exec -T postgres pg_dump -U "$DB_USER" -Fc "$DB_NAME" > "$out" || error "pg_dump failed; nothing was changed."
  objects="$(docker compose exec -T postgres pg_restore --list < "$out" | grep -c 'TABLE DATA' || true)"
  [[ "${objects:-0}" -gt 0 ]] || error "The dump could not be read back ($out); nothing was changed."
  chmod 600 "$out"
  # Keep the five newest dumps.
  # shellcheck disable=SC2012
  ls -1t backups/pre-upgrade-*.dump 2>/dev/null | tail -n +6 | xargs -r rm -f
  success "Database dump verified ($objects tables, $(du -h "$out" | cut -f1))."
}

checkout_ref() { # ref
  local ref=$1 sha before recorded actual
  before="$(git rev-parse HEAD)"
  info "Current commit: $(git rev-parse --short HEAD) ($(git describe --tags --always 2>/dev/null))"
  if [[ "${SKIP_FETCH:-}" != "1" ]]; then
    info "Fetching from origin..."
    git fetch --tags --prune origin || error "git fetch failed; nothing was changed."
  fi
  if git show-ref --verify --quiet "refs/remotes/origin/$ref"; then
    # A branch: stay on it, fast-forward only.
    git checkout -q "$ref" 2>/dev/null || git checkout -q -b "$ref" --track "origin/$ref"
    git merge -q --ff-only "origin/$ref" || error "Local branch $ref cannot be fast-forwarded to origin/$ref."
  else
    sha="$(git rev-parse --verify --quiet "$ref^{commit}")" || error "Unknown ref: $ref"
    git checkout -q --detach "$sha"
  fi
  [[ "$(git rev-parse HEAD)" == "$before" ]] || echo "$before" > .upgrade-previous-commit
  success "Now at $(git rev-parse --short HEAD) ($(git describe --tags --always 2>/dev/null))."

  # The website checkout is deployed on its own schedule: never move it unasked.
  if [[ -f .gitmodules ]]; then
    if [[ "${UPDATE_WWW:-}" == "1" ]]; then
      git submodule update --init www && success "www submodule moved to the recorded commit."
    elif [[ -e www/.git ]]; then
      recorded="$(git ls-tree HEAD www | awk '{print $3}')"
      actual="$(git -C www rev-parse HEAD 2>/dev/null || true)"
      [[ "$recorded" == "$actual" ]] || warn "www is at ${actual:0:7}, this release records ${recorded:0:7}. Left as it is (UPDATE_WWW=1 moves it)."
    fi
  fi
}

migrate_env() {
  if grep -qE '^DATABASE_URL=postgres(ql)?://' .env; then
    sed -i -E 's#^DATABASE_URL=postgres(ql)?://#DATABASE_URL=postgresql+psycopg2://#' .env
    success ".env: DATABASE_URL now names the psycopg2 driver."
  fi
  chmod 600 .env
  local missing
  missing="$(comm -23 <(grep -oE '^[A-Z][A-Z0-9_]*=' .env.example | sort -u) <(grep -oE '^[A-Z][A-Z0-9_]*=' .env | sort -u) | tr -d '=' | tr '\n' ' ')"
  [[ -n "$missing" ]] && info "Settings in .env.example that your .env does not set (defaults apply): $missing"
  return 0
}

update_origin_lock() {
  if [[ -x /usr/local/sbin/cf-origin-lock || "${ORIGIN_LOCK:-}" == "1" ]]; then
    info "Updating the Cloudflare origin lock..."
    bash ops/cf-origin-lock/install.sh || error "Origin lock update failed — see: journalctl -u cf-origin-lock.service"
    success "Origin lock up to date."
  fi
}

# Keep the image each service runs now under the tag :previous, for rollback.
tag_previous() {
  local svc cid image
  for svc in "$@"; do
    cid="$(docker compose ps -q "$svc" 2>/dev/null | head -1)"
    [[ -n "$cid" ]] || continue
    image="$(docker inspect -f '{{.Config.Image}}' "$cid" 2>/dev/null || true)"
    [[ -n "$image" && "$image" != *@* && "$image" != *:* ]] || continue
    docker tag "$(docker inspect -f '{{.Image}}' "$cid")" "$image:previous" 2>/dev/null || true
  done
}

build_and_start() {
  local -a all wanted built=()
  local svc
  mapfile -t all < <(docker compose config --services)
  if [[ -n "${SERVICES:-}" ]]; then
    read -r -a wanted <<< "$SERVICES"
    for svc in "${wanted[@]}"; do in_list "$svc" "${all[@]}" || error "Unknown service in SERVICES: $svc"; done
  else
    wanted=("${all[@]}")
  fi
  info "Services in this run: ${wanted[*]}"
  tag_previous "${wanted[@]}"

  # Pinned upstream images first (postgres), then the images built here.
  docker compose pull --ignore-buildable "${wanted[@]}"
  for svc in "${wanted[@]}"; do [[ "$svc" == postgres ]] || built+=("$svc"); done
  if [[ ${#built[@]} -gt 0 ]]; then
    info "Building images (this may take a few minutes)..."
    docker compose build --pull "${built[@]}"
    success "Images built."
  fi

  if in_list postgres "${wanted[@]}"; then
    info "Starting PostgreSQL..."
    docker compose up -d --no-deps postgres
    wait_healthy postgres 90 || error "PostgreSQL did not become healthy. Check: docker compose logs postgres"
    success "PostgreSQL is healthy."
  fi
  for svc in tor dashboard; do
    in_list "$svc" "${wanted[@]}" || continue
    info "Starting $svc..."
    docker compose up -d --no-deps "$svc"
  done
  if in_list dashboard "${wanted[@]}"; then
    wait_healthy dashboard 150 || { docker compose logs --tail 40 dashboard || true; error "The dashboard did not become healthy (its healthcheck queries the database)."; }
    success "Dashboard is healthy."
  fi

  if in_list nginx "${wanted[@]}"; then
    info "Starting nginx..."
    docker compose up -d --no-deps nginx
    sleep 5
  fi
  # A reload makes nginx look up the dashboard container again. It never runs the entrypoint.
  if docker compose ps --status running --services 2>/dev/null | grep -qx nginx; then
    if docker compose exec -T nginx nginx -s reload 2>/dev/null; then success "nginx reloaded."; fi
  fi

  # A full run also starts anything new and removes services that left the compose file.
  if [[ -z "${SERVICES:-}" ]]; then
    docker compose up -d --remove-orphans
  fi
}

final_checks() {
  local domain www urls url code bad=0 version
  version="$(docker compose exec -T dashboard python3 -c 'from darkweb_scanner import __version__; print(__version__)' 2>/dev/null || true)"
  [[ -n "$version" ]] && info "Running version: $version"
  docker compose ps --format 'table {{.Service}}\t{{.Status}}'

  urls="${SITE_URLS:-}"
  if [[ -z "$urls" ]]; then
    domain="$(env_value DOMAIN)"
    www="$(env_value WWW_DOMAIN)"
    [[ -n "$domain" ]] && urls="https://$domain/login"
    [[ -n "$www" ]] && urls="$urls https://$www/"
  fi
  if [[ -z "$urls" ]]; then
    code="$(curl -sk -o /dev/null -m 20 -w '%{http_code}' https://localhost/login || true)"
    if [[ "$code" == "200" ]]; then success "https://localhost/login -> 200"; else warn "https://localhost/login -> $code"; bad=1; fi
  else
    info "Checking the public URLs..."
    sleep 3
    for url in $urls; do
      code="$(curl -s -o /dev/null -m 30 -w '%{http_code}' "$url" || true)"
      if [[ "$code" == "200" ]]; then success "$url -> 200"; else warn "$url -> $code"; bad=1; fi
    done
  fi
  return "$bad"
}

main() {
  local ref="${1:-main}"
  cd "$(dirname "${BASH_SOURCE[0]}")"

  if [[ "${UPGRADE_PHASE:-1}" == "1" ]]; then
    exec 9> /var/lock/threatintel-upgrade.lock
    flock -n 9 || error "Another upgrade is running."
    echo ""
    echo -e "${CYAN}threatintel-platform — upgrade to ${ref}${NC}"
    echo ""
    preflight
    backup_database
    checkout_ref "$ref"
    # The checkout may have replaced this script: run the rest from the new copy.
    UPGRADE_PHASE=2 exec bash "./upgrade.sh" "$ref"
  fi

  migrate_env
  update_origin_lock
  build_and_start
  echo ""
  if final_checks; then
    success "Upgrade complete."
  else
    warn "Upgrade finished, but a check above did not return 200. Roll back with: ./upgrade.sh $(cat .upgrade-previous-commit 2>/dev/null || echo PREVIOUS_COMMIT)"
    exit 1
  fi
  if [[ -s .upgrade-previous-commit ]]; then
    echo "  Previous commit: $(cat .upgrade-previous-commit)   (roll back: ./upgrade.sh <that commit>)"
  fi
}

main "$@"
