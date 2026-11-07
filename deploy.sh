#!/usr/bin/env bash
# =============================================================================
#  threatintel-platform — Zero-prerequisite deployment script
#  Repo: https://github.com/osintph/threatintel-platform
#
#  Usage (recommended):
#    curl -fsSL https://raw.githubusercontent.com/osintph/threatintel-platform/main/deploy.sh -o /tmp/deploy.sh && sudo bash /tmp/deploy.sh
#
#  Or if already downloaded:
#    sudo bash deploy.sh
#
#  Optional env overrides:
#    INSTALL_DIR=/opt/threatintel-platform sudo bash deploy.sh
#    DOMAIN=scanner.example.com SSL_EMAIL=you@email.com sudo bash deploy.sh
#    INSTALL_TIMER=1 sudo bash deploy.sh
#    ORIGIN_LOCK=1 sudo bash deploy.sh      # only if every public name is proxied through Cloudflare
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/osintph/threatintel-platform"
RUN_USER="${SUDO_USER:-$(whoami)}"
RUN_USER_HOME=$(getent passwd "$RUN_USER" | cut -d: -f6)
INSTALL_DIR="${INSTALL_DIR:-${RUN_USER_HOME}/threatintel-platform}"
DOMAIN="${DOMAIN:-}"
SSL_EMAIL="${SSL_EMAIL:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
# Never stop without saying where: with set -e a failing command would otherwise end the script silently.
trap 'echo -e "${RED}[ERROR]${NC} deploy.sh stopped at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR

[[ $EUID -ne 0 ]] && error "Please run as root:  sudo bash deploy.sh"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   threatintel-platform  —  Deployment    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── Detect OS ────────────────────────────────────────────────────────────────
[[ -f /etc/os-release ]] || error "Cannot detect OS — /etc/os-release missing."
source /etc/os-release
OS_ID="${ID,,}"
OS_LIKE="${ID_LIKE:-}"
info "Detected: $PRETTY_NAME"

is_debian_like() { [[ "$OS_ID" =~ ^(ubuntu|debian|kali|linuxmint|pop|raspbian)$ ]] || [[ "$OS_LIKE" =~ debian ]]; }
is_fedora_like() { [[ "$OS_ID" =~ ^(fedora)$ ]]; }
is_rhel_like()   { [[ "$OS_ID" =~ ^(rhel|centos|almalinux|rocky|ol)$ ]] || [[ "$OS_LIKE" =~ rhel ]]; }

# ── Install base packages ─────────────────────────────────────────────────────
info "Installing base packages..."
if is_debian_like; then
  apt-get update -qq
  apt-get install -y --no-install-recommends curl git make ca-certificates gnupg lsb-release openssl
elif is_fedora_like; then
  dnf install -y curl git make ca-certificates gnupg openssl
elif is_rhel_like; then
  dnf install -y curl git make ca-certificates gnupg openssl
else
  error "Unsupported distro: $OS_ID"
fi
success "Base packages ready."

# ── Install Docker CE ─────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker CE..."
  if is_debian_like; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${OS_ID} $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif is_fedora_like; then
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif is_rhel_like; then
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  success "Docker installed."
else
  success "Docker already installed: $(docker --version)"
fi

systemctl enable docker --now
success "Docker daemon running."

if [[ "$RUN_USER" != "root" ]]; then
  usermod -aG docker "$RUN_USER"
  success "User '$RUN_USER' added to docker group (log out/in to take effect)."
fi

docker compose version &>/dev/null || error "docker compose plugin not found."
success "docker compose: $(docker compose version --short)"

# ── Clone or update repo ──────────────────────────────────────────────────────
info "Setting up repo at $INSTALL_DIR..."
if [[ -d "$INSTALL_DIR/.git" ]]; then
  warn "Repo exists — pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only || warn "Pull failed (local changes?). Continuing."
else
  git clone "$REPO_URL" "$INSTALL_DIR"
fi
[[ "$RUN_USER" != "root" ]] && chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR"
success "Repo ready at $INSTALL_DIR"

cd "$INSTALL_DIR"

# ── Copy example configs ──────────────────────────────────────────────────────
info "Copying example config files..."
cp -n .env.example .env                                  2>/dev/null || true
cp -n config/keywords.example.yaml config/keywords.yaml  2>/dev/null || true
cp -n config/seeds.example.txt config/seeds.txt          2>/dev/null || true
chmod 600 .env
success "Config files ready."

# ── Patch .env ────────────────────────────────────────────────────────────────
# Every secret is generated once, while its value is still empty or a placeholder.
# Running this script again keeps what is there: a new database password in .env
# would not match the one the existing database volume was created with, and a new
# session secret would sign everyone out. Values are never printed.
env_get() { grep -m1 "^$1=" .env | cut -d= -f2- | tr -d '[:space:]' || true; }
env_set() {
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else printf '%s=%s\n' "$1" "$2" >> .env; fi
}

case "$(env_get DASHBOARD_SECRET_KEY)" in
  ""|changeme|change-me-in-production|change-me-to-a-long-random-string)
    env_set DASHBOARD_SECRET_KEY "$(openssl rand -hex 32)"
    info "Generated DASHBOARD_SECRET_KEY." ;;
  *) info "Keeping the DASHBOARD_SECRET_KEY already in .env." ;;
esac

case "$(env_get POSTGRES_PASSWORD)" in
  ""|changeme)
    if docker volume inspect darkweb-scanner_pg_data &>/dev/null; then
      error "POSTGRES_PASSWORD in .env is empty or a placeholder, but the database volume darkweb-scanner_pg_data already exists. Put the password that database was created with into .env (POSTGRES_PASSWORD and DATABASE_URL), or set a new one as described in docs/deployment.md under 'Password authentication failed'."
    fi
    PG_PASS="$(openssl rand -hex 24)"
    env_set POSTGRES_PASSWORD "$PG_PASS"
    env_set DATABASE_URL "postgresql+psycopg2://scanner:${PG_PASS}@postgres:5432/darkweb_scanner"
    unset PG_PASS
    info "Generated POSTGRES_PASSWORD and DATABASE_URL." ;;
  *) info "Keeping the POSTGRES_PASSWORD and DATABASE_URL already in .env." ;;
esac

# One-time token for creating the first administrator at /register.
if [[ -z "$(env_get SETUP_TOKEN)" ]]; then
  env_set SETUP_TOKEN "$(openssl rand -hex 24)"
fi

# Set domain and SSL email if provided
if [[ -n "$DOMAIN" ]]; then
  sed -i "s/^DOMAIN=.*/DOMAIN=${DOMAIN}/" .env
  info "Domain set to: $DOMAIN"
fi
if [[ -n "$SSL_EMAIL" ]]; then
  sed -i "s/^SSL_EMAIL=.*/SSL_EMAIL=${SSL_EMAIL}/" .env
fi

success "Configuration patched."

# ── Validate secret key ────────────────────────────────────────────────────────
# The app will also check on startup, but fail fast here before building images.
_SECRET_VAL=$(grep '^DASHBOARD_SECRET_KEY=' .env | cut -d= -f2- | tr -d '[:space:]')
if [[ -z "$_SECRET_VAL" || "$_SECRET_VAL" == "changeme" || "$_SECRET_VAL" == "change-me-in-production" || "$_SECRET_VAL" == "change-me-to-a-long-random-string" || ${#_SECRET_VAL} -lt 32 ]]; then
  error "DASHBOARD_SECRET_KEY is empty, a placeholder, or shorter than 32 characters. Edit .env and set a real secret before deploying."
fi
success "Secret key validated."

# ── Build all images ──────────────────────────────────────────────────────────
info "Building all Docker images (this may take a few minutes)..."
docker compose build --no-cache
success "Images built."

# ── Fix /app/data ownership for non-root container ────────────────────────────
# The app container runs as appuser (uid 1000). On a first deploy or after a
# volume was populated by a root-owned container, /app/data may be owned by root.
info "Ensuring /app/data is owned by appuser (uid 1000)..."
docker compose run --rm --user root dashboard chown -R 1000:1000 /app/data 2>/dev/null || \
  warn "Could not chown /app/data — if the container fails to write data, run this manually."
success "/app/data ownership set."

# ── Start all services ────────────────────────────────────────────────────────
info "Starting all containers..."
# Start postgres first and wait for it to be healthy
info "Starting PostgreSQL..."
docker compose up -d postgres
info "Waiting for PostgreSQL to be ready..."
timeout=30
until docker compose exec postgres pg_isready -U scanner -d darkweb_scanner >/dev/null 2>&1; do
  timeout=$((timeout-1))
  if [[ $timeout -le 0 ]]; then
    warn "PostgreSQL did not become ready in time — continuing anyway"
    break
  fi
  sleep 1
done
success "PostgreSQL is ready."

# Start remaining services
docker compose up -d
success "Containers started."

# ── Wait for dashboard container to be healthy ────────────────────────────────
info "Waiting for dashboard container to become healthy (up to 60 s)..."
ELAPSED=0
until [[ "$(docker compose ps dashboard --format json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Health',''))" 2>/dev/null)" == "healthy" ]]; do
  if [[ $ELAPSED -ge 60 ]]; then
    warn "Dashboard health check timed out after 60 s — check: docker compose logs dashboard"
    break
  fi
  sleep 3; ELAPSED=$((ELAPSED + 3))
done
[[ $ELAPSED -lt 60 ]] && success "Dashboard container is healthy."

# ── Wait for dashboard ────────────────────────────────────────────────────────
# nginx answers only for the configured name, so ask for that name on loopback.
CHECK_HOST="${DOMAIN:-$(env_get DOMAIN)}"; CHECK_HOST="${CHECK_HOST:-localhost}"
check_https() { curl -sk -o /dev/null -m 10 -w '%{http_code}' --resolve "${CHECK_HOST}:443:127.0.0.1" "https://${CHECK_HOST}/login" 2>/dev/null || true; }
info "Waiting for HTTPS to respond..."
TIMEOUT=90; ELAPSED=0
until [[ "$(check_https)" == "200" ]]; do
  [[ $ELAPSED -ge $TIMEOUT ]] && { warn "HTTPS not responding after ${TIMEOUT}s. Check: docker compose logs nginx"; break; }
  sleep 3; ELAPSED=$((ELAPSED + 3))
done
[[ "$(check_https)" == "200" ]] && success "HTTPS is live!"

# ── Wait for Tor to bootstrap ─────────────────────────────────────────────────
info "Waiting for Tor to bootstrap (up to 3 minutes)..."
ELAPSED=0
until docker compose logs tor 2>/dev/null | grep -q "Bootstrapped 100%"; do
  if [[ $ELAPSED -ge 180 ]]; then
    warn "Tor still bootstrapping — check with: docker compose logs tor | grep Bootstrapped"
    break
  fi
  sleep 10; ELAPSED=$((ELAPSED + 10))
done
docker compose logs tor 2>/dev/null | grep -q "Bootstrapped 100%" && success "Tor bootstrapped and ready."

# ── Post-deploy smoke check ───────────────────────────────────────────────────
info "Running post-deploy smoke check..."
_HTTP_STATUS="$(check_https)"
if [[ "$_HTTP_STATUS" == "200" ]]; then
  success "Smoke check passed (HTTP ${_HTTP_STATUS})."
else
  warn "Smoke check returned HTTP ${_HTTP_STATUS} — the dashboard may not be fully up yet."
fi

# ── Optional: systemd scan timer ─────────────────────────────────────────────
if [[ "${INSTALL_TIMER:-}" == "1" ]]; then
  info "Installing systemd scan timer (every 6 hours)..."
  tee /etc/systemd/system/threatintel-scan.service > /dev/null <<EOF
[Unit]
Description=threatintel-platform — scheduled crawl
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose --profile scan run --rm scanner
EOF

  tee /etc/systemd/system/threatintel-scan.timer > /dev/null <<EOF
[Unit]
Description=Run threatintel-platform crawler every 6 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now threatintel-scan.timer
  success "Systemd scan timer enabled (every 6h)."
fi

# ── Optional: Cloudflare origin lock ─────────────────────────────────────────
# Limits the published web ports to Cloudflare's ranges. See docs/runbook.md.
if [[ "${ORIGIN_LOCK:-}" == "1" ]]; then
  info "Installing the Cloudflare origin lock (DOCKER-USER rules, weekly refresh)..."
  if bash ops/cf-origin-lock/install.sh; then
    success "Origin lock installed. Check it with: cf-origin-lock selftest"
  else
    warn "Origin lock install failed — see: journalctl -u cf-origin-lock.service"
  fi
fi

# ── Version display ───────────────────────────────────────────────────────────
_VERSION=$(docker compose exec -T dashboard python3 -c \
  "from darkweb_scanner import __version__; print(f'Deployed version: {__version__}')" 2>/dev/null || true)
[[ -n "$_VERSION" ]] && info "$_VERSION"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✅  Deployment Complete                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Install dir:  ${CYAN}${INSTALL_DIR}${NC}"
if [[ -n "$DOMAIN" ]]; then
  echo -e "  Dashboard:    ${CYAN}https://${DOMAIN}${NC}"
else
  echo -e "  Dashboard:    ${CYAN}https://YOUR_SERVER_IP${NC}  (self-signed cert — accept browser warning)"
  echo -e "  For a real SSL cert, redeploy with:"
  echo -e "     ${YELLOW}DOMAIN=yourdomain.com SSL_EMAIL=you@email.com sudo bash deploy.sh${NC}"
fi
echo ""
echo -e "${YELLOW}First-time setup — create your admin account:${NC}"
if [[ -n "$DOMAIN" ]]; then
  echo -e "  1. Visit ${CYAN}https://${DOMAIN}/register${NC}"
else
  echo -e "  1. Visit ${CYAN}https://YOUR_SERVER_IP/register${NC}"
fi
echo -e "  2. Enter the setup token. Show it with:"
echo -e "       ${CYAN}grep '^SETUP_TOKEN=' ${INSTALL_DIR}/.env${NC}"
echo -e "  3. Choose a user name and password, then enrol an authenticator app (mandatory)."
echo -e "  (The page works only while no users exist, and only with the token.)"
echo ""
echo -e "${YELLOW}Edit your configuration before running scans:${NC}"
echo -e "  vi ${INSTALL_DIR}/.env"
echo -e "  vi ${INSTALL_DIR}/config/keywords.yaml"
echo -e "  vi ${INSTALL_DIR}/config/seeds.txt"
echo ""
echo -e "${YELLOW}Useful commands (run from ${INSTALL_DIR}):${NC}"
echo -e "  make scan          # run a crawl (foreground)"
echo -e "  make check-tor     # verify Tor connectivity"
echo -e "  make stats         # show scan statistics"
echo -e "  make hits          # show keyword hits"
echo -e "  make logs          # tail all container logs"
echo -e "  make stop          # stop all containers"
echo ""
if [[ "$RUN_USER" != "root" ]]; then
  echo -e "${YELLOW}Log out and back in${NC} (or run 'newgrp docker') so"
  echo -e "   '${RUN_USER}' can use docker without sudo."
  echo ""
fi
