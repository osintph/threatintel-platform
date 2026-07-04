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
SECRET_KEY="$(openssl rand -hex 32)"
sed -i "s/^DASHBOARD_SECRET_KEY=.*/DASHBOARD_SECRET_KEY=${SECRET_KEY}/" .env
PG_PASS="$(openssl rand -hex 24)"
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${PG_PASS}/" .env
sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://scanner:${PG_PASS}@postgres:5432/darkweb_scanner|" .env

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
if [[ -z "$_SECRET_VAL" || "$_SECRET_VAL" == "changeme" || "$_SECRET_VAL" == "change-me-in-production" || "$_SECRET_VAL" == "change-me-to-a-long-random-string" ]]; then
  error "DASHBOARD_SECRET_KEY is empty or set to a placeholder. Edit .env and set a real secret before deploying."
fi
success "Secret key validated."

# ── Generate Tor control password ─────────────────────────────────────────────
info "Building Tor image to generate control password hash..."
docker compose build tor

TOR_PLAIN_PASS="$(openssl rand -hex 16)"
TOR_HASH="$(docker run --rm darkweb-scanner-tor tor --hash-password "${TOR_PLAIN_PASS}" 2>/dev/null | grep '^16:' | tail -1)"

if [[ -n "$TOR_HASH" ]]; then
  sed -i "s|^# HashedControlPassword is injected.*|HashedControlPassword ${TOR_HASH}|" docker/tor/torrc
  grep -q "^HashedControlPassword" docker/tor/torrc || echo "HashedControlPassword ${TOR_HASH}" >> docker/tor/torrc
  sed -i "s/^TOR_CONTROL_PASSWORD=.*/TOR_CONTROL_PASSWORD=${TOR_PLAIN_PASS}/" .env
  success "Tor control password configured."
else
  warn "Could not generate Tor hash — circuit rotation may not work."
  sed -i '/^# HashedControlPassword is injected/d' docker/tor/torrc
fi

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
info "Waiting for HTTPS to respond..."
TIMEOUT=90; ELAPSED=0
until curl -sfk "https://localhost" -o /dev/null 2>/dev/null; do
  [[ $ELAPSED -ge $TIMEOUT ]] && { warn "HTTPS not responding after ${TIMEOUT}s. Check: docker compose logs nginx"; break; }
  sleep 3; ELAPSED=$((ELAPSED + 3))
done
curl -sfk "https://localhost" -o /dev/null 2>/dev/null && success "HTTPS is live!"

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
_HTTP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost" 2>/dev/null || true)
if [[ "$_HTTP_STATUS" == "200" || "$_HTTP_STATUS" == "302" ]]; then
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
  echo -e "  Visit ${CYAN}https://${DOMAIN}/register${NC} to create your admin account"
else
  echo -e "  Visit ${CYAN}https://YOUR_SERVER_IP/register${NC} to create your admin account"
fi
echo -e "  (Registration is only open when no users exist — it closes after the first account is created)"
echo ""
echo -e "${YELLOW}Edit your configuration before running scans:${NC}"
echo -e "  nano ${INSTALL_DIR}/.env"
echo -e "  nano ${INSTALL_DIR}/config/keywords.yaml"
echo -e "  nano ${INSTALL_DIR}/config/seeds.txt"
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
