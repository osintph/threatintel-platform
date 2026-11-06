#!/usr/bin/env bash
# =============================================================================
#  configure-ssl.sh — Set up SSL/domain without redeploying
#  Run on your server: sudo bash ~/darkweb-scanner/scripts/configure-ssl.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Please run as root: sudo bash scripts/configure-ssl.sh"

# Find the repo — script may be run from anywhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$REPO_DIR/.env"

[[ -f "$ENV_FILE" ]] || error "Could not find .env at $ENV_FILE — are you running from the right directory?"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     darkweb-scanner — SSL Configuration  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Show current config
CURRENT_DOMAIN=$(grep "^DOMAIN=" "$ENV_FILE" | cut -d= -f2 || echo "")
CURRENT_EMAIL=$(grep "^SSL_EMAIL=" "$ENV_FILE" | cut -d= -f2 || echo "")

if [[ -n "$CURRENT_DOMAIN" ]]; then
  info "Current domain: $CURRENT_DOMAIN"
else
  info "No domain currently configured (using self-signed cert)"
fi

echo ""

# Prompt for domain
read -rp "Enter your domain (e.g. scanner.yourdomain.com) or press Enter to use self-signed: " DOMAIN
DOMAIN="${DOMAIN// /}"  # strip spaces

if [[ -z "$DOMAIN" ]]; then
  info "No domain entered — will use self-signed certificate."
  # Clear domain/email from .env
  sed -i "s/^DOMAIN=.*/DOMAIN=/" "$ENV_FILE"
  sed -i "s/^SSL_EMAIL=.*/SSL_EMAIL=/" "$ENV_FILE"
else
  # Validate looks like a domain
  if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
    error "Invalid domain format: $DOMAIN"
  fi

  # Prompt for email
  read -rp "Enter email for Let's Encrypt registration: " SSL_EMAIL
  SSL_EMAIL="${SSL_EMAIL// /}"
  [[ -z "$SSL_EMAIL" ]] && error "Email is required for Let's Encrypt."

  # Check DNS resolves to this server
  info "Checking DNS for $DOMAIN..."
  SERVER_IP=$(curl -sf https://api.ipify.org 2>/dev/null || curl -sf https://ifconfig.me 2>/dev/null || echo "")
  DOMAIN_IP=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1 || echo "")

  if [[ -n "$SERVER_IP" && -n "$DOMAIN_IP" ]]; then
    if [[ "$SERVER_IP" == "$DOMAIN_IP" ]]; then
      success "DNS check passed: $DOMAIN -> $DOMAIN_IP"
    else
      warn "DNS mismatch: $DOMAIN resolves to $DOMAIN_IP but this server is $SERVER_IP"
      warn "Let's Encrypt will fail if DNS is not pointing to this server."
      read -rp "Continue anyway? [y/N] " CONFIRM
      [[ "${CONFIRM,,}" == "y" ]] || { info "Aborted."; exit 0; }
    fi
  else
    warn "Could not verify DNS automatically — continuing."
  fi

  # Update .env — add lines if they don't exist yet
  if grep -q "^DOMAIN=" "$ENV_FILE"; then
    sed -i "s/^DOMAIN=.*/DOMAIN=${DOMAIN}/" "$ENV_FILE"
  else
    echo "DOMAIN=${DOMAIN}" >> "$ENV_FILE"
  fi

  if grep -q "^SSL_EMAIL=" "$ENV_FILE"; then
    sed -i "s/^SSL_EMAIL=.*/SSL_EMAIL=${SSL_EMAIL}/" "$ENV_FILE"
  else
    echo "SSL_EMAIL=${SSL_EMAIL}" >> "$ENV_FILE"
  fi

  success "Domain and email saved to .env (not committed to git)"
fi

# Restart nginx container to pick up new config and get cert
info "Restarting nginx to apply SSL configuration..."
cd "$REPO_DIR"
# "up -d" recreates the container, so the new DOMAIN and SSL_EMAIL from .env are read.
docker compose up -d nginx

# Wait for nginx to come up
sleep 5

# Tail logs briefly so user can see what's happening
info "Nginx startup log:"
docker compose logs nginx --since 15s | grep -v "^$" | head -30

echo ""
if [[ -n "$DOMAIN" ]]; then
  success "Done! Your dashboard should be available at: https://${DOMAIN}"
  info "Note: It may take 1-2 minutes for the Let's Encrypt certificate to be issued."
  info "If it fails, check: docker compose logs nginx"
else
  success "Done! Dashboard available at https://YOUR_SERVER_IP (self-signed cert)"
fi
echo ""
