#!/usr/bin/env bash
# nginx entrypoint: certificates, generated virtual hosts, then nginx.
#
# Certificate rule, the reason this script was rewritten: it NEVER writes
# through an existing path. $CERT_DIR/*.pem are links into /etc/letsencrypt
# once a certificate exists; an openssl run that wrote to those names used to
# replace the Let's Encrypt chain and private key at every container start.
# Self-signed files are now created only when no Let's Encrypt certificate
# exists, and only after removing whatever is at the target path.
set -euo pipefail

DOMAIN="${DOMAIN:-}"
SSL_EMAIL="${SSL_EMAIL:-}"
WWW_DOMAIN="${WWW_DOMAIN:-}"
THREATWATCH_DOMAIN="${THREATWATCH_DOMAIN:-}"
CERT_DIR="${CERT_DIR:-/etc/nginx/certs}"
LE_LIVE="${LE_LIVE:-/etc/letsencrypt/live}"
CONF="${NGINX_CONF_OUT:-/etc/nginx/conf.d/darkweb.conf}"
WEBROOT=/var/www/certbot
mkdir -p "$CERT_DIR" "$WEBROOT"

log() { echo "[nginx] $*"; }

# ── Certificates ──────────────────────────────────────────────────────────────

has_le_cert() { [[ -n "$1" && -s "$LE_LIVE/$1/fullchain.pem" && -s "$LE_LIVE/$1/privkey.pem" ]]; }

# ensure_cert PREFIX DOMAIN: make $CERT_DIR/${PREFIX}cert.pem and ${PREFIX}key.pem usable.
ensure_cert() {
  local prefix=$1 domain=$2 cert key cn
  cert="$CERT_DIR/${prefix}cert.pem"
  key="$CERT_DIR/${prefix}key.pem"
  if has_le_cert "$domain"; then
    # ln -sfn replaces the name itself; it never opens the old target.
    ln -sfn "$LE_LIVE/$domain/fullchain.pem" "$cert"
    ln -sfn "$LE_LIVE/$domain/privkey.pem" "$key"
    log "$domain: Let's Encrypt certificate linked."
    return 0
  fi
  # No Let's Encrypt certificate. Keep a self-signed pair that is still good for 30 days.
  if [[ ! -L "$cert" && ! -L "$key" && -s "$cert" && -s "$key" ]] \
    && openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
    return 0
  fi
  cn="${domain:-localhost}"
  # Remove first: if these names are links left by an earlier run, writing to
  # them would overwrite the files they point at.
  rm -f "$cert" "$key"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$key" -out "$cert" \
    -subj "/O=threatintel-platform self-signed/CN=$cn" \
    -addext "subjectAltName=DNS:$cn,IP:127.0.0.1" 2>/dev/null
  log "$cn: self-signed certificate generated."
}

ensure_all_certs() {
  ensure_cert "" "$DOMAIN"
  [[ -n "$WWW_DOMAIN" ]] && ensure_cert "www-" "$WWW_DOMAIN"
  [[ -n "$THREATWATCH_DOMAIN" ]] && ensure_cert "threatwatch-" "$THREATWATCH_DOMAIN"
  return 0
}

# A lineage is damaged when fullchain.pem no longer starts with the certificate
# certbot issued (cert.pem), or the key does not belong to it. That is what the
# old version of this script left behind.
lineage_damaged() {
  local dir="$LE_LIVE/$1" issued served cert_key priv_key
  [[ -s "$dir/cert.pem" && -s "$dir/fullchain.pem" && -s "$dir/privkey.pem" ]] || return 1
  issued="$(openssl x509 -in "$dir/cert.pem" -noout -fingerprint -sha256 2>/dev/null || true)"
  served="$(openssl x509 -in "$dir/fullchain.pem" -noout -fingerprint -sha256 2>/dev/null || true)"
  [[ -n "$issued" && "$issued" == "$served" ]] || return 0
  cert_key="$(openssl x509 -in "$dir/cert.pem" -noout -pubkey 2>/dev/null | openssl sha256)"
  priv_key="$(openssl pkey -in "$dir/privkey.pem" -pubout 2>/dev/null | openssl sha256)"
  [[ "$cert_key" != "$priv_key" ]]
}

# An entrypoint should not order certificates on its own (rate limits, restart
# loops), so a damaged lineage is only reported, with the command that repairs it.
warn_damaged_lineages() {
  local d
  for d in "$DOMAIN" "$WWW_DOMAIN" "$THREATWATCH_DOMAIN"; do
    [[ -n "$d" ]] || continue
    lineage_damaged "$d" || continue
    log "WARNING: the certificate files for $d were overwritten by an older version of this script."
    log "WARNING: repair with: docker compose exec nginx certbot renew --cert-name $d --force-renewal --no-random-sleep-on-renew && docker compose exec nginx nginx -s reload"
  done
  return 0
}

request_missing_certs() {
  local d
  for d in "$DOMAIN" "$WWW_DOMAIN" "$THREATWATCH_DOMAIN"; do
    [[ -n "$d" ]] || continue
    has_le_cert "$d" && continue
    certbot certonly --webroot --webroot-path "$WEBROOT" \
      --email "$SSL_EMAIL" --agree-tos --no-eff-email --non-interactive -d "$d" \
      || log "WARNING: no certificate for $d yet; serving a self-signed one."
  done
}

# ── Virtual hosts ─────────────────────────────────────────────────────────────

TLS_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256"

# Headers for a request passed to the dashboard. X-Forwarded-For and
# X-Forwarded-Host are set here, never passed through from the client.
proxy_headers() {
  cat <<'EOF'
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
EOF
}

write_nginx_config() {
  local listen_tls="443 ssl" listen_plain="80" name="${DOMAIN:-_}"
  : > "$CONF"

  if [[ -n "$DOMAIN" ]]; then
    # Unknown host names end here instead of reaching the dashboard.
    cat >> "$CONF" <<EOF
server {
    listen 80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 444; }
}
server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOF
  else
    # No domain: the dashboard is reached by IP address, so it is the default.
    listen_tls="443 ssl default_server"
    listen_plain="80 default_server"
  fi

  cat >> "$CONF" <<EOF
server {
    listen $listen_plain;
    server_name $name;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen $listen_tls;
    server_name $name;
    ssl_certificate     $CERT_DIR/cert.pem;
    ssl_certificate_key $CERT_DIR/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers $TLS_CIPHERS;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # A variable makes nginx resolve the name per request (see resolver in nginx.conf).
    set \$dashboard http://dashboard:8080;

    location /.well-known/acme-challenge/ { root $WEBROOT; }

    # The container healthcheck endpoint is not for the outside.
    location = /healthz { return 404; }

    # Sign-in steps: 10 requests a minute per visitor, short bursts allowed.
    location ~ ^/(login|register|totp/verify|totp/setup)\$ {
        limit_req zone=login burst=10 nodelay;
        proxy_pass \$dashboard;
$(proxy_headers)
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }
    location / {
        proxy_pass \$dashboard;
$(proxy_headers)
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }
    location /ws {
        proxy_pass \$dashboard;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

  if [[ -n "$WWW_DOMAIN" ]]; then
    cat >> "$CONF" <<EOF
server {
    listen 80;
    server_name ${WWW_DOMAIN} www.${WWW_DOMAIN} osintph.net www.osintph.net;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${WWW_DOMAIN} www.${WWW_DOMAIN} osintph.net www.osintph.net;
    ssl_certificate     $CERT_DIR/www-cert.pem;
    ssl_certificate_key $CERT_DIR/www-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers $TLS_CIPHERS;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    root /var/www/osintph-www;
    index index.html;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { try_files \$uri \$uri/ =404; }
    error_page 404 /404.html;
    location = /index-de.html { return 301 /index.html; }
    location = /index-th.html { return 301 /index.html; }
    location = /contact-th.html { return 301 /contact.html; }
    location ~* \.(svg|png|jpg|jpeg|gif|ico|webp|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    gzip on;
    gzip_types text/css application/javascript image/svg+xml application/json;
    location ~ /\.(?!well-known/) { deny all; }
}
EOF
    log "www virtual host configured for: ${WWW_DOMAIN}"
  fi

  if [[ -n "$THREATWATCH_DOMAIN" ]]; then
    cat >> "$CONF" <<EOF
server {
    listen 80;
    server_name ${THREATWATCH_DOMAIN};
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${THREATWATCH_DOMAIN};
    ssl_certificate     $CERT_DIR/threatwatch-cert.pem;
    ssl_certificate_key $CERT_DIR/threatwatch-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers $TLS_CIPHERS;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # CSP — all API calls go via /api/* proxy, only CDNs and fonts needed externally
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://esm.sh; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https:;" always;
    root /var/www/threatwatch;
    index index.html;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { try_files \$uri \$uri/ /index.html; }
    location ~* \.(svg|png|jpg|jpeg|gif|ico|webp|woff2?)$ {
        expires 1h;
        add_header Cache-Control "public";
    }
    gzip on;
    gzip_types text/css application/javascript image/svg+xml application/json;
    location ~ /\.(?!well-known/) { deny all; }

    # ── Relays for the page's own scripts ─────────────────────────────────────
    # Same-origin only (no CORS header), one fixed upstream path each, one
    # method each, small bodies, and a per-visitor rate limit. Upstream names
    # are variables so nginx starts even when one of them does not resolve.
    set \$relay_nvd services.nvd.nist.gov;
    set \$relay_threatfox threatfox-api.abuse.ch;
    set \$relay_urlhaus urlhaus-api.abuse.ch;

    # NVD / NIST CVE API (GET with a query string)
    location = /api/nvd/ {
        limit_except GET { deny all; }
        limit_req zone=relay burst=20 nodelay;
        proxy_pass https://\$relay_nvd/rest/json/cves/2.0\$is_args\$args;
        proxy_ssl_server_name on;
        proxy_set_header Host services.nvd.nist.gov;
        proxy_set_header Accept "application/json";
        proxy_hide_header Access-Control-Allow-Origin;
    }

    # Abuse.ch ThreatFox (POST, JSON body)
    location = /api/threatfox {
        limit_except POST { deny all; }
        limit_req zone=relay burst=20 nodelay;
        client_max_body_size 4k;
        proxy_pass https://\$relay_threatfox/api/v1/;
        proxy_ssl_server_name on;
        proxy_set_header Host threatfox-api.abuse.ch;
        proxy_set_header Content-Type "application/json";
        proxy_hide_header Access-Control-Allow-Origin;
        proxy_http_version 1.1;
    }

    # Abuse.ch URLhaus (POST, form body)
    location = /api/urlhaus {
        limit_except POST { deny all; }
        limit_req zone=relay burst=20 nodelay;
        client_max_body_size 4k;
        proxy_pass https://\$relay_urlhaus/v1/urls/recent/;
        proxy_ssl_server_name on;
        proxy_set_header Host urlhaus-api.abuse.ch;
        proxy_hide_header Access-Control-Allow-Origin;
        proxy_http_version 1.1;
    }
}
EOF
    log "threatwatch vhost configured for: ${THREATWATCH_DOMAIN}"
  fi
  log "Config written."
}

# ── Main ──────────────────────────────────────────────────────────────────────

if [[ -n "$DOMAIN" && -n "$SSL_EMAIL" ]]; then
  log "Domain mode: $DOMAIN"
  ensure_all_certs

  NEED_CERTBOT=false
  for d in "$DOMAIN" "$WWW_DOMAIN" "$THREATWATCH_DOMAIN"; do
    [[ -n "$d" ]] && ! has_le_cert "$d" && NEED_CERTBOT=true
  done

  if [[ "$NEED_CERTBOT" == "true" ]]; then
    log "Certificates missing — starting a temporary nginx for the ACME challenge..."
    write_nginx_config
    nginx
    sleep 2
    request_missing_certs
    nginx -s stop 2>/dev/null || true
    sleep 2
    ensure_all_certs
  else
    log "All certificates exist — skipping certbot."
  fi

  write_nginx_config
  echo "0 12 * * * certbot renew --quiet && nginx -s reload" | crontab -
  crond -b 2>/dev/null || true
  warn_damaged_lineages
else
  log "No DOMAIN — using self-signed."
  ensure_all_certs
  write_nginx_config
fi

nginx -t
log "Starting Nginx..."
exec nginx -g "daemon off;"
