#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-}"
SSL_EMAIL="${SSL_EMAIL:-}"
WWW_DOMAIN="${WWW_DOMAIN:-}"
THREATWATCH_DOMAIN="${THREATWATCH_DOMAIN:-}"   # NEW: threatwatch.osintph.info
CERT_DIR="/etc/nginx/certs"
mkdir -p "$CERT_DIR"

generate_self_signed() {
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -subj "/C=US/ST=State/L=City/O=DarkWebScanner/CN=${DOMAIN:-localhost}" \
    -addext "subjectAltName=DNS:${DOMAIN:-localhost},IP:127.0.0.1" 2>/dev/null
  echo "[nginx] Self-signed certificate generated."
}

write_nginx_config() {
  cat > /etc/nginx/conf.d/darkweb.conf <<EOF
server {
    listen 80;
    server_name ${DOMAIN:-_};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${DOMAIN:-_};
    ssl_certificate     $CERT_DIR/cert.pem;
    ssl_certificate_key $CERT_DIR/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    location / {
        proxy_pass http://dashboard:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }
    location /ws {
        proxy_pass http://dashboard:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

  if [[ -n "$WWW_DOMAIN" ]]; then
    cat >> /etc/nginx/conf.d/darkweb.conf <<EOF
server {
    listen 80;
    server_name ${WWW_DOMAIN} www.${WWW_DOMAIN} osintph.net www.osintph.net;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${WWW_DOMAIN} www.${WWW_DOMAIN} osintph.net www.osintph.net;
    ssl_certificate     $CERT_DIR/www-cert.pem;
    ssl_certificate_key $CERT_DIR/www-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    root /var/www/osintph-www;
    index index.html;
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
    location ~ /\. { deny all; }
    location /api/send-brief {
        proxy_pass http://dashboard:8080/api/send-brief;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
    }
}
EOF
    echo "[nginx] www virtual host configured for: ${WWW_DOMAIN}"
  fi

  # ── THREATWATCH vhost ────────────────────────────────────────────────────────
  if [[ -n "$THREATWATCH_DOMAIN" && -f "$CERT_DIR/threatwatch-cert.pem" ]]; then
    cat >> /etc/nginx/conf.d/darkweb.conf <<EOF
server {
    listen 80;
    server_name ${THREATWATCH_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${THREATWATCH_DOMAIN};
    ssl_certificate     $CERT_DIR/threatwatch-cert.pem;
    ssl_certificate_key $CERT_DIR/threatwatch-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
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
    location / { try_files \$uri \$uri/ /index.html; }
    location ~* \.(svg|png|jpg|jpeg|gif|ico|webp|woff2?)$ {
        expires 1h;
        add_header Cache-Control "public";
    }
    gzip on;
    gzip_types text/css application/javascript image/svg+xml application/json;
    location ~ /\. { deny all; }
    location /api/send-brief {
        proxy_pass http://dashboard:8080/api/send-brief;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
    }

    # ── API PROXY — avoids browser CORS restrictions ──────────────────────────
    # NVD / NIST CVE API
    location /api/nvd/ {
        proxy_pass https://services.nvd.nist.gov/rest/json/cves/2.0;
        proxy_ssl_server_name on;
        proxy_set_header Host services.nvd.nist.gov;
        proxy_set_header Accept "application/json";
        proxy_hide_header Access-Control-Allow-Origin;
        add_header Access-Control-Allow-Origin "*" always;
        proxy_cache_valid 200 5m;
    }

    # Abuse.ch ThreatFox
    location /api/threatfox {
        proxy_pass https://threatfox-api.abuse.ch/api/v1/;
        proxy_ssl_server_name on;
        proxy_set_header Host threatfox-api.abuse.ch;
        proxy_set_header Content-Type "application/json";
        proxy_hide_header Access-Control-Allow-Origin;
        add_header Access-Control-Allow-Origin "*" always;
        proxy_pass_request_body on;
        proxy_http_version 1.1;
    }

    # Abuse.ch URLhaus
    location /api/urlhaus {
        proxy_pass https://urlhaus-api.abuse.ch/v1/urls/recent/;
        proxy_ssl_server_name on;
        proxy_set_header Host urlhaus-api.abuse.ch;
        proxy_hide_header Access-Control-Allow-Origin;
        add_header Access-Control-Allow-Origin "*" always;
        proxy_pass_request_body on;
        proxy_http_version 1.1;
    }
}
EOF
    echo "[nginx] threatwatch vhost configured for: ${THREATWATCH_DOMAIN}"
  else
    echo "[nginx] No threatwatch cert found or THREATWATCH_DOMAIN not set — skipping threatwatch vhost."
  fi
  # ── end THREATWATCH ──────────────────────────────────────────────────────────

  if [[ -f "$CERT_DIR/webcheck-cert.pem" ]]; then
    cat >> /etc/nginx/conf.d/darkweb.conf <<WCEOF
server {
    listen 80;
    server_name webcheck.${DOMAIN#*.};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name webcheck.${DOMAIN#*.};
    ssl_certificate     $CERT_DIR/webcheck-cert.pem;
    ssl_certificate_key $CERT_DIR/webcheck-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    location / {
        proxy_pass http://webcheck:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
    }
}
WCEOF
    echo "[nginx] webcheck vhost configured."
  else
    echo "[nginx] No webcheck cert found — skipping webcheck vhost."
  fi
  echo "[nginx] Config written."
}

if [[ -n "$DOMAIN" && -n "$SSL_EMAIL" ]]; then
  echo "[nginx] Domain mode: $DOMAIN"

  SCANNER_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  NEED_CERTBOT=false
  [[ ! -f "$SCANNER_CERT" ]] && NEED_CERTBOT=true
  [[ -n "$WWW_DOMAIN" && ! -f "/etc/letsencrypt/live/${WWW_DOMAIN}/fullchain.pem" ]] && NEED_CERTBOT=true
  # Check threatwatch cert too
  [[ -n "$THREATWATCH_DOMAIN" && ! -f "/etc/letsencrypt/live/${THREATWATCH_DOMAIN}/fullchain.pem" ]] && NEED_CERTBOT=true

  if [[ "$NEED_CERTBOT" == "true" ]]; then
    echo "[nginx] Certs missing — starting temp nginx for ACME challenge..."
    generate_self_signed
    if [[ -n "$WWW_DOMAIN" ]]; then
      openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$CERT_DIR/www-key.pem" -out "$CERT_DIR/www-cert.pem" \
        -subj "/CN=${WWW_DOMAIN}" 2>/dev/null
    fi
    if [[ -n "$THREATWATCH_DOMAIN" ]]; then
      openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$CERT_DIR/threatwatch-key.pem" -out "$CERT_DIR/threatwatch-cert.pem" \
        -subj "/CN=${THREATWATCH_DOMAIN}" 2>/dev/null
    fi
    write_nginx_config
    nginx
    sleep 2
    [[ ! -f "$SCANNER_CERT" ]] && \
      certbot certonly --webroot --webroot-path /var/www/certbot \
        --email "$SSL_EMAIL" --agree-tos --no-eff-email -d "$DOMAIN" || true
    [[ -n "$WWW_DOMAIN" && ! -f "/etc/letsencrypt/live/${WWW_DOMAIN}/fullchain.pem" ]] && \
      certbot certonly --webroot --webroot-path /var/www/certbot \
        --email "$SSL_EMAIL" --agree-tos --no-eff-email -d "$WWW_DOMAIN" || true
    # Issue cert for threatwatch subdomain
    [[ -n "$THREATWATCH_DOMAIN" && ! -f "/etc/letsencrypt/live/${THREATWATCH_DOMAIN}/fullchain.pem" ]] && \
      certbot certonly --webroot --webroot-path /var/www/certbot \
        --email "$SSL_EMAIL" --agree-tos --no-eff-email -d "$THREATWATCH_DOMAIN" || true
    nginx -s stop 2>/dev/null || true
    sleep 2
  else
    echo "[nginx] All certs exist — skipping certbot."
    generate_self_signed
    if [[ -n "$WWW_DOMAIN" ]]; then
      openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$CERT_DIR/www-key.pem" -out "$CERT_DIR/www-cert.pem" \
        -subj "/CN=${WWW_DOMAIN}" 2>/dev/null
    fi
    if [[ -n "$THREATWATCH_DOMAIN" ]]; then
      openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$CERT_DIR/threatwatch-key.pem" -out "$CERT_DIR/threatwatch-cert.pem" \
        -subj "/CN=${THREATWATCH_DOMAIN}" 2>/dev/null
    fi
  fi

  [[ -f "$SCANNER_CERT" ]] && \
    ln -sf "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_DIR/cert.pem" && \
    ln -sf "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"   "$CERT_DIR/key.pem" && \
    echo "[nginx] Scanner cert linked."

  if [[ -n "$WWW_DOMAIN" && -f "/etc/letsencrypt/live/${WWW_DOMAIN}/fullchain.pem" ]]; then
    ln -sf "/etc/letsencrypt/live/${WWW_DOMAIN}/fullchain.pem" "$CERT_DIR/www-cert.pem"
    ln -sf "/etc/letsencrypt/live/${WWW_DOMAIN}/privkey.pem"   "$CERT_DIR/www-key.pem"
    echo "[nginx] www cert linked."
  fi

  # Link threatwatch cert if obtained
  if [[ -n "$THREATWATCH_DOMAIN" && -f "/etc/letsencrypt/live/${THREATWATCH_DOMAIN}/fullchain.pem" ]]; then
    ln -sf "/etc/letsencrypt/live/${THREATWATCH_DOMAIN}/fullchain.pem" "$CERT_DIR/threatwatch-cert.pem"
    ln -sf "/etc/letsencrypt/live/${THREATWATCH_DOMAIN}/privkey.pem"   "$CERT_DIR/threatwatch-key.pem"
    echo "[nginx] threatwatch cert linked."
  fi

  write_nginx_config
  echo "0 12 * * * certbot renew --quiet && nginx -s reload" | crontab -
  crond -b 2>/dev/null || true

else
  echo "[nginx] No DOMAIN — using self-signed."
  generate_self_signed
  if [[ -n "$WWW_DOMAIN" ]]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$CERT_DIR/www-key.pem" -out "$CERT_DIR/www-cert.pem" \
      -subj "/CN=${WWW_DOMAIN:-localhost}" 2>/dev/null
  fi
  if [[ -n "$THREATWATCH_DOMAIN" ]]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$CERT_DIR/threatwatch-key.pem" -out "$CERT_DIR/threatwatch-cert.pem" \
      -subj "/CN=${THREATWATCH_DOMAIN}" 2>/dev/null
  fi
  write_nginx_config
fi

echo "[nginx] Starting Nginx..."
exec nginx -g "daemon off;"
