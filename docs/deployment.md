# Deployment Guide

## Quick Deploy (Recommended)

The fastest way to get running on any fresh Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/osintph/threatintel-platform/main/deploy.sh -o /tmp/deploy.sh && sudo bash /tmp/deploy.sh
```

This installs Docker, clones the repo, configures Tor, generates secrets, and starts all services automatically.

---

## SSL / HTTPS

The dashboard runs behind an Nginx reverse proxy with SSL enabled by default.

### Self-Signed Certificate (default)

If you do not set a domain, a self-signed certificate is generated automatically. The dashboard will be accessible at `https://YOUR_SERVER_IP` but browsers will show a "Not secure" warning. Traffic is still encrypted.

### Trusted SSL with Let's Encrypt (recommended for production)

You need a domain name pointed at your server's public IP.

**Option A — Set domain at deploy time:**
```bash
DOMAIN=scanner.yourdomain.com SSL_EMAIL=you@example.com sudo bash /tmp/deploy.sh
```

**Option B — Set domain after deployment:**
```bash
sudo bash ~/threatintel-platform/scripts/configure-ssl.sh
```

### DNS Setup

1. Add an **A record** at your DNS provider pointing to your server's public IP
2. **Cloudflare users:** Set proxy status to **DNS only** (grey cloud) during cert issuance

---

## Production Setup on Ubuntu 22.04 VPS

### 1. Initial Server Hardening

```bash
apt update && apt upgrade -y
adduser scanner
usermod -aG sudo,docker scanner
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### 2. Deploy

```bash
su - scanner
curl -fsSL https://raw.githubusercontent.com/osintph/threatintel-platform/main/deploy.sh -o /tmp/deploy.sh && \
  DOMAIN=scanner.yourdomain.com SSL_EMAIL=you@example.com sudo bash /tmp/deploy.sh
```

### 3. Configure API keys

```bash
nano ~/threatintel-platform/.env
```

---

## Environment Variables Reference

All configuration lives in `.env`. **Never commit this file.**

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | (empty) | Public domain for Let's Encrypt SSL |
| `SSL_EMAIL` | (empty) | Email for Let's Encrypt registration |
| `DASHBOARD_SECRET_KEY` | (auto-generated) | Flask session secret |
| `TOR_CONTROL_PASSWORD` | (auto-generated) | Tor control port password |
| `DATABASE_URL` | SQLite | SQLite or PostgreSQL connection string |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### Alerting

| Variable | Description |
|----------|-------------|
| `ALERT_WEBHOOK_URL` | Slack/Discord webhook for keyword hit alerts |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for email alerts |
| `SMTP_USER` / `SMTP_PASSWORD` | SMTP credentials |
| `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | Alert email addresses |

### Daily Digest (Mailgun)

| Variable | Description |
|----------|-------------|
| `MAILGUN_API_KEY` | Mailgun API key — required for digest delivery |
| `MAILGUN_DOMAIN` | Your Mailgun sending domain |
| `MAILGUN_FROM` | Sender display name and address |

### Threat Intelligence Feeds

| Variable | Description |
|----------|-------------|
| `OTX_API_KEY` | AlienVault OTX API key — free at otx.alienvault.com |

### IP Investigation

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB — free tier: 1,000 checks/day |
| `VIRUSTOTAL_API_KEY` | VirusTotal — free tier: 4 req/min |

### Telegram Scraper

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGRAM_API_ID` | (empty) | From my.telegram.org/apps |
| `TELEGRAM_API_HASH` | (empty) | From my.telegram.org/apps |
| `TELEGRAM_CHANNELS` | (empty) | Comma-separated channel usernames (no @) |
| `TELEGRAM_SESSION_PATH` | `/app/data/telegram.session` | Session file path |
| `TELEGRAM_LIMIT_PER_CHANNEL` | `200` | Max messages per channel |

### OAuth (optional)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth credentials |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth credentials |

---

## Daily Digest Setup

The digest sends curated threat intelligence every morning at 08:00 PHT.

**1. Configure Mailgun** (free tier: 1,000 emails/month at mailgun.com)

**2. Configure OTX** — free API key at otx.alienvault.com

**3. Add subscribers** via dashboard (Settings → Digest → Subscribers)

**4. Schedule with cron:**
```bash
0 0 * * * cd ~/threatintel-platform && docker compose exec -T dashboard \
  python -c "from darkweb_scanner.digest import send_digest; from darkweb_scanner.storage import Storage; send_digest(Storage())"
```

---

## DNS Reconnaissance

No additional setup required. Uses free public sources (crt.sh, HackerTarget, ip-api.com). The `dnspython` package is included in default dependencies.

---

## Updating

```bash
cd ~/threatintel-platform
git pull
docker compose build --no-cache
docker compose up -d
```

---

## Troubleshooting

**Tor not connecting:** `docker compose logs tor | grep Bootstrapped`

**Dashboard not loading:** `docker compose logs dashboard`

**Digest not sending:** Check `MAILGUN_API_KEY` is set in `.env`

**Full restart:** `docker compose down && docker compose up -d`

---

## Web Check Integration

Web Check provides OSINT analysis for any domain — DNS, SSL, headers, ports, tech stack, and more. It runs as a separate service at `webcheck.osintph.info` and is accessible via the **🔍 Web Check** button in the dashboard nav bar.

### Fresh Deploy Steps

Web Check lives outside the main repo at `/root/web-check` and must be set up manually after deploying the main platform:

**1. Install Node.js 20+ and yarn**
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install nodejs -y
npm install -g yarn
```

**2. Clone and build web-check**
```bash
cd /root
git clone https://github.com/lissy93/web-check.git
cd web-check
BASE_URL=/ yarn install && yarn build
```

**3. Add DNS record**

Add an A record for `webcheck.YOURDOMAIN` pointing to your server IP. Set to DNS only (grey cloud) in Cloudflare during cert issuance.

**4. Start the container**
```bash
cd /root/threatintel-platform
docker compose up -d webcheck
```

**5. Issue SSL certificate**
```bash
docker compose exec nginx certbot certonly --webroot --webroot-path /var/www/certbot \
  --email YOUR_SSL_EMAIL --agree-tos --no-eff-email \
  -d webcheck.YOURDOMAIN
```

**6. Link cert and reload nginx**
```bash
docker compose exec nginx sh -c "
  ln -sf /etc/letsencrypt/live/webcheck.YOURDOMAIN/fullchain.pem /etc/nginx/certs/webcheck-cert.pem &&
  ln -sf /etc/letsencrypt/live/webcheck.YOURDOMAIN/privkey.pem /etc/nginx/certs/webcheck-key.pem
"
docker compose up -d --build nginx
```

### SSL Renewal

The webcheck.osintph.info cert renews automatically via the certbot cron job inside the nginx container as long as the container stays running.

### Troubleshooting

**Web Check not loading:** `docker compose logs webcheck`

> **Note:** After deploying your own instance, update the Web Check button URL in `src/darkweb_scanner/dashboard/templates/index.html` — search for `webcheck.osintph.info` and replace with your own domain e.g. `webcheck.yourdomain.com`.

**502 Bad Gateway on webcheck subdomain:** Container may still be starting — wait 30 seconds and retry.

---

## PostgreSQL

The platform uses PostgreSQL 16 by default. It runs as a Docker service alongside the dashboard and is configured automatically by `deploy.sh`.

### Fresh deploy

No extra steps needed — `deploy.sh` generates a secure `POSTGRES_PASSWORD`, updates `DATABASE_URL`, and starts the postgres container automatically before the dashboard.

### Environment variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | Auto-generated by deploy.sh — do not change after first run |
| `DATABASE_URL` | Set automatically to `postgresql://scanner:PASSWORD@postgres:5432/darkweb_scanner` |

### Backups
```bash
# Dump the database
docker compose exec postgres pg_dump -U scanner darkweb_scanner > backup_$(date +%Y%m%d).sql

# Restore
docker compose exec -T postgres psql -U scanner darkweb_scanner < backup_20260223.sql
```

### Migrating from SQLite

If you have an existing SQLite deployment and want to migrate:
```bash
# 1. Back up SQLite first
docker compose exec dashboard sh -c 'cp /app/data/results.db /app/data/results.db.bak.$(date +%Y%m%d)'

# 2. Start postgres
docker compose up -d postgres

# 3. Install psycopg2 in dashboard container
docker compose exec dashboard pip install psycopg2-binary -q

# 4. Run migration script (available in scripts/migrate_sqlite_to_postgres.py)
PG_PASS=$(grep POSTGRES_PASSWORD .env | cut -d= -f2)
docker compose cp scripts/migrate_sqlite_to_postgres.py dashboard:/tmp/
docker compose exec -e POSTGRES_PASSWORD=$PG_PASS dashboard python3 /tmp/migrate_sqlite_to_postgres.py

# 5. Update DATABASE_URL in .env and restart
sed -i "s|DATABASE_URL=sqlite:.*|DATABASE_URL=postgresql://scanner:${PG_PASS}@postgres:5432/darkweb_scanner|" .env
docker compose restart dashboard
```

### Troubleshooting

**Dashboard fails to start:** `docker compose logs postgres` — check postgres is healthy before dashboard starts

**Password authentication failed:** Ensure `POSTGRES_PASSWORD` in `.env` matches what postgres was initialized with. If changed after first run, you must recreate the volume: `docker compose down -v && docker compose up -d`
