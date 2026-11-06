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

### How certificates are handled

- Let's Encrypt files live in the `letsencrypt` volume. A container start only links to them; it never writes to them. A self-signed pair is generated only for a name that has no certificate yet, and is kept until it has less than 30 days left.
- Renewal runs daily inside the nginx container (`certbot renew`, then `nginx -s reload`).
- Behind Cloudflare, set the zone's SSL mode to **Full (strict)** once the origin serves a Let's Encrypt chain. Check from the server:

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername scanner.yourdomain.com 2>/dev/null \
  | openssl x509 -noout -issuer -enddate
```

- Versions before 1.1.1 replaced the certificate chain and private key with a self-signed pair at every container start. If the nginx log says `the certificate files for <name> were overwritten`, repair that name once (see the [runbook](runbook.md#certificates)):

```bash
docker compose exec nginx certbot renew --cert-name scanner.yourdomain.com --force-renewal
docker compose exec nginx nginx -s reload
```

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
vi ~/threatintel-platform/.env
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
sudo ./upgrade.sh            # tip of main
sudo ./upgrade.sh v1.1.1     # or a release tag
```

The script takes a verified database dump, checks out the release, rebuilds and recreates the containers, and checks at the end that nginx answers 200 for each site. See the [runbook](runbook.md#upgrading) for what each step does and how to roll back.

To apply a change you made in `.env`, recreate the service; `docker compose restart` does not re-read `.env`:

```bash
docker compose up -d dashboard
```

---

## Troubleshooting

**Tor not connecting:** `docker compose logs tor | grep Bootstrapped`

**Dashboard not loading:** `docker compose logs dashboard`

**Digest not sending:** Check `MAILGUN_API_KEY` is set in `.env`

**Full restart:** `docker compose down && docker compose up -d`

**502 from nginx right after a rebuild:** the dashboard is still starting; nginx finds it again by itself within about 10 seconds. No nginx restart is needed.

**429 on the sign-in page:** more than 10 sign-in requests a minute from one address; wait a minute.

---

## PostgreSQL

The platform uses PostgreSQL 16 by default. It runs as a Docker service alongside the dashboard and is configured automatically by `deploy.sh`.

### Fresh deploy

No extra steps needed — `deploy.sh` generates a secure `POSTGRES_PASSWORD`, updates `DATABASE_URL`, and starts the postgres container automatically before the dashboard.

### Environment variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | Auto-generated by deploy.sh — do not change after first run |
| `DATABASE_URL` | Set automatically to `postgresql+psycopg2://scanner:PASSWORD@postgres:5432/darkweb_scanner`. Keep the `+psycopg2` driver name: SQLAlchemy 2.1 maps a bare `postgresql://` URL to a driver the image does not ship. The app and `upgrade.sh` both correct a bare URL |

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
sed -i "s|DATABASE_URL=sqlite:.*|DATABASE_URL=postgresql+psycopg2://scanner:${PG_PASS}@postgres:5432/darkweb_scanner|" .env
docker compose up -d dashboard
```

### Troubleshooting

**Dashboard fails to start:** `docker compose logs postgres` — check postgres is healthy before dashboard starts

**Password authentication failed:** Ensure `POSTGRES_PASSWORD` in `.env` matches what postgres was initialized with. If changed after first run, you must recreate the volume: `docker compose down -v && docker compose up -d`
