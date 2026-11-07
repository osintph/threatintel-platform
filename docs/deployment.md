# Deployment Guide

## Quick Deploy (Recommended)

The fastest way to get running on any fresh Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/osintph/threatintel-platform/main/deploy.sh -o /tmp/deploy.sh && sudo bash /tmp/deploy.sh
```

This installs Docker, clones the repo, generates secrets, and starts all services automatically.

Running it again on the same server is safe: a secret that `.env` already holds (`DASHBOARD_SECRET_KEY`, `POSTGRES_PASSWORD`, `SETUP_TOKEN`) is kept, and only a value that is still empty or a placeholder is generated. If the script stops, it prints the line it stopped at. To move an existing install to a newer release, use `upgrade.sh` (see [Updating](#updating)).

### Create the first administrator

1. Open `https://YOUR_DOMAIN/register` (or `https://YOUR_SERVER_IP/register`).
2. Enter the setup token that `deploy.sh` wrote to `.env`. Read it on the server: `grep '^SETUP_TOKEN=' ~/threatintel-platform/.env`.
3. Choose a user name and a password (at least 12 characters, with an uppercase letter, a lowercase letter, a number and a symbol).
4. Enrol an authenticator app. Two-factor sign-in is mandatory for every account.

The page works only while there are no users, and only with the token. Further users are created by an administrator in the dashboard. See the [runbook](runbook.md#accounts-and-sign-in) for lockouts and a lost authenticator.

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
docker compose exec nginx certbot renew --cert-name scanner.yourdomain.com --force-renewal --no-random-sleep-on-renew
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
| `DASHBOARD_SECRET_KEY` | (auto-generated) | Session secret, at least 32 characters; the dashboard does not start without it. Changing it signs everyone out |
| `SETUP_TOKEN` | (auto-generated) | Needed once, to create the first administrator at `/register`; at least 24 characters |
| `DATABASE_URL` | (auto-generated) | PostgreSQL connection string. Required: the dashboard and the command-line tools do not start without it |
| `ROTATE_CIRCUIT_EVERY` | `50` | Pages crawled before the crawler moves to a new Tor circuit |
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
| `TELEGRAM_PHONE` | (empty) | Phone number of the Telegram account, for Channel Monitor |
| `CHANNEL_MONITOR_RETENTION_DAYS` | `90` | Channel Monitor archives are deleted after this many days |

Sign-in is by local account with a password and an authenticator app. There is no OAuth sign-in (removed in 1.2.0).

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

No additional setup required. Uses free public sources (crt.sh, HackerTarget, ipwho.is for geolocation over HTTPS). The `dnspython` package is included in default dependencies.

---

## Updating

```bash
cd ~/threatintel-platform
sudo ./upgrade.sh            # tip of main
sudo ./upgrade.sh v1.3.0     # or a release tag
```

The script takes a verified database dump, checks out the release, rebuilds and recreates the containers, and checks at the end that nginx answers 200 for each site. The dashboard brings the database schema up to date when it starts. See the [runbook](runbook.md#upgrading) for what each step does and how to roll back.

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

**"Too many failed attempts":** the account or the address is locked for 15 minutes after repeated failures. To lift it sooner: `docker compose exec dashboard python -m darkweb_scanner.main user-unlock NAME` (see the [runbook](runbook.md#accounts-and-sign-in)).

**Lost authenticator:** another administrator resets it on the **Users** tab ("Reset 2FA"), or on the server: `docker compose exec dashboard python -m darkweb_scanner.main user-reset-mfa NAME`.

**Dashboard restarts in a loop after an upgrade:** `docker compose logs dashboard` names the cause. From 1.2.0 it needs `DATABASE_URL` and a `DASHBOARD_SECRET_KEY` of at least 32 characters.

---

## PostgreSQL

The platform uses PostgreSQL 16 by default. It runs as a Docker service alongside the dashboard and is configured automatically by `deploy.sh`.

### Fresh deploy

No extra steps needed — `deploy.sh` generates a secure `POSTGRES_PASSWORD`, updates `DATABASE_URL`, and starts the postgres container automatically before the dashboard.

### Environment variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | Generated by `deploy.sh` on the first run and kept on later runs. To change it, see "Password authentication failed" below |
| `DATABASE_URL` | Set automatically to `postgresql+psycopg2://scanner:PASSWORD@postgres:5432/darkweb_scanner`. Keep the `+psycopg2` driver name: SQLAlchemy 2.1 maps a bare `postgresql://` URL to a driver the image does not ship. The app and `upgrade.sh` both correct a bare URL |

### Backups

```bash
# Dump the database (custom format, over the socket inside the container: no password needed)
docker compose exec -T postgres pg_dump -U scanner -Fc darkweb_scanner > backup_$(date +%Y%m%d).dump

# Check that the dump restores, in a throwaway container; the live database is not touched
scripts/restore-test.sh backup_20261107.dump

# Restore it into the live database
docker compose stop dashboard
docker compose exec -T postgres pg_restore -U scanner -d darkweb_scanner --clean --if-exists < backup_20261107.dump
docker compose up -d dashboard
```

The database is one part of a backup. The [runbook](runbook.md#backups-and-restore-test) lists the rest (`.env`, `config/`, the data and certificate volumes, files you added) and describes the restore test.

### Migrating from SQLite

Only for an install that still keeps its data in SQLite (`DATABASE_URL=sqlite:...`). After the migration, and once the PostgreSQL install has been checked, delete `results.db` and its copies from the data volume: they hold password hashes and authenticator secrets.

To migrate:
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

**Password authentication failed:** the password in `.env` is not the one the database was created with (the `pg_data` volume keeps the first one). Do not delete the volume; set the database to the password that `.env` holds. `psql` asks for it; type the value of `POSTGRES_PASSWORD` from `.env`:

```bash
docker compose exec postgres psql -U scanner -d darkweb_scanner -c '\password scanner'
docker compose up -d dashboard
```

Then check that `DATABASE_URL` in `.env` carries the same password. `\password` sends the new password hashed, so it appears in no log and no process list. `docker compose down -v` is never the remedy: it deletes the database, the Telegram sessions, the Channel Monitor archives and the certificates.
