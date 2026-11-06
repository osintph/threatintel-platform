# Operations runbook

Day-to-day operations for a production install. Commands are run as root from the install directory unless stated otherwise.

- [Upgrading](#upgrading)
- [Accounts and sign-in](#accounts-and-sign-in)
- [Dependencies and base images](#dependencies-and-base-images)
- [Health and logs](#health-and-logs)
- [Tor](#tor)
- [Channel Monitor](#channel-monitor)
- [nginx](#nginx)
- [Certificates](#certificates)
- [Cloudflare origin lock](#cloudflare-origin-lock)

---

## Upgrading

```bash
cd /path/to/install
sudo ./upgrade.sh            # tip of main
sudo ./upgrade.sh v1.2.0     # a release tag, branch or commit
```

What it does, in order:

1. **Pre-flight.** Stops if a git operation is unfinished (cherry-pick, merge, rebase) or tracked files have local changes. Untracked files, `.env`, `config/` and a `docker-compose.override.yml` are left alone.
2. **Database dump** to `backups/pre-upgrade-<UTC time>.dump` (`pg_dump -Fc`), read back with `pg_restore --list`. The five newest are kept. `SKIP_BACKUP=1` skips it.
3. **Checkout.** A branch is fast-forwarded; a tag or commit is checked out detached. The commit you came from is written to `.upgrade-previous-commit`. The `www` submodule is not moved unless you pass `UPDATE_WWW=1`, because the website is deployed on its own schedule.
4. **`.env` fixes and checks.** `DATABASE_URL` gets the `postgresql+psycopg2://` driver name; the file is set to mode 600. Settings that no release reads any more (`TOR_CONTROL_PORT`, `TOR_CONTROL_PASSWORD`, `FLASK_DEBUG`, `DASHBOARD_PORT` and the OAuth client settings) are removed, after the old file is copied to `backups/env-before-<UTC time>` (mode 600); their names are printed, values never. The script stops here, before anything is rebuilt, if `DASHBOARD_SECRET_KEY` is shorter than 32 characters. Settings that `.env.example` has and your `.env` lacks are listed by name.
5. **Origin lock.** Updated in place when it is installed (see below).
6. **Build and start.** The image each service runs is kept as `<image>:previous`. Images are rebuilt from `requirements.lock` and the pinned base images, then PostgreSQL, Tor, the dashboard and nginx are recreated in that order, each waited for. nginx is reloaded at the end. A full run (no `SERVICES`) also removes containers of services that are no longer in `docker-compose.yml`.
7. **Checks.** Version and container states, then every URL in `SITE_URLS` (default: `https://DOMAIN/login` and `https://WWW_DOMAIN/`) is requested from this server's own nginx on loopback, under its host name, and must answer 200; the script exits non-zero otherwise. The same URLs are then tried the public way. A server error (5xx) there also fails the run. Any other answer is only reported: Cloudflare, for one, answers requests from the server's own address with a challenge page (403), which says nothing about the site, so open the URL from another machine.

`SERVICES="tor dashboard" sudo ./upgrade.sh` limits steps 6 and 7 to those services.

### Roll back

```bash
sudo ./upgrade.sh "$(cat .upgrade-previous-commit)"
```

That rebuilds the previous commit. If the build itself is the problem, start the kept image instead:

```bash
docker tag darkweb-scanner-dashboard:previous darkweb-scanner-dashboard:latest
docker compose up -d --no-deps --no-build dashboard
```

Restore the database only if the upgrade changed data you need back:

```bash
docker compose stop dashboard
docker compose exec -T postgres pg_restore -U scanner -d darkweb_scanner --clean --if-exists < backups/pre-upgrade-<time>.dump
docker compose up -d dashboard
```

## Accounts and sign-in

The rules, as the application enforces them on every request (they are also shown to users under **Help & privacy** in the dashboard):

- **Roles.** A user is an administrator or not. Global settings (keywords, seeds, sources, channel lists), crawl control, deletes, digest subscribers, user administration and Channel Monitor are for administrators. Everything else is a workspace shared by all signed-in users.
- **Second factor.** Mandatory for everyone. An account without one can only reach the enrolment page. A code works once.
- **Passwords.** At least 12 characters with an uppercase letter, a lowercase letter, a number and a symbol. A new user gets a temporary password from the administrator and must replace it at the first sign-in.
- **Lockouts.** 10 wrong passwords for one user name, or 20 failed attempts from one address, within 15 minutes: sign-in is refused for 15 minutes. 5 wrong codes: the second step is locked for 15 minutes. nginx also limits the sign-in pages to 10 requests a minute per visitor.
- **Sessions** end 12 hours after sign-in. Signing out, a password change, a second-factor change, an administrator's reset or deleting the user ends that user's sessions everywhere. Changing `DASHBOARD_SECRET_KEY` ends everyone's.

### First administrator

`/register` works only while the database holds no users, and only with the `SETUP_TOKEN` from `.env` (`deploy.sh` generates it; at least 24 characters). With no token set the page is closed. After the administrator exists the token has no further use; remove the line if you like.

```bash
grep '^SETUP_TOKEN=' .env          # run this on the server, in your own terminal
```

Further users are created by an administrator on the dashboard's **Users** tab.

### Locked out, or a lost authenticator

An administrator can reset another user's second factor on the **Users** tab ("Reset 2FA"). For the administrator's own account, or when nobody can sign in, use the commands on the server. They need no password and show no secrets:

```bash
docker compose exec dashboard python -m darkweb_scanner.main user-list
docker compose exec dashboard python -m darkweb_scanner.main user-unlock NAME [--address 203.0.113.9]
docker compose exec dashboard python -m darkweb_scanner.main user-reset-mfa NAME
```

- `user-list` shows each account (id, name, admin, second factor on or off, temporary password pending, last sign-in) and the locks in force.
- `user-unlock` lifts the password lock and the code lock of that user and, with `--address`, the lock on a network address.
- `user-reset-mfa` removes the second factor and ends the user's sessions; the user signs in with the password and enrols a new authenticator straight away.

Both changes are written to the sign-in log.

### Sign-in log

Sign-ins, failures, lockouts, sign-outs, password and second-factor changes and user administration are stored in the `auth_events` table for 365 days, with the time, user name and address. Administrators read it on the dashboard's **Users** tab (Sign-in log) or with:

```bash
docker compose logs dashboard | grep 'auth event='
```

## Dependencies and base images

- `requirements.lock` holds the exact version and hashes of every Python package. The image installs only from it (`pip install --require-hashes`). Change a dependency in `pyproject.toml`, then run `make lock` and commit both files.
- The base images in `docker/*/Dockerfile` and the PostgreSQL image in `docker-compose.yml` are pinned by digest. Dependabot opens a pull request each month when a newer digest exists.
- **Monthly:** run `make lock`, merge the Dependabot pull requests, let CI pass, then `sudo ./upgrade.sh` on the server. This picks up security fixes in Python packages and in the base images.

## Health and logs

- `GET /healthz` on the dashboard runs `SELECT 1` and answers 200 or 503. The container healthcheck uses it, so `docker compose ps` shows `unhealthy` when the app cannot reach PostgreSQL. It needs no login and returns no data.
- Every service logs through `json-file` with at most 5 files of 20 MB. Read them with `docker compose logs --tail 200 <service>`.
- The dashboard is served by gunicorn with **one worker process and 8 threads**. Keep it at one worker: crawl state and the Quick Scan and Channel Monitor jobs live in that process's memory, and a second worker would not see them. There is no debug mode.
- The dashboard does not start without `DATABASE_URL`, or with a `DASHBOARD_SECRET_KEY` shorter than 32 characters; the reason is in `docker compose logs dashboard`.
- A change in `.env` takes effect after `docker compose up -d dashboard` (`restart` does not re-read the file).

## Tor

- The Tor container is a client only. Its `torrc` is written by `docker/tor/entrypoint.sh` each time the container starts; neither the repository nor the image holds one. See it with `docker compose exec tor cat /etc/tor/torrc`.
- There is **no control port** and no control password. The crawler gets a new circuit every `ROTATE_CIRCUIT_EVERY` pages by opening its next connections with new SOCKS credentials, which Tor keeps on separate circuits.
- The SOCKS port (9050) is reachable from the stack's Docker network only; it is not published on the host.
- Check: `make check-tor`, or `docker compose logs tor | grep Bootstrapped`.

## Channel Monitor

- **Administrators only**, and **public channels only**: a public user name, `@name` or a `t.me/name` link. Private chats, saved messages, phone numbers, numeric ids and invite links are refused before Telegram is contacted, and again after the name is resolved.
- **Translation uses Google Translate.** The text of each message that is not English is sent from the server to `translate.google.com` (no key, no account; media, sender and channel name are not sent). Do not run a job on content that must not be disclosed to Google.
- **Retention.** A job folder and its archive are deleted `CHANNEL_MONITOR_RETENTION_DAYS` days (default 90) after their last change. The sweep runs when the dashboard starts and at most once an hour while Channel Monitor is in use. It never touches a running job or the Telegram session file. **The first start of 1.2.0 deletes every job folder older than the limit**, so download what you want to keep before upgrading.
- Jobs record the administrator who started them. A running job cannot be deleted.
- The report (`messages.html` in the archive) shows channel content as text only and carries a policy that blocks scripts and remote content.

## nginx

The virtual hosts are generated by `docker/nginx/entrypoint.sh` when the container starts; `docker/nginx/nginx.conf` holds the shared settings. A change to either needs the image rebuilt (`SERVICES=nginx sudo ./upgrade.sh`).

- **Unknown host names** are refused: port 80 closes the connection (444), port 443 rejects the TLS handshake. Only `DOMAIN`, `WWW_DOMAIN` (with `www.`) and `THREATWATCH_DOMAIN` are served. Without `DOMAIN` the dashboard answers on any name, for installs reached by IP address.
- **Visitor address.** `docker/nginx/cloudflare-realip.conf` lists Cloudflare's ranges; for connections from them, `CF-Connecting-IP` becomes `$remote_addr` (logs, rate limits, `X-Real-IP`). From any other peer the header is ignored. `X-Forwarded-For` and `X-Forwarded-Host` are set by nginx and never passed through from the client. When Cloudflare changes its ranges, run `scripts/update-cloudflare-ips.sh`, commit, and rebuild nginx.
- **Rate limits** (HTTP 429): `/login`, `/register`, `/totp/setup`, `/totp/verify` and the public `/api/digest/subscribe` and `/api/send-brief` share 10 requests a minute per visitor with a burst of 10. The three relays on the threat-watch site (`/api/nvd/`, `/api/threatfox`, `/api/urlhaus`) allow 30 a minute with a burst of 20, one method each, same-origin only.
- **The dashboard is looked up at request time** (Docker's DNS, cached for 10 seconds). Rebuilding or recreating the dashboard needs no nginx restart, and nginx starts even when the dashboard is down (it answers 502 until it is back).
- **`/healthz`** is for the container healthcheck and answers 404 through nginx.
- **Reload without a restart:** `docker compose exec nginx nginx -s reload`.

## Certificates

- Let's Encrypt certificates and keys are in the `letsencrypt` volume (`/etc/letsencrypt` in the nginx container). `/etc/nginx/certs/*.pem` are links to them. A container start replaces the links and never writes to the files behind them.
- A name without a certificate gets a self-signed pair (a regular file in `/etc/nginx/certs`), kept until it has less than 30 days left. In domain mode the entrypoint then asks Let's Encrypt for a certificate over the webroot challenge.
- Renewal: `certbot renew` runs daily at 12:00 in the nginx container, followed by `nginx -s reload`.
- When you run `certbot renew` from a script or over a session without a terminal, add `--no-random-sleep-on-renew`; without it certbot waits up to eight minutes before it starts.

Check what the origin serves and what certbot holds:

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername scanner.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
docker compose exec nginx certbot certificates
```

**Repair after a version before 1.1.1.** Those versions overwrote `fullchain.pem` and `privkey.pem` with a self-signed pair at every container start. certbot does not notice, because it reads the untouched `cert.pem`. nginx logs `the certificate files for <name> were overwritten` at start when that is the case. Order a new certificate once for each name that is reported, then reload:

```bash
docker compose exec nginx certbot renew --cert-name scanner.example.com --force-renewal --no-random-sleep-on-renew
docker compose exec nginx nginx -s reload
```

Let's Encrypt allows five certificates for the same set of names per week, so do not repeat this in a loop. When the origin serves a Let's Encrypt chain for every name, set the Cloudflare SSL mode to **Full (strict)**.

**Removing a name** (for example a retired service): delete its certificate so the daily renewal stops asking for it, and remove its DNS record:

```bash
docker compose exec nginx certbot delete --cert-name old.example.com
```

---

## Cloudflare origin lock

**Use this only when every public name of the server is proxied through Cloudflare.** Docker publishes ports 80 and 443 through its own NAT rules, which bypass ufw, so anyone who knows the server's address can reach nginx directly and skip Cloudflare. The origin lock drops new inbound connections to those ports unless they come from one of Cloudflare's published ranges.

Files, all installed from `ops/cf-origin-lock/`:

| File | Purpose |
|---|---|
| `/usr/local/sbin/cf-origin-lock` | the script: `apply`, `refresh`, `selftest`, `remove`, `status` |
| `/etc/systemd/system/cf-origin-lock.service` | oneshot at boot, after Docker and the CrowdSec firewall bouncer; `ExecStop` removes the lock |
| `/etc/systemd/system/cf-origin-lock-refresh.service` and `cf-origin-lock.timer` | weekly refresh of Cloudflare's ranges |
| `/etc/cf-origin-lock/ips-v4`, `ips-v6` | last good copy of Cloudflare's lists; used when a download fails |
| `/etc/default/cf-origin-lock` | settings: `IFACE` (written at install time from the default route) and `PORTS` (default `80 443`) |

### What it does

1. Downloads `https://www.cloudflare.com/ips-v4` and `ips-v6`. A download replaces the cached copy only if every line is a CIDR, no range is wider than /8 (IPv4) or /16 (IPv6) and the list is not unusually short. Otherwise the previous copy is kept.
2. Builds the ipsets `cf4` and `cf6` in a temporary set and swaps them in, so the live set is never empty.
3. Adds, for `iptables` with `cf4` and `ip6tables` with `cf6`, for each port:

   ```
   -A DOCKER-USER -i <iface> -p tcp -m conntrack --ctorigdstport <port> --ctdir ORIGINAL -m set ! --match-set <set> src -j DROP
   ```

   `--ctdir ORIGINAL` is essential. Without it the rule also matches the replies to connections that containers open to ports 80/443 elsewhere, and every container loses outbound HTTP(S). Each run deletes any rule of that older form.
4. Self-test: the four rules exist, both ipsets hold as many entries as the lists, and one HTTPS request from inside a running container succeeds. Any failure is logged to the journal and the unit ends in the `failed` state (the rules stay in place).

It touches the `DOCKER-USER` chain and the two ipsets only. It makes no SSH or ufw changes.

### Install or update

```bash
sudo bash ops/cf-origin-lock/install.sh
```

`deploy.sh` runs this when called with `ORIGIN_LOCK=1`. `upgrade.sh` runs it whenever the lock is already installed.

### Check it

```bash
systemctl status cf-origin-lock.service          # active (exited) is the healthy state
systemctl list-timers cf-origin-lock.timer       # next weekly refresh
cf-origin-lock status                            # rules with packet counters, ipset sizes
cf-origin-lock selftest; echo "exit=$?"          # 0 = all good
journalctl -u cf-origin-lock.service -u cf-origin-lock-refresh.service -n 50
```

Every proxied site should still answer through Cloudflare, and a container should still reach the internet:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://YOUR_DOMAIN/login
docker compose exec dashboard python3 -c "import socket; socket.create_connection(('149.154.167.51', 443), 10); print('egress ok')"
```

### Roll back

```bash
systemctl stop cf-origin-lock.service            # removes the four rules and both ipsets
systemctl disable cf-origin-lock.service cf-origin-lock.timer
```

The ports are then reachable from any address again. `systemctl start cf-origin-lock.service` puts the lock back.

### After a reboot

The unit applies the lock on its own. To confirm: `cf-origin-lock selftest`, then the two checks above.
