# Operations runbook

Day-to-day operations for a production install. Commands are run as root from the install directory unless stated otherwise.

- [Upgrading](#upgrading)
- [Dependencies and base images](#dependencies-and-base-images)
- [Health and logs](#health-and-logs)
- [Cloudflare origin lock](#cloudflare-origin-lock)

---

## Upgrading

```bash
cd /path/to/install
sudo ./upgrade.sh            # tip of main
sudo ./upgrade.sh v1.1.1     # a release tag, branch or commit
```

What it does, in order:

1. **Pre-flight.** Stops if a git operation is unfinished (cherry-pick, merge, rebase) or tracked files have local changes. Untracked files, `.env`, `config/` and a `docker-compose.override.yml` are left alone.
2. **Database dump** to `backups/pre-upgrade-<UTC time>.dump` (`pg_dump -Fc`), read back with `pg_restore --list`. The five newest are kept. `SKIP_BACKUP=1` skips it.
3. **Checkout.** A branch is fast-forwarded; a tag or commit is checked out detached. The commit you came from is written to `.upgrade-previous-commit`. The `www` submodule is not moved unless you pass `UPDATE_WWW=1`, because the website is deployed on its own schedule.
4. **`.env` fixes.** `DATABASE_URL` gets the `postgresql+psycopg2://` driver name; the file is set to mode 600; settings that `.env.example` has and your `.env` lacks are listed by name.
5. **Origin lock.** Updated in place when it is installed (see below).
6. **Build and start.** The image each service runs is kept as `<image>:previous`. Images are rebuilt from `requirements.lock` and the pinned base images, then PostgreSQL, Tor, the dashboard and nginx are recreated in that order, each waited for. nginx is reloaded so it finds the new dashboard container.
7. **Checks.** Version, container states, and every URL in `SITE_URLS` (default: `https://DOMAIN/login` and `https://WWW_DOMAIN/`) must answer 200. The script exits non-zero otherwise.

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

## Dependencies and base images

- `requirements.lock` holds the exact version and hashes of every Python package. The image installs only from it (`pip install --require-hashes`). Change a dependency in `pyproject.toml`, then run `make lock` and commit both files.
- The base images in `docker/*/Dockerfile` and the PostgreSQL image in `docker-compose.yml` are pinned by digest. Dependabot opens a pull request each month when a newer digest exists.
- **Monthly:** run `make lock`, merge the Dependabot pull requests, let CI pass, then `sudo ./upgrade.sh` on the server. This picks up security fixes in Python packages and in the base images.

## Health and logs

- `GET /healthz` on the dashboard runs `SELECT 1` and answers 200 or 503. The container healthcheck uses it, so `docker compose ps` shows `unhealthy` when the app cannot reach PostgreSQL. It needs no login and returns no data.
- Every service logs through `json-file` with at most 5 files of 20 MB. Read them with `docker compose logs --tail 200 <service>`.

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
