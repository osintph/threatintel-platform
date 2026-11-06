# Operations runbook

Day-to-day operations for a production install. Commands are run as root from the install directory unless stated otherwise.

- [Cloudflare origin lock](#cloudflare-origin-lock)

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
| `/etc/default/cf-origin-lock` | optional settings: `IFACE` (default: the interface of the default route), `PORTS` (default `80 443`) |

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
