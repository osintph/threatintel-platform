#!/usr/bin/env bash
# Install or update the Cloudflare origin lock from this directory.
# Used by deploy.sh (ORIGIN_LOCK=1) and upgrade.sh; safe to run again.
#
#   sudo bash ops/cf-origin-lock/install.sh            install/update, enable, apply
#   sudo bash ops/cf-origin-lock/install.sh --files    install/update the files only
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for t in iptables ip6tables ipset curl systemctl; do
  command -v "$t" >/dev/null 2>&1 || { echo "cf-origin-lock install: '$t' is required" >&2; exit 1; }
done

install -o root -g root -m 755 "$HERE/cf-origin-lock" /usr/local/sbin/cf-origin-lock
install -o root -g root -m 644 "$HERE/cf-origin-lock.service" /etc/systemd/system/cf-origin-lock.service
install -o root -g root -m 644 "$HERE/cf-origin-lock-refresh.service" /etc/systemd/system/cf-origin-lock-refresh.service
install -o root -g root -m 644 "$HERE/cf-origin-lock.timer" /etc/systemd/system/cf-origin-lock.timer
install -d -o root -g root -m 755 /etc/cf-origin-lock

# Pin the public interface at install time, so a boot never depends on the
# default route being up when the unit starts. Edit the file to change it.
if [ ! -e /etc/default/cf-origin-lock ]; then
  iface="$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
  [ -n "$iface" ] || { echo "cf-origin-lock install: cannot find the public interface; create /etc/default/cf-origin-lock with IFACE=<name>" >&2; exit 1; }
  printf '# Settings for /usr/local/sbin/cf-origin-lock. See docs/runbook.md.\nIFACE=%s\nPORTS="80 443"\n' "$iface" > /etc/default/cf-origin-lock
  chmod 644 /etc/default/cf-origin-lock
  echo "cf-origin-lock: public interface pinned to $iface in /etc/default/cf-origin-lock"
fi

systemctl daemon-reload
echo "cf-origin-lock: files installed"

[ "${1:-}" = "--files" ] && exit 0

systemctl enable cf-origin-lock.service cf-origin-lock.timer
# "restart" runs the remove step and then a full apply, the same path as a boot.
systemctl restart cf-origin-lock.service
systemctl start cf-origin-lock.timer
systemctl --no-pager --lines=12 status cf-origin-lock.service || true
