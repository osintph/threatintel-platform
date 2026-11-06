#!/usr/bin/env bash
# Regenerate docker/nginx/cloudflare-realip.conf from Cloudflare's published lists.
# Run from the repository root, commit the result, then rebuild the nginx image.
set -euo pipefail
out=docker/nginx/cloudflare-realip.conf
tmp="$(mktemp)"
{
  echo "# Cloudflare's published ranges (https://www.cloudflare.com/ips-v4 and ips-v6)."
  echo "# The CF-Connecting-IP header is trusted only on connections from these."
  echo "# Regenerate with scripts/update-cloudflare-ips.sh."
  for v in 4 6; do
    curl -fsS --max-time 20 "https://www.cloudflare.com/ips-v$v" | tr -d '\r' | while read -r net || [ -n "$net" ]; do
      [[ "$net" =~ ^[0-9A-Fa-f:.]+/[0-9]{1,3}$ ]] || { echo "unexpected line: $net" >&2; exit 1; }
      echo "set_real_ip_from $net;"
    done
  done
  echo "real_ip_header CF-Connecting-IP;"
} > "$tmp"
[ "$(grep -c set_real_ip_from "$tmp")" -ge 15 ] || { echo "list too short; $out left unchanged" >&2; rm -f "$tmp"; exit 1; }
mv "$tmp" "$out"
chmod 644 "$out"
echo "$out: $(grep -c set_real_ip_from "$out") ranges"
