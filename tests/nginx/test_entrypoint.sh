#!/usr/bin/env bash
# Regression test for docker/nginx/entrypoint.sh. Needs only docker.
#
#   tests/nginx/test_entrypoint.sh [image]      (default: darkweb-scanner-nginx)
#
# 1. Certificates: a volume laid out the way certbot leaves it (archive/ files,
#    live/ links) plus the links an earlier entrypoint left in /etc/nginx/certs.
#    After three starts every certificate and key file must be byte-identical
#    and nginx must serve the issued certificate.
# 2. A stale link with no certificate behind it must be replaced, not written through.
# 3. Self-signed mode: generated once, kept on the next start.
# 4. A lineage whose chain was overwritten is reported in the log.
# 5. Virtual hosts: unknown names are refused, /healthz is not public, sign-in
#    is rate limited, forwarded headers cannot be forged, and nginx starts and
#    recovers when the dashboard is down.
set -uo pipefail

IMAGE="${1:-darkweb-scanner-nginx}"
P="ngx-test-$$"
D1=scanner.test.example D2=test.example D3=threatwatch.test.example
FAILED=0

ok()   { echo "  ok    $*"; }
fail() { echo "  FAIL  $*"; FAILED=1; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1 (expected '$3', got '$2')"; fi; }

cleanup() {
  docker rm -f "$P-n" "$P-dash" >/dev/null 2>&1
  docker volume rm -f "$P-le" "$P-certs" "$P-le2" "$P-certs2" "$P-certs3" >/dev/null 2>&1
  docker network rm "$P-net" "$P-cf" >/dev/null 2>&1
}
trap cleanup EXIT

# Run a shell snippet in a throwaway container of the image, with the test volumes.
helper() { docker run --rm -i --network none --entrypoint bash -v "$P-le:/etc/letsencrypt" -v "$P-certs:/etc/nginx/certs" "$IMAGE" -s; }

# start NAME-SUFFIX-less container; args: extra docker run options. Waits for nginx to listen.
start_nginx() {
  docker rm -f "$P-n" >/dev/null 2>&1
  docker run -d --name "$P-n" "$@" "$IMAGE" >/dev/null || return 1
  for _ in $(seq 1 40); do
    if docker exec "$P-n" sh -c 'nc -z 127.0.0.1 443' 2>/dev/null; then return 0; fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$P-n" 2>/dev/null)" != "true" ]]; then break; fi
    sleep 0.5
  done
  echo "  nginx did not come up:"; docker logs "$P-n" 2>&1 | tail -8 | sed 's/^/    /'
  return 1
}
served_fp() { docker exec "$P-n" sh -c "echo | openssl s_client -connect 127.0.0.1:443 -servername $1 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null"; }
code() { docker exec "$P-n" curl -sk -o /dev/null -m 10 -w '%{http_code}' "$@" 2>/dev/null; }

echo "image: $IMAGE"
docker volume create "$P-le" >/dev/null; docker volume create "$P-certs" >/dev/null

echo "1. certificate files survive restarts"
helper <<EOF || { echo "could not prepare the test volume"; exit 1; }
set -e
cd /tmp
openssl req -x509 -nodes -newkey rsa:2048 -days 30 -keyout ca.key -out ca.pem -subj "/CN=Test Issuing CA" 2>/dev/null
for d in $D1 $D2 $D3; do
  a=/etc/letsencrypt/archive/\$d; l=/etc/letsencrypt/live/\$d
  mkdir -p \$a \$l
  openssl req -nodes -newkey rsa:2048 -keyout \$a/privkey1.pem -out \$d.csr -subj "/CN=\$d" 2>/dev/null
  printf 'subjectAltName=DNS:%s\n' "\$d" > \$d.ext
  openssl x509 -req -in \$d.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile \$d.ext -out \$a/cert1.pem 2>/dev/null
  cp ca.pem \$a/chain1.pem
  cat \$a/cert1.pem \$a/chain1.pem > \$a/fullchain1.pem
  for f in cert chain fullchain privkey; do ln -s ../../archive/\$d/\${f}1.pem \$l/\$f.pem; done
done
# The links an earlier version of the entrypoint created.
c=/etc/nginx/certs
ln -sf /etc/letsencrypt/live/$D1/fullchain.pem \$c/cert.pem
ln -sf /etc/letsencrypt/live/$D1/privkey.pem \$c/key.pem
ln -sf /etc/letsencrypt/live/$D2/fullchain.pem \$c/www-cert.pem
ln -sf /etc/letsencrypt/live/$D2/privkey.pem \$c/www-key.pem
ln -sf /etc/letsencrypt/live/$D3/fullchain.pem \$c/threatwatch-cert.pem
ln -sf /etc/letsencrypt/live/$D3/privkey.pem \$c/threatwatch-key.pem
cd /etc/letsencrypt && find archive -type f | sort | xargs sha256sum > /etc/letsencrypt/SUMS
EOF
DOMAIN_ENV=(-e "DOMAIN=$D1" -e SSL_EMAIL=test@test.example -e "WWW_DOMAIN=$D2" -e "THREATWATCH_DOMAIN=$D3")
VOLS=(-v "$P-le:/etc/letsencrypt" -v "$P-certs:/etc/nginx/certs")
for n in 1 2 3; do
  start_nginx --network none "${DOMAIN_ENV[@]}" "${VOLS[@]}" || fail "start $n"
done
check "12 archive files unchanged after 3 starts" "$(helper <<<'cd /etc/letsencrypt && if sha256sum -c SUMS >/dev/null 2>&1; then echo same; else echo CHANGED; fi')" "same"
for d in $D1 $D2 $D3; do
  check "$d serves the issued certificate" "$(served_fp "$d")" "$(helper <<<"openssl x509 -in /etc/letsencrypt/live/$d/cert.pem -noout -fingerprint -sha256")"
done
check "no damage warning for intact lineages" "$(docker logs "$P-n" 2>&1 | grep -c 'were overwritten')" "0"

echo "4. an overwritten chain is reported"
helper <<EOF
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -keyout /etc/letsencrypt/archive/$D3/privkey1.pem -out /etc/letsencrypt/archive/$D3/fullchain1.pem -subj "/CN=$D3" 2>/dev/null
EOF
start_nginx --network none "${DOMAIN_ENV[@]}" "${VOLS[@]}" || fail "start with a damaged lineage"
check "warning names the damaged lineage only" "$(docker logs "$P-n" 2>&1 | grep 'were overwritten' | grep -o '[a-z.]*test\.example' | sort -u | tr '\n' ' ')" "$D3 "

echo "2. a stale link is replaced, not written through"
docker volume create "$P-le2" >/dev/null; docker volume create "$P-certs2" >/dev/null
docker run --rm -i --network none --entrypoint bash -v "$P-le2:/etc/letsencrypt" -v "$P-certs2:/etc/nginx/certs" "$IMAGE" -s <<'EOF'
mkdir -p /etc/letsencrypt/keep
echo "sentinel certificate" > /etc/letsencrypt/keep/cert.pem
echo "sentinel key" > /etc/letsencrypt/keep/key.pem
ln -s /etc/letsencrypt/keep/cert.pem /etc/nginx/certs/cert.pem
ln -s /etc/letsencrypt/keep/key.pem /etc/nginx/certs/key.pem
EOF
start_nginx --network none -v "$P-le2:/etc/letsencrypt" -v "$P-certs2:/etc/nginx/certs" || fail "start with stale links"
check "files behind the stale links untouched" "$(docker exec "$P-n" sh -c 'cat /etc/letsencrypt/keep/cert.pem /etc/letsencrypt/keep/key.pem | tr "\n" "|"')" "sentinel certificate|sentinel key|"
check "cert.pem is now a regular self-signed file" "$(docker exec "$P-n" sh -c '[ ! -L /etc/nginx/certs/cert.pem ] && openssl x509 -in /etc/nginx/certs/cert.pem -noout -subject | grep -c self-signed')" "1"

echo "3. self-signed certificate is generated once"
docker volume create "$P-certs3" >/dev/null
start_nginx --network none -v "$P-certs3:/etc/nginx/certs" || fail "first self-signed start"
FP1="$(served_fp localhost)"
start_nginx --network none -v "$P-certs3:/etc/nginx/certs" || fail "second self-signed start"
check "same self-signed certificate on the next start" "$(served_fp localhost)" "$FP1"
[[ -n "$FP1" ]] || fail "no certificate served in self-signed mode"

echo "5. virtual hosts"
docker network create "$P-net" >/dev/null
# nginx first, with no dashboard on the network at all.
start_nginx --network "$P-net" "${DOMAIN_ENV[@]}" "${VOLS[@]}" || fail "start without a dashboard"
check "starts without the dashboard; /login is 502" "$(code --resolve "$D1:443:127.0.0.1" "https://$D1/login")" "502"
# A stand-in dashboard that echoes the request headers it received.
docker run -d --name "$P-dash" --network "$P-net" --network-alias dashboard --entrypoint python3 "${DASH_IMAGE:-python:3.11-slim}" -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = "".join("%s: %s\n" % (k, v) for k, v in self.headers.items()).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()' >/dev/null
for _ in $(seq 1 40); do
  [[ "$(code --resolve "$D1:443:127.0.0.1" "https://$D1/")" == "200" ]] && break; sleep 0.5
done
check "finds the dashboard once it exists, without a restart" "$(code --resolve "$D1:443:127.0.0.1" "https://$D1/")" "200"
check "/healthz is not served to the outside" "$(code --resolve "$D1:443:127.0.0.1" "https://$D1/healthz")" "404"
check "unknown name on 443: handshake refused" "$(code --resolve "other.example:443:127.0.0.1" "https://other.example/")" "000"
check "unknown name on 80: connection closed" "$(code -H 'Host: other.example' "http://127.0.0.1/")" "000"
check "known name on 80 redirects to https" "$(code -H "Host: $D1" "http://127.0.0.1/x")" "301"
HDRS="$(docker exec "$P-n" curl -sk -m 10 --resolve "$D1:443:127.0.0.1" -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Forwarded-Host: evil.example' -H 'CF-Connecting-IP: 203.0.113.10' "https://$D1/")"
check "client-supplied X-Forwarded-For is replaced" "$(grep -i '^X-Forwarded-For:' <<<"$HDRS" | tr -d '\r')" "X-Forwarded-For: 127.0.0.1"
check "client-supplied X-Forwarded-Host is replaced" "$(grep -i '^X-Forwarded-Host:' <<<"$HDRS" | tr -d '\r')" "X-Forwarded-Host: $D1"
check "CF-Connecting-IP from a non-Cloudflare peer is ignored" "$(grep -i '^X-Real-IP:' <<<"$HDRS" | tr -d '\r')" "X-Real-IP: 127.0.0.1"
# A peer inside one of Cloudflare's ranges: a local docker network that uses a slice of 131.0.72.0/22.
docker network create --subnet 131.0.72.0/28 "$P-cf" >/dev/null && docker network connect "$P-cf" "$P-n"
NGX_CF_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$P-cf\").IPAddress}}" "$P-n")"
HDRS="$(docker run --rm --network "$P-cf" --entrypoint curl "$IMAGE" -sk -m 10 --resolve "$D1:443:$NGX_CF_IP" -H 'CF-Connecting-IP: 203.0.113.10' -H 'X-Forwarded-For: 198.51.100.7' "https://$D1/")"
check "CF-Connecting-IP from a Cloudflare peer becomes the client address" "$(grep -iE '^(X-Real-IP|X-Forwarded-For):' <<<"$HDRS" | tr -d '\r' | sort | tr '\n' ' ')" "X-Forwarded-For: 203.0.113.10 X-Real-IP: 203.0.113.10 "
docker network disconnect "$P-cf" "$P-n" >/dev/null 2>&1
LIMITED=0
for _ in $(seq 1 30); do [[ "$(code --resolve "$D1:443:127.0.0.1" "https://$D1/login")" == "429" ]] && LIMITED=$((LIMITED + 1)); done
if [[ "$LIMITED" -ge 15 ]]; then ok "/login rate limited ($LIMITED of 30 quick requests got 429)"; else fail "/login rate limit ($LIMITED of 30 got 429)"; fi
check "other paths are not limited" "$(for _ in $(seq 1 30); do code --resolve "$D1:443:127.0.0.1" "https://$D1/api/x"; echo; done | sort | uniq -c | awk '{print $2"x"$1}' | tr '\n' ' ')" "200x30 "
check "no /api/send-brief relay on the static sites" "$(docker exec "$P-n" grep -c 'location /api/send-brief' /etc/nginx/conf.d/darkweb.conf)" "0"
check "threatwatch relay refuses other methods" "$(code -X DELETE --resolve "$D3:443:127.0.0.1" "https://$D3/api/urlhaus")" "403"
check "no web-check virtual host" "$(docker exec "$P-n" grep -c webcheck /etc/nginx/conf.d/darkweb.conf)" "0"

echo
if [[ "$FAILED" -eq 0 ]]; then echo "PASS"; else echo "FAILED"; exit 1; fi
