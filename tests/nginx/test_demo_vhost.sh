#!/usr/bin/env bash
# The demo parts of docker/nginx/entrypoint.sh, cut out and run without nginx.
# The full start of nginx is covered by tests/nginx/test_entrypoint.sh.
# usage: tests/nginx/test_demo_vhost.sh
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0
ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILED=1; }
has()  { if grep -qF -- "$2" "$WORK/conf"; then ok "$1"; else fail "$1 (no '$2')"; fi; }
hasnt() { if grep -qF -- "$2" "$WORK/conf"; then fail "$1 (found '$2')"; else ok "$1"; fi; }

E="$REPO/docker/nginx/entrypoint.sh"
# A function ends at a "}" in column 0 that is not inside a here-document.
cut_function() {
  awk -v start="$1() {" '$0 == start { on = 1 } on { print } on && /<</ { doc = 1 } /^EOF$/ { doc = 0 } on && !doc && /^}$/ { exit }' "$E"
}
for f in proxy_headers write_demo_vhost own_cert_names; do cut_function "$f"; done > "$WORK/funcs.sh"

export CONF="$WORK/conf"
: > "$CONF"
# shellcheck disable=SC2016
DEMO_DOMAIN=demo.test.example CERT_DIR=/c WEBROOT=/w TLS_CIPHERS=X bash -c 'source "$1"; write_demo_vhost' _ "$WORK/funcs.sh" || fail "write_demo_vhost failed"

has "serves the demo name" "server_name demo.test.example;"
has "uses the demo certificate" "ssl_certificate     /c/demo-cert.pem;"
has "upstream is a variable, so nginx starts without the demo" 'set $demo_dashboard http://demo-dashboard:8080;'
has "proxies to the variable" 'proxy_pass $demo_dashboard;'
hasnt "never a static upstream" "proxy_pass http://"
hasnt "never the production dashboard" "http://dashboard:8080"
has "healthcheck is not public" "location = /healthz { return 404; }"
has "sign-in is rate limited" "limit_req zone=login"
has "forwarded headers are set here" 'proxy_set_header X-Forwarded-For $remote_addr;'
has "not indexed" "X-Robots-Tag"

names() { DOMAIN=a WWW_DOMAIN=b THREATWATCH_DOMAIN=c DEMO_DOMAIN=d DEMO_CERT_NAME="$1" bash -c 'source "$1"; own_cert_names | tr "\n" " "' _ "$WORK/funcs.sh"; }
[[ "$(names '')" == "a b c d " ]] && ok "no shared certificate: the demo name is ordered" || fail "names: $(names '')"
[[ "$(names shared)" == "a b c " ]] && ok "shared certificate: nothing is ordered for the demo" || fail "names: $(names shared)"

exit "$FAILED"
