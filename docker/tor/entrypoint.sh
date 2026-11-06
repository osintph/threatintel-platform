#!/bin/sh
# Writes the Tor configuration when the container starts, then runs Tor.
#
# The configuration is rendered here, at deploy time, so the repository and
# the image hold no torrc and no password hash. There is no control port:
# nothing in the stack needs one (the crawler gets new circuits through SOCKS
# isolation), and an open control port lets any container on the network
# reconfigure Tor.
set -eu

TORRC=/etc/tor/torrc
umask 077

cat > "$TORRC" <<TORRC_EOF
# Rendered by /usr/local/bin/tor-entrypoint at container start. Do not edit; changes are lost.
# Tor CLIENT only: not a relay, not an exit.

# SOCKS proxy for the other containers on the Docker network (not published on the host).
SocksPort 0.0.0.0:${TOR_SOCKS_PORT:-9050}

ExitPolicy reject *:*
ExitRelay 0

DataDirectory /var/lib/tor
Log notice stdout

# Refuse to connect to private addresses on behalf of a client (Tor's default, stated on purpose).
ClientRejectInternalAddresses 1
TORRC_EOF

# Fail here, with a clear message, when the rendered file is not valid.
tor --verify-config -f "$TORRC" >/dev/null || { echo "tor-entrypoint: rendered torrc is not valid" >&2; exit 1; }

exec tor -f "$TORRC"
