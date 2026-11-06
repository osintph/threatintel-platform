# Base image pinned by digest; .github/dependabot.yml proposes updates monthly.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# No torrc in the image: the entrypoint renders it at container start (see entrypoint.sh).
COPY entrypoint.sh /usr/local/bin/tor-entrypoint

# The entrypoint writes /etc/tor/torrc as debian-tor (not root)
RUN chmod 755 /usr/local/bin/tor-entrypoint \
    && rm -f /etc/tor/torrc \
    && chown debian-tor:debian-tor /etc/tor \
    && chown -R debian-tor:debian-tor /var/lib/tor

EXPOSE 9050

USER debian-tor

CMD ["/usr/local/bin/tor-entrypoint"]
