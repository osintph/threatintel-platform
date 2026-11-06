# Base image pinned by digest; .github/dependabot.yml proposes updates monthly.
FROM nginx:alpine@sha256:b2f80f8f88146b0772fdcc7d92cea621aa8c2889fa8d07ed61d4884fcea53e09

RUN apk add --no-cache openssl certbot certbot-nginx bash

# The stock default.conf would answer unknown host names on port 80.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY cloudflare-realip.conf /etc/nginx/cloudflare-realip.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
