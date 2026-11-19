# Base image pinned by digest; .github/dependabot.yml proposes updates monthly.
FROM nginx:1.31.9-alpine@sha256:90b6bd2aec278b16b98221d64deb1d6d35d164567f507ab0716e6053878315aa

RUN apk add --no-cache openssl certbot certbot-nginx bash

# The stock default.conf would answer unknown host names on port 80.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY cloudflare-realip.conf /etc/nginx/cloudflare-realip.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
