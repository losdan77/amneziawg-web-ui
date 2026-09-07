FROM teddysun/xray:26.3.27 AS xray_tools
FROM golang:1.25-alpine AS awg_builder
# Official AWG 3.0 release v3.0.20260805; pin the commit as tags can move.
ARG AWG_GO_COMMIT=08d68cdae27762c3e07f36bbb12d2bad32f81926
RUN apk add --no-cache git make
WORKDIR /src/awg
RUN git init && git remote add origin https://github.com/amnezia-vpn/amneziawg-go.git \
    && git fetch --depth 1 origin "$AWG_GO_COMMIT" && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$AWG_GO_COMMIT" \
    && go mod download && go mod verify \
    && printf 'package main\n\nconst Version = "v3.0.20260805"\n' > version.go \
    && CGO_ENABLED=0 go build -trimpath -o amneziawg-go .

FROM alpine:3.22 AS awg_tools_builder
# Official tools release v3.0.20260730, matching the userspace UAPI.
ARG AWG_TOOLS_COMMIT=d09ecc38425082e472368dd2bf8c4c42d10cae03
RUN apk add --no-cache git build-base linux-headers
WORKDIR /src/tools
RUN git init && git remote add origin https://github.com/amnezia-vpn/amneziawg-tools.git \
    && git fetch --depth 1 origin "$AWG_TOOLS_COMMIT" && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$AWG_TOOLS_COMMIT" \
    && make -C src

FROM alpine:3.22
COPY --from=awg_builder /src/awg/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg_tools_builder /src/tools/src/wg /usr/bin/awg
COPY --from=awg_tools_builder /src/tools/src/wg-quick/linux.bash /usr/bin/awg-quick
RUN chmod +x /usr/bin/awg-quick \
    && ln -s /usr/bin/awg /usr/bin/wg \
    && ln -s /usr/bin/awg-quick /usr/bin/wg-quick

# Used by the Web UI to run `xray x25519` when creating VLESS REALITY servers (must match xray service image tag).
COPY --from=xray_tools /usr/bin/xray /usr/bin/xray

# Install dependencies for web UI
RUN apk update && apk add \
    bash \
    iproute2 \
    iproute2-tc \
    iptables \
    openresolv \
    python3 \
    py3-pip \
    nginx \
    nginx-mod-stream \
    supervisor \
    curl \
    apache2-utils \
    certbot \
    certbot-nginx \
    iptables-legacy \
    && rm -rf /var/cache/apk/*

RUN pip3 install flask flask_socketio flask-wtf requests python-socketio eventlet --break-system-packages

RUN mkdir -p /app/web-ui /var/log/supervisor /var/log/webui /var/log/amnezia /var/log/nginx /etc/amnezia/amneziawg /etc/letsencrypt /var/www/le

COPY web-ui /app/web-ui/

RUN mkdir -p /run/nginx /etc/nginx/stream.d
# Copy the main nginx.conf (with stream module include) and HTTP server configs.
COPY config/nginx/nginx.conf /etc/nginx/nginx.conf
COPY config/nginx/default.conf /etc/nginx/http.d/default.conf
COPY config/nginx/ssl.conf.template /etc/nginx/http.d/ssl.conf.template
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
# cli.ini is a template — start.sh copies it into /etc/letsencrypt/cli.ini at
# runtime and seds in SSL_EMAIL / SSL_DOMAIN. Stored under /app so a host
# bind mount over /etc/letsencrypt doesn't shadow it.
COPY config/cli.ini /app/config/cli.ini.template

COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh \
    && python3 /app/scripts/force_awg_userspace.py /usr/bin/awg-quick \
    && bash -n /usr/bin/awg-quick \
    && /usr/bin/awg --version

# Expose default ports
EXPOSE 80
EXPOSE 51820/udp

ENV NGINX_PORT=80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sh -lc 'curl -fk "https://localhost:$NGINX_PORT/status" || curl -f "http://localhost:$NGINX_PORT/status"'

ENTRYPOINT ["/app/scripts/start.sh"]
