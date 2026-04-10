FROM teddysun/xray:26.3.27 AS xray_tools
FROM amneziavpn/amneziawg-go:latest

# Used by the Web UI to run `xray x25519` when creating VLESS REALITY servers (must match xray service image tag).
COPY --from=xray_tools /usr/bin/xray /usr/bin/xray

# Install dependencies for web UI
RUN apk update && apk add \
    python3 \
    py3-pip \
    nginx \
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
COPY config/cli.ini /etc/letsencrypt/cli.ini

COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Expose default ports
EXPOSE 80
EXPOSE 51820/udp

ENV NGINX_PORT=80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sh -lc 'curl -fk "https://localhost:$NGINX_PORT/status" || curl -f "http://localhost:$NGINX_PORT/status"'

ENTRYPOINT ["/app/scripts/start.sh"]