#!/bin/sh

mkdir -p /var/log/amnezia /var/log/nginx /var/log/supervisor
chmod 755 /var/log/amnezia /var/log/nginx /var/log/supervisor
chmod -R 755 /app/web-ui/
chown :www-data /var/www/le
chmod -R 755 /var/www/le

# Ensure dynamic nginx include exists for VLESS locations.
touch /etc/nginx/vless_locations.inc

# Ensure stream routing config exists (empty at startup; updated by web UI and SSL setup).
# nginx includes this file from nginx.conf; a comment-only file is valid nginx syntax.
if [ ! -f /etc/nginx/stream_reality.conf ]; then
    echo "# REALITY stream routing — managed by web UI (see /api/vless/sni-presets)" > /etc/nginx/stream_reality.conf
fi

lsmod | grep -E "^nf_tables|^nft_"
nft_true=$?

if [ "$nft_true" -ne 0 ]; then
    ln -sf /sbin/iptables-legacy /sbin/iptables
    echo "iptables-legacy set as default"
fi

NGINX_CONFIG_FILE="/etc/nginx/http.d/default.conf"
LE_CONFIG_FILE="/etc/letsencrypt/cli.ini"

if [ -n "$NGINX_PORT" ] && [ "$NGINX_PORT" != "80" ]; then
    echo "Configuring nginx to listen on port $NGINX_PORT"
    sed -i "1,/listen 80;/ s/listen 80;/listen $NGINX_PORT;/" $NGINX_CONFIG_FILE
fi

if [ -n "$IP_LIST" ]; then
    ALLOW_RULES=$(echo "$IP_LIST" | tr -d '[:space:]' | tr ',' '\n' | awk 'NF {printf "        allow %s;\\n", $0}')
    ALLOW_RULES="${ALLOW_RULES}        deny all;"

    sed -i "/# ALLOW_RULES_START/,/# ALLOW_RULES_END/c\        # ALLOW_RULES_START\\n${ALLOW_RULES}\\n        # ALLOW_RULES_END" $NGINX_CONFIG_FILE
    echo "Nginx allow rules set: ${ALLOW_RULES}"
fi

: "${NGINX_USER:=admin}"
: "${NGINX_PASSWORD:=changeme}"
htpasswd -bc /etc/nginx/.htpasswd "$NGINX_USER" "$NGINX_PASSWORD"

nginx -t

if [ -n "$SSL_EMAIL" ] && [ "$SSL_DOMAIN" ]; then
    mv /etc/nginx/http.d/ssl.conf.template /etc/nginx/http.d/ssl.conf
    nginx
    echo "Configuring certbot to use $SSL_EMAIL and $SSL_DOMAIN"
    sed -i "s/email_placeholder/$SSL_EMAIL/" $LE_CONFIG_FILE
    sed -i "s/domain_placeholder/$SSL_DOMAIN/" $LE_CONFIG_FILE

    certbot certonly -c $LE_CONFIG_FILE --non-interactive
    certbot certificates | grep VALID
    cert_valid=$?

    if [ "$cert_valid" -eq 0 ]; then
        # Move nginx HTTPS to internal port 4443 so that nginx stream can own external port 443.
        # The stream block (stream_reality.conf) routes:
        #   - REALITY mask-domain SNI  -> specific Xray inbound (managed by web UI)
        #   - Everything else          -> nginx HTTPS on 127.0.0.1:4443
        sed -i \
            -e "1,/listen $NGINX_PORT;/ s/listen $NGINX_PORT;/listen 4443 ssl http2;/" \
            -e "1,/server_name _;/ s/server_name _;/server_name $SSL_DOMAIN;/" \
            -e "/server_name $SSL_DOMAIN;/a\\
    # SSL certificate configuration\\
    ssl_certificate /etc/letsencrypt/live/$SSL_DOMAIN/fullchain.pem;\\
    ssl_certificate_key /etc/letsencrypt/live/$SSL_DOMAIN/privkey.pem;"\
            $NGINX_CONFIG_FILE

        certbot install --cert-name $SSL_DOMAIN

        sed -i "/ssl_certificate_key \/etc\/letsencrypt\/live\/$SSL_DOMAIN\/privkey.pem;/a\\
    include /etc/letsencrypt/options-ssl-nginx.conf;\\
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;" \
            $NGINX_CONFIG_FILE

        # Write the base stream routing block.  The web UI will append REALITY mask-domain
        # entries when VLESS servers with use_stream=true are created.
        cat > /etc/nginx/stream_reality.conf << 'STREAM_EOF'
stream {
    # SNI -> backend map; REALITY entries are added/removed by the web UI.
    map $ssl_preread_server_name $backend_443 {
        hostnames;
        # <REALITY_ENTRIES> — do not remove this marker; web UI uses it
        default   nginx_https_4443;
    }

    upstream nginx_https_4443 {
        server 127.0.0.1:4443;
    }

    server {
        listen 443;
        ssl_preread on;
        proxy_pass $backend_443;
    }
}
STREAM_EOF
        echo "Stream routing enabled: external :443 -> nginx stream (REALITY mask SNIs -> Xray; others -> nginx HTTPS :4443)"

        croncmd="/usr/bin/certbot renew --quiet --deploy-hook \"nginx -s reload\""
        cronjob="30 3 * * 2 $croncmd"
        ( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab -
        if [ $? -eq 0 ]; then
            echo "Cert renewal Cronjob successfully created"
            crontab -l | grep "$croncmd"
        fi
    fi
    nginx -s quit
fi

# Start supervisord
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf