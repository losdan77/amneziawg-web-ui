#!/usr/bin/env python3
import os
import json
import subprocess
import tempfile
import uuid
import base64
import random
import secrets
import requests
import calendar
import ipaddress
import socket
import re
from urllib.parse import quote
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_socketio import SocketIO
import threading
import time
from datetime import datetime, timezone

# Get the absolute path to the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# Essential environment variables
NGINX_PORT = os.getenv('NGINX_PORT', '80')
AUTO_START_SERVERS = os.getenv('AUTO_START_SERVERS', 'true').lower() == 'true'
DEFAULT_MTU = int(os.getenv('DEFAULT_MTU', '1280'))
DEFAULT_SUBNET = os.getenv('DEFAULT_SUBNET', '10.0.0.0/24')
DEFAULT_PORT = int(os.getenv('DEFAULT_PORT', '51820'))
DEFAULT_DNS = os.getenv('DEFAULT_DNS', '8.8.8.8,1.1.1.1')
CLIENT_EXPIRATION_CHECK_INTERVAL = int(os.getenv('CLIENT_EXPIRATION_CHECK_INTERVAL', '60'))
LINK_HEALTH_CHECK_INTERVAL = int(os.getenv('LINK_HEALTH_CHECK_INTERVAL', '15'))
LINK_HANDSHAKE_TIMEOUT = int(os.getenv('LINK_HANDSHAKE_TIMEOUT', '3600'))
RU_SPLIT_CIDR_FILE = os.getenv('RU_SPLIT_CIDR_FILE', '/etc/amnezia/ru_cidrs.txt')
RU_SPLIT_FETCH_URL = os.getenv('RU_SPLIT_FETCH_URL', 'https://www.ipdeny.com/ipblocks/data/countries/ru.zone')
RU_SPLIT_AUTO_FETCH = os.getenv('RU_SPLIT_AUTO_FETCH', 'true').lower() == 'true'
RU_SPLIT_INLINE_CIDRS = os.getenv('RU_SPLIT_INLINE_CIDRS', '')

# Parse DNS servers from comma-separated string
DNS_SERVERS = [dns.strip() for dns in DEFAULT_DNS.split(',') if dns.strip()]

# Fixed values for other settings
WEB_UI_PORT = 5000
CONFIG_DIR = '/etc/amnezia'
WIREGUARD_CONFIG_DIR = os.path.join(CONFIG_DIR, 'amneziawg')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'web_config.json')
XRAY_CONFIG_DIR = os.path.join(CONFIG_DIR, 'xray')
XRAY_CONFIG_FILE = os.path.join(XRAY_CONFIG_DIR, 'config.json')
XRAY_BASE_PORT = int(os.getenv('XRAY_BASE_PORT', '8443'))
# Ports 9443-9642: internal-only Xray inbounds for stream-routed (port-443) REALITY servers.
# These are NOT published to the host; nginx stream proxies from external :443 by SNI.
XRAY_STREAM_BASE_PORT = int(os.getenv('XRAY_STREAM_BASE_PORT', '9443'))
NGINX_STREAM_CONFIG_FILE = '/etc/nginx/stream_reality.conf'
PUBLIC_IP_SERVICE = 'http://ifconfig.me'
ENABLE_OBFUSCATION = True

# Curated list of domains suitable as REALITY mask targets.
#
# SELECTION CRITERIA:
#   1. Reachable from a foreign VPS (not geo-blocking non-RU IPs) — critical for REALITY handshake
#   2. Not blocked inside Russia — ideally whitelisted by ISPs
#   3. TLS 1.3 + H2, stable, high-traffic (looks natural)
#
# Russian domains may geo-block foreign IPs — always verify from your VPS before use:
#
#   for d in max.ru web.max.ru vk.com yandex.ru gosuslugi.ru sberbank.ru; do
#     timeout 5 bash -c "echo Q | openssl s_client -connect $d:443 -servername $d 2>&1" \
#       | grep -q CONNECTED && echo "OK  $d" || echo "FAIL $d"
#   done
REALITY_SNI_PRESETS = [
    # ── ★ ЛУЧШИЕ для белых списков РФ (из рабочих WL-конфигов 2025-2026) ─────────────────────
    # Эти домены встречаются в реально работающих whitelist-конфигах для МТС/Мегафон/Билайн.
    # ВАЖНО: домен должен быть доступен с вашего VPS (проверьте: openssl s_client -connect vkvideo.ru:443)
    {"host": "vkvideo.ru:443",             "desc": "★ VK Video — в белых списках МТС/Мегафон, рекомендован для WL"},
    {"host": "rutube.ru:443",              "desc": "★ Rutube — государственный видеохостинг, широко разрешён в WL"},
    {"host": "cloud.mail.ru:443",          "desc": "★ Mail.ru Cloud — фигурирует в рабочих WL-конфигах"},
    {"host": "ir.ozone.ru:443",            "desc": "★ Ozon CDN — встречается в whitelist-конфигах"},
    {"host": "www.vk.com:443",             "desc": "★ ВКонтакте — используется в рабочих WL-конфигах"},
    # ── Иностранные: глобально доступны + в белых списках RU ISP ─────────────────────────────
    {"host": "www.microsoft.com:443",      "desc": "Microsoft — Windows Update, в белых списках всех ISP"},
    {"host": "www.apple.com:443",          "desc": "Apple — Software Update, широко разрешён"},
    {"host": "addons.mozilla.org:443",     "desc": "Mozilla CDN (Cloudflare) — обновления Firefox"},
    {"host": "dl.google.com:443",          "desc": "Google Downloads — обновления Chrome/Android"},
    {"host": "github.com:443",             "desc": "GitHub — не заблокирован в РФ, доступен глобально"},
    {"host": "cdn.jsdelivr.net:443",       "desc": "jsDelivr CDN — популярный CDN, TLS 1.3"},
    {"host": "releases.ubuntu.com:443",    "desc": "Ubuntu CDN — обновления ОС, не блокируется"},
    {"host": "www.cloudflare.com:443",     "desc": "Cloudflare — инфраструктурный домен"},
    # ── Мессенджер Макс (VK Max) — проверить доступность с VPS ──────────────────────────────
    {"host": "max.ru:443",                 "desc": "Max — главный домен мессенджера"},
    {"host": "web.max.ru:443",             "desc": "Max — веб-версия мессенджера (высокий трафик)"},
    {"host": "static.max.ru:443",          "desc": "Max — статика / CDN"},
    {"host": "api.max.ru:443",             "desc": "Max — API"},
    {"host": "userapi.com:443",            "desc": "VK/Max — CDN медиафайлов и аватаров"},
    {"host": "vk-cdn.net:443",             "desc": "VK/Max — CDN видео и аудио"},
    {"host": "vkuseraudio.net:443",        "desc": "VK/Max — стриминг аудио"},
    {"host": "vkuservideo.net:443",        "desc": "VK/Max — стриминг видео"},
    # ── ВКонтакте — проверить доступность с VPS ─────────────────────────────────────────────
    {"host": "vk.com:443",                 "desc": "ВКонтакте — соцсеть"},
    {"host": "id.vk.com:443",              "desc": "VK ID — авторизация"},
    {"host": "m.vk.com:443",               "desc": "ВКонтакте — мобильная версия"},
    # ── Яндекс — проверить доступность с VPS ────────────────────────────────────────────────
    {"host": "yandex.ru:443",              "desc": "Яндекс — главная страница"},
    {"host": "ya.ru:443",                  "desc": "Яндекс — короткий домен"},
    {"host": "yastatic.net:443",           "desc": "Яндекс — CDN статики"},
    {"host": "yandex.net:443",             "desc": "Яндекс — инфраструктурный домен"},
    {"host": "mail.yandex.ru:443",         "desc": "Яндекс.Почта"},
    # ── Mail.ru Group / VK Tech — проверить доступность с VPS ───────────────────────────────
    {"host": "mail.ru:443",                "desc": "Mail.ru — почта"},
    {"host": "ok.ru:443",                  "desc": "Одноклассники"},
    {"host": "my.mail.ru:443",             "desc": "Mail.ru — социальная сеть"},
    # ── Банки и финансы — проверить доступность с VPS ───────────────────────────────────────
    {"host": "www.tbank.ru:443",           "desc": "Т-Банк (Тинькофф)"},
    {"host": "www.sberbank.ru:443",        "desc": "Сбербанк"},
    {"host": "online.sberbank.ru:443",     "desc": "Сбербанк Онлайн"},
    {"host": "www.vtb.ru:443",             "desc": "ВТБ"},
    {"host": "alfabank.ru:443",            "desc": "Альфа-Банк"},
    {"host": "www.raiffeisen.ru:443",      "desc": "Райффайзен Банк"},
    # ── Госсервисы — проверить доступность с VPS ────────────────────────────────────────────
    {"host": "www.gosuslugi.ru:443",       "desc": "Госуслуги — портал госсервисов РФ"},
    {"host": "esia.gosuslugi.ru:443",      "desc": "ЕСИА — авторизация Госуслуг"},
    {"host": "mos.ru:443",                 "desc": "Mos.ru — портал Москвы"},
    {"host": "www.nalog.gov.ru:443",       "desc": "ФНС — налоговая служба"},
    {"host": "pfr.gov.ru:443",             "desc": "СФР (ПФР) — пенсионный фонд"},
    # ── СМИ и медиа — проверить доступность с VPS ───────────────────────────────────────────
    {"host": "ria.ru:443",                 "desc": "РИА Новости — государственное СМИ"},
    {"host": "1tv.ru:443",                 "desc": "Первый канал"},
    {"host": "rbc.ru:443",                 "desc": "РБК — деловые новости"},
    {"host": "kommersant.ru:443",          "desc": "Коммерсантъ"},
    {"host": "tass.ru:443",                "desc": "ТАСС — государственное СМИ"},
    {"host": "www.kp.ru:443",              "desc": "Комсомольская правда"},
    {"host": "lenta.ru:443",               "desc": "Лента.ру — новости"},
    {"host": "iz.ru:443",                  "desc": "Известия"},
    {"host": "gazeta.ru:443",              "desc": "Газета.ру"},
    # ── Стриминг и развлечения — проверить доступность с VPS ────────────────────────────────
    {"host": "www.ivi.ru:443",             "desc": "IVI — стриминг видео"},
    {"host": "www.kinopoisk.ru:443",       "desc": "Кинопоиск (Яндекс)"},
    {"host": "okko.tv:443",                "desc": "Okko — стриминг (Сбер)"},
    {"host": "more.tv:443",                "desc": "more.tv — стриминг НТВ"},
    {"host": "premier.one:443",            "desc": "PREMIER — стриминг"},
    # ── Маркетплейсы и e-commerce — проверить доступность с VPS ─────────────────────────────
    {"host": "www.wildberries.ru:443",     "desc": "Wildberries — маркетплейс"},
    {"host": "www.ozon.ru:443",            "desc": "Ozon — маркетплейс"},
    {"host": "www.avito.ru:443",           "desc": "Авито — объявления"},
    {"host": "www.dns-shop.ru:443",        "desc": "DNS — магазин электроники"},
    {"host": "www.citilink.ru:443",        "desc": "Ситилинк — электроника"},
]

print(f"Base directory: {BASE_DIR}")
print(f"Template directory: {TEMPLATE_DIR}")
print(f"Static directory: {STATIC_DIR}")
# Print environment configuration for debugging
print("=== Environment Configuration ===")
print(f"NGINX_PORT: {NGINX_PORT}")
print(f"AUTO_START_SERVERS: {AUTO_START_SERVERS}")
print(f"DEFAULT_MTU: {DEFAULT_MTU}")
print(f"DEFAULT_SUBNET: {DEFAULT_SUBNET}")
print(f"DEFAULT_PORT: {DEFAULT_PORT}")
print(f"DEFAULT_DNS: {DEFAULT_DNS}")
print(f"DNS_SERVERS: {DNS_SERVERS}")
print("==================================")
print("Fixed Configuration:")
print(f"WEB_UI_PORT: {WEB_UI_PORT} (internal)")
print(f"CONFIG_DIR: {CONFIG_DIR}")
print(f"ENABLE_OBFUSCATION: {ENABLE_OBFUSCATION}")
print("==================================")

# Check if directories exist
print(f"Templates exist: {os.path.exists(TEMPLATE_DIR)}")
print(f"Static exist: {os.path.exists(STATIC_DIR)}")
if os.path.exists(TEMPLATE_DIR):
    print(f"Template files: {os.listdir(TEMPLATE_DIR)}")
if os.path.exists(STATIC_DIR):
    print(f"Static files: {os.listdir(STATIC_DIR)}")

app = Flask(__name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)
app.secret_key = os.urandom(24)
socketio = SocketIO(
    app,
    async_mode='eventlet',
    cors_allowed_origins="*",  # Allow all origins for development
    path='/socket.io'  # Explicitly set the path
)

class AmneziaManager:
    def __init__(self):
        self.config_lock = threading.RLock()
        self.stop_expiration_worker = threading.Event()
        self.config = self.load_config()
        self.ensure_directories()
        self.ru_split_cidrs = self.load_ru_split_cidrs()
        self.public_ip = self.detect_public_ip()
        self.migrate_clients_expiration_fields()
        self.migrate_server_link_fields()

        # Keep derived configs in sync on every startup.
        # This ensures nginx/xray configs are regenerated after container restarts.
        try:
            self._write_xray_config()
            self._write_vless_nginx_locations()
            self._write_vless_stream_config()
        except Exception as e:
            print(f"Failed initializing vless configs: {e}")

        # Auto-start servers based on environment variable
        if AUTO_START_SERVERS:
            self.auto_start_servers()

        self.start_client_expiration_worker()
        self.start_link_health_worker()

    def _normalize_duration_code(self, duration_code):
        """Normalize user-provided duration to internal code."""
        if duration_code is None:
            return "forever"

        duration_text = str(duration_code).strip().lower()
        aliases = {
            "1m": "1m",
            "month": "1m",
            "1month": "1m",
            "3m": "3m",
            "3months": "3m",
            "6m": "6m",
            "6months": "6m",
            "12m": "12m",
            "year": "12m",
            "1y": "12m",
            "12months": "12m",
            "forever": "forever",
            "permanent": "forever",
            "lifetime": "forever",
            "unlimited": "forever",
            "navsegda": "forever",
            "навсегда": "forever"
        }
        normalized = aliases.get(duration_text)
        if not normalized:
            raise ValueError(f"Unsupported client duration: {duration_code}")
        return normalized

    def _duration_label(self, duration_code):
        labels = {
            "1m": "1 month",
            "3m": "3 months",
            "6m": "6 months",
            "12m": "1 year",
            "forever": "Forever"
        }
        return labels.get(duration_code, "Forever")

    def _add_calendar_months_utc(self, base_ts, months):
        """Add calendar months in UTC without fixed-day approximations."""
        dt = datetime.fromtimestamp(base_ts, tz=timezone.utc)
        month_index = dt.month - 1 + months
        year = dt.year + month_index // 12
        month = month_index % 12 + 1
        day = min(dt.day, calendar.monthrange(year, month)[1])
        shifted = dt.replace(year=year, month=month, day=day)
        return shifted.timestamp()

    def _calculate_expires_at(self, duration_code, base_ts):
        duration = self._normalize_duration_code(duration_code)
        months_map = {"1m": 1, "3m": 3, "6m": 6, "12m": 12}
        if duration == "forever":
            return None
        return self._add_calendar_months_utc(base_ts, months_map[duration])

    def _is_client_expired(self, client_config, now_ts=None):
        expires_at = client_config.get("expires_at")
        if expires_at is None:
            return False
        now_value = now_ts if now_ts is not None else time.time()
        return now_value >= float(expires_at)

    def _sync_client_expiration_fields(self, server_client, global_client, duration_code, expires_at):
        duration_label = self._duration_label(duration_code)
        updates = {
            "duration_code": duration_code,
            "duration_label": duration_label,
            "expires_at": expires_at
        }
        for key, value in updates.items():
            server_client[key] = value
            if global_client is not None:
                global_client[key] = value

    def migrate_clients_expiration_fields(self):
        """Backfill expiration fields for old clients after upgrades."""
        updated = False
        now_ts = time.time()

        for server in self.config.get("servers", []):
            for server_client in server.get("clients", []):
                global_client = self.config.get("clients", {}).get(server_client.get("id"))
                raw_duration = server_client.get("duration_code") or (global_client or {}).get("duration_code") or "forever"
                created_at = server_client.get("created_at") or (global_client or {}).get("created_at") or now_ts
                expires_at = server_client.get("expires_at")
                if expires_at is None and global_client is not None:
                    expires_at = global_client.get("expires_at")

                try:
                    duration_code = self._normalize_duration_code(raw_duration)
                except ValueError:
                    duration_code = "forever"

                if duration_code != "forever" and expires_at is None:
                    expires_at = self._calculate_expires_at(duration_code, created_at)
                    updated = True

                if "duration_code" not in server_client or "duration_label" not in server_client or "expires_at" not in server_client:
                    updated = True
                if global_client is not None and (
                    "duration_code" not in global_client or "duration_label" not in global_client or "expires_at" not in global_client
                ):
                    updated = True

                self._sync_client_expiration_fields(server_client, global_client, duration_code, expires_at)

        if updated:
            self.save_config()

    def migrate_server_link_fields(self):
        """Backfill linked-server fields for backward compatibility."""
        updated = False
        for server in self.config.get("servers", []):
            mode = server.get("mode", "standalone")
            if mode not in ("standalone", "edge_linked"):
                mode = "standalone"
            if server.get("mode") != mode:
                server["mode"] = mode
                updated = True

            if mode == "edge_linked":
                upstream = server.get("upstream")
                if not isinstance(upstream, dict):
                    server["mode"] = "standalone"
                    server["upstream"] = None
                    server["egress_interface"] = "eth+"
                    updated = True
                    continue

                if not upstream.get("interface"):
                    upstream["interface"] = f"{server['interface']}-up"
                    updated = True
                if not upstream.get("config_path"):
                    upstream["config_path"] = os.path.join(
                        WIREGUARD_CONFIG_DIR,
                        f"{upstream['interface']}.conf"
                    )
                    updated = True
                if upstream.get("obfuscation_enabled") is not True:
                    upstream["obfuscation_enabled"] = True
                    updated = True
                if not upstream.get("obfuscation_params"):
                    upstream["obfuscation_params"] = self.generate_obfuscation_params(server.get("mtu", DEFAULT_MTU))
                    updated = True
                if not upstream.get("client_public_key") and upstream.get("private_key"):
                    upstream["client_public_key"] = self.execute_command(f"echo '{upstream['private_key']}' | wg pubkey") or ""
                    updated = True
                if not upstream.get("table_id"):
                    try:
                        table_offset = int(server["id"][:2], 16) % 100
                    except ValueError:
                        table_offset = random.randint(1, 99)
                    upstream["table_id"] = 200 + table_offset
                    updated = True

                if server.get("linked_failover_mode") not in ("fail_close", "fail_open"):
                    server["linked_failover_mode"] = "fail_close"
                    updated = True
                if server.get("routing_state") not in ("upstream", "local"):
                    server["routing_state"] = "upstream"
                    updated = True
                if "split_ru_local" not in upstream:
                    upstream["split_ru_local"] = True
                    updated = True
                expected_egress = "eth+" if server.get("routing_state") == "local" else upstream["interface"]
            else:
                expected_egress = "eth+"
                if server.get("linked_failover_mode") is not None:
                    server["linked_failover_mode"] = None
                    updated = True
                if server.get("routing_state") is not None:
                    server["routing_state"] = None
                    updated = True

            if server.get("egress_interface") != expected_egress:
                server["egress_interface"] = expected_egress
                updated = True

        if updated:
            self.save_config()

    def _to_bool(self, value, default=False):
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    def _normalize_cidr_list(self, entries):
        cidrs = []
        seen = set()
        for item in entries:
            value = str(item).strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if network.version != 4:
                continue
            network_text = str(network)
            if network_text in seen:
                continue
            seen.add(network_text)
            cidrs.append(network_text)
        return cidrs

    def load_ru_split_cidrs(self):
        """Load CIDR ranges that should use local RU egress."""
        inline_parts = []
        for chunk in RU_SPLIT_INLINE_CIDRS.replace(",", "\n").splitlines():
            chunk = chunk.strip()
            if chunk:
                inline_parts.append(chunk)
        if inline_parts:
            cidrs = self._normalize_cidr_list(inline_parts)
            print(f"Loaded RU split CIDRs from inline env: {len(cidrs)}")
            return cidrs

        file_entries = []
        if os.path.exists(RU_SPLIT_CIDR_FILE):
            try:
                with open(RU_SPLIT_CIDR_FILE, "r") as f:
                    for line in f:
                        value = line.strip()
                        if value and not value.startswith("#"):
                            file_entries.append(value)
            except Exception as e:
                print(f"Failed reading RU split CIDR file: {e}")

        cidrs = self._normalize_cidr_list(file_entries)
        if cidrs:
            print(f"Loaded RU split CIDRs from file: {len(cidrs)}")
            return cidrs

        if RU_SPLIT_AUTO_FETCH:
            try:
                response = requests.get(RU_SPLIT_FETCH_URL, timeout=15)
                if response.status_code == 200:
                    fetched = [line.strip() for line in response.text.splitlines() if line.strip()]
                    cidrs = self._normalize_cidr_list(fetched)
                    if cidrs:
                        try:
                            with open(RU_SPLIT_CIDR_FILE, "w") as f:
                                f.write("\n".join(cidrs) + "\n")
                        except Exception as e:
                            print(f"Failed writing RU split CIDR cache: {e}")
                        print(f"Fetched RU split CIDRs: {len(cidrs)}")
                        return cidrs
            except Exception as e:
                print(f"Failed fetching RU split CIDRs: {e}")

        print("RU split CIDRs are empty; split routing to local RU egress is disabled.")
        return []

    def prune_expired_clients(self):
        """Delete expired clients and return list of removed IDs."""
        expired_clients = []
        now_ts = time.time()

        with self.config_lock:
            for client_id, client in list(self.config.get("clients", {}).items()):
                if self._is_client_expired(client, now_ts):
                    expired_clients.append((client.get("server_id"), client_id))

        removed_ids = []
        for server_id, client_id in expired_clients:
            if server_id and self.delete_client(server_id, client_id, reason="expired"):
                removed_ids.append(client_id)
        return removed_ids

    def client_expiration_worker(self):
        """Background worker that removes expired clients."""
        while not self.stop_expiration_worker.is_set():
            try:
                removed_ids = self.prune_expired_clients()
                if removed_ids:
                    print(f"Expired clients removed: {', '.join(removed_ids)}")
            except Exception as e:
                print(f"Failed to prune expired clients: {e}")
            self.stop_expiration_worker.wait(CLIENT_EXPIRATION_CHECK_INTERVAL)

    def start_client_expiration_worker(self):
        worker = threading.Thread(target=self.client_expiration_worker, daemon=True)
        worker.start()

    def is_interface_running(self, interface):
        if not interface:
            return False
        result = self.execute_command(f"ip link show {interface} 2>/dev/null")
        return bool(result and "state UNKNOWN" in result)

    def get_upstream_handshake_age(self, upstream_interface, upstream_public_key):
        if not upstream_interface or not upstream_public_key:
            return None
        output = self.execute_command(f"/usr/bin/awg show {upstream_interface} latest-handshakes")
        if not output:
            return None

        now_ts = int(time.time())
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            if parts[0].strip() != upstream_public_key.strip():
                continue
            try:
                handshake_ts = int(parts[1].strip())
            except ValueError:
                return None
            if handshake_ts <= 0:
                return None
            return max(0, now_ts - handshake_ts)
        return None

    def is_upstream_healthy(self, server):
        upstream = server.get("upstream") or {}
        upstream_interface = upstream.get("interface")
        upstream_public_key = upstream.get("public_key")
        if not upstream_interface or not upstream_public_key:
            return False, None

        link_state = self.execute_command(f"ip link show {upstream_interface} 2>/dev/null")
        if not (link_state and "state UNKNOWN" in link_state):
            return False, None

        age = self.get_upstream_handshake_age(upstream_interface, upstream_public_key)
        if age is None:
            return False, None
        return age <= LINK_HANDSHAKE_TIMEOUT, age

    def switch_server_egress(self, server, target_state):
        """Switch linked server egress between upstream and local."""
        if target_state not in ("upstream", "local"):
            return False
        if server.get("mode") != "edge_linked":
            return False

        interface = server.get("interface")
        subnet = server.get("subnet")
        upstream_interface = ((server.get("upstream") or {}).get("interface"))
        current_egress = server.get("egress_interface", "eth+")

        if target_state == "upstream":
            new_egress = upstream_interface
            if not new_egress:
                return False
            if not self.start_upstream_link(server):
                return False
        else:
            new_egress = "eth+"
            self.cleanup_upstream_routing(server)

        if current_egress != new_egress:
            self.cleanup_iptables(interface, subnet, current_egress)
            if not self.setup_iptables(interface, subnet, new_egress):
                return False

        server["egress_interface"] = new_egress
        server["routing_state"] = target_state
        self.save_config()
        print(f"Linked server {server.get('name')} switched routing to {target_state}")
        return True

    def link_health_worker(self):
        """Monitor linked servers and apply failover policy."""
        while not self.stop_expiration_worker.is_set():
            try:
                for server in self.config.get("servers", []):
                    if server.get("mode") != "edge_linked":
                        continue
                    if not self.is_interface_running(server.get("interface")):
                        continue

                    failover_mode = server.get("linked_failover_mode", "fail_close")
                    healthy, handshake_age = self.is_upstream_healthy(server)
                    if healthy:
                        if server.get("routing_state") != "upstream":
                            self.switch_server_egress(server, "upstream")
                        if handshake_age is not None:
                            print(f"Linked health OK for {server.get('name')}, handshake age={handshake_age}s")
                    else:
                        if failover_mode == "fail_open" and server.get("routing_state") != "local":
                            self.switch_server_egress(server, "local")
                            print(f"Linked health degraded for {server.get('name')}, switched to local egress")
                        elif failover_mode == "fail_close":
                            print(f"Linked health degraded for {server.get('name')} (fail_close active)")
            except Exception as e:
                print(f"Failed linked health check: {e}")
            self.stop_expiration_worker.wait(LINK_HEALTH_CHECK_INTERVAL)

    def start_link_health_worker(self):
        worker = threading.Thread(target=self.link_health_worker, daemon=True)
        worker.start()

    def ensure_directories(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.makedirs(WIREGUARD_CONFIG_DIR, exist_ok=True)
        os.makedirs(XRAY_CONFIG_DIR, exist_ok=True)
        os.makedirs('/var/log/amnezia', exist_ok=True)

    def detect_public_ip(self):
        """Detect the public IP address of the server"""
        try:
            # Try multiple services in case one fails
            services = [
                'http://ifconfig.me',
                'https://api.ipify.org',
                'https://ident.me'
            ]

            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        if self.is_valid_ip(ip):
                            print(f"Detected public IP: {ip}")
                            return ip
                except:
                    continue

            # Fallback: try to get from network interfaces
            try:
                result = self.execute_command("ip route get 1 | awk '{print $7}' | head -1")
                if result and self.is_valid_ip(result):
                    print(f"Detected local IP: {result}")
                    return result
            except:
                pass

        except Exception as e:
            print(f"Failed to detect public IP: {e}")

        return "YOUR_SERVER_IP"  # Fallback

    def is_valid_ip(self, ip):
        """Check if the string is a valid IP address"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False

    def auto_start_servers(self):
        """Auto-start servers that have config files and were running before"""
        print("Checking for existing servers to auto-start...")
        for server in self.config.get("servers", []):
            # Only WireGuard/AmneziaWG servers are started by this container.
            if server.get("protocol") != "wireguard":
                continue

            config_path = server.get("config_path")
            if not config_path:
                continue

            if os.path.exists(config_path):
                current_status = self.get_server_status(server.get('id'))
                if current_status == 'stopped' and server.get('auto_start', True):
                    print(f"Auto-starting server: {server.get('name')}")
                    self.start_server(server.get('id'))

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Add bandwidth_tiers if not present (backward compatibility)
                if 'bandwidth_tiers' not in config:
                    config['bandwidth_tiers'] = {
                        'free': {'name': 'Free', 'limit_mbit': 6, 'burst_mbit': 10},
                        'vip': {'name': 'VIP', 'limit_mbit': 50, 'burst_mbit': 100},
                        'super_vip': {'name': 'Super VIP', 'limit_mbit': 0, 'burst_mbit': 0}  # 0 = unlimited
                    }
                return config
        return {
            "servers": [], 
            "clients": {},
            "bandwidth_tiers": {
                'free': {'name': 'Free', 'limit_mbit': 6, 'burst_mbit': 10},
                'vip': {'name': 'VIP', 'limit_mbit': 50, 'burst_mbit': 100},
                'super_vip': {'name': 'Super VIP', 'limit_mbit': 0, 'burst_mbit': 0}
            }
        }

    def save_config(self):
        with self.config_lock:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)

    def execute_command(self, command):
        """Execute shell command and return result"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {e}")
            return None

    def _sanitize_label(self, value, fallback="VPN"):
        text = str(value or "").strip()
        if not text:
            return fallback
        text = re.sub(r"[\r\n\t]+", " ", text).strip()
        return text[:64]

    def _validate_domain(self, domain):
        value = str(domain or "").strip().lower()
        if not value:
            raise ValueError("domain is required for VLESS server")
        if len(value) > 253:
            raise ValueError("domain is too long")
        if not re.fullmatch(r"[a-z0-9.-]+", value):
            raise ValueError("domain must contain only letters, digits, dot, and hyphen")
        if value.startswith("-") or value.endswith("-") or ".." in value:
            raise ValueError("domain format is invalid")
        return value

    def _normalize_vless_path(self, path):
        value = str(path or "").strip()
        if not value:
            raise ValueError("path is required for VLESS xhttp")
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        if re.search(r"\s", value):
            raise ValueError("path must not contain whitespace")
        if len(value) > 200:
            raise ValueError("path is too long")
        return value

    def _normalize_xhttp_mode(self, mode):
        # packet-up: each upstream chunk is a separate HTTP POST — looks like browser file uploads,
        # harder to fingerprint than a persistent stream.  Recommended for whitelist-bypass setups.
        value = str(mode or "").strip().lower() or "packet-up"
        allowed = {"stream-up", "stream-down", "packet-up", "auto"}
        if value not in allowed:
            raise ValueError(f"mode must be one of: {', '.join(sorted(allowed))}")
        return value

    def _vless_is_reality(self, vless):
        """REALITY+XHTTP terminates TLS in Xray; legacy mode uses Nginx TLS + xhttp with security none."""
        if not vless:
            return False
        if vless.get("security") == "reality":
            return True
        return bool(vless.get("reality_private_key"))

    def _normalize_reality_dest(self, dest):
        raw = str(dest or "").strip()
        if not raw:
            raw = "www.microsoft.com:443"
        if ":" in raw:
            host_part, port_part = raw.rsplit(":", 1)
            host_part = host_part.strip().lower()
            try:
                port = int(port_part.strip())
            except ValueError as e:
                raise ValueError("reality dest port must be an integer") from e
        else:
            host_part = raw.strip().lower()
            port = 443
        if not host_part:
            raise ValueError("reality dest host is required")
        if not re.fullmatch(r"[a-z0-9.-]+", host_part):
            raise ValueError("reality dest host must contain only letters, digits, dot, and hyphen")
        if port < 1 or port > 65535:
            raise ValueError("reality dest port must be between 1 and 65535")
        return f"{host_part}:{port}", host_part

    # Foreign mask SNIs appended to every Reality server's accepted SNI list.
    # Russian whitelist SNIs (vkvideo.ru, max.ru, rutube.ru, …) are fine for
    # direct client → exit traffic from a non-Russian network, but RU outbound
    # DPI on the *bridge* VPS provider cuts TLS to a foreign IP whenever the
    # ClientHello SNI is a Russian whitelist domain (verified empirically:
    # SNI=rutube.ru → foreign IP dropped at ~5 s; SNI=www.google.com survives
    # 60 s+). The bridge → exit chain leg therefore must use a foreign SNI,
    # which means the exit's Reality and the upstream nginx stream map have
    # to accept it. We append the masks here so every newly created exit is
    # bridge-ready out of the box; legacy exits get migrated lazily by
    # `create_bridge_config`.
    REALITY_FOREIGN_CHAIN_MASKS = ("www.microsoft.com", "microsoft.com")

    def _reality_server_names_for_host(self, hostname):
        h = str(hostname or "").strip().lower()
        if not h:
            return list(self.REALITY_FOREIGN_CHAIN_MASKS)
        names = [h]
        if h.startswith("www.") and len(h) > 4:
            names.append(h[4:])
        else:
            names.append("www." + h)
        names.extend(self.REALITY_FOREIGN_CHAIN_MASKS)
        out = []
        seen = set()
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out

    def _parse_x25519_cli_output(self, out, exit_code=None):
        """
        Parse `xray x25519` stdout/stderr. Newer cores label the public key as
        `Password (PublicKey):` (see XTLS/Xray-core); older builds use `PublicKey:`.
        Do not use `Hash32` as pbk — it is not the x25519 public key.
        """
        text = (out or "").strip()
        token = r"([A-Za-z0-9+/=_-]+)"
        priv_patterns = (
            rf"Private\s*[Kk]ey\s*:\s*{token}",
            rf"PrivateKey\s*:\s*{token}",
        )
        pub_patterns = (
            rf"Password\s*\(\s*Public\s*[Kk]ey\s*\)\s*:\s*{token}",
            rf"Public\s*[Kk]ey\s*:\s*{token}",
        )
        priv = None
        pub = None
        for pat in priv_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                priv = m.group(1).strip()
                break
        for pat in pub_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                pub = m.group(1).strip()
                break
        if not priv or not pub:
            hint = exit_code if exit_code is not None else "?"
            raise ValueError(f"xray x25519 failed or returned unexpected output (exit {hint}): {text[:400]!r}")
        return priv, pub

    def _generate_reality_keypair(self):
        try:
            r = subprocess.run(
                ["xray", "x25519"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except FileNotFoundError as e:
            raise ValueError(
                "xray binary not found; rebuild the image so /usr/bin/xray is available for REALITY key generation"
            ) from e
        out = (r.stdout or "") + "\n" + (r.stderr or "")
        return self._parse_x25519_cli_output(out, r.returncode)

    def _generate_reality_short_id(self):
        return secrets.token_hex(4)

    def _generate_random_path(self):
        """Random URL path that looks like a legit API endpoint."""
        segments = [
            "api", "v1", "v2", "data", "update", "sync", "upload", "push",
            "stream", "feed", "event", "metrics", "health", "status",
        ]
        words = [
            "user", "device", "session", "token", "report", "log", "stats",
            "telemetry", "beacon", "ping", "batch", "bulk", "queue", "notify",
        ]
        part1 = random.choice(segments)
        part2 = random.choice(words)
        suffix = secrets.token_hex(3)
        return f"/{part1}/{part2}/{suffix}"

    def _generate_subscription_id(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8").rstrip("=")

    def _write_vless_nginx_locations(self):
        """
        Generate /etc/nginx/vless_locations.inc with proxy rules to xray container.
        This keeps nginx config in sync with stored servers list.
        """
        lines = []
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            vless = server.get("vless") or {}
            if self._vless_is_reality(vless):
                continue
            path = vless.get("path")
            inbound_port = vless.get("inbound_port")
            if not path or not inbound_port:
                continue
            # IMPORTANT:
            # - Use prefix match (^~) to allow xhttp internal URL variants (e.g. with trailing slash / query).
            # - Disable basic auth for this location, otherwise clients get 401 and never reach xray.
            lines.append(f"location ^~ {path} {{")
            lines.append("    auth_basic off;")
            lines.append(f"    proxy_pass http://xray:{int(inbound_port)};")
            lines.append("    proxy_http_version 1.1;")
            lines.append("    proxy_buffering off;")
            lines.append("    proxy_request_buffering off;")
            lines.append("    proxy_read_timeout 86400s;")
            lines.append("    proxy_send_timeout 86400s;")
            lines.append("    proxy_set_header Host $host;")
            lines.append("    proxy_set_header X-Real-IP $remote_addr;")
            lines.append("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
            lines.append("    proxy_set_header X-Forwarded-Proto $scheme;")
            lines.append("}")
            lines.append("")

        try:
            with open("/etc/nginx/vless_locations.inc", "w") as f:
                f.write("\n".join(lines))
        except Exception as e:
            print(f"Failed to write vless nginx locations: {e}")

        # Reload nginx best-effort.
        self.execute_command("nginx -s reload 2>/dev/null || true")

    def _allocate_xray_inbound_port(self):
        used = set()
        for server in self.config.get("servers", []):
            vless = server.get("vless") or {}
            port = vless.get("inbound_port")
            if port:
                try:
                    used.add(int(port))
                except ValueError:
                    continue
        # Try a small range.
        for offset in range(0, 200):
            candidate = XRAY_BASE_PORT + offset
            if candidate not in used:
                return candidate
        raise ValueError("No free xray inbound ports available")

    def _allocate_xray_stream_inbound_port(self):
        """Allocate an internal-only port for stream-routed (port 443) REALITY inbounds.

        These ports (9443+) are never published to the host; nginx stream proxies to them
        from external :443 based on the TLS SNI of the ClientHello.
        """
        used = set()
        for server in self.config.get("servers", []):
            vless = server.get("vless") or {}
            if vless.get("use_stream"):
                port = vless.get("inbound_port")
                if port:
                    try:
                        used.add(int(port))
                    except ValueError:
                        continue
        for offset in range(0, 200):
            candidate = XRAY_STREAM_BASE_PORT + offset
            if candidate not in used:
                return candidate
        raise ValueError("No free xray stream inbound ports available")

    def _write_vless_stream_config(self):
        """Generate /etc/nginx/stream_reality.conf for port-443 REALITY SNI routing.

        For every stream-routed VLESS server (use_stream=True), maps each of its
        reality_server_names to the server's internal Xray inbound port so that
        nginx stream forwards the raw TLS connection to the right Xray inbound.
        Non-REALITY SNIs (web-UI domain etc.) fall through to nginx HTTPS on :4443.
        """
        # Map: mask_hostname -> xray_inbound_port (last writer wins for same hostname)
        sni_to_port: dict = {}
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            vless = server.get("vless") or {}
            if not self._vless_is_reality(vless) or not vless.get("use_stream"):
                continue
            inbound_port = vless.get("inbound_port")
            if not inbound_port:
                continue
            for sn in (vless.get("reality_server_names") or []):
                sni_to_port[sn] = int(inbound_port)

        # Group unique ports for upstream blocks (multiple SNIs can share the same Xray port).
        port_set: set = set(sni_to_port.values())

        if not sni_to_port:
            # Check if there is already a stream block present (written by start.sh for SSL).
            # If so, keep the structural skeleton with no REALITY entries.
            try:
                with open(NGINX_STREAM_CONFIG_FILE) as f:
                    existing = f.read()
                if "stream {" not in existing:
                    # SSL not configured yet — leave the file as a comment.
                    return
                # Reconstruct the block with an empty map (no REALITY entries).
                content = self._build_stream_conf({}, set())
            except OSError:
                return
        else:
            content = self._build_stream_conf(sni_to_port, port_set)

        try:
            with open(NGINX_STREAM_CONFIG_FILE, "w") as f:
                f.write(content)
            self.execute_command("nginx -s reload 2>/dev/null || true")
        except Exception as e:
            print(f"Failed writing nginx stream config: {e}")

    def _build_stream_conf(self, sni_to_port: dict, port_set: set) -> str:
        """Render the nginx stream{} block from the SNI→port mapping."""
        map_lines = []
        for sn, port in sorted(sni_to_port.items()):
            map_lines.append(f"        {sn}   xray_{port};")

        upstream_blocks = []
        for port in sorted(port_set):
            upstream_blocks.append(
                f"    upstream xray_{port} {{\n        server xray:{port};\n    }}"
            )

        map_body = "\n".join(map_lines) if map_lines else ""
        upstreams = "\n".join(upstream_blocks)

        return (
            "stream {\n"
            "    map $ssl_preread_server_name $backend_443 {\n"
            "        hostnames;\n"
            + (f"{map_body}\n" if map_body else "")
            + "        # <REALITY_ENTRIES> — do not remove this marker; web UI uses it\n"
            "        default   nginx_https_4443;\n"
            "    }\n\n"
            "    upstream nginx_https_4443 {\n"
            "        server 127.0.0.1:4443;\n"
            "    }\n"
            + (f"\n{upstreams}\n" if upstreams else "")
            + "\n"
            "    server {\n"
            "        listen 443;\n"
            "        ssl_preread on;\n"
            "        proxy_pass $backend_443;\n"
            "    }\n"
            "}\n"
        )

    def _write_xray_config(self):
        """
        Generate xray config with one inbound per VLESS server.
        - Legacy (security=tls): xhttp with security none; TLS is terminated by nginx in front.
        - REALITY: xhttp + security reality; TLS is handled by Xray (publish inbound_port on the host).
        """
        inbounds = []
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            vless = server.get("vless") or {}
            inbound_port = vless.get("inbound_port")
            domain = vless.get("domain")
            path = vless.get("path")
            mode = vless.get("mode") or "stream-up"
            host = vless.get("host") or domain
            if not inbound_port or not domain or not path:
                continue

            clients = []
            for client in server.get("clients", []):
                if self._is_client_expired(client):
                    continue
                if not client.get("uuid"):
                    continue
                clients.append({"id": client["uuid"], "email": self._sanitize_label(client.get("name"), "client")})

            # Common XHTTP anti-DPI parameters shared by REALITY and legacy inbounds.
            # Kept in one place so both paths benefit from the same masking tuning.
            common_xhttp = {
                "path": path,
                "mode": mode,
                "host": host,
                # Random padding per packet defeats traffic-size fingerprinting by DPI.
                "xPaddingBytes": "100-1000",
                # Limit individual POST chunk size to stay within typical browser upload range.
                "scMaxEachPostBytes": 1000000,
                # Minimum interval between consecutive upstream POSTs (ms).
                "scMinPostsIntervalMs": 30,
                # Cap buffered packet-up posts per session; prevents a single client from
                # allocating unbounded memory and keeps the burst pattern close to a browser.
                "scMaxBufferedPosts": 30,
                # Keep default SSE-style Content-Type header so traffic mimics EventSource streams.
                "noSSEHeader": False,
            }
            # Socket-level options applied to the Xray inbound socket. BBR gives more stable
            # throughput under loss (common on congested RU ISP links) and shifts RTT patterns
            # away from the default cubic signature. Kernels without BBR fall back silently.
            common_sockopt = {
                "tcpcongestion": "bbr",
                "tcpKeepAliveInterval": 30,
                "tcpKeepAliveIdle": 300,
                "tcpFastOpen": True,
            }

            if self._vless_is_reality(vless):
                reality_dest = vless.get("reality_dest") or "www.microsoft.com:443"
                server_names = vless.get("reality_server_names") or self._reality_server_names_for_host(
                    reality_dest.split(":")[0]
                )
                short_ids = vless.get("reality_short_ids")
                if not short_ids:
                    sid = vless.get("reality_short_id") or ""
                    # Only include non-empty short IDs (empty string = no auth required, security risk)
                    short_ids = [sid] if sid else [""]
                priv = vless.get("reality_private_key")
                if not priv:
                    continue
                stream_settings = {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        # `target` is the current RealityObject name; `dest` is a compatible alias (XTLS docs).
                        "target": reality_dest,
                        "xver": 0,
                        "serverNames": server_names,
                        "privateKey": priv,
                        "shortIds": short_ids,
                        # Allow up to 70 s clock drift between client and server.
                        # Without this, a client with a slightly off clock gets silently rejected by
                        # Reality's timestamp check — looks like the VPN "doesn't connect".
                        "maxTimeDiff": 70000,
                    },
                    "xhttpSettings": dict(common_xhttp),
                    "sockopt": dict(common_sockopt),
                }
            else:
                stream_settings = {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": dict(common_xhttp),
                    "sockopt": dict(common_sockopt),
                }

            inbounds.append({
                "tag": f"vless-{server.get('id')}",
                "listen": "0.0.0.0",
                "port": int(inbound_port),
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "streamSettings": stream_settings,
            })

        config = {
            "log": {"loglevel": "warning"},
            "dns": {
                # DoH-first resolver list encrypts the resolver's own lookups so that
                # upstream providers / observers cannot see which domains (including
                # reality_dest targets) Xray is resolving. Plain UDP 1.1.1.1 stays
                # as a fallback for cold-start bootstrap before TLS is ready.
                "servers": [
                    {"address": "https://1.1.1.1/dns-query"},
                    {"address": "https://dns.google/dns-query"},
                    "1.1.1.1",
                ],
                "queryStrategy": "UseIP",
            },
            "inbounds": inbounds,
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {"domainStrategy": "UseIP"},
                    "tag": "direct",
                    # BBR on the outbound socket stabilises throughput for exit-to-internet
                    # traffic; TFO reduces RTT for repeat connections to popular origins.
                    "streamSettings": {
                        "sockopt": {
                            "tcpcongestion": "bbr",
                            "tcpFastOpen": True,
                        }
                    },
                }
            ],
        }

        try:
            os.makedirs(XRAY_CONFIG_DIR, exist_ok=True)
            with open(XRAY_CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Failed writing xray config: {e}")

    def create_vless_server(self, server_data):
        server_name = server_data.get("name", "New VLESS Server")
        domain = self._validate_domain(server_data.get("domain"))
        path = self._normalize_vless_path(server_data.get("path"))
        mode = self._normalize_xhttp_mode(server_data.get("xhttp_mode") or server_data.get("mode"))
        host = self._validate_domain(server_data.get("host") or domain)
        reality_dest, dest_host = self._normalize_reality_dest(server_data.get("reality_dest"))
        server_names = self._reality_server_names_for_host(dest_host)
        priv, pub = self._generate_reality_keypair()
        short_id = self._generate_reality_short_id()
        # Non-empty shortId only: the empty string allows unauthenticated connections.
        short_ids = [short_id]

        # Fingerprint: which TLS client fingerprint Xray impersonates. chrome is the safest
        # default; iOS users may benefit from ios/safari.
        _valid_fps = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
        fingerprint = str(server_data.get("fingerprint") or "chrome").strip().lower()
        if fingerprint not in _valid_fps:
            fingerprint = "chrome"

        # use_stream=True: Xray listens on an internal-only port; nginx stream proxies
        # external :443 to it based on the REALITY mask-domain SNI.  This is required for
        # ISPs that use whitelist-based blocking (port 443 + whitelisted SNI = allowed).
        use_stream = bool(server_data.get("use_stream", True))

        server_id = str(uuid.uuid4())[:6]
        subscription_id = self._generate_subscription_id()
        if use_stream:
            inbound_port = self._allocate_xray_stream_inbound_port()
            client_port = 443
        else:
            inbound_port = self._allocate_xray_inbound_port()
            client_port = inbound_port

        server_config = {
            "id": server_id,
            "name": server_name,
            "protocol": "vless",
            # top-level port is the client-facing port (443 for stream mode, inbound_port otherwise)
            "port": client_port,
            "status": "ready",
            "public_ip": self.public_ip,
            "created_at": time.time(),
            "clients": [],
            "vless": {
                "domain": domain,
                # client_port: what vless:// URIs advertise (443 in stream mode)
                "port": client_port,
                "client_port": client_port,
                "path": path,
                "mode": mode,
                "host": host,
                "security": "reality",
                "transport": "xhttp",
                "encryption": "none",
                "subscription_id": subscription_id,
                # inbound_port: what Xray actually listens on (9443+ in stream mode)
                "inbound_port": inbound_port,
                "use_stream": use_stream,
                "reality_dest": reality_dest,
                "reality_server_names": server_names,
                "reality_private_key": priv,
                "reality_public_key": pub,
                "reality_short_id": short_id,
                "reality_short_ids": short_ids,
                "reality_fingerprint": fingerprint,
            },
        }

        self.config["servers"].append(server_config)
        self.save_config()
        self._write_xray_config()
        self._write_vless_nginx_locations()
        self._write_vless_stream_config()
        return server_config

    def create_bridge_config(self, server_id, bridge_data):
        """
        Generate an Xray relay (bridge/chain) config for a Russian VPS.

        Architecture:
            Client → Bridge VPS (Russian, whitelisted IP)
                        └─ vnext ─→ Exit VPS (this server, foreign)
                                         └─→ Internet

        The bridge VPS accepts VLESS+Reality+XHTTP from clients and
        forwards all traffic to the exit node (this server) via vnext.
        TSPU allows traffic to the Russian VPS because its IP is whitelisted.
        """
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server or server.get('protocol') != 'vless':
            raise ValueError("VLESS server not found")
        vless = server.get('vless') or {}
        if not self._vless_is_reality(vless):
            raise ValueError("Bridge is only supported for REALITY servers")

        # ── Bridge VPS parameters ────────────────────────────────────────────
        bridge_ip = str(bridge_data.get('bridge_ip') or '').strip()
        if not bridge_ip:
            raise ValueError("bridge_ip is required")
        try:
            ipaddress.ip_address(bridge_ip)
        except ValueError as exc:
            raise ValueError("bridge_ip must be a valid IP address") from exc

        bridge_port = int(bridge_data.get('bridge_port') or 443)
        if not 1 <= bridge_port <= 65535:
            raise ValueError("bridge_port must be between 1 and 65535")

        raw_dest = str(bridge_data.get('bridge_reality_dest') or 'vkvideo.ru:443').strip()
        bridge_reality_dest, bridge_dest_host = self._normalize_reality_dest(raw_dest)
        bridge_server_names = self._reality_server_names_for_host(bridge_dest_host)

        bridge_path = str(bridge_data.get('bridge_path') or '').strip() or self._generate_random_path()
        if not bridge_path.startswith('/'):
            bridge_path = '/' + bridge_path

        _valid_fps = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}
        bridge_fp = str(bridge_data.get('bridge_fingerprint') or 'chrome').strip().lower()
        if bridge_fp not in _valid_fps:
            bridge_fp = 'chrome'

        # ── Generate fresh cryptographic material for the bridge inbound ────
        bridge_priv, bridge_pub = self._generate_reality_keypair()
        bridge_short_id = self._generate_reality_short_id()
        bridge_uuid = str(uuid.uuid4())

        # ── Create a dedicated exit-node client for the bridge ───────────────
        # Using a separate UUID prevents bridge traffic from being mixed with
        # regular users and makes it easier to revoke bridge access later.
        bridge_client_name = f"bridge-{bridge_ip.replace('.', '-')}"
        existing_bridge_client = next(
            (c for c in server.get('clients', [])
             if c.get('name') == bridge_client_name and not self._is_client_expired(c)),
            None
        )
        if existing_bridge_client:
            exit_uuid = existing_bridge_client['uuid']
        else:
            new_client, _, _ = self.add_vless_client(server_id, bridge_client_name, "forever")
            exit_uuid = new_client['uuid']

        # ── Exit node connection parameters ──────────────────────────────────
        # `exit_host` is the HTTP Host header the exit's xhttp inbound expects
        # (set to the server's domain at creation in `_validate_domain(host or domain)`).
        # `exit_sni` is the Reality TLS ServerName (the masked whitelist domain).
        # These are different in normal setups — using SNI as the Host header makes
        # the exit's xhttp respond 404 and the chain silently dies after the bridge
        # logs an `accepted ... -> chain-to-exit` line.
        exit_domain = vless.get('domain') or server.get('public_ip') or ''
        exit_port = int(vless.get('client_port') or vless.get('port') or 443)
        exit_path = vless.get('path') or '/'
        exit_mode = vless.get('mode') or 'packet-up'
        exit_host = vless.get('host') or exit_domain
        # Chain-leg SNI must be a foreign mask (see REALITY_FOREIGN_CHAIN_MASKS
        # comment). Pick the first foreign mask present in the exit's accepted
        # SNI list; for legacy exits created before the foreign-mask rollout,
        # migrate the exit's serverNames in place so its Reality inbound and
        # the upstream nginx stream map start accepting the foreign SNI too.
        exit_server_names = list(vless.get('reality_server_names') or [])
        foreign_masks = list(self.REALITY_FOREIGN_CHAIN_MASKS)
        exit_sni = next((n for n in exit_server_names if n in foreign_masks), None)
        if exit_sni is None:
            for fm in foreign_masks:
                if fm not in exit_server_names:
                    exit_server_names.append(fm)
            vless['reality_server_names'] = exit_server_names
            self.save_config()
            self._write_xray_config()
            self._write_vless_stream_config()
            exit_sni = foreign_masks[0]
        exit_pbk = vless.get('reality_public_key') or ''
        exit_sid = vless.get('reality_short_id') or ''
        exit_fp = vless.get('reality_fingerprint') or 'chrome'

        # Socket options reused on both bridge inbound and the chain-to-exit outbound.
        # BBR improves throughput on congested RU links; TFO shortens repeat RTTs.
        bridge_sockopt = {
            "tcpcongestion": "bbr",
            "tcpKeepAliveInterval": 30,
            "tcpKeepAliveIdle": 300,
            "tcpFastOpen": True,
        }

        # ── Compose bridge Xray config ────────────────────────────────────────
        bridge_config = {
            # `info` (one step above default `warning`) prints chain-to-exit
            # dial errors and rejection reasons — without it a host/key
            # mismatch is invisible past the first `accepted` line.
            "log": {"loglevel": "info"},
            "dns": {
                # DoH first so the bridge VPS doesn't leak exit-domain lookups to its ISP.
                "servers": [
                    {"address": "https://1.1.1.1/dns-query"},
                    {"address": "https://dns.google/dns-query"},
                    "1.1.1.1",
                ],
                "queryStrategy": "UseIP"
            },
            "inbounds": [{
                "tag": "bridge-inbound",
                "listen": "0.0.0.0",
                "port": bridge_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": bridge_uuid, "email": "bridge"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": bridge_reality_dest,
                        "xver": 0,
                        "serverNames": bridge_server_names,
                        "privateKey": bridge_priv,
                        "shortIds": [bridge_short_id],
                        "maxTimeDiff": 70000,
                    },
                    "xhttpSettings": {
                        "path": bridge_path,
                        "mode": "packet-up",
                        "host": bridge_dest_host,
                        "xPaddingBytes": "100-1000",
                        "scMaxEachPostBytes": 1000000,
                        "scMinPostsIntervalMs": 30,
                        "scMaxBufferedPosts": 30,
                        "noSSEHeader": False,
                    },
                    "sockopt": dict(bridge_sockopt),
                }
            }],
            "outbounds": [
                {
                    "tag": "chain-to-exit",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": exit_domain,
                            "port": exit_port,
                            "users": [{
                                "id": exit_uuid,
                                "flow": "",
                                "encryption": "none"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "reality",
                        "realitySettings": {
                            "fingerprint": exit_fp,
                            "serverName": exit_sni,
                            "publicKey": exit_pbk,
                            "shortId": exit_sid,
                            # Tolerate clock drift on the RU bridge (often on virtualised VPS
                            # with poor NTP sync) — matches the exit inbound setting.
                            "maxTimeDiff": 70000,
                        },
                        "xhttpSettings": {
                            "mode": exit_mode,
                            "path": exit_path,
                            # XHTTP Host header must match what the exit inbound
                            # was created with (the server's `host` field, not the
                            # Reality SNI mask).
                            "host": exit_host,
                            # Mirror the exit inbound's XHTTP tuning so the chain's
                            # upstream leg has the same browser-like pattern as clients.
                            "xPaddingBytes": "100-1000",
                            "scMaxEachPostBytes": 1000000,
                            "scMinPostsIntervalMs": 30,
                            "scMaxBufferedPosts": 30,
                            "noSSEHeader": False,
                        },
                        "sockopt": dict(bridge_sockopt),
                    }
                },
                {"protocol": "freedom", "tag": "direct"}
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-inbound"],
                    "outboundTag": "chain-to-exit"
                }]
            }
        }

        # ── Client vless:// link pointing to the bridge ───────────────────────
        label = self._sanitize_label(f"{server.get('name', 'VPN')}-via-Bridge")
        client_link = (
            f"vless://{bridge_uuid}@{bridge_ip}:{bridge_port}"
            f"?encryption=none"
            f"&security=reality"
            f"&type=xhttp"
            f"&path={quote(bridge_path, safe='')}"
            f"&mode=packet-up"
            f"&host={quote(bridge_dest_host, safe='')}"
            f"&sni={quote(bridge_server_names[0], safe='')}"
            f"&fp={quote(bridge_fp, safe='')}"
            f"&pbk={quote(bridge_pub, safe='')}"
            f"&sid={quote(bridge_short_id, safe='')}"
            f"&spx={quote('/', safe='')}"
            f"&flow="
            f"#{quote(label, safe='')}"
        )

        return {
            "bridge_config": bridge_config,
            "client_link": client_link,
            "bridge_uuid": bridge_uuid,
            "bridge_pub": bridge_pub,
            "bridge_short_id": bridge_short_id,
            "exit_uuid": exit_uuid,
            "bridge_ip": bridge_ip,
            "bridge_port": bridge_port,
            "bridge_reality_dest": bridge_reality_dest,
        }

    def generate_vless_client_link(self, server, client_config):
        vless = server.get("vless") or {}
        domain = vless.get("domain")
        # Use client_port (the port clients actually connect to).
        # For stream-routed servers this is 443; for direct servers it's the inbound port.
        port = int(
            vless.get("client_port")
            or vless.get("port")
            or vless.get("inbound_port")
            or 443
        )
        path = vless.get("path") or "/"
        mode = vless.get("mode") or "stream-up"
        host = vless.get("host") or domain

        label = self._sanitize_label(f"{server.get('name', 'Server')}-{client_config.get('name', 'Client')}")

        if self._vless_is_reality(vless):
            names = vless.get("reality_server_names") or []
            sni = names[0] if names else "www.microsoft.com"
            fp = vless.get("reality_fingerprint") or "chrome"
            pbk = vless.get("reality_public_key") or ""
            sid = vless.get("reality_short_id") or ""
            # `spx` maps to client reality spiderX (/); improves compatibility with REALITY-capable apps (HAPP, v2rayN, etc.).
            q = (
                "encryption=none"
                "&security=reality"
                "&type=xhttp"
                f"&path={quote(path, safe='')}"
                f"&mode={quote(mode, safe='')}"
                f"&host={quote(host, safe='')}"
                f"&sni={quote(sni, safe='')}"
                f"&fp={quote(fp, safe='')}"
                f"&pbk={quote(pbk, safe='')}"
                f"&sid={quote(sid, safe='')}"
                f"&spx={quote('/', safe='')}"
                "&flow="
            )
        else:
            q = (
                "encryption=none"
                "&security=tls"
                "&type=xhttp"
                f"&path={quote(path, safe='')}"
                f"&mode={quote(mode, safe='')}"
                f"&host={quote(host, safe='')}"
            )
        return f"vless://{client_config['uuid']}@{domain}:{port}?{q}#{quote(label, safe='')}"

    def add_vless_client(self, server_id, client_name, duration_code="forever"):
        """Add a client to a VLESS xhttp server (link/QR only)."""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return None
        if server.get("protocol") != "vless":
            raise ValueError("Server is not a VLESS server")

        existing = next((c for c in server.get("clients", []) if c.get("name") == client_name), None)
        if existing is not None:
            client, err = self.extend_client(server_id, existing["id"], duration_code)
            if err:
                return None
            server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
            if not server:
                return None
            link = self.generate_vless_client_link(server, client)
            return client, link, True

        created_at = time.time()
        normalized_duration = self._normalize_duration_code(duration_code)
        expires_at = self._calculate_expires_at(normalized_duration, created_at)

        client_id = str(uuid.uuid4())[:6]
        vless_uuid = str(uuid.uuid4())

        client_config = {
            "id": client_id,
            "name": client_name,
            "server_id": server_id,
            "server_name": server.get("name"),
            "status": "active",
            "created_at": created_at,
            "duration_code": normalized_duration,
            "duration_label": self._duration_label(normalized_duration),
            "expires_at": expires_at,
            "extended_count": 0,
            "protocol": "vless",
            "uuid": vless_uuid,
        }

        server.setdefault("clients", []).append(client_config)
        self.config.setdefault("clients", {})[client_id] = client_config
        self.save_config()

        self._write_xray_config()

        link = self.generate_vless_client_link(server, client_config)
        return client_config, link, False

    def generate_wireguard_keys(self):
        """Generate real WireGuard keys"""
        try:
            private_key = self.execute_command("wg genkey")
            if private_key:
                public_key = self.execute_command(f"echo '{private_key}' | wg pubkey")
                return {
                    "private_key": private_key,
                    "public_key": public_key
                }
        except Exception as e:
            print(f"Key generation failed: {e}")

        # Fallback - generate random keys
        fake_private = base64.b64encode(os.urandom(32)).decode('utf-8')
        fake_public = base64.b64encode(os.urandom(32)).decode('utf-8')
        return {
            "private_key": fake_private,
            "public_key": fake_public
        }

    def generate_preshared_key(self):
        """Generate preshared key"""
        try:
            return self.execute_command("wg genpsk")
        except:
            return base64.b64encode(os.urandom(32)).decode('utf-8')

    def generate_obfuscation_params(self, mtu=1420):
        import random
        S1 = random.randint(15, min(150, mtu - 148))
        # S2 must not be S1+56
        s2_candidates = [s for s in range(15, min(150, mtu - 92) + 1) if s != S1 + 56]
        S2 = random.choice(s2_candidates)
        # Jmin/Jmax bound the per-packet junk length. The legal range is
        # [4, MTU], but values near the extremes are either too small to
        # perturb DPI classifiers or large enough to cause fragmentation on
        # weak links. A realistic browser-like jitter envelope is ~[8..200]
        # bytes, which is what the validator still allows the operator to
        # override for imported configs.
        jmin_lower, jmin_upper = 8, 80
        jmax_delta_lo, jmax_delta_hi = 50, 150
        # Clamp against the hard MTU ceiling so we never produce invalid params.
        jmin_upper = min(jmin_upper, max(jmin_lower + 1, mtu - 2))
        Jmin = random.randint(jmin_lower, jmin_upper)
        jmax_lower = min(Jmin + jmax_delta_lo, mtu)
        jmax_upper = min(Jmin + jmax_delta_hi, mtu)
        if jmax_upper <= jmax_lower:
            jmax_upper = min(jmax_lower + 1, mtu)
        Jmax = random.randint(jmax_lower, jmax_upper)
        return {
            "Jc": random.randint(4, 12),
            "Jmin": Jmin,
            "Jmax": Jmax,
            "S1": S1,
            "S2": S2,
            "H1": random.randint(10000, 100000),
            "H2": random.randint(100000, 200000),
            "H3": random.randint(200000, 300000),
            "H4": random.randint(300000, 400000),
            "MTU": mtu
        }

    def validate_obfuscation_params(self, params, mtu):
        """Validate Amnezia obfuscation params against MTU constraints."""
        if not isinstance(params, dict):
            raise ValueError("Obfuscation params must be an object")

        required = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
        normalized = {}
        for key in required:
            if key not in params:
                raise ValueError(f"Missing obfuscation parameter: {key}")
            try:
                normalized[key] = int(params[key])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Obfuscation parameter {key} must be integer") from exc

        if normalized["Jc"] < 4 or normalized["Jc"] > 12:
            raise ValueError("Jc must be between 4 and 12")
        if not (normalized["Jmin"] < normalized["Jmax"] <= mtu):
            raise ValueError(f"Jmin must be less than Jmax and Jmax <= MTU ({mtu})")
        if not (15 <= normalized["S1"] <= 150 and normalized["S1"] <= (mtu - 148)):
            raise ValueError(f"S1 must be in [15,150] and <= MTU-148 ({mtu - 148})")
        if not (15 <= normalized["S2"] <= 150 and normalized["S2"] <= (mtu - 92)):
            raise ValueError(f"S2 must be in [15,150] and <= MTU-92 ({mtu - 92})")
        if normalized["S1"] + 56 == normalized["S2"]:
            raise ValueError("S1 + 56 must not equal S2")
        return normalized

    def get_default_route_info(self):
        """Return default route gateway and device."""
        route = self.execute_command("ip -4 route show default | head -n1")
        if not route:
            return None, None

        gateway = None
        device = None
        parts = route.split()
        for idx, part in enumerate(parts):
            if part == "via" and idx + 1 < len(parts):
                gateway = parts[idx + 1]
            if part == "dev" and idx + 1 < len(parts):
                device = parts[idx + 1]
        return gateway, device

    def resolve_ipv4(self, host):
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None

    def parse_endpoint(self, endpoint, fallback_port=51820):
        """Parse endpoint in host:port format."""
        value = (endpoint or "").strip()
        if not value:
            return None, None

        if ":" in value and value.count(":") == 1:
            host, port_text = value.split(":")
            try:
                return host.strip(), int(port_text.strip())
            except ValueError:
                return None, None
        return value, int(fallback_port)

    def parse_amnezia_config_text(self, config_text):
        """Parse Amnezia/WireGuard config text into interface/peer dictionaries."""
        if not config_text or not str(config_text).strip():
            raise ValueError("Upstream config text is empty")

        sections = {"Interface": {}, "Peer": {}}
        current_section = None
        for raw_line in str(config_text).splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section_name = line[1:-1].strip()
                current_section = section_name if section_name in sections else None
                continue
            if "=" not in line or not current_section:
                continue
            key, value = line.split("=", 1)
            sections[current_section][key.strip()] = value.strip()

        interface_data = sections["Interface"]
        peer_data = sections["Peer"]
        if not interface_data or not peer_data:
            raise ValueError("Upstream config must contain both [Interface] and [Peer] sections")

        required_interface = ["PrivateKey", "Address"]
        required_peer = ["PublicKey", "Endpoint"]
        for key in required_interface:
            if not interface_data.get(key):
                raise ValueError(f"Upstream config missing Interface field: {key}")
        for key in required_peer:
            if not peer_data.get(key):
                raise ValueError(f"Upstream config missing Peer field: {key}")

        return interface_data, peer_data

    def generate_upstream_config_content(self, upstream, mtu):
        config = f"""[Interface]
PrivateKey = {upstream['private_key']}
Address = {upstream['local_address']}
MTU = {mtu}
Table = off
"""

        params = upstream.get("obfuscation_params")
        if upstream.get("obfuscation_enabled") and params:
            config += f"""Jc = {params['Jc']}
Jmin = {params['Jmin']}
Jmax = {params['Jmax']}
S1 = {params['S1']}
S2 = {params['S2']}
H1 = {params['H1']}
H2 = {params['H2']}
H3 = {params['H3']}
H4 = {params['H4']}
"""

        config += f"""
[Peer]
PublicKey = {upstream['public_key']}
AllowedIPs = {upstream['allowed_ips']}
Endpoint = {upstream['endpoint']}
PersistentKeepalive = {upstream.get('persistent_keepalive', 25)}
"""
        if upstream.get("preshared_key"):
            config += f"PresharedKey = {upstream['preshared_key']}\n"
        return config

    def configure_upstream_routing(self, server):
        """Route server subnet traffic through upstream interface."""
        upstream = server.get("upstream") or {}
        table_id = int(upstream.get("table_id", 200))
        server_subnet = server["subnet"]
        upstream_interface = upstream.get("interface")
        if not upstream_interface:
            return False

        endpoint_host, endpoint_port = self.parse_endpoint(upstream.get("endpoint"), DEFAULT_PORT)
        if not endpoint_host:
            return False

        endpoint_ip = self.resolve_ipv4(endpoint_host) or endpoint_host
        gateway, default_device = self.get_default_route_info()

        self.execute_command(f"ip rule add from {server_subnet} table {table_id} priority {10000 + table_id} 2>/dev/null || true")
        self.execute_command(f"ip route replace default dev {upstream_interface} table {table_id}")

        if default_device:
            if gateway:
                self.execute_command(f"ip route replace {endpoint_ip}/32 via {gateway} dev {default_device}")
            else:
                self.execute_command(f"ip route replace {endpoint_ip}/32 dev {default_device}")
        elif gateway:
            self.execute_command(f"ip route replace {endpoint_ip}/32 via {gateway}")

        split_ru_local = self._to_bool(upstream.get("split_ru_local"), True)
        ru_route_count = 0
        if split_ru_local and default_device and self.ru_split_cidrs:
            for cidr in self.ru_split_cidrs:
                if gateway:
                    self.execute_command(f"ip route replace {cidr} via {gateway} dev {default_device} table {table_id}")
                else:
                    self.execute_command(f"ip route replace {cidr} dev {default_device} table {table_id}")
                ru_route_count += 1

        print(
            f"Upstream routing configured: subnet={server_subnet}, table={table_id}, "
            f"endpoint={endpoint_host}:{endpoint_port}, iface={upstream_interface}, "
            f"split_ru_local={split_ru_local}, ru_routes={ru_route_count}"
        )
        return True

    def cleanup_upstream_routing(self, server):
        upstream = server.get("upstream") or {}
        table_id = int(upstream.get("table_id", 200))
        server_subnet = server.get("subnet")
        if server_subnet:
            self.execute_command(f"ip rule del from {server_subnet} table {table_id} priority {10000 + table_id} 2>/dev/null || true")
        self.execute_command(f"ip route flush table {table_id} 2>/dev/null || true")
        return True

    def start_upstream_link(self, server):
        upstream = server.get("upstream") or {}
        upstream_interface = upstream.get("interface")
        config_path = upstream.get("config_path")
        if not upstream_interface or not config_path:
            return False
        if not os.path.exists(config_path):
            return False

        link_state = self.execute_command(f"ip link show {upstream_interface} 2>/dev/null")
        if not (link_state and "state UNKNOWN" in link_state):
            result = self.execute_command(f"/usr/bin/awg-quick up {upstream_interface}")
            if result is None:
                return False
        return self.configure_upstream_routing(server)

    def stop_upstream_link(self, server):
        upstream = server.get("upstream") or {}
        upstream_interface = upstream.get("interface")
        self.cleanup_upstream_routing(server)
        if not upstream_interface:
            return True
        self.execute_command(f"/usr/bin/awg-quick down {upstream_interface} 2>/dev/null || true")
        return True

    def create_wireguard_server(self, server_data):
        """Create a new WireGuard server configuration with environment defaults"""
        server_name = server_data.get('name', 'New Server')
        port = server_data.get('port', DEFAULT_PORT)
        subnet = server_data.get('subnet', DEFAULT_SUBNET)
        mtu = server_data.get('mtu', DEFAULT_MTU)
        bandwidth_tier = server_data.get('bandwidth_tier', 'free')

        # Get DNS servers from request or use environment default
        custom_dns = server_data.get('dns')
        if custom_dns:
            # Parse custom DNS from request
            if isinstance(custom_dns, str):
                dns_servers = [dns.strip() for dns in custom_dns.split(',') if dns.strip()]
            elif isinstance(custom_dns, list):
                dns_servers = custom_dns
            else:
                dns_servers = DNS_SERVERS
        else:
            dns_servers = DNS_SERVERS

        # Validate MTU
        if mtu < 1280 or mtu > 1440:
            raise ValueError(f"MTU must be between 1280 and 1440, got {mtu}")

        # Validate DNS servers
        for dns in dns_servers:
            if not self.is_valid_ip(dns):
                raise ValueError(f"Invalid DNS server IP: {dns}")

        mode = str(server_data.get('mode', 'standalone')).strip().lower()
        if mode not in ('standalone', 'edge_linked'):
            raise ValueError("mode must be 'standalone' or 'edge_linked'")

        # Fixed values for other settings
        enable_obfuscation = server_data.get('obfuscation', ENABLE_OBFUSCATION)
        if mode == 'edge_linked':
            enable_obfuscation = True
        auto_start = server_data.get('auto_start', AUTO_START_SERVERS)

        server_id = str(uuid.uuid4())[:6]
        interface_name = f"wg-{server_id}"
        config_path = os.path.join(WIREGUARD_CONFIG_DIR, f"{interface_name}.conf")

        egress_interface = "eth+"
        upstream_config = None

        # Generate server keys
        server_keys = self.generate_wireguard_keys()

        # Generate and use provided obfuscation parameters if enabled
        obfuscation_params = None
        if enable_obfuscation:
            if 'obfuscation_params' in server_data:
                obfuscation_params = self.validate_obfuscation_params(server_data['obfuscation_params'], mtu)
            else:
                obfuscation_params = self.generate_obfuscation_params(mtu)

        # Parse subnet for server IP
        subnet_parts = subnet.split('/')
        network = subnet_parts[0]
        prefix = subnet_parts[1] if len(subnet_parts) > 1 else "24"
        server_ip = self.get_server_ip(network)

        if mode == "edge_linked":
            upstream_data = server_data.get("upstream") or {}
            failover_mode = str(upstream_data.get("failover_mode", "fail_close")).strip().lower()
            if failover_mode not in ("fail_close", "fail_open"):
                raise ValueError("upstream.failover_mode must be fail_close or fail_open")
            import_config_text = str(upstream_data.get("import_config", "")).strip()
            if not import_config_text:
                raise ValueError("Linked Edge mode requires imported EU client config")
            split_ru_local = self._to_bool(upstream_data.get("split_ru_local"), True)
            imported_obfuscation = {}
            interface_cfg, peer_cfg = self.parse_amnezia_config_text(import_config_text)
            endpoint_value = peer_cfg.get("Endpoint", "")
            public_key_value = peer_cfg.get("PublicKey", "")
            allowed_ips_value = peer_cfg.get("AllowedIPs", "0.0.0.0/0")
            local_address_value = interface_cfg.get("Address", "172.31.254.2/30")
            try:
                keepalive_value = int(peer_cfg.get("PersistentKeepalive", 25))
            except (TypeError, ValueError) as exc:
                raise ValueError("PersistentKeepalive in imported config must be integer") from exc
            if keepalive_value < 1 or keepalive_value > 120:
                raise ValueError("PersistentKeepalive must be between 1 and 120")
            imported_private_key = interface_cfg.get("PrivateKey", "")
            imported_preshared_key = peer_cfg.get("PresharedKey", "")
            try:
                imported_mtu = int(interface_cfg.get("MTU", mtu))
            except (TypeError, ValueError) as exc:
                raise ValueError("MTU in imported config must be integer") from exc
            if imported_mtu < 1280 or imported_mtu > 1440:
                raise ValueError("MTU in imported config must be between 1280 and 1440")
            mtu = imported_mtu
            for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
                if key in interface_cfg and str(interface_cfg.get(key)).strip():
                    try:
                        imported_obfuscation[key] = int(str(interface_cfg[key]).strip())
                    except ValueError as exc:
                        raise ValueError(f"Invalid upstream obfuscation value for {key}") from exc
            if len(imported_obfuscation) != 9:
                raise ValueError("Imported config must include all obfuscation parameters (Jc..H4)")
            imported_obfuscation = self.validate_obfuscation_params(imported_obfuscation, mtu)

            endpoint_host, endpoint_port = self.parse_endpoint(endpoint_value, DEFAULT_PORT)

            if not endpoint_host or not endpoint_port:
                raise ValueError("For edge_linked mode, upstream endpoint must be in host:port format")
            if endpoint_port < 1 or endpoint_port > 65535:
                raise ValueError("Upstream endpoint port must be between 1 and 65535")
            if not public_key_value:
                raise ValueError("For edge_linked mode, upstream public key is required")
            try:
                ipaddress.ip_interface(local_address_value)
            except ValueError as exc:
                raise ValueError(f"Invalid upstream local_address: {local_address_value}") from exc

            upstream_interface = f"{interface_name}-up"
            upstream_config_path = os.path.join(WIREGUARD_CONFIG_DIR, f"{upstream_interface}.conf")
            upstream_keys = self.generate_wireguard_keys()
            upstream_private_key = imported_private_key or str(upstream_data.get("private_key", "")).strip() or upstream_keys["private_key"]
            upstream_client_public_key = str(upstream_data.get("client_public_key", "")).strip()
            if not upstream_client_public_key:
                if upstream_private_key:
                    upstream_client_public_key = self.execute_command(f"echo '{upstream_private_key}' | wg pubkey") or ""
                else:
                    upstream_client_public_key = upstream_keys["public_key"]
            upstream_preshared_key = imported_preshared_key

            # In linked mode, use imported/derived upstream obfuscation for RU entry server too.
            obfuscation_params = dict(imported_obfuscation)

            try:
                table_offset = int(server_id[:2], 16) % 100
            except ValueError:
                table_offset = random.randint(1, 99)

            upstream_config = {
                "interface": upstream_interface,
                "config_path": upstream_config_path,
                "endpoint": f"{endpoint_host}:{endpoint_port}",
                "public_key": public_key_value,
                "private_key": upstream_private_key,
                "client_public_key": upstream_client_public_key,
                "preshared_key": upstream_preshared_key,
                "allowed_ips": allowed_ips_value,
                "local_address": local_address_value,
                "persistent_keepalive": keepalive_value,
                "obfuscation_enabled": True,
                "obfuscation_params": imported_obfuscation,
                "table_id": 200 + table_offset,
                "split_ru_local": split_ru_local
            }
            egress_interface = upstream_interface
        else:
            failover_mode = None

        # Create WireGuard server configuration
        server_config_content = f"""[Interface]
PrivateKey = {server_keys['private_key']}
Address = {server_ip}/{prefix}
ListenPort = {port}
SaveConfig = false
MTU = {mtu}
"""

        # Add obfuscation parameters if enabled
        if enable_obfuscation and obfuscation_params:
            server_config_content += f"""Jc = {obfuscation_params['Jc']}
Jmin = {obfuscation_params['Jmin']}
Jmax = {obfuscation_params['Jmax']}
S1 = {obfuscation_params['S1']}
S2 = {obfuscation_params['S2']}
H1 = {obfuscation_params['H1']}
H2 = {obfuscation_params['H2']}
H3 = {obfuscation_params['H3']}
H4 = {obfuscation_params['H4']}
"""

        server_config = {
            "id": server_id,
            "name": server_name,
            "protocol": "wireguard",
            "port": port,
            "status": "stopped",
            "interface": interface_name,
            "config_path": config_path,
            "server_public_key": server_keys['public_key'],
            "server_private_key": server_keys['private_key'],
            "subnet": subnet,
            "server_ip": server_ip,
            "mtu": mtu,
            "public_ip": self.public_ip,
            "bandwidth_tier": bandwidth_tier,
            "obfuscation_enabled": enable_obfuscation,
            "obfuscation_params": obfuscation_params,
            "auto_start": auto_start,
            "dns": dns_servers,  # Store DNS servers
            "mode": mode,
            "upstream": upstream_config,
            "egress_interface": egress_interface,
            "linked_failover_mode": failover_mode,
            "routing_state": "upstream" if mode == "edge_linked" else None,
            "clients": [],
            "created_at": time.time()
        }

        # Save WireGuard config file
        with open(config_path, 'w') as f:
            f.write(server_config_content)

        if upstream_config:
            with open(upstream_config["config_path"], "w") as f:
                f.write(self.generate_upstream_config_content(upstream_config, mtu))

        self.config["servers"].append(server_config)
        self.save_config()

        # Auto-start if enabled (from environment or request)
        if auto_start:
            print(f"Auto-starting new server: {server_name}")
            self.start_server(server_id)

        return server_config
    
    def apply_live_config(self, interface):
        """Apply the latest config to the running WireGuard interface using wg syncconf."""
        try:
            # Use bash -c to support process substitution
            command = f"bash -c 'awg syncconf {interface} <(awg-quick strip {interface})'"
            result = self.execute_command(command)
            if result is not None:
                print(f"Live config applied to {interface}")
                return True
            else:
                print(f"Failed to apply live config to {interface}")
                return False
        except Exception as e:
            print(f"Error applying live config to {interface}: {e}")
            return False

    def get_server_ip(self, network):
        """Get server IP from network (first usable IP)"""
        parts = network.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        return "10.0.0.1"

    def get_client_ip(self, server, client_index=None):
        """Get next available client IP from server subnet"""
        # Parse server IP to get network prefix
        server_ip_parts = server['server_ip'].split('.')
        if len(server_ip_parts) != 4:
            # Fallback for invalid server IP
            return f"10.0.0.2"
        
        # Get subnet mask to determine max hosts
        subnet = server.get('subnet', '10.0.0.0/24')
        prefix = int(subnet.split('/')[-1]) if '/' in subnet else 24
        
        # Calculate max IP based on subnet mask
        # For /24 subnet: IPs 2-254 are available (1 is server, 255 is broadcast)
        # For /16 subnet: more IPs available, etc.
        if prefix == 24:
            max_last_octet = 254
        elif prefix == 16:
            max_last_octet = 255  # Can use full range for 3rd and 4th octet
        else:
            max_last_octet = 254  # Conservative default
        
        # Collect all currently used IPs in this server
        used_ips = set()
        used_ips.add(server['server_ip'])  # Server IP is used
        
        # Add all client IPs
        for client in server.get('clients', []):
            used_ips.add(client.get('client_ip', ''))
        
        # Find first available IP
        base_prefix = f"{server_ip_parts[0]}.{server_ip_parts[1]}.{server_ip_parts[2]}"
        
        # Start from .2 (since .1 is typically the server)
        for i in range(2, max_last_octet + 1):
            candidate_ip = f"{base_prefix}.{i}"
            if candidate_ip not in used_ips:
                return candidate_ip
        
        # If no IPs available in /24 range, could expand to next subnet
        # or raise an error
        raise ValueError(f"No available IP addresses in subnet {subnet}")

    def delete_server(self, server_id):
        """Delete a server and all its clients"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False

        if server.get("protocol") == "vless":
            # Remove all clients associated with this server
            self.config["clients"] = {
                k: v for k, v in self.config.get("clients", {}).items()
                if v.get("server_id") != server_id
            }
            # Remove the server
            self.config["servers"] = [s for s in self.config.get("servers", []) if s.get("id") != server_id]
            self.save_config()
            self._write_xray_config()
            self._write_vless_nginx_locations()
            self._write_vless_stream_config()
            return True

        # Stop the server if running
        if server['status'] == 'running':
            self.stop_server(server_id)

        # Remove config file
        if os.path.exists(server['config_path']):
            os.remove(server['config_path'])
        upstream_conf_path = ((server.get("upstream") or {}).get("config_path"))
        if upstream_conf_path and os.path.exists(upstream_conf_path):
            os.remove(upstream_conf_path)

        # Remove all clients associated with this server
        self.config["clients"] = {k: v for k, v in self.config["clients"].items()
                                if v.get("server_id") != server_id}

        # Remove the server
        self.config["servers"] = [s for s in self.config["servers"] if s["id"] != server_id]
        self.save_config()
        return True

    def add_wireguard_client(self, server_id, client_name, duration_code="forever"):
        """Add a client to a WireGuard server.

        If a client with the same name already exists on this server, the requested
        duration is applied like ``extend_client`` (from max(current expiry, now),
        so expired peers are extended from today).
        """
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return None

        existing = next((c for c in server["clients"] if c["name"] == client_name), None)
        if existing is not None:
            client, err = self.extend_client(server_id, existing["id"], duration_code)
            if err:
                return None
            server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
            if not server:
                return None
            config_content = self.generate_wireguard_client_config(server, client, include_comments=True)
            return client, config_content, True

        client_id = str(uuid.uuid4())[:6]

        # Generate client keys
        client_keys = self.generate_wireguard_keys()
        preshared_key = self.generate_preshared_key()

        # Assign client IP
        try:
            client_ip = self.get_client_ip(server)
        except ValueError as e:
            print(f"Error: {e}")
            return None

        # Get bandwidth tier from server
        tier = server.get('bandwidth_tier', 'free')

        created_at = time.time()
        normalized_duration = self._normalize_duration_code(duration_code)
        expires_at = self._calculate_expires_at(normalized_duration, created_at)

        # Per-client randomised keepalive breaks the timing fingerprint that
        # fixed 25-second WireGuard beacons produce across every client on a
        # server. Range 15..30 stays within values real clients commonly use
        # so the traffic still looks like legitimate WireGuard.
        persistent_keepalive = random.randint(15, 30)

        client_config = {
            "id": client_id,
            "name": client_name,
            "server_id": server_id,
            "server_name": server["name"],
            "status": "inactive",
            "created_at": created_at,
            "client_private_key": client_keys["private_key"],
            "client_public_key": client_keys["public_key"],
            "preshared_key": preshared_key,
            "client_ip": client_ip,
            "bandwidth_tier": tier,
            "obfuscation_enabled": server["obfuscation_enabled"],
            "obfuscation_params": server["obfuscation_params"],
            "persistent_keepalive": persistent_keepalive,
            "duration_code": normalized_duration,
            "duration_label": self._duration_label(normalized_duration),
            "expires_at": expires_at,
            "extended_count": 0
        }

        # Add client to server config
        client_peer_config = f"""
# Client: {client_config['name']} ({client_config['id']})
[Peer]
PublicKey = {client_keys['public_key']}
PresharedKey = {preshared_key}
AllowedIPs = {client_ip}/32
"""

        # Append client to server config file
        with open(server['config_path'], 'a') as f:
            f.write(client_peer_config)

        server["clients"].append(client_config)

        # Store in global clients dict
        self.config["clients"][client_id] = client_config
        self.save_config()
        
        # Apply live config if server is running
        if server['status'] == 'running':
            self.apply_live_config(server['interface'])
            # Apply bandwidth limit from server tier
            self.apply_bandwidth_limit(server['interface'], client_ip, tier)
            
        print(f"Client {client_config['name']} added")

        config_content = self.generate_wireguard_client_config(server, client_config, include_comments=True)
        return client_config, config_content, False

    def delete_client(self, server_id, client_id, reason="manual"):
        """Delete a client from a server and update the config file"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False

        if server.get("protocol") == "vless":
            client = next((c for c in server.get("clients", []) if c.get("id") == client_id), None)
            if not client:
                return False

            server["clients"] = [c for c in server.get("clients", []) if c.get("id") != client_id]
            if client_id in self.config.get("clients", {}):
                del self.config["clients"][client_id]
            self.save_config()
            self._write_xray_config()
            print(f"Client {server.get('name')}:{client.get('name')} removed ({reason})")
            return True

        client = next((c for c in server["clients"] if c["id"] == client_id), None)
        if not client:
            return False

        # Remove client from server's client list
        server["clients"] = [c for c in server["clients"] if c["id"] != client_id]

        # Remove from global clients dict
        if client_id in self.config["clients"]:
            del self.config["clients"][client_id]

        # Rewrite the config file without the deleted client's [Peer] block
        self.rewrite_server_conf_without_client(server, client)

        self.save_config()

        # Apply live config if server is running
        if server['status'] == 'running':
            self.apply_live_config(server['interface'])
            
        print(f"Client {server['name']}:{client['name']} removed ({reason})")

        return True

    def extend_client(self, server_id, client_id, duration_code):
        """Extend client expiration by duration from current expiry or now."""
        normalized_duration = self._normalize_duration_code(duration_code)
        now_ts = time.time()

        with self.config_lock:
            server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
            if not server:
                return None, "Server not found"

            server_client = next((c for c in server["clients"] if c["id"] == client_id), None)
            if not server_client:
                return None, "Client not found"

            global_client = self.config["clients"].get(client_id)

            current_expires_at = server_client.get("expires_at")
            if current_expires_at is not None:
                base_ts = max(float(current_expires_at), now_ts)
            else:
                base_ts = now_ts

            new_expires_at = self._calculate_expires_at(normalized_duration, base_ts)
            self._sync_client_expiration_fields(server_client, global_client, normalized_duration, new_expires_at)

            new_extended_count = int(server_client.get("extended_count", 0)) + 1
            server_client["extended_count"] = new_extended_count
            if global_client is not None:
                global_client["extended_count"] = new_extended_count

            self.save_config()
            return server_client, None
    
    def rewrite_server_conf_without_client(self, server, client):
        """Rewrite the server conf file without the specified client's [Peer] block"""
        if not os.path.exists(server['config_path']):
            return

        with open(server['config_path'], 'r') as f:
            lines = f.readlines()

        new_lines = []
        skip = False
        client_id = client.get("id")
        client_name = client.get("name", "")
        old_client_marker = f"# Client: {client_name}"
        new_client_marker = f"# Client: {client_name} ({client_id})"

        for line in lines:
            stripped = line.strip()

            # Start skipping when we find the client marker line
            if stripped in (old_client_marker, new_client_marker):
                skip = True
                continue

            # Stop skipping when we hit the next client marker line
            if skip and stripped.startswith("# Client:"):
                skip = False

            # If skipping, skip all lines until next client marker
            if skip:
                continue

            # Otherwise, keep the line
            new_lines.append(line)

        # Remove trailing blank lines if any
        while new_lines and new_lines[-1].strip() == '':
            new_lines.pop()

        with open(server['config_path'], 'w') as f:
            f.writelines(new_lines)

    def generate_wireguard_client_config(self, server, client_config, include_comments=True):
        """Generate WireGuard client configuration"""
        config = ""
        
        # Add comments only if requested
        if include_comments:
            config = f"""# AmneziaWG Client Configuration
# Server: {server['name']}
# Client: {client_config['name']}
# Generated: {time.ctime()}
# Server IP: {server['public_ip']}:{server['port']}

"""

        config += f"""[Interface]
PrivateKey = {client_config['client_private_key']}
Address = {client_config['client_ip']}/32
DNS = {', '.join(server['dns'])}
MTU = {server['mtu']}
"""

        # Add obfuscation parameters if enabled
        if client_config['obfuscation_enabled'] and client_config['obfuscation_params']:
            params = client_config['obfuscation_params']
            config += f"""Jc = {params['Jc']}
Jmin = {params['Jmin']}
Jmax = {params['Jmax']}
S1 = {params['S1']}
S2 = {params['S2']}
H1 = {params['H1']}
H2 = {params['H2']}
H3 = {params['H3']}
H4 = {params['H4']}
"""

        # Per-client keepalive if stored (new clients); fall back to 25 for legacy entries.
        keepalive = client_config.get('persistent_keepalive') or 25
        config += f"""
[Peer]
PublicKey = {server['server_public_key']}
PresharedKey = {client_config['preshared_key']}
Endpoint = {server['public_ip']}:{server['port']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {keepalive}
"""
        return config

    def setup_iptables(self, interface, subnet, egress_interface="eth+"):
        """Setup iptables rules for WireGuard interface"""
        try:
            script_path = "/app/scripts/setup_iptables.sh"
            if os.path.exists(script_path):
                result = self.execute_command(f"{script_path} {interface} {subnet} {egress_interface}")
                if result is not None:
                    print(f"iptables setup completed for {interface}")
                    return True
                else:
                    print(f"iptables setup failed for {interface}")
                    return False
            else:
                print(f"iptables script not found at {script_path}")
                return False
        except Exception as e:
            print(f"Error setting up iptables for {interface}: {e}")
            return False

    def cleanup_iptables(self, interface, subnet, egress_interface="eth+"):
        """Cleanup iptables rules for WireGuard interface"""
        try:
            script_path = "/app/scripts/cleanup_iptables.sh"
            if os.path.exists(script_path):
                result = self.execute_command(f"{script_path} {interface} {subnet} {egress_interface}")
                if result is not None:
                    print(f"iptables cleanup completed for {interface}")
                    return True
                else:
                    print(f"iptables cleanup failed for {interface}")
                    return False
            else:
                print(f"iptables cleanup script not found at {script_path}")
                return False
        except Exception as e:
            print(f"Error cleaning up iptables for {interface}: {e}")
            return False

    def apply_bandwidth_limit(self, interface, client_ip, tier):
        """Apply bandwidth limit to a specific client based on tier"""
        try:
            tier_config = self.config['bandwidth_tiers'].get(tier)
            if not tier_config:
                print(f"Unknown tier: {tier}")
                return False
            
            limit_mbit = tier_config['limit_mbit']
            burst_mbit = tier_config.get('burst_mbit', limit_mbit * 2)
            
            # Skip if unlimited (0 = no limit)
            if limit_mbit == 0:
                print(f"Tier {tier} is unlimited, skipping bandwidth limit")
                return True
            
            # Create HTB root qdisc if not exists
            self.execute_command(f"tc qdisc add dev {interface} root handle 1: htb default 30 2>/dev/null || true")
            
            # Get class ID from last octet of IP
            class_id = client_ip.split('.')[-1]
            
            # Remove existing class if any
            self.execute_command(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null || true")
            self.execute_command(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 2>/dev/null || true")
            
            # Add class with bandwidth limit
            cmd = f"tc class add dev {interface} parent 1: classid 1:{class_id} htb rate {limit_mbit}mbit burst 15k ceil {burst_mbit}mbit"
            result = self.execute_command(cmd)
            
            if result is None:
                print(f"Warning: Failed to add tc class for {client_ip}")
            
            # Add filter to match client IP
            cmd = f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {client_ip} flowid 1:{class_id}"
            result = self.execute_command(cmd)
            
            if result is None:
                print(f"Warning: Failed to add tc filter for {client_ip}")
                return False
            
            print(f"Bandwidth limit applied: {client_ip} -> {limit_mbit} Mbit/s (burst: {burst_mbit} Mbit/s)")
            return True
            
        except Exception as e:
            print(f"Error applying bandwidth limit for {client_ip}: {e}")
            return False

    def remove_bandwidth_limit(self, interface, client_ip):
        """Remove bandwidth limit for a specific client"""
        try:
            class_id = client_ip.split('.')[-1]
            
            # Remove filter
            self.execute_command(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 2>/dev/null || true")
            
            # Remove class
            self.execute_command(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null || true")
            
            print(f"Bandwidth limit removed for {client_ip}")
            return True
        except Exception as e:
            print(f"Error removing bandwidth limit for {client_ip}: {e}")
            return False

    def update_server_tier(self, server_id, new_tier):
        """Update bandwidth tier for server (applies to all clients)"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False
        
        # Validate tier
        if new_tier not in self.config['bandwidth_tiers']:
            return False
        
        # Update tier in server config
        server['bandwidth_tier'] = new_tier
        
        # Update tier for all clients of this server
        for client in server['clients']:
            client['bandwidth_tier'] = new_tier
            if client['id'] in self.config['clients']:
                self.config['clients'][client['id']]['bandwidth_tier'] = new_tier
        
        self.save_config()
        
        # Apply new bandwidth limits if server is running
        if server['status'] == 'running':
            for client in server['clients']:
                self.remove_bandwidth_limit(server['interface'], client['client_ip'])
                self.apply_bandwidth_limit(server['interface'], client['client_ip'], new_tier)
        
        print(f"Server {server['name']} tier updated to {new_tier} for all {len(server['clients'])} clients")
        return True

    def update_server_failover_mode(self, server_id, new_mode):
        """Update linked server failover policy and apply immediately if possible."""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False, "Server not found"
        if server.get("mode") != "edge_linked":
            return False, "Failover mode can be changed only for linked servers"

        mode_value = str(new_mode or "").strip().lower()
        if mode_value not in ("fail_close", "fail_open"):
            return False, "Mode must be fail_close or fail_open"

        server["linked_failover_mode"] = mode_value

        # Apply immediately for running servers.
        if self.is_interface_running(server.get("interface")):
            healthy, _ = self.is_upstream_healthy(server)
            if mode_value == "fail_close":
                if healthy:
                    self.switch_server_egress(server, "upstream")
            else:
                if not healthy:
                    self.switch_server_egress(server, "local")

        self.save_config()
        return True, None

    def update_tier_settings(self, tier, name, limit_mbit, burst_mbit):
        """Update settings for a bandwidth tier"""
        if tier not in self.config['bandwidth_tiers']:
            return False
        
        self.config['bandwidth_tiers'][tier] = {
            'name': name,
            'limit_mbit': int(limit_mbit),
            'burst_mbit': int(burst_mbit)
        }
        self.save_config()
        
        # Reapply limits to all clients with this tier on running servers
        for server in self.config['servers']:
            if server['status'] == 'running':
                for client in server['clients']:
                    if client.get('bandwidth_tier') == tier:
                        self.remove_bandwidth_limit(server['interface'], client['client_ip'])
                        self.apply_bandwidth_limit(server['interface'], client['client_ip'], tier)
        
        print(f"Tier {tier} settings updated")
        return True

    def start_server(self, server_id):
        """Start a WireGuard server using awg-quick with iptables setup"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False

        try:
            mode = server.get("mode", "standalone")
            egress_interface = server.get("egress_interface", "eth+")
            failover_mode = server.get("linked_failover_mode", "fail_close")

            # Use awg-quick to bring up the interface
            result = self.execute_command(f"/usr/bin/awg-quick up {server['interface']}")
            if result is not None:
                if mode == "edge_linked":
                    upstream_started = self.start_upstream_link(server)
                    if not upstream_started:
                        if failover_mode == "fail_open":
                            print(f"Upstream start failed for {server['name']}, starting in local fallback mode")
                            self.cleanup_upstream_routing(server)
                            egress_interface = "eth+"
                            server["egress_interface"] = egress_interface
                            server["routing_state"] = "local"
                        else:
                            print(f"Failed to start upstream link for {server['name']}")
                            self.execute_command(f"/usr/bin/awg-quick down {server['interface']} 2>/dev/null || true")
                            return False
                    else:
                        egress_interface = ((server.get("upstream") or {}).get("interface")) or egress_interface
                        server["routing_state"] = "upstream"
                        server["egress_interface"] = egress_interface

                # Setup iptables rules
                iptables_success = self.setup_iptables(server['interface'], server['subnet'], egress_interface)

                server['status'] = 'running'
                self.save_config()

                print(f"Server {server['name']} started successfully")
                if iptables_success:
                    print(f"iptables rules configured for {server['interface']}")
                else:
                    print(f"Warning: iptables setup may have failed for {server['interface']}")

                # Apply bandwidth limits to all clients
                for client in server['clients']:
                    tier = client.get('bandwidth_tier', 'free')
                    self.apply_bandwidth_limit(server['interface'], client['client_ip'], tier)

                threading.Thread(target=self.simulate_server_operation, args=(server_id, 'running')).start()
                return True
            else:
                print(f"Failed to start server {server['name']}")
        except Exception as e:
            print(f"Failed to start server {server_id}: {e}")

        return False

    def stop_server(self, server_id):
        """Stop a WireGuard server using awg-quick with iptables cleanup"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False

        try:
            mode = server.get("mode", "standalone")
            egress_interface = server.get("egress_interface", "eth+")

            # Cleanup iptables rules first
            iptables_cleaned = self.cleanup_iptables(server['interface'], server['subnet'], egress_interface)
            if mode == "edge_linked":
                self.stop_upstream_link(server)

            # Use awg-quick to bring down the interface
            result = self.execute_command(f"/usr/bin/awg-quick down {server['interface']}")
            if result is not None:
                server['status'] = 'stopped'
                self.save_config()

                print(f"Server {server['name']} stopped successfully")
                if iptables_cleaned:
                    print(f"iptables rules cleaned up for {server['interface']}")

                threading.Thread(target=self.simulate_server_operation, args=(server_id, 'stopped')).start()
                return True
            else:
                print(f"Failed to stop server {server['name']}")
        except Exception as e:
            print(f"Failed to stop server {server_id}: {e}")

        return False

    def get_server_status(self, server_id):
        """Check actual server status by checking interface"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return "not_found"

        try:
            # Check if interface exists and is up
            if not self.is_interface_running(server.get("interface")):
                return "stopped"

            if server.get("mode") == "edge_linked":
                upstream_interface = ((server.get("upstream") or {}).get("interface"))
                if not upstream_interface:
                    return "stopped"
                if not self.is_interface_running(upstream_interface):
                    if server.get("linked_failover_mode") == "fail_open" and server.get("routing_state") == "local":
                        return "running"
                    return "stopped"
            return "running"
        except:
            return "stopped"

    def simulate_server_operation(self, server_id, status):
        """Simulate server operation with status updates"""
        time.sleep(2)
        socketio.emit('server_status', {
            'server_id': server_id,
            'status': status
        })

    def get_client_configs(self, server_id=None):
        """Get all client configs, optionally filtered by server"""
        self.prune_expired_clients()
        if server_id:
            return [client for client in self.config["clients"].values()
                   if client.get("server_id") == server_id]
        return list(self.config["clients"].values())

    def get_clients_expiring_within(self, days=3, include_expired=False):
        """Return clients expiring within N days for reminder workflows."""
        self.prune_expired_clients()

        now_ts = time.time()
        window_ts = max(int(days), 0) * 24 * 60 * 60
        deadline_ts = now_ts + window_ts
        results = []

        for client in self.config.get("clients", {}).values():
            expires_at = client.get("expires_at")
            if expires_at is None:
                continue

            try:
                expires_at = float(expires_at)
            except (TypeError, ValueError):
                continue

            is_expired = expires_at <= now_ts
            if is_expired and not include_expired:
                continue
            if not is_expired and expires_at > deadline_ts:
                continue

            results.append({
                "client_id": client.get("id"),
                "client_name": client.get("name"),
                "server_id": client.get("server_id"),
                "server_name": client.get("server_name"),
                "client_ip": client.get("client_ip"),
                "duration_code": client.get("duration_code"),
                "duration_label": client.get("duration_label"),
                "created_at": client.get("created_at"),
                "expires_at": expires_at,
                "expires_at_iso": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
                "seconds_left": int(expires_at - now_ts),
                "days_left": round((expires_at - now_ts) / (24 * 60 * 60), 3),
                "status": "expired" if is_expired else "active",
            })

        results.sort(key=lambda item: item["expires_at"])
        return results

    def get_traffic_for_server(self, server_id):
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return None

        interface = server['interface']
        output = self.execute_command(f"/usr/bin/awg show {interface}")
        if not output:
            return None

        # Parse output to get traffic per peer public key
        traffic_data = {}

        lines = output.splitlines()
        current_peer = None
        for line in lines:
            line = line.strip()
            if line.startswith("peer:"):
                current_peer = line.split("peer:")[1].strip()
            elif line.startswith("transfer:") and current_peer:
                # Example: transfer: 1.39 MiB received, 6.59 MiB sent
                transfer_line = line[len("transfer:"):].strip()
                # Parse received and sent
                parts = transfer_line.split(',')
                received = parts[0].strip() if len(parts) > 0 else ""
                sent = parts[1].strip() if len(parts) > 1 else ""
                traffic_data[current_peer] = {
                    "received": received,
                    "sent": sent
                }
                current_peer = None

        # Map traffic data to clients by matching public keys
        clients_traffic = {}
        for client_id, client in self.config["clients"].items():
            if client.get("server_id") == server_id:
                pubkey = client.get("client_public_key")
                if pubkey in traffic_data:
                    clients_traffic[client_id] = traffic_data[pubkey]
                else:
                    clients_traffic[client_id] = {"received": "0 B", "sent": "0 B"}

        return clients_traffic


amnezia_manager = AmneziaManager()

# API Routes
@app.route('/')
def index():
    print("Serving index.html")
    return render_template('index.html')

# Explicit static file route to ensure they're served
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)

@app.route('/api/servers', methods=['POST'])
def create_server():
    data = request.json or {}
    try:
        protocol = str(data.get("protocol") or "wireguard").strip().lower()
        if protocol == "vless":
            server = amnezia_manager.create_vless_server(data)
        else:
            server = amnezia_manager.create_wireguard_server(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(server)

@app.route('/api/servers/<server_id>', methods=['DELETE'])
def delete_server(server_id):
    if amnezia_manager.delete_server(server_id):
        return jsonify({"status": "deleted", "server_id": server_id})
    return jsonify({"error": "Server not found"}), 404

@app.route('/api/servers/<server_id>/start', methods=['POST'])
def start_server(server_id):
    server = next((s for s in amnezia_manager.config.get('servers', []) if s.get('id') == server_id), None)
    if server and server.get("protocol") == "vless":
        return jsonify({"error": "VLESS is handled by the Xray sidecar; no start action in the UI."}), 400
    if amnezia_manager.start_server(server_id):
        return jsonify({"status": "started"})
    return jsonify({"error": "Server not found or failed to start"}), 404

@app.route('/api/servers/<server_id>/stop', methods=['POST'])
def stop_server(server_id):
    server = next((s for s in amnezia_manager.config.get('servers', []) if s.get('id') == server_id), None)
    if server and server.get("protocol") == "vless":
        return jsonify({"error": "VLESS is handled by the Xray sidecar; no stop action in the UI."}), 400
    if amnezia_manager.stop_server(server_id):
        return jsonify({"status": "stopped"})
    return jsonify({"error": "Server not found or failed to stop"}), 404

@app.route('/api/servers/<server_id>/clients', methods=['GET'])
def get_server_clients(server_id):
    clients = amnezia_manager.get_client_configs(server_id)
    return jsonify(clients)

@app.route('/api/servers/<server_id>/clients', methods=['POST'])
def add_client(server_id):
    data = request.json or {}
    client_name = data.get('name', 'New Client')
    duration_code = data.get('duration', 'forever')

    try:
        server = next((s for s in amnezia_manager.config.get('servers', []) if s.get('id') == server_id), None)
        if not server:
            return jsonify({"error": "Server not found"}), 404

        if server.get("protocol") == "vless":
            result = amnezia_manager.add_vless_client(server_id, client_name, duration_code)
        else:
            result = amnezia_manager.add_wireguard_client(server_id, client_name, duration_code)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if result:
        client_config, payload_value, renewal = result
        if server.get("protocol") == "vless":
            return jsonify({
                "client": client_config,
                "link": payload_value,
                "renewal": renewal,
                "action": "renewed" if renewal else "created",
            })

        config_content = payload_value
        clean_config = amnezia_manager.generate_wireguard_client_config(
            server, client_config, include_comments=False
        )
        return jsonify({
            "client": client_config,
            "config": config_content,
            "clean_config": clean_config,
            "renewal": renewal,
            "action": "renewed" if renewal else "created",
        })
    return jsonify({"error": "Server not found"}), 404

@app.route('/api/servers/<server_id>/clients/<client_id>/extend', methods=['POST'])
def extend_client(server_id, client_id):
    data = request.json or {}
    duration_code = data.get('duration', '1m')

    try:
        client, error = amnezia_manager.extend_client(server_id, client_id, duration_code)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if error:
        return jsonify({"error": error}), 404

    return jsonify({
        "status": "extended",
        "client_id": client_id,
        "duration_code": client.get("duration_code"),
        "duration_label": client.get("duration_label"),
        "expires_at": client.get("expires_at"),
        "extended_count": client.get("extended_count", 0)
    })

@app.route('/api/servers/<server_id>/clients/<client_id>', methods=['DELETE'])
def delete_client(server_id, client_id):
    if amnezia_manager.delete_client(server_id, client_id):
        return jsonify({"status": "deleted", "client_id": client_id})
    return jsonify({"error": "Client not found"}), 404

@app.route('/api/servers/<server_id>/clients/<client_id>/config')
def download_client_config(server_id, client_id):
    """Download client configuration file (with comments)"""
    client = amnezia_manager.config["clients"].get(client_id)
    if not client or client.get("server_id") != server_id:
        return jsonify({"error": "Client not found"}), 404

    server = next((s for s in amnezia_manager.config['servers'] if s['id'] == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    if server.get("protocol") == "vless":
        link = amnezia_manager.generate_vless_client_link(server, client)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(link + "\n")
            temp_path = f.name
        filename = f"{client.get('name','client')}.txt".replace("_", "")
        return send_file(temp_path, as_attachment=True, download_name=filename)

    # Use full version with comments for download
    config_content = amnezia_manager.generate_wireguard_client_config(
        server, client, include_comments=True
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(config_content)
        temp_path = f.name

    filename = f"{client['name']}.conf".replace("_", "")
    return send_file(temp_path, as_attachment=True, download_name=filename)

@app.route('/api/clients', methods=['GET'])
def get_all_clients():
    clients = amnezia_manager.get_client_configs()
    return jsonify(clients)

@app.route('/api/bot/reminders/expiring-clients', methods=['GET'])
def get_expiring_clients_for_bot():
    """
    Bot endpoint for renewal reminders.
    Access control is expected at reverse proxy level (nginx auth).
    """
    try:
        days = int(request.args.get('days', '3'))
    except ValueError:
        return jsonify({"error": "days must be integer"}), 400

    if days < 0 or days > 365:
        return jsonify({"error": "days must be between 0 and 365"}), 400

    include_expired = request.args.get('include_expired', 'false').lower() in ('1', 'true', 'yes')
    clients = amnezia_manager.get_clients_expiring_within(days=days, include_expired=include_expired)

    return jsonify({
        "days": days,
        "include_expired": include_expired,
        "count": len(clients),
        "generated_at": time.time(),
        "generated_at_iso": datetime.now(timezone.utc).isoformat(),
        "clients": clients
    })

@app.route('/api/bandwidth/tiers', methods=['GET'])
def get_bandwidth_tiers():
    """Get all bandwidth tiers"""
    return jsonify(amnezia_manager.config['bandwidth_tiers'])

@app.route('/api/bandwidth/tiers/<tier>', methods=['PUT'])
def update_bandwidth_tier(tier):
    """Update settings for a bandwidth tier"""
    data = request.json
    name = data.get('name')
    limit_mbit = data.get('limit_mbit', 0)
    burst_mbit = data.get('burst_mbit', 0)
    
    if amnezia_manager.update_tier_settings(tier, name, limit_mbit, burst_mbit):
        return jsonify({"status": "updated", "tier": tier})
    return jsonify({"error": "Failed to update tier"}), 400

@app.route('/api/servers/<server_id>/tier', methods=['PUT'])
def update_server_tier(server_id):
    """Update bandwidth tier for server (applies to all clients)"""
    data = request.json
    new_tier = data.get('tier')
    
    if not new_tier:
        return jsonify({"error": "Tier not specified"}), 400
    
    if amnezia_manager.update_server_tier(server_id, new_tier):
        return jsonify({"status": "updated", "tier": new_tier})
    return jsonify({"error": "Failed to update server tier"}), 400

@app.route('/api/servers/<server_id>/failover', methods=['PUT'])
def update_server_failover(server_id):
    """Update linked server failover policy"""
    data = request.json or {}
    mode = data.get('mode')

    success, error = amnezia_manager.update_server_failover_mode(server_id, mode)
    if not success:
        if error == "Server not found":
            return jsonify({"error": error}), 404
        return jsonify({"error": error}), 400
    return jsonify({"status": "updated", "mode": mode})

@app.route('/api/system/status')
def system_status():
    status = {
        "awg_available": os.path.exists("/usr/bin/awg") and os.path.exists("/usr/bin/awg-quick"),
        "public_ip": amnezia_manager.public_ip,
        "total_servers": len(amnezia_manager.config["servers"]),
        "total_clients": len(amnezia_manager.config["clients"]),
        "active_servers": len([
            s for s in amnezia_manager.config["servers"]
            if (s.get("protocol") == "wireguard" and amnezia_manager.get_server_status(s["id"]) == "running")
            or (s.get("protocol") == "vless" and s.get("status") in ("ready", "running"))
        ]),
        "timestamp": time.time(),
        "environment": {
            "nginx_port": NGINX_PORT,
            "auto_start_servers": AUTO_START_SERVERS,
            "default_mtu": DEFAULT_MTU,
            "default_subnet": DEFAULT_SUBNET,
            "default_port": DEFAULT_PORT,
            "default_dns": DEFAULT_DNS,
            "link_health_check_interval": LINK_HEALTH_CHECK_INTERVAL,
            "link_handshake_timeout": LINK_HANDSHAKE_TIMEOUT,
            "ru_split_auto_fetch": RU_SPLIT_AUTO_FETCH,
            "ru_split_cidrs_loaded": len(amnezia_manager.ru_split_cidrs)
        }
    }
    return jsonify(status)

@app.route('/api/system/refresh-ip')
def refresh_ip():
    """Refresh public IP address"""
    new_ip = amnezia_manager.detect_public_ip()
    amnezia_manager.public_ip = new_ip

    # Update all servers with new IP
    for server in amnezia_manager.config["servers"]:
        server["public_ip"] = new_ip

    amnezia_manager.save_config()
    return jsonify({"public_ip": new_ip})

@app.route('/api/servers/<server_id>/config')
def get_server_config(server_id):
    """Get the raw WireGuard server configuration"""
    server = next((s for s in amnezia_manager.config['servers'] if s['id'] == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    if server.get("protocol") == "vless":
        return jsonify({
            "server_id": server_id,
            "server_name": server.get("name"),
            "protocol": "vless",
            "vless": server.get("vless") or {},
        })

    try:
        # Read the actual config file
        if os.path.exists(server['config_path']):
            with open(server['config_path'], 'r') as f:
                config_content = f.read()

            return jsonify({
                "server_id": server_id,
                "server_name": server['name'],
                "config_path": server['config_path'],
                "config_content": config_content,
                "interface": server['interface'],
                "public_key": server['server_public_key']
            })
        else:
            return jsonify({"error": "Config file not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to read config: {str(e)}"}), 500

@app.route('/api/servers/<server_id>/config/download')
def download_server_config(server_id):
    """Download the WireGuard server configuration file"""
    server = next((s for s in amnezia_manager.config['servers'] if s['id'] == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    if server.get("protocol") == "vless":
        content = json.dumps(server.get("vless") or {}, indent=2)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(content)
            temp_path = f.name
        return send_file(temp_path, as_attachment=True, download_name=f"{server.get('name','vless')}.json")

    try:
        if os.path.exists(server['config_path']):
            return send_file(
                server['config_path'],
                as_attachment=True,
                download_name=f"{server['interface']}.conf"
            )
        else:
            return jsonify({"error": "Config file not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to download config: {str(e)}"}), 500

@app.route('/api/servers/<server_id>/info')
def get_server_info(server_id):
    """Get detailed server information including config preview"""
    server = next((s for s in amnezia_manager.config['servers'] if s['id'] == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    if server.get("protocol") == "vless":
        vless = server.get("vless") or {}
        return jsonify({
            "id": server.get("id"),
            "name": server.get("name"),
            "protocol": "vless",
            "port": vless.get("port", 443),
            "status": server.get("status", "ready"),
            "public_ip": server.get("public_ip"),
            "clients_count": len(server.get("clients", [])),
            "created_at": server.get("created_at"),
            "vless": vless,
        })

    # Get current status
    current_status = amnezia_manager.get_server_status(server_id)
    server['current_status'] = current_status

    # Try to read config file for preview
    config_preview = ""
    if os.path.exists(server['config_path']):
        try:
            with open(server['config_path'], 'r') as f:
                # Read first 10 lines for preview
                lines = f.readlines()
                config_preview = ''.join(lines[:min(10, len(lines))])
        except:
            config_preview = "Unable to read config file"

    # Ensure MTU is included (handle both old and new servers)
    mtu_value = server.get('mtu', 1420)  # Default to 1420 if not set
    mode_value = server.get('mode', 'standalone')
    egress_value = server.get('egress_interface', 'eth+')
    failover_value = server.get('linked_failover_mode')
    routing_value = server.get('routing_state')

    server_info = {
        "id": server['id'],
        "name": server['name'],
        "protocol": server['protocol'],
        "port": server['port'],
        "status": current_status,
        "interface": server['interface'],
        "config_path": server['config_path'],
        "public_ip": server['public_ip'],
        "server_ip": server['server_ip'],
        "subnet": server['subnet'],
        "mtu": mtu_value,  # Make sure MTU is included
        "mode": mode_value,
        "egress_interface": egress_value,
        "linked_failover_mode": failover_value,
        "routing_state": routing_value,
        "upstream": server.get('upstream'),
        "obfuscation_enabled": server['obfuscation_enabled'],
        "obfuscation_params": server.get('obfuscation_params', {}),
        "clients_count": len(server['clients']),
        "created_at": server['created_at'],
        "config_preview": config_preview,
        "public_key": server['server_public_key'],
        "dns": server['dns']
    }

    return jsonify(server_info)

@app.route('/api/servers', methods=['GET'])
def get_servers():
    amnezia_manager.prune_expired_clients()

    # Update server status based on actual interface state
    for server in amnezia_manager.config["servers"]:
        if server.get("protocol") == "vless":
            if "status" not in server:
                server["status"] = "ready"
            continue
        if "mode" not in server:
            server["mode"] = "standalone"
        if server["mode"] == "edge_linked":
            if "linked_failover_mode" not in server or server["linked_failover_mode"] not in ("fail_close", "fail_open"):
                server["linked_failover_mode"] = "fail_close"
            if "routing_state" not in server or server["routing_state"] not in ("upstream", "local"):
                server["routing_state"] = "upstream"
            expected_egress = "eth+" if server["routing_state"] == "local" else ((server.get("upstream") or {}).get("interface"))
            if not expected_egress:
                expected_egress = "eth+"
            if server.get("egress_interface") != expected_egress:
                server["egress_interface"] = expected_egress
        else:
            server["linked_failover_mode"] = None
            server["routing_state"] = None
            if server.get("egress_interface") != "eth+":
                server["egress_interface"] = "eth+"
        server["status"] = amnezia_manager.get_server_status(server["id"])
        # Ensure MTU is included in basic server list
        if 'mtu' not in server:
            server['mtu'] = 1420  # Default value

    amnezia_manager.save_config()
    return jsonify(amnezia_manager.config["servers"])

@app.route('/api/system/iptables-test')
def iptables_test():
    """Test iptables setup for a specific server"""
    server_id = request.args.get('server_id')
    if not server_id:
        return jsonify({"error": "server_id parameter required"}), 400

    server = next((s for s in amnezia_manager.config['servers'] if s['id'] == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    egress_interface = server.get("egress_interface", "eth+")

    # Test iptables rules
    try:
        # Check if rules exist
        check_commands = [
            f"iptables -L INPUT -n | grep {server['interface']}",
            f"iptables -L FORWARD -n | grep {server['interface']}",
            f"iptables -t nat -L POSTROUTING -n | grep {server['subnet']}",
            f"iptables -L FORWARD -n | grep {egress_interface}"
        ]

        results = {}
        for cmd in check_commands:
            try:
                result = amnezia_manager.execute_command(cmd)
                results[cmd] = "Found" if result else "Not found"
            except:
                results[cmd] = "Error"

        return jsonify({
            "server_id": server_id,
            "server_name": server['name'],
            "interface": server['interface'],
            "egress_interface": egress_interface,
            "subnet": server['subnet'],
            "iptables_check": results
        })

    except Exception as e:
        return jsonify({"error": f"iptables test failed: {str(e)}"}), 500
    
@app.route('/api/servers/<server_id>/clients/<client_id>/config-both')
def get_client_config_both(server_id, client_id):
    """Get both clean and full client configurations"""
    client = amnezia_manager.config["clients"].get(client_id)
    if not client or client.get("server_id") != server_id:
        return jsonify({"error": "Client not found"}), 404

    server = next((s for s in amnezia_manager.config['servers'] if s['id'] == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    if server.get("protocol") == "vless":
        link = amnezia_manager.generate_vless_client_link(server, client)
        return jsonify({
            "server_id": server_id,
            "client_id": client_id,
            "client_name": client.get('name'),
            "clean_config": link,
            "full_config": link,
            "clean_length": len(link),
            "full_length": len(link)
        })

    # Generate both versions
    clean_config = amnezia_manager.generate_wireguard_client_config(
        server, client, include_comments=False
    )
    
    full_config = amnezia_manager.generate_wireguard_client_config(
        server, client, include_comments=True
    )
    
    return jsonify({
        "server_id": server_id,
        "client_id": client_id,
        "client_name": client['name'],
        "clean_config": clean_config,
        "full_config": full_config,
        "clean_length": len(clean_config),
        "full_length": len(full_config)
    })

@app.route('/api/vless/sni-presets')
def vless_sni_presets():
    """Return curated REALITY mask-domain presets for the UI."""
    return jsonify(REALITY_SNI_PRESETS)


@app.route('/api/servers/<server_id>/bridge', methods=['POST'])
def generate_bridge_config(server_id):
    """
    Generate an Xray relay config for a Russian 'bridge' VPS.

    POST body (JSON):
      bridge_ip          – IP of the Russian VPS (required)
      bridge_port        – listen port on the bridge, default 443
      bridge_reality_dest– Reality mask domain, e.g. vkvideo.ru:443
      bridge_path        – XHTTP path, auto-generated if omitted
      bridge_fingerprint – uTLS fingerprint (chrome/firefox/…)
    """
    data = request.get_json(force=True, silent=True) or {}
    try:
        result = amnezia_manager.create_bridge_config(server_id, data)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"Bridge config generation error: {e}")
        return jsonify({"error": "Internal error generating bridge config"}), 500


@app.route('/api/sub/vless/<subscription_id>')
def vless_subscription(subscription_id):
    """Plain text subscription (one vless:// link per line)."""
    amnezia_manager.prune_expired_clients()
    server = next(
        (
            s for s in amnezia_manager.config.get("servers", [])
            if s.get("protocol") == "vless" and (s.get("vless") or {}).get("subscription_id") == subscription_id
        ),
        None
    )
    if not server:
        return jsonify({"error": "Subscription not found"}), 404

    lines = []
    for client in server.get("clients", []):
        if amnezia_manager._is_client_expired(client):
            continue
        try:
            lines.append(amnezia_manager.generate_vless_client_link(server, client))
        except Exception:
            continue

    return app.response_class("\n".join(lines) + ("\n" if lines else ""), mimetype="text/plain")
    
@app.route('/api/servers/<server_id>/traffic')
def get_server_traffic(server_id):
    traffic = amnezia_manager.get_traffic_for_server(server_id)
    if traffic is None:
        return jsonify({"error": "Server not found or no traffic data"}), 404
    return jsonify(traffic)

@app.route('/status')
def get_container_uptime():
    # Get the modification time of /proc/1/cmdline (container start time epoch)
    result = subprocess.check_output(["stat", "-c %Y", "/proc/1/cmdline"], text=True)
    uptime_seconds_epoch = int(result.strip())

    now_epoch = int(time.time())
    
    uptime_seconds = now_epoch - uptime_seconds_epoch
    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60
    
    return f"Container Uptime: {days}d {hours}h {minutes}m {seconds}s"

@socketio.on('connect')
def handle_connect():
    print(f"WebSocket connected from {request.remote_addr}")
    
    # Include the port in the status message
    socketio.emit('status', {
        'message': 'Connected to AmneziaWG Web UI',
        'public_ip': amnezia_manager.public_ip,
        'nginx_port': NGINX_PORT,
        'server_port': request.environ.get('SERVER_PORT', 'unknown'),
        'client_port': request.environ.get('HTTP_X_FORWARDED_PORT', 'unknown')
    })

@socketio.on('disconnect')
def handle_disconnect():
    print(f"WebSocket disconnected from {request.remote_addr}")

if __name__ == '__main__':
    print(f"AmneziaWG Web UI starting...")
    print(f"Configuration:")
    print(f"  NGINX Port: {NGINX_PORT}")
    print(f"  Auto-start: {AUTO_START_SERVERS}")
    print(f"  Default MTU: {DEFAULT_MTU}")
    print(f"  Default Subnet: {DEFAULT_SUBNET}")
    print(f"  Default Port: {DEFAULT_PORT}")
    print(f"Detected public IP: {amnezia_manager.public_ip}")

    if AUTO_START_SERVERS:
        print("Auto-starting existing servers...")

    socketio.run(app, host='0.0.0.0', port=WEB_UI_PORT, debug=False, allow_unsafe_werkzeug=True)