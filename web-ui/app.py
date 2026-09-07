#!/usr/bin/env python3
import os
import json
import copy
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
import ssl
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
import re
from urllib.parse import quote
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, Response
from flask_socketio import SocketIO
import threading
import time
from datetime import datetime, timezone
from awg_protocol import (OBFUSCATION_KEYS, V3_KEYS, generate_params, normalize_params,
                          import_params, normalize_keepalive, protocol_version,
                          upgrade_params, render_params, replace_interface_params)

# Get the absolute path to the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# Essential environment variables
NGINX_PORT = os.getenv('NGINX_PORT', '80')
ADMIN_USERNAME = os.getenv('NGINX_USER', 'admin')
ADMIN_PASSWORD = os.getenv('NGINX_PASSWORD', 'changeme')
PUBLIC_SERVER_SUBSCRIPTIONS = os.getenv('PUBLIC_SERVER_SUBSCRIPTIONS', 'false').lower() == 'true'
AUTO_START_SERVERS = os.getenv('AUTO_START_SERVERS', 'true').lower() == 'true'
DEFAULT_MTU = int(os.getenv('DEFAULT_MTU', '1280'))
DEFAULT_SUBNET = os.getenv('DEFAULT_SUBNET', '10.0.0.0/24')
DEFAULT_PORT = int(os.getenv('DEFAULT_PORT', '51820'))
DEFAULT_DNS = os.getenv('DEFAULT_DNS', '8.8.8.8,1.1.1.1')
CLIENT_EXPIRATION_CHECK_INTERVAL = int(os.getenv('CLIENT_EXPIRATION_CHECK_INTERVAL', '60'))
# Grace period after expires_at before a client is actually deleted.
# Within this window the client keeps working and can be renewed seamlessly.
# Default 3 days. Set 0 to delete immediately on expiration (legacy behaviour).
CLIENT_DELETE_GRACE_DAYS = float(os.getenv('CLIENT_DELETE_GRACE_DAYS', '3'))
LINK_HEALTH_CHECK_INTERVAL = int(os.getenv('LINK_HEALTH_CHECK_INTERVAL', '15'))
LINK_HANDSHAKE_TIMEOUT = int(os.getenv('LINK_HANDSHAKE_TIMEOUT', '3600'))
RU_SPLIT_CIDR_FILE = os.getenv('RU_SPLIT_CIDR_FILE', '/etc/amnezia/ru_cidrs.txt')
RU_SPLIT_FETCH_URL = os.getenv('RU_SPLIT_FETCH_URL', 'https://www.ipdeny.com/ipblocks/data/countries/ru.zone')
RU_SPLIT_AUTO_FETCH = os.getenv('RU_SPLIT_AUTO_FETCH', 'true').lower() == 'true'
RU_SPLIT_INLINE_CIDRS = os.getenv('RU_SPLIT_INLINE_CIDRS', '')

# Branding for the multi-server VLESS subscription. Shown to clients in HAPP/v2rayN
# as the profile title and in the per-link labels. Override via env if you fork.
MEMEVPN_BRAND = os.getenv('MEMEVPN_BRAND', 'MemeVPN')
# How often clients (HAPP/v2rayN) should refresh the subscription, in hours.
# When you add a new VLESS server, existing users will see it after this interval.
MEMEVPN_SUB_UPDATE_HOURS = int(os.getenv('MEMEVPN_SUB_UPDATE_HOURS', '24'))
# HAPP app-management flags. `hide-settings` disables viewing/editing server
# configs in HAPP; advanced HAPP parameters require ProviderID when available.
HAPP_HIDE_SERVER_SETTINGS = os.getenv('HAPP_HIDE_SERVER_SETTINGS', 'true').lower() == 'true'
HAPP_PROVIDER_ID = os.getenv('HAPP_PROVIDER_ID', '').strip()

# Xray/VLESS hardening knobs. Defaults favor compatibility on restrictive
# mobile networks; operators can opt into the faster but more brittle options.
XRAY_DNS_QUERY_STRATEGY = os.getenv('XRAY_DNS_QUERY_STRATEGY', 'UseIPv4').strip() or 'UseIPv4'
XRAY_DOMAIN_STRATEGY = os.getenv('XRAY_DOMAIN_STRATEGY', 'UseIPv4').strip() or 'UseIPv4'
XRAY_TCP_FAST_OPEN = os.getenv('XRAY_TCP_FAST_OPEN', 'false').lower() == 'true'
XRAY_TCP_MAX_SEG = int(os.getenv('XRAY_TCP_MAX_SEG', '0') or '0')
XRAY_REALITY_MAX_TIME_DIFF_MS = int(os.getenv('XRAY_REALITY_MAX_TIME_DIFF_MS', '70000'))
XRAY_REALITY_SHORT_ID_BYTES = max(1, min(8, int(os.getenv('XRAY_REALITY_SHORT_ID_BYTES', '8') or '8')))
XRAY_WS_EARLY_DATA_BYTES = max(0, min(8192, int(os.getenv('XRAY_WS_EARLY_DATA_BYTES', '2560') or '2560')))

# ── Federation / satellite mode ─────────────────────────────────────────────
# When SATELLITE_API_KEY is set, this instance exposes an authenticated
# /api/satellite/* API that a remote "hub" instance can call to provision
# clients on this VPS's local Xray. Clients only ever connect *directly* to
# this VPS — the hub just orchestrates. Leave empty to disable satellite mode.
SATELLITE_API_KEY = os.getenv('SATELLITE_API_KEY', '').strip()
# How long the hub's outbound HTTP calls to satellites wait before giving up.
SATELLITE_HTTP_TIMEOUT = int(os.getenv('SATELLITE_HTTP_TIMEOUT', '10'))

# Parse DNS servers from comma-separated string
DNS_SERVERS = [dns.strip() for dns in DEFAULT_DNS.split(',') if dns.strip()]

# Fixed values for other settings
WEB_UI_PORT = 5000
CONFIG_DIR = '/etc/amnezia'
WIREGUARD_CONFIG_DIR = os.path.join(CONFIG_DIR, 'amneziawg')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'web_config.json')
XRAY_CONFIG_DIR = os.path.join(CONFIG_DIR, 'xray')
XRAY_CONFIG_FILE = os.path.join(XRAY_CONFIG_DIR, 'config.json')
# Ports 9443-9642: internal-only Xray inbounds for stream-routed (port-443) REALITY servers.
# These are NOT published to the host; nginx stream proxies from external :443 by SNI.
XRAY_STREAM_BASE_PORT = int(os.getenv('XRAY_STREAM_BASE_PORT', '9443'))
# Hostname/IP nginx uses to reach Xray. In the default compose file Xray shares
# the web-ui network namespace so it can route marked VLESS egress via AWG.
XRAY_UPSTREAM_HOST = os.getenv('XRAY_UPSTREAM_HOST', 'xray')
NGINX_STREAM_CONFIG_FILE = '/etc/nginx/stream_reality.conf'
# Xray runs in a sibling Docker service. In own-domain REALITY mode it receives
# both valid REALITY handshakes and ordinary TLS probes for the same SNI; the
# latter must fall through to the real nginx HTTPS listener, not loop back to :443.
REALITY_INTERNAL_FALLBACK_TARGET = os.getenv('XRAY_REALITY_FALLBACK_TARGET', '127.0.0.1:4443')
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

def _admin_auth_ok():
    auth = request.authorization
    if not auth:
        return False
    return (
        secrets.compare_digest(auth.username or "", ADMIN_USERNAME)
        and secrets.compare_digest(auth.password or "", ADMIN_PASSWORD)
    )

def _admin_auth_required():
    return Response(
        "Admin authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="AmneziaWG Web UI"'},
    )

@app.before_request
def protect_admin_api():
    """Defense-in-depth for direct Flask access.

    nginx already protects admin routes, but if port 5000 is ever exposed by
    mistake, Flask must not serve raw server/client configs without admin auth.
    Personal subscription URLs remain public because clients need to fetch them.
    """
    if request.method == "OPTIONS":
        return None

    path = request.path or ""
    if not path.startswith("/api/"):
        return None
    if path.startswith("/api/satellite/"):
        return None
    if path.startswith("/api/sub/user/"):
        return None
    if path.startswith("/api/sub/vless/") and PUBLIC_SERVER_SUBSCRIPTIONS:
        return None

    if _admin_auth_ok():
        return None
    return _admin_auth_required()

def synchronized_config(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self.config_lock:
            return method(self, *args, **kwargs)
    return locked


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
        self.migrate_vless_metadata()

        # Auto-start servers based on environment variable. Linked VLESS servers
        # need their AWG policy routes in place before Xray accepts traffic.
        if AUTO_START_SERVERS:
            self.auto_start_servers()

        # Keep derived configs in sync on every startup.
        # This ensures nginx/xray configs are regenerated after container restarts.
        try:
            self._write_xray_config()
            self._write_vless_nginx_locations()
            self._write_vless_stream_config()
        except Exception as e:
            print(f"Failed initializing vless configs: {e}")

        self.start_client_expiration_worker()
        self.start_link_health_worker()

    # ── Flexible client expiration ──────────────────────────────────────
    # The web UI / bot can pass any of the following as the ``duration`` field:
    #   • ``"forever"`` / ``"permanent"`` / ``"lifetime"`` / ``"unlimited"`` /
    #     ``"never"`` / ``"навсегда"``  → client never expires.
    #   • ``"<N>d"`` / ``"<N>day(s)"`` — N calendar days.
    #   • ``"<N>h"`` / ``"<N>hour(s)"`` — N hours.
    #   • ``"<N>w"`` / ``"<N>week(s)"`` — N weeks.
    #   • ``"<N>m"`` / ``"<N>mo"`` / ``"<N>month(s)"`` — N calendar months.
    #   • ``"<N>y"`` / ``"<N>year(s)"`` — N years.
    #   • A bare integer (``"30"``) — treated as N days.
    #   • An ISO date ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM[:SS]`` — absolute
    #     expiry timestamp (UTC if no timezone is given). Stored as ``abs:<ts>``.
    #   • Legacy fixed codes ``"1m" / "3m" / "6m" / "12m"`` keep working — they
    #     normalise to the same ``Nm`` form.
    # The internal canonical code is stored in ``client["duration_code"]`` and
    # its human-readable form in ``client["duration_label"]``. ``expires_at``
    # is the absolute UNIX timestamp at which the client stops working.

    _DURATION_UNIT_ALIASES = {
        "h": "h", "hr": "h", "hrs": "h", "hour": "h", "hours": "h",
        "d": "d", "day": "d", "days": "d",
        "w": "w", "wk": "w", "wks": "w", "week": "w", "weeks": "w",
        "m": "m", "mo": "m", "mon": "m", "month": "m", "months": "m",
        "y": "y", "yr": "y", "yrs": "y", "year": "y", "years": "y",
    }

    _DURATION_FOREVER_ALIASES = {
        "", "0", "forever", "permanent", "lifetime", "unlimited",
        "never", "navsegda", "навсегда", "вечно", "infinity", "inf",
    }

    def _normalize_duration_code(self, duration_code):
        """Normalize user-provided duration to an internal canonical code.

        Returns one of:
          • ``"forever"``
          • ``"<N><unit>"`` where unit ∈ {h, d, w, m, y} and N is a positive int
          • ``"abs:<timestamp>"`` for an absolute UTC expiry timestamp
        """
        if duration_code is None:
            return "forever"

        # Allow callers to pass already-canonical strings, plain ints (days)
        # or floats from older code paths.
        if isinstance(duration_code, bool):
            raise ValueError(f"Unsupported client duration: {duration_code}")
        if isinstance(duration_code, (int, float)):
            n = int(duration_code)
            if n <= 0:
                return "forever"
            return f"{n}d"

        text = str(duration_code).strip().lower().replace(" ", "")
        if text in self._DURATION_FOREVER_ALIASES:
            return "forever"

        # Pre-normalised ``abs:`` form coming back from saved config or a
        # satellite — just validate the timestamp.
        if text.startswith("abs:"):
            try:
                ts = float(text[4:])
            except ValueError:
                raise ValueError(f"Unsupported client duration: {duration_code}")
            return f"abs:{ts}"

        # Absolute ISO date / datetime (UTC if naive).
        iso_match = re.fullmatch(
            r"(\d{4}-\d{2}-\d{2})(?:[t ](\d{2}:\d{2}(?::\d{2})?))?", text
        )
        if iso_match:
            date_part, time_part = iso_match.group(1), iso_match.group(2)
            iso_text = f"{date_part}T{time_part}" if time_part else date_part
            try:
                dt = datetime.fromisoformat(iso_text)
            except ValueError:
                raise ValueError(f"Unsupported client duration: {duration_code}")
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return f"abs:{dt.timestamp()}"

        # Bare integer → days.
        if text.isdigit():
            n = int(text)
            return "forever" if n <= 0 else f"{n}d"

        # ``<N><unit>`` relative duration.
        rel_match = re.fullmatch(r"(\d+)([a-zа-я]+)", text)
        if rel_match:
            n = int(rel_match.group(1))
            unit_raw = rel_match.group(2)
            unit = self._DURATION_UNIT_ALIASES.get(unit_raw)
            if unit is None:
                raise ValueError(f"Unsupported client duration: {duration_code}")
            if n <= 0:
                return "forever"
            return f"{n}{unit}"

        # Legacy bare unit aliases like ``"month"`` / ``"year"`` (no number).
        unit = self._DURATION_UNIT_ALIASES.get(text)
        if unit is not None:
            return f"1{unit}"

        raise ValueError(f"Unsupported client duration: {duration_code}")

    def _duration_label(self, duration_code):
        """Return a human-readable label for a canonical duration code."""
        if duration_code is None or duration_code == "forever":
            return "Forever"

        text = str(duration_code)
        if text.startswith("abs:"):
            try:
                ts = float(text[4:])
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
                    return f"Until {dt.strftime('%Y-%m-%d')}"
                return f"Until {dt.strftime('%Y-%m-%d %H:%M UTC')}"
            except (ValueError, OSError):
                return "Forever"

        rel_match = re.fullmatch(r"(\d+)([hdwmy])", text)
        if rel_match:
            n = int(rel_match.group(1))
            unit = rel_match.group(2)
            unit_names = {
                "h": ("hour", "hours"),
                "d": ("day", "days"),
                "w": ("week", "weeks"),
                "m": ("month", "months"),
                "y": ("year", "years"),
            }
            singular, plural = unit_names[unit]
            return f"{n} {singular if n == 1 else plural}"

        return text

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
        """Compute the absolute expiry timestamp for ``duration_code``.

        For relative durations the returned timestamp is ``base_ts`` shifted
        forward by the requested amount; for absolute (``abs:<ts>``) durations
        the stored timestamp is returned verbatim regardless of ``base_ts``.
        Returns ``None`` for ``forever``.
        """
        duration = self._normalize_duration_code(duration_code)
        if duration == "forever":
            return None

        if duration.startswith("abs:"):
            return float(duration[4:])

        rel_match = re.fullmatch(r"(\d+)([hdwmy])", duration)
        if not rel_match:
            raise ValueError(f"Unsupported client duration: {duration_code}")

        n = int(rel_match.group(1))
        unit = rel_match.group(2)
        if unit == "h":
            return base_ts + n * 3600
        if unit == "d":
            return base_ts + n * 86400
        if unit == "w":
            return base_ts + n * 7 * 86400
        if unit == "m":
            return self._add_calendar_months_utc(base_ts, n)
        if unit == "y":
            return self._add_calendar_months_utc(base_ts, n * 12)

        raise ValueError(f"Unsupported client duration: {duration_code}")

    def _duration_is_absolute(self, duration_code):
        """Return True if ``duration_code`` represents an absolute timestamp."""
        if duration_code is None:
            return False
        return str(duration_code).startswith("abs:")

    def _is_client_expired(self, client_config, now_ts=None):
        expires_at = client_config.get("expires_at")
        if expires_at is None:
            return False
        now_value = now_ts if now_ts is not None else time.time()
        return now_value >= float(expires_at)

    def _should_delete_expired_client(self, client_config, now_ts=None):
        """Should this expired client be physically deleted now?

        Clients are kept for ``CLIENT_DELETE_GRACE_DAYS`` after ``expires_at`` so
        that a paying user can renew without losing their config. Within the
        grace window the client is still treated as expired by ``_is_client_expired``
        (so the UI shows an "expired" badge and reminders fire), but ``prune_expired_clients``
        leaves it alone until the grace period elapses.
        """
        expires_at = client_config.get("expires_at")
        if expires_at is None:
            return False
        now_value = now_ts if now_ts is not None else time.time()
        grace_seconds = max(0.0, CLIENT_DELETE_GRACE_DAYS) * 24 * 60 * 60
        return now_value >= float(expires_at) + grace_seconds

    def _absolute_duration_code(self, expires_at):
        """Return a duration code that preserves an exact expiry timestamp."""
        if expires_at is None:
            return "forever"
        return f"abs:{float(expires_at)}"

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

    def migrate_vless_metadata(self):
        """Backfill VLESS server location/branding fields and seed user records.

        Old VLESS servers created before the multi-server subscription rollout
        had no ``country_code``/``flag_emoji``/``display_location``. We add the
        keys with empty strings so the rest of the codebase can read them
        without ``KeyError``. The subscription endpoint falls back to the server
        name when ``display_location`` is empty.
        """
        updated = False
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            for key in ("country_code", "flag_emoji", "display_location", "description"):
                if key not in server:
                    server[key] = ""
                    updated = True
            # Auto-derive flag from country_code if operator only set the latter.
            cc = self._normalize_country_code(server.get("country_code"))
            if cc and not server.get("flag_emoji"):
                server["flag_emoji"] = self._country_code_to_flag(cc)
                updated = True
            vless = server.get("vless") or {}
            if isinstance(vless, dict) and not vless.get("transport"):
                vless["transport"] = "xhttp"
                updated = True
            if isinstance(vless, dict) and vless.get("transport") in ("tcp", "raw") and "flow" not in vless:
                vless["flow"] = "xtls-rprx-vision"
                updated = True
            if isinstance(vless, dict) and "reality_profile" not in vless:
                domain = str(vless.get("domain") or "").strip().lower()
                names = [str(n or "").strip().lower() for n in (vless.get("reality_server_names") or [])]
                vless["reality_profile"] = "own_domain" if domain and domain in names else "external_mask"
                updated = True
            if (
                isinstance(vless, dict)
                and vless.get("reality_profile") == "own_domain"
                and (
                    "reality_fallback_target" not in vless
                    or str(vless.get("reality_fallback_target") or "").strip() == "web-ui:4443"
                )
            ):
                vless["reality_fallback_target"] = REALITY_INTERNAL_FALLBACK_TARGET
                updated = True
            if isinstance(vless, dict):
                # New deployments use only external TCP :443 for VLESS. Existing
                # direct-port servers are converted at metadata level so
                # regenerated links advertise the stream endpoint too.
                if not vless.get("use_stream"):
                    vless["use_stream"] = True
                    updated = True
                if server.get("port") != 443:
                    server["port"] = 443
                    updated = True
                if vless.get("port") != 443:
                    vless["port"] = 443
                    updated = True
                if vless.get("client_port") != 443:
                    vless["client_port"] = 443
                    updated = True

        # Seed top-level keys for the user-level subscription model.
        if "users" not in self.config:
            self.config["users"] = {}
            updated = True
        if "user_tokens" not in self.config:
            self.config["user_tokens"] = {}
            updated = True
        # Federation: registered satellite instances and operator-curated
        # decorative entries that get appended to every user's subscription
        # (e.g. "Renew at @bot" placeholder lines like popular VPN providers do).
        if "satellites" not in self.config:
            self.config["satellites"] = {}
            updated = True
        if "promo_lines" not in self.config:
            self.config["promo_lines"] = []
            updated = True

        # Rebuild reverse-lookup map from ``users`` in case it's drifted.
        rebuilt_tokens = {}
        for uid, record in self.config.get("users", {}).items():
            token = record.get("token") if isinstance(record, dict) else None
            if token:
                rebuilt_tokens[token] = uid
        if rebuilt_tokens != self.config.get("user_tokens"):
            self.config["user_tokens"] = rebuilt_tokens
            updated = True

        if updated:
            self.save_config()

    def update_vless_server_metadata(self, server_id, metadata):
        """Edit location/branding fields on an existing VLESS server."""
        with self.config_lock:
            server = next((s for s in self.config.get("servers", []) if s.get("id") == server_id), None)
            if not server:
                return None
            if server.get("protocol") != "vless":
                raise ValueError("Metadata edits are only supported for VLESS servers")

            if "name" in metadata and metadata["name"] is not None:
                server["name"] = self._sanitize_label(metadata["name"], fallback=server.get("name", "VLESS Server"))

            if "country_code" in metadata:
                cc = self._normalize_country_code(metadata.get("country_code"))
                server["country_code"] = cc
                # If operator hasn't manually overridden flag, regenerate from new CC.
                if not metadata.get("flag_emoji"):
                    server["flag_emoji"] = self._country_code_to_flag(cc) if cc else ""

            if "flag_emoji" in metadata and metadata["flag_emoji"] is not None:
                server["flag_emoji"] = str(metadata["flag_emoji"]).strip()

            if "display_location" in metadata and metadata["display_location"] is not None:
                server["display_location"] = str(metadata["display_location"]).strip()

            if "description" in metadata and metadata["description"] is not None:
                server["description"] = str(metadata["description"]).strip()

            self.save_config()
            return server

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
                    if server.get("protocol") == "vless":
                        upstream["interface"] = f"vl-{server.get('id', 'vless')}-up"[:15]
                    else:
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
                    upstream["obfuscation_params"] = self.generate_obfuscation_params(server.get("mtu", DEFAULT_MTU), version="2")
                    updated = True
                if not upstream.get("client_public_key") and upstream.get("private_key"):
                    upstream["client_public_key"] = self.execute_command(f"echo '{upstream['private_key']}' | wg pubkey") or ""
                    updated = True
                if not upstream.get("table_id"):
                    base = 300 if server.get("protocol") == "vless" else 200
                    upstream["table_id"] = self._allocate_upstream_table_id(base=base)
                    updated = True
                if server.get("protocol") == "vless" and not upstream.get("fwmark"):
                    upstream["fwmark"] = self._allocate_upstream_fwmark()
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

    def _allocate_upstream_table_id(self, base=200, span=500):
        used = set()
        for server in self.config.get("servers", []):
            upstream = server.get("upstream") or {}
            table_id = upstream.get("table_id")
            try:
                if table_id:
                    used.add(int(table_id))
            except (TypeError, ValueError):
                continue
        for candidate in range(int(base), int(base) + int(span)):
            if candidate not in used:
                return candidate
        return int(base) + random.randint(1, int(span) - 1)

    def _allocate_upstream_fwmark(self, base=0xA000, span=0x0FFF):
        used = set()
        for server in self.config.get("servers", []):
            upstream = server.get("upstream") or {}
            fwmark = upstream.get("fwmark")
            try:
                if fwmark:
                    used.add(int(fwmark))
            except (TypeError, ValueError):
                continue
        for candidate in range(int(base), int(base) + int(span)):
            if candidate not in used:
                return candidate
        return int(base) + random.randint(1, int(span) - 1)

    def _server_has_linked_upstream(self, server):
        return (
            bool(server)
            and server.get("mode") == "edge_linked"
            and isinstance(server.get("upstream"), dict)
        )

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
        """Delete expired clients past the grace period and return removed IDs.

        Clients within ``CLIENT_DELETE_GRACE_DAYS`` of their ``expires_at`` are
        kept so that a renewal can restore service without re-creating keys.
        """
        expired_clients = []
        now_ts = time.time()

        with self.config_lock:
            for client_id, client in list(self.config.get("clients", {}).items()):
                if self._should_delete_expired_client(client, now_ts):
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
        if not self._server_has_linked_upstream(server):
            return False

        if server.get("protocol") == "vless":
            return self.switch_vless_egress(server, target_state)

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

    def switch_vless_egress(self, server, target_state):
        upstream_interface = ((server.get("upstream") or {}).get("interface"))
        if target_state == "upstream":
            if not upstream_interface:
                return False
            if not self.start_upstream_link(server):
                if server.get("linked_failover_mode") == "fail_open":
                    self.cleanup_vless_upstream_routing(server)
                    server["routing_state"] = "local"
                    server["egress_interface"] = "eth+"
                else:
                    self.configure_vless_fail_closed_routing(server)
                    server["routing_state"] = "upstream"
                    server["egress_interface"] = upstream_interface
                    self.save_config()
                    self._write_xray_config()
                return server.get("linked_failover_mode") != "fail_open"
            server["egress_interface"] = upstream_interface
            server["routing_state"] = "upstream"
        else:
            self.cleanup_vless_upstream_routing(server)
            server["egress_interface"] = "eth+"
            server["routing_state"] = "local"

        self.save_config()
        self._write_xray_config()
        print(f"Linked VLESS server {server.get('name')} switched routing to {target_state}")
        return True

    def link_health_worker(self):
        """Monitor linked servers and apply failover policy."""
        while not self.stop_expiration_worker.is_set():
            try:
                for server in self.config.get("servers", []):
                    if not self._server_has_linked_upstream(server):
                        continue
                    if server.get("protocol") != "vless" and not self.is_interface_running(server.get("interface")):
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
                            if server.get("protocol") == "vless":
                                self.configure_vless_fail_closed_routing(server)
                                if server.get("routing_state") != "upstream":
                                    server["routing_state"] = "upstream"
                                    server["egress_interface"] = (server.get("upstream") or {}).get("interface")
                                    self.save_config()
                                    self._write_xray_config()
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
            if server.get("protocol") == "vless":
                if self._server_has_linked_upstream(server) and server.get("auto_start", True):
                    print(f"Auto-starting VLESS upstream link: {server.get('name')}")
                    if self.start_upstream_link(server):
                        server["routing_state"] = "upstream"
                        server["egress_interface"] = (server.get("upstream") or {}).get("interface")
                    elif server.get("linked_failover_mode") == "fail_open":
                        self.cleanup_vless_upstream_routing(server)
                        server["routing_state"] = "local"
                        server["egress_interface"] = "eth+"
                    else:
                        self.configure_vless_fail_closed_routing(server)
                        server["routing_state"] = "upstream"
                        server["egress_interface"] = (server.get("upstream") or {}).get("interface")
                    self.save_config()
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
        # An interrupted explicit upgrade is rolled back before any auto-start.
        journal = os.path.join(CONFIG_DIR, 'awg3-upgrade.pending.json')
        if os.path.exists(journal):
            with open(journal, encoding='utf-8') as f:
                recovery = json.load(f)
            for target, backup in recovery['files'].items():
                with open(backup, encoding='utf-8') as f:
                    self._atomic_config_write(target, f.read())
            os.unlink(journal)
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
            self._atomic_config_write(CONFIG_FILE, json.dumps(self.config, indent=2))

    @staticmethod
    def _atomic_config_write(path, content):
        """Replace a secret-bearing config without exposing a partially written file."""
        fd, temporary = tempfile.mkstemp(prefix='.awg-', dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

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

    def _normalize_country_code(self, value):
        """ISO 3166-1 alpha-2 (e.g. 'DE', 'NL'). Returns '' if invalid/empty."""
        if not value:
            return ""
        text = str(value).strip().upper()
        if len(text) != 2 or not text.isalpha():
            return ""
        return text

    def _country_code_to_flag(self, country_code):
        """Convert ISO alpha-2 country code to the regional-indicator emoji flag.

        'DE' -> '🇩🇪'. Returns '' for invalid input. The flag rendering depends on
        the user's font support, but HAPP / v2rayN / Hiddify all render emoji.
        """
        cc = self._normalize_country_code(country_code)
        if not cc:
            return ""
        # 0x1F1E6 == '🇦' (regional indicator A). Offset each letter from 'A'.
        return "".join(chr(0x1F1E6 + (ord(ch) - ord('A'))) for ch in cc)

    def _get_server_location_meta(self, server):
        """Return ``(country_code, flag, display_location)`` with sensible fallbacks.

        Old VLESS servers without location fields still work; they fall back to
        the server name for display and an empty flag.
        """
        if not isinstance(server, dict):
            return "", "", ""
        cc = self._normalize_country_code(server.get("country_code"))
        flag = server.get("flag_emoji") or self._country_code_to_flag(cc)
        display = (server.get("display_location") or server.get("name") or "Server").strip()
        return cc, flag, display

    def _format_memevpn_label_from_remote(self, remote):
        """Build a MemeVPN-style label for a satellite-cached client.

        ``remote`` is one of the entries in ``user_record["remote_clients"]``
        (the cached payload of a satellite's add_vless_client response, plus
        country/flag/display fields the hub copied at provision time).
        """
        return self._format_memevpn_subscription_label({
            "name": remote.get("display_location") or remote.get("satellite_label") or "Server",
            "country_code": remote.get("country_code", ""),
            "flag_emoji": remote.get("flag_emoji", ""),
            "display_location": remote.get("display_location", ""),
        })

    def _replace_vless_link_label(self, link, new_label):
        """Replace the URI fragment (text after the last #) on a vless:// link.

        Satellites generate links with their own legacy ``Server-Client`` labels
        — the hub re-writes those to MemeVPN brand format before emitting them
        in the multi-server subscription so HAPP shows a coherent list.
        """
        if not link:
            return link
        base, sep, _old = link.rpartition("#")
        if not sep:
            base = link
        return f"{base}#{quote(new_label, safe='')}"

    def _format_memevpn_subscription_label(self, server):
        """Pretty per-link label shown in HAPP's server list.

        Format: ``MemeVPN | 🇩🇪 Germany #1``. If no flag is configured, the pipe
        before it is dropped; if no display location either, the server name is
        used. Length is capped to 64 chars to stay safe across clients.
        """
        cc, flag, display = self._get_server_location_meta(server)
        parts = [MEMEVPN_BRAND.strip() or "MemeVPN", "|"]
        if flag:
            parts.append(flag)
        parts.append(display or server.get("name", "Server"))
        return self._sanitize_label(" ".join(parts))

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
            raise ValueError("path is required for VLESS HTTP transports")
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

    def _normalize_vless_transport(self, transport, default="tcp"):
        value = str(transport or default).strip().lower()
        aliases = {
            "tcp": "tcp",
            "raw": "tcp",
            "xhttp": "xhttp",
            "ws": "ws",
            "websocket": "ws",
        }
        if value not in aliases:
            raise ValueError("transport must be one of: tcp, raw, xhttp, ws, websocket")
        return aliases[value]

    def _vless_transport(self, vless):
        # Missing transport means an older server created before TCP/RAW support.
        # Keep those on xhttp so regeneration does not silently change live links.
        return self._normalize_vless_transport((vless or {}).get("transport"), default="xhttp")

    def _normalize_vless_flow(self, flow, transport="tcp"):
        if self._normalize_vless_transport(transport, default="tcp") != "tcp":
            return ""
        value = str(flow or "").strip().lower()
        aliases = {
            "": "",
            "none": "",
            "off": "",
            "vision": "xtls-rprx-vision",
            "xtls-rprx-vision": "xtls-rprx-vision",
        }
        if value not in aliases:
            raise ValueError("flow must be one of: none, xtls-rprx-vision")
        return aliases[value]

    def _vless_flow(self, vless):
        return self._normalize_vless_flow((vless or {}).get("flow"), self._vless_transport(vless))

    def _normalize_reality_profile(self, profile):
        value = str(profile or "").strip().lower().replace("-", "_")
        aliases = {
            "": "own_domain",
            "own": "own_domain",
            "self": "own_domain",
            "domain": "own_domain",
            "own_domain": "own_domain",
            "ultimate": "own_domain",
            "ultimate_like": "own_domain",
            "mask": "external_mask",
            "external": "external_mask",
            "external_mask": "external_mask",
            "legacy": "external_mask",
            "sni_mask": "external_mask",
        }
        if value not in aliases:
            raise ValueError("reality_profile must be one of: own_domain, external_mask")
        return aliases[value]

    def _vless_reality_profile(self, vless):
        return self._normalize_reality_profile((vless or {}).get("reality_profile"))

    def _reality_server_names_for_domain(self, domain):
        value = self._validate_domain(domain)
        return [value]

    def _vless_reality_server_names(self, vless):
        names = [str(n or "").strip().lower() for n in ((vless or {}).get("reality_server_names") or [])]
        names = [n for n in names if n]
        if names:
            return names
        if self._vless_reality_profile(vless) == "own_domain":
            return self._reality_server_names_for_domain((vless or {}).get("domain"))
        reality_dest = (vless or {}).get("reality_dest") or "microsoft.com:443"
        return self._reality_server_names_for_host(reality_dest.split(":")[0])

    def _vless_reality_target(self, vless):
        if self._vless_reality_profile(vless) == "own_domain":
            return (vless or {}).get("reality_fallback_target") or REALITY_INTERNAL_FALLBACK_TARGET
        return (vless or {}).get("reality_dest") or "microsoft.com:443"

    def _vless_is_reality(self, vless):
        """REALITY terminates TLS-like handshakes in Xray for xhttp or tcp/raw."""
        if not vless:
            return False
        if vless.get("security") == "reality":
            return True
        return bool(vless.get("reality_private_key"))

    def _normalize_reality_dest(self, dest):
        raw = str(dest or "").strip()
        if not raw:
            raw = "microsoft.com:443"
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
    # DPI on bridge VPS providers cuts TLS to a foreign IP whenever the
    # ClientHello SNI is a Russian whitelist domain. The bridge → exit chain
    # leg therefore must use a foreign SNI, which means the exit's Reality
    # and the upstream nginx stream map have to accept it. We append the
    # masks here so every newly created exit is bridge-ready out of the box;
    # legacy exits get migrated lazily by `create_bridge_config`.
    #
    # Choice of mask matters: well-known Reality default masks (microsoft.com,
    # apple.com, etc.) are heuristically detected and cut by some RU VPS
    # providers' DPI within ~5 s. www.google.com is verified to survive ≥30 s
    # because it sees so much real Russian-user traffic that DPI can't
    # reliably distinguish VPN from legitimate use.
    REALITY_FOREIGN_CHAIN_MASKS = ("www.google.com", "google.com")

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
        # Xray allows up to 8 bytes (16 hex chars). Use the full length for new
        # servers to reduce active-probing guessability without affecting UX.
        return secrets.token_hex(XRAY_REALITY_SHORT_ID_BYTES)

    def _generate_reality_spiderx(self):
        return self._generate_random_path()

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
            transport = self._vless_transport(vless)
            path = vless.get("path")
            inbound_port = vless.get("inbound_port")
            if not path or not inbound_port:
                continue
            # IMPORTANT:
            # - Use prefix match (^~) to allow HTTP transport URL variants (e.g. trailing slash / query).
            # - Disable basic auth for this location, otherwise clients get 401 and never reach xray.
            lines.append(f"location ^~ {path} {{")
            lines.append("    auth_basic off;")
            lines.append(f"    proxy_pass http://{XRAY_UPSTREAM_HOST}:{int(inbound_port)};")
            lines.append("    proxy_http_version 1.1;")
            if transport == "ws":
                lines.append("    proxy_set_header Upgrade $http_upgrade;")
                lines.append('    proxy_set_header Connection "upgrade";')
                lines.append("    proxy_cache off;")
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

    def _vless_stream_sni_conflicts(self):
        """Return stream-routed REALITY SNI names used by more than one server.

        nginx stream can only route a TLS ClientHello to one backend based on
        SNI. If two VLESS inbounds on the same VPS accept the same REALITY SNI,
        one of them will receive clients intended for the other and those
        clients will be rejected by Xray.
        """
        by_sni = {}
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            vless = server.get("vless") or {}
            if not self._vless_is_reality(vless) or not vless.get("use_stream"):
                continue
            for sn in (vless.get("reality_server_names") or []):
                key = str(sn or "").strip().lower()
                if not key:
                    continue
                by_sni.setdefault(key, []).append({
                    "server_id": server.get("id"),
                    "server_name": server.get("name"),
                    "inbound_port": vless.get("inbound_port"),
                })
        return {sni: refs for sni, refs in by_sni.items() if len(refs) > 1}

    def _find_vless_reality_sni_owners(self, server_names, exclude_id=None):
        """Return existing stream-routed REALITY servers that already own these SNI names."""
        wanted = {
            str(sn or "").strip().lower()
            for sn in (server_names or [])
            if str(sn or "").strip()
        }
        if not wanted:
            return []
        owners = []
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            if exclude_id and server.get("id") == exclude_id:
                continue
            vless = server.get("vless") or {}
            if not self._vless_is_reality(vless) or not vless.get("use_stream"):
                continue
            existing = {
                str(sn or "").strip().lower()
                for sn in (vless.get("reality_server_names") or [])
                if str(sn or "").strip()
            }
            overlap = sorted(wanted & existing)
            if overlap:
                owners.append({
                    "server_id": server.get("id"),
                    "server_name": server.get("name"),
                    "sni": overlap,
                })
        return owners

    def vless_server_warnings(self, server, sni_conflicts=None):
        warnings = []
        if not server or server.get("protocol") != "vless":
            return warnings
        vless = server.get("vless") or {}
        if self._server_has_linked_upstream(server) and XRAY_UPSTREAM_HOST not in ("127.0.0.1", "localhost"):
            warnings.append(
                "Linked VLESS via AmneziaWG requires Xray to share the web-ui network namespace; set XRAY_UPSTREAM_HOST=127.0.0.1 and use the updated docker-compose.yml."
            )
        transport = self._vless_transport(vless)
        if transport == "ws" and not self._vless_is_reality(vless):
            ssl_domain = os.getenv("SSL_DOMAIN", "").strip().lower()
            ssl_email = os.getenv("SSL_EMAIL", "").strip()
            vless_domain = str(vless.get("domain") or "").strip().lower()
            if NGINX_PORT == "443" and (not ssl_domain or not ssl_email):
                warnings.append(
                    "WebSocket+TLS needs SSL_DOMAIN and SSL_EMAIL configured so nginx can terminate HTTPS on internal :4443 behind the external :443 stream listener."
                )
            elif vless_domain and ssl_domain != vless_domain:
                warnings.append(
                    f"WebSocket+TLS certificate SNI should match the VLESS domain ({vless_domain}); current SSL_DOMAIN is {ssl_domain}."
                )
        if self._vless_is_reality(vless) and vless.get("use_stream"):
            short_ids = [
                str(sid or "").strip()
                for sid in (vless.get("reality_short_ids") or [vless.get("reality_short_id")])
                if str(sid or "").strip()
            ]
            if any(len(sid) < 16 for sid in short_ids):
                warnings.append(
                    "REALITY shortId is shorter than the recommended 8 bytes (16 hex chars). Existing clients keep working, but new/rotated servers should use a full-length shortId."
                )
            ssl_domain = os.getenv("SSL_DOMAIN", "").strip().lower()
            ssl_email = os.getenv("SSL_EMAIL", "").strip()
            vless_domain = str(vless.get("domain") or "").strip().lower()
            if NGINX_PORT == "443" and (not ssl_domain or not ssl_email):
                warnings.append(
                    "Port 443 stream routing needs both SSL_DOMAIN and SSL_EMAIL configured so nginx HTTP moves to internal :4443 and nginx stream can own external :443."
                )
            elif self._vless_reality_profile(vless) == "own_domain" and vless_domain and ssl_domain != vless_domain:
                warnings.append(
                    f"Own-domain REALITY fallback works best when SSL_DOMAIN matches the VLESS domain ({vless_domain}); current SSL_DOMAIN is {ssl_domain}."
                )
            conflicts = sni_conflicts if sni_conflicts is not None else self._vless_stream_sni_conflicts()
            own_id = server.get("id")
            conflict_names = []
            for sn in (vless.get("reality_server_names") or []):
                key = str(sn or "").strip().lower()
                refs = conflicts.get(key) or []
                if any(ref.get("server_id") == own_id for ref in refs):
                    others = [ref.get("server_id") for ref in refs if ref.get("server_id") != own_id]
                    if others:
                        conflict_names.append(f"{key} also used by {', '.join(others)}")
            if conflict_names:
                warnings.append(
                    "REALITY SNI conflict on port 443: "
                    + "; ".join(conflict_names)
                    + ". Use a unique REALITY dest per VLESS server on the same VPS, or keep one VLESS server per VPS."
                )
        return warnings

    def _build_stream_conf(self, sni_to_port: dict, port_set: set) -> str:
        """Render the nginx stream{} block from the SNI→port mapping."""
        map_lines = []
        for sn, port in sorted(sni_to_port.items()):
            map_lines.append(f"        {sn}   xray_{port};")

        upstream_blocks = []
        for port in sorted(port_set):
            upstream_blocks.append(
                f"    upstream xray_{port} {{\n        server {XRAY_UPSTREAM_HOST}:{port};\n    }}"
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
        - REALITY: xhttp or tcp/raw + security reality; TLS-like handshakes are handled by Xray.
        """
        inbounds = []
        outbounds = [
            {
                "protocol": "freedom",
                "settings": {"domainStrategy": XRAY_DOMAIN_STRATEGY},
                "tag": "direct",
                # BBR on the outbound socket stabilises throughput for exit-to-internet
                # traffic; TFO is opt-in because some restrictive networks mishandle it.
                "streamSettings": {
                    "sockopt": {
                        "tcpcongestion": "bbr",
                        "tcpFastOpen": XRAY_TCP_FAST_OPEN,
                    }
                },
            }
        ]
        routing_rules = []
        for server in self.config.get("servers", []):
            if server.get("protocol") != "vless":
                continue
            vless = server.get("vless") or {}
            transport = self._vless_transport(vless)
            flow = self._vless_flow(vless)
            inbound_port = vless.get("inbound_port")
            domain = vless.get("domain")
            path = vless.get("path")
            mode = vless.get("mode") or "stream-up"
            host = vless.get("host") or domain
            if not inbound_port or not domain:
                continue
            if transport in ("xhttp", "ws") and not path:
                continue

            clients = []
            for client in server.get("clients", []):
                if self._should_delete_expired_client(client):
                    continue
                if not client.get("uuid"):
                    continue
                item = {"id": client["uuid"], "email": self._sanitize_label(client.get("name"), "client")}
                if self._vless_is_reality(vless) and transport == "tcp" and flow:
                    item["flow"] = flow
                clients.append(item)

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
                "tcpFastOpen": XRAY_TCP_FAST_OPEN,
            }
            if XRAY_TCP_MAX_SEG > 0:
                common_sockopt["tcpMaxSeg"] = XRAY_TCP_MAX_SEG

            if self._vless_is_reality(vless):
                reality_target = self._vless_reality_target(vless)
                server_names = self._vless_reality_server_names(vless)
                short_ids = vless.get("reality_short_ids")
                if not short_ids:
                    sid = vless.get("reality_short_id") or ""
                    # Only include non-empty short IDs (empty string = no auth required, security risk)
                    short_ids = [sid] if sid else [""]
                priv = vless.get("reality_private_key")
                if not priv:
                    continue
                stream_settings = {
                    "network": "raw" if transport == "tcp" else "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        # Own-domain mode falls back to the real nginx HTTPS listener;
                        # legacy mode keeps using the operator-selected external mask.
                        "target": reality_target,
                        "xver": 0,
                        "spiderX": vless.get("reality_spiderx") or "/",
                        "serverNames": server_names,
                        "privateKey": priv,
                        "shortIds": short_ids,
                        # Allow up to 70 s clock drift between client and server.
                        # Without this, a client with a slightly off clock gets silently rejected by
                        # Reality's timestamp check — looks like the VPN "doesn't connect".
                        "maxTimeDiff": XRAY_REALITY_MAX_TIME_DIFF_MS,
                    },
                    "xhttpSettings": dict(common_xhttp),
                    "sockopt": dict(common_sockopt),
                }
                if transport == "tcp":
                    stream_settings.pop("xhttpSettings", None)
                    stream_settings["rawSettings"] = {
                        "acceptProxyProtocol": False,
                        "header": {"type": "none"},
                    }
            else:
                if transport == "ws":
                    stream_settings = {
                        "network": "websocket",
                        "security": "none",
                        "wsSettings": {
                            "acceptProxyProtocol": False,
                            "path": path,
                            "host": host,
                        },
                        "sockopt": dict(common_sockopt),
                    }
                else:
                    stream_settings = {
                        "network": "xhttp",
                        "security": "none",
                        "xhttpSettings": dict(common_xhttp),
                        "sockopt": dict(common_sockopt),
                    }

            inbound_tag = f"vless-{server.get('id')}"
            inbounds.append({
                "tag": inbound_tag,
                "listen": "0.0.0.0",
                "port": int(inbound_port),
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
                "streamSettings": stream_settings,
            })

            if self._server_has_linked_upstream(server):
                outbound_tag = "direct"
                if server.get("routing_state", "upstream") == "upstream":
                    upstream = server.get("upstream") or {}
                    fwmark = int(upstream.get("fwmark") or upstream.get("table_id") or 0)
                    if fwmark:
                        outbound_tag = f"{inbound_tag}-awg"
                        outbounds.append({
                            "protocol": "freedom",
                            "settings": {"domainStrategy": XRAY_DOMAIN_STRATEGY},
                            "tag": outbound_tag,
                            "streamSettings": {
                                "sockopt": {
                                    "mark": fwmark,
                                    "tcpcongestion": "bbr",
                                    "tcpFastOpen": XRAY_TCP_FAST_OPEN,
                                }
                            },
                        })
                routing_rules.append({
                    "type": "field",
                    "inboundTag": [inbound_tag],
                    "outboundTag": outbound_tag,
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
                "queryStrategy": XRAY_DNS_QUERY_STRATEGY,
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
        }
        if routing_rules:
            config["routing"] = {
                "domainStrategy": "IPIfNonMatch",
                "rules": routing_rules,
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
        transport = self._normalize_vless_transport(
            server_data.get("transport") or server_data.get("network"),
            default="tcp",
        )
        if transport in ("xhttp", "ws"):
            path = self._normalize_vless_path(server_data.get("path"))
            host = self._validate_domain(server_data.get("host") or domain)
            if transport == "xhttp":
                legacy_mode = str(server_data.get("mode") or "").strip().lower()
                legacy_xhttp_mode = legacy_mode if legacy_mode not in ("standalone", "edge_linked") else ""
                xhttp_mode = self._normalize_xhttp_mode(server_data.get("xhttp_mode") or legacy_xhttp_mode)
            else:
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                    raise ValueError("WebSocket+TLS requires a DNS name with a valid SSL certificate, not a bare IP address")
                xhttp_mode = ""
        else:
            raw_path = str(server_data.get("path") or "").strip()
            path = self._normalize_vless_path(raw_path) if raw_path else ""
            xhttp_mode = ""
            host = domain
        flow_raw = server_data.get("flow")
        if transport == "tcp" and flow_raw is None:
            flow_raw = "xtls-rprx-vision"
        flow = self._normalize_vless_flow(flow_raw, transport)
        is_reality_transport = transport in ("tcp", "xhttp")
        if is_reality_transport:
            reality_profile = self._normalize_reality_profile(server_data.get("reality_profile"))
            if reality_profile == "own_domain":
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                    raise ValueError("own-domain REALITY profile requires a DNS name, not a bare IP address")
                reality_dest = f"{domain}:443"
                server_names = self._reality_server_names_for_domain(domain)
                reality_fallback_target = str(
                    server_data.get("reality_fallback_target") or REALITY_INTERNAL_FALLBACK_TARGET
                ).strip()
            else:
                reality_dest, dest_host = self._normalize_reality_dest(server_data.get("reality_dest"))
                server_names = self._reality_server_names_for_host(dest_host)
                reality_fallback_target = ""
            priv, pub = self._generate_reality_keypair()
            short_id = self._generate_reality_short_id()
            # Non-empty shortId only: the empty string allows unauthenticated connections.
            short_ids = [short_id]
            reality_spiderx = str(server_data.get("reality_spiderx") or self._generate_reality_spiderx()).strip()
            sni_owners = self._find_vless_reality_sni_owners(server_names)
            if sni_owners:
                details = "; ".join(
                    f"{', '.join(owner['sni'])} -> {owner.get('server_name') or owner.get('server_id')}"
                    for owner in sni_owners
                )
                raise ValueError(
                    "REALITY SNI is already used by another VLESS server on this VPS. "
                    "nginx stream can route one SNI to only one Xray inbound; add clients to the existing server "
                    f"or use a different domain/mask. Conflicts: {details}"
                )
        else:
            reality_profile = ""
            reality_dest = ""
            server_names = []
            reality_fallback_target = ""
            priv = ""
            pub = ""
            short_id = ""
            short_ids = []
            reality_spiderx = ""

        # Location metadata for the multi-server MemeVPN subscription (HAPP labels).
        # All optional — old code paths that don't set these still work.
        country_code = self._normalize_country_code(server_data.get("country_code"))
        flag_emoji = (server_data.get("flag_emoji") or "").strip()
        if not flag_emoji and country_code:
            flag_emoji = self._country_code_to_flag(country_code)
        display_location = (server_data.get("display_location") or "").strip()
        description = (server_data.get("description") or "").strip()

        # Fingerprint: which TLS client fingerprint Xray impersonates. chrome is the safest
        # default; iOS users may benefit from ios/safari.
        _valid_fps = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
        fingerprint = str(server_data.get("fingerprint") or "chrome").strip().lower()
        if fingerprint not in _valid_fps:
            fingerprint = "chrome"

        # VLESS is always client-facing on external TCP :443. Xray listens on an
        # internal-only port and nginx stream proxies :443 to it by REALITY SNI.
        use_stream = True

        server_id = str(uuid.uuid4())[:6]
        server_mode = str(server_data.get("mode", "standalone")).strip().lower()
        if server_mode not in ("standalone", "edge_linked"):
            raise ValueError("mode must be 'standalone' or 'edge_linked'")
        auto_start = self._to_bool(server_data.get("auto_start"), True)
        upstream_config = None
        failover_mode = None
        routing_state = None
        egress_interface = "eth+"
        upstream_mtu = DEFAULT_MTU
        if server_mode == "edge_linked":
            upstream_interface = f"vl-{server_id}-up"[:15]
            upstream_config, failover_mode, upstream_mtu, _ = self.build_imported_upstream_config(
                server_id=server_id,
                upstream_interface=upstream_interface,
                upstream_data=server_data.get("upstream") or {},
                mtu=DEFAULT_MTU,
                table_base=300,
                include_fwmark=True,
            )
            routing_state = "upstream"
            egress_interface = upstream_interface

        subscription_id = self._generate_subscription_id()
        inbound_port = self._allocate_xray_stream_inbound_port()
        client_port = 443

        server_config = {
            "id": server_id,
            "name": server_name,
            "protocol": "vless",
            # top-level port is the client-facing port (443 for stream mode, inbound_port otherwise)
            "port": client_port,
            "status": "ready",
            "public_ip": self.public_ip,
            "created_at": time.time(),
            "mode": server_mode,
            "auto_start": auto_start,
            "upstream": upstream_config,
            "egress_interface": egress_interface,
            "linked_failover_mode": failover_mode,
            "routing_state": routing_state,
            "mtu": upstream_mtu,
            "clients": [],
            # Location metadata used by the multi-server subscription endpoint.
            "country_code": country_code,
            "flag_emoji": flag_emoji,
            "display_location": display_location,
            "description": description,
            "vless": {
                "domain": domain,
                # client_port: what vless:// URIs advertise (443 in stream mode)
                "port": client_port,
                "client_port": client_port,
                "path": path,
                "mode": xhttp_mode,
                "host": host,
                "security": "reality" if is_reality_transport else "tls",
                "transport": transport,
                "flow": flow,
                "encryption": "none",
                "subscription_id": subscription_id,
                # inbound_port: what Xray actually listens on (9443+ in stream mode)
                "inbound_port": inbound_port,
                "use_stream": use_stream,
                "reality_profile": reality_profile,
                "reality_dest": reality_dest,
                "reality_fallback_target": reality_fallback_target,
                "reality_server_names": server_names,
                "reality_private_key": priv,
                "reality_public_key": pub,
                "reality_short_id": short_id,
                "reality_short_ids": short_ids,
                "reality_spiderx": reality_spiderx,
                "reality_fingerprint": fingerprint,
                "tls_fingerprint": fingerprint,
                "ws_early_data": XRAY_WS_EARLY_DATA_BYTES if transport == "ws" else 0,
            },
        }

        self.config["servers"].append(server_config)
        self.save_config()

        if upstream_config:
            with open(upstream_config["config_path"], "w") as f:
                f.write(self.generate_upstream_config_content(upstream_config, upstream_mtu))
            if auto_start:
                if self.start_upstream_link(server_config):
                    server_config["routing_state"] = "upstream"
                    server_config["egress_interface"] = upstream_config["interface"]
                elif failover_mode == "fail_open":
                    self.cleanup_vless_upstream_routing(server_config)
                    server_config["routing_state"] = "local"
                    server_config["egress_interface"] = "eth+"
                else:
                    self.configure_vless_fail_closed_routing(server_config)
                    server_config["routing_state"] = "upstream"
                    server_config["egress_interface"] = upstream_config["interface"]
                self.save_config()
            else:
                self.configure_vless_fail_closed_routing(server_config)
                server_config["routing_state"] = "upstream"
                server_config["egress_interface"] = upstream_config["interface"]
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
        bridge_spiderx = self._generate_reality_spiderx()
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
            exit_spiderx = existing_bridge_client.get('reality_spiderx') or vless.get('reality_spiderx') or '/'
        else:
            new_client, _, _ = self.add_vless_client(server_id, bridge_client_name, "forever")
            exit_uuid = new_client['uuid']
            exit_spiderx = new_client.get('reality_spiderx') or vless.get('reality_spiderx') or '/'

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
        exit_transport = self._vless_transport(vless)
        exit_flow = self._vless_flow(vless)

        # Socket options reused on both bridge inbound and the chain-to-exit outbound.
        # BBR improves throughput on congested RU links; TFO is opt-in for compatibility.
        bridge_sockopt = {
            "tcpcongestion": "bbr",
            "tcpKeepAliveInterval": 30,
            "tcpKeepAliveIdle": 300,
            "tcpFastOpen": XRAY_TCP_FAST_OPEN,
        }
        if XRAY_TCP_MAX_SEG > 0:
            bridge_sockopt["tcpMaxSeg"] = XRAY_TCP_MAX_SEG
        bridge_outbound_sockopt = dict(bridge_sockopt)
        bridge_outbound_sockopt["domainStrategy"] = XRAY_DOMAIN_STRATEGY

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
                "queryStrategy": XRAY_DNS_QUERY_STRATEGY
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
                        "spiderX": bridge_spiderx,
                        "maxTimeDiff": XRAY_REALITY_MAX_TIME_DIFF_MS,
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
                            "spiderX": exit_spiderx,
                            # Tolerate clock drift on the RU bridge (often on virtualised VPS
                            # with poor NTP sync) — matches the exit inbound setting.
                            "maxTimeDiff": XRAY_REALITY_MAX_TIME_DIFF_MS,
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
                        "sockopt": dict(bridge_outbound_sockopt),
                    }
                },
                {
                    "protocol": "freedom",
                    "settings": {"domainStrategy": XRAY_DOMAIN_STRATEGY},
                    "tag": "direct",
                }
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
        if exit_transport == "tcp":
            chain = bridge_config["outbounds"][0]
            chain["settings"]["vnext"][0]["users"][0]["flow"] = exit_flow
            chain_stream = chain["streamSettings"]
            chain_stream["network"] = "raw"
            chain_stream.pop("xhttpSettings", None)
            chain_stream["rawSettings"] = {
                "acceptProxyProtocol": False,
                "header": {"type": "none"},
            }

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
            f"&spx={quote(bridge_spiderx, safe='')}"
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

    def generate_vless_client_link(self, server, client_config, *, label_style="legacy"):
        """Build a ``vless://...#label`` URI.

        ``label_style``:
          - ``"legacy"``: keeps the existing ``Server-Client`` label so old
            single-server subscriptions and per-client downloads don't change.
          - ``"memevpn"``: uses ``MemeVPN | 🇩🇪 Germany`` for the multi-server
            subscription endpoint.
        """
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
        transport = self._vless_transport(vless)
        flow = self._vless_flow(vless)

        if label_style == "memevpn":
            label = self._format_memevpn_subscription_label(server)
        else:
            label = self._sanitize_label(f"{server.get('name', 'Server')}-{client_config.get('name', 'Client')}")

        if self._vless_is_reality(vless):
            names = vless.get("reality_server_names") or []
            sni = names[0] if names else "www.microsoft.com"
            fp = vless.get("reality_fingerprint") or "chrome"
            pbk = vless.get("reality_public_key") or ""
            sid = vless.get("reality_short_id") or ""
            spiderx = client_config.get("reality_spiderx") or vless.get("reality_spiderx") or "/"
            # `spx` maps to client reality spiderX (/); improves compatibility with REALITY-capable apps (HAPP, v2rayN, etc.).
            if transport == "tcp":
                parts = [
                    "encryption=none",
                    "security=reality",
                    "type=tcp",
                    "headerType=none",
                    f"sni={quote(sni, safe='')}",
                    f"fp={quote(fp, safe='')}",
                    f"pbk={quote(pbk, safe='')}",
                    f"sid={quote(sid, safe='')}",
                    f"spx={quote(spiderx, safe='')}",
                ]
                if flow:
                    parts.append(f"flow={quote(flow, safe='')}")
                q = "&".join(parts)
            else:
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
                    f"&spx={quote(spiderx, safe='')}"
                    "&flow="
                )
        else:
            fp = vless.get("tls_fingerprint") or vless.get("reality_fingerprint") or "chrome"
            if transport == "ws":
                ws_path = path
                try:
                    early_data = int(vless.get("ws_early_data") or XRAY_WS_EARLY_DATA_BYTES or 0)
                except (TypeError, ValueError):
                    early_data = XRAY_WS_EARLY_DATA_BYTES
                early_data = max(0, min(8192, early_data))
                if early_data:
                    separator = "&" if "?" in ws_path else "?"
                    ws_path = f"{ws_path}{separator}ed={early_data}"
                parts = [
                    "encryption=none",
                    "security=tls",
                    "type=ws",
                    f"path={quote(ws_path, safe='')}",
                    f"host={quote(host, safe='')}",
                    f"sni={quote(domain, safe='')}",
                    f"fp={quote(fp, safe='')}",
                    "alpn=http%2F1.1",
                ]
                q = "&".join(parts)
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

    def add_vless_client(self, server_id, client_name, duration_code="forever", user_id=None):
        """Add a client to a VLESS server (link/QR only).

        ``user_id`` (optional) ties this client to a logical user owner so the
        multi-server subscription endpoint can collect all of a user's clients
        across servers. ``None`` keeps the legacy single-server bot flow working.
        """
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
            # Allow tagging an existing client with a user_id on first provision.
            if user_id and not client.get("user_id"):
                client["user_id"] = user_id
                global_client = self.config.get("clients", {}).get(client["id"])
                if global_client is not None:
                    global_client["user_id"] = user_id
                self.save_config()
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
            "user_id": user_id or None,
            "reality_spiderx": self._generate_reality_spiderx(),
        }

        server.setdefault("clients", []).append(client_config)
        self.config.setdefault("clients", {})[client_id] = client_config
        self.save_config()

        self._write_xray_config()

        link = self.generate_vless_client_link(server, client_config)
        return client_config, link, False

    # ─────────────────────────────────────────────────────────────────────
    # Multi-server (per-user) subscription model.
    #
    # A "user" here is one logical owner — typically a Telegram bot user — who
    # may have one client on each VLESS server. Bot calls /api/users/<id>/provision
    # once; every server gets a new VLESS client tagged with the user_id, and
    # the user gets a single subscription URL that lists all of them.
    # ─────────────────────────────────────────────────────────────────────

    def _normalize_user_id(self, user_id):
        text = str(user_id or "").strip()
        if not text:
            raise ValueError("user_id is required")
        if len(text) > 128:
            raise ValueError("user_id is too long (max 128)")
        if not re.fullmatch(r"[A-Za-z0-9._:@-]+", text):
            raise ValueError("user_id may contain only A-Z, a-z, 0-9, '.', '_', ':', '@', '-'")
        return text

    def _get_or_create_user(self, user_id, name=None):
        """Return the user record, creating it (with a fresh subscription token)
        on first call. The token never rotates automatically — call
        ``rotate_user_token`` explicitly if a leak is suspected.
        """
        uid = self._normalize_user_id(user_id)
        with self.config_lock:
            users = self.config.setdefault("users", {})
            tokens = self.config.setdefault("user_tokens", {})
            record = users.get(uid)
            if record is None:
                token = self._generate_subscription_id()
                # Avoid the astronomically rare token collision with another user.
                while token in tokens:
                    token = self._generate_subscription_id()
                record = {
                    "user_id": uid,
                    "name": (str(name).strip() if name else "") or uid,
                    "token": token,
                    "created_at": time.time(),
                }
                users[uid] = record
                tokens[token] = uid
                self.save_config()
            elif name and not record.get("name"):
                record["name"] = str(name).strip()
                self.save_config()
            return record

    def _resolve_user_token(self, token):
        """Return ``(user_id, record)`` for a subscription token or ``(None, None)``."""
        if not token:
            return None, None
        uid = self.config.get("user_tokens", {}).get(token)
        if not uid:
            return None, None
        record = self.config.get("users", {}).get(uid)
        return uid, record

    def _get_user_clients(self, user_id):
        """Return live client configs for a user across all servers (skipping
        clients past the grace period — they're effectively gone)."""
        uid = self._normalize_user_id(user_id)
        results = []
        now_ts = time.time()
        for server in self.config.get("servers", []):
            for client in server.get("clients", []):
                if client.get("user_id") != uid:
                    continue
                if self._should_delete_expired_client(client, now_ts):
                    continue
                results.append((server, client))
        return results

    def get_active_vless_servers(self):
        return [s for s in self.config.get("servers", []) if s.get("protocol") == "vless"]

    def _fanout_provision_to_satellites(self, uid, duration_code, user_record, provisioned):
        """Create or top-up clients on every registered satellite for this user.

        Mutates ``user_record["remote_clients"]`` so the next subscription fetch
        returns the new links. Failures per satellite are non-fatal — they're
        recorded in ``user_record["remote_errors"]`` for the operator UI.
        """
        sats = self.config.get("satellites", {})
        if not sats:
            return
        remote_clients = user_record.setdefault("remote_clients", [])
        remote_errors = []

        # Build an O(1) lookup of existing remotes so re-provision extends instead
        # of creating duplicate clients on the satellite.
        existing_idx = {(r.get("satellite_id"), r.get("remote_server_id")): r for r in remote_clients}

        for sat_id, sat in sats.items():
            for srv in sat.get("servers", []):
                key = (sat_id, srv["id"])
                client_name = f"user-{uid}"
                try:
                    if key in existing_idx:
                        # Already provisioned — extend on the satellite to align expiry.
                        existing = existing_idx[key]
                        ext = self._satellite_request(
                            sat["base_url"], sat["api_key"], "POST",
                            f"/api/satellite/servers/{srv['id']}/clients/{existing['remote_client_id']}/extend",
                            {"duration_code": duration_code},
                            basic_auth=self._satellite_basic_auth(sat),
                        )
                        existing["expires_at"] = ext.get("expires_at")
                        existing["country_code"] = srv.get("country_code", "")
                        existing["flag_emoji"] = srv.get("flag_emoji", "")
                        existing["display_location"] = srv.get("display_location", "")
                    else:
                        created = self._satellite_request(
                            sat["base_url"], sat["api_key"], "POST",
                            "/api/satellite/clients",
                            {
                                "server_id": srv["id"],
                                "client_name": client_name,
                                "duration_code": duration_code,
                            },
                            basic_auth=self._satellite_basic_auth(sat),
                        )
                        remote_clients.append({
                            "satellite_id": sat_id,
                            "satellite_label": sat.get("label"),
                            "remote_server_id": srv["id"],
                            "remote_client_id": created["client_id"],
                            "uuid": created.get("uuid"),
                            "country_code": srv.get("country_code", ""),
                            "flag_emoji": srv.get("flag_emoji", ""),
                            "display_location": srv.get("display_location", ""),
                            "link": created.get("link"),
                            "expires_at": created.get("expires_at"),
                        })
                        provisioned.append({
                            "server_id": srv["id"],
                            "server_name": srv.get("name"),
                            "satellite_id": sat_id,
                            "country_code": srv.get("country_code", ""),
                            "client_id": created["client_id"],
                            "uuid": created.get("uuid"),
                            "expires_at": created.get("expires_at"),
                            "renewed": False,
                            "link": created.get("link"),
                        })
                except ValueError as e:
                    remote_errors.append({"satellite_id": sat_id, "server_id": srv["id"], "error": str(e)})
                    print(f"provision: satellite {sat_id} server {srv['id']} failed: {e}")

        user_record["remote_errors"] = remote_errors
        with self.config_lock:
            self.save_config()

    def _remote_client_is_live_for_broadcast(self, remote, now_ts=None):
        exp = (remote or {}).get("expires_at")
        if exp is None:
            return True
        try:
            grace = max(0.0, CLIENT_DELETE_GRACE_DAYS) * 24 * 60 * 60
            return (now_ts or time.time()) < float(exp) + grace
        except (TypeError, ValueError):
            return True

    def _user_has_live_clients_for_broadcast(self, uid, record=None):
        if self._get_user_clients(uid):
            return True
        record = record or self.config.get("users", {}).get(uid) or {}
        now_ts = time.time()
        return any(
            self._remote_client_is_live_for_broadcast(remote, now_ts)
            for remote in record.get("remote_clients", [])
        )

    def _broadcast_duration_for_user(self, uid, user_record, fallback_duration_code):
        """Preserve a user's current subscription expiry when adding a server.

        Broadcast should not sell/extend time. It creates a client on the new
        server with the same effective expiry the user already has elsewhere.
        If the user has a permanent client, the new one is permanent too.
        """
        now_ts = time.time()
        expiries = []
        has_forever = False

        for _server, client in self._get_user_clients(uid):
            exp = client.get("expires_at")
            if exp is None:
                has_forever = True
            else:
                try:
                    expiries.append(float(exp))
                except (TypeError, ValueError):
                    pass

        for remote in (user_record or {}).get("remote_clients", []):
            if not self._remote_client_is_live_for_broadcast(remote, now_ts):
                continue
            exp = remote.get("expires_at")
            if exp is None:
                has_forever = True
            else:
                try:
                    expiries.append(float(exp))
                except (TypeError, ValueError):
                    pass

        if has_forever:
            return "forever"
        if expiries:
            # Use the subscription expiry visible to HAPP (latest active/grace
            # client expiry), preserving remaining time instead of adding more.
            return self._absolute_duration_code(max(expiries))
        return self._normalize_duration_code(fallback_duration_code)

    def _find_satellite_server_for_broadcast(self, target):
        """Resolve a satellite broadcast target.

        Accepts either a remote server id if it is unique across satellites, or
        the explicit ``satellite_id:server_id`` format.
        """
        raw = str(target or "").strip()
        sat_hint = None
        remote_id = raw
        if ":" in raw:
            sat_hint, remote_id = [part.strip() for part in raw.split(":", 1)]
            if not sat_hint or not remote_id:
                raise ValueError("Satellite target must be satellite_id:server_id")

        matches = []
        for sat_id, sat in self.config.get("satellites", {}).items():
            if sat_hint and sat_id != sat_hint:
                continue
            for srv in sat.get("servers", []):
                if srv.get("id") == remote_id:
                    matches.append((sat_id, sat, srv))

        if not matches:
            return None
        if len(matches) > 1:
            raise ValueError(
                "Satellite server_id is ambiguous; use satellite_id:server_id"
            )
        return matches[0]

    def _provision_single_satellite_server_for_user(
        self, uid, duration_code, user_record, sat_id, sat, srv
    ):
        remote_clients = user_record.setdefault("remote_clients", [])
        existing = next(
            (
                r for r in remote_clients
                if r.get("satellite_id") == sat_id
                and r.get("remote_server_id") == srv.get("id")
            ),
            None,
        )

        if existing:
            ext = self._satellite_request(
                sat["base_url"], sat["api_key"], "POST",
                f"/api/satellite/servers/{srv['id']}/clients/{existing['remote_client_id']}/extend",
                {"duration_code": duration_code},
                basic_auth=self._satellite_basic_auth(sat),
            )
            existing["expires_at"] = ext.get("expires_at")
            existing["country_code"] = srv.get("country_code", "")
            existing["flag_emoji"] = srv.get("flag_emoji", "")
            existing["display_location"] = srv.get("display_location", "")
            entry = existing
            renewed = True
        else:
            created = self._satellite_request(
                sat["base_url"], sat["api_key"], "POST",
                "/api/satellite/clients",
                {
                    "server_id": srv["id"],
                    "client_name": f"user-{uid}",
                    "duration_code": duration_code,
                },
                basic_auth=self._satellite_basic_auth(sat),
            )
            entry = {
                "satellite_id": sat_id,
                "satellite_label": sat.get("label"),
                "remote_server_id": srv["id"],
                "remote_client_id": created["client_id"],
                "uuid": created.get("uuid"),
                "country_code": srv.get("country_code", ""),
                "flag_emoji": srv.get("flag_emoji", ""),
                "display_location": srv.get("display_location", ""),
                "link": created.get("link"),
                "expires_at": created.get("expires_at"),
            }
            remote_clients.append(entry)
            renewed = False

        user_record["remote_errors"] = [
            e for e in user_record.get("remote_errors", [])
            if not (
                e.get("satellite_id") == sat_id
                and e.get("server_id") == srv.get("id")
            )
        ]
        return {
            "server_id": srv["id"],
            "server_name": srv.get("name"),
            "satellite_id": sat_id,
            "country_code": srv.get("country_code", ""),
            "client_id": entry.get("remote_client_id"),
            "uuid": entry.get("uuid"),
            "expires_at": entry.get("expires_at"),
            "renewed": renewed,
            "link": entry.get("link"),
            "scope": "satellite",
        }

    def provision_user(self, user_id, duration_code="1m", server_ids=None, name=None):
        """Ensure the user has a client on every local VLESS server *and* on
        every satellite-side VLESS server. Returns the user record, a list of
        provisioned/extended client descriptors, and the subscription URL path.
        """
        uid = self._normalize_user_id(user_id)
        user_record = self._get_or_create_user(uid, name=name)

        all_vless = self.get_active_vless_servers()
        sats = self.config.get("satellites", {})
        if not all_vless and not sats:
            raise ValueError("No VLESS servers exist locally and no satellites are registered")

        if server_ids:
            wanted = set(server_ids)
            target_servers = [s for s in all_vless if s.get("id") in wanted]
            missing = wanted - {s.get("id") for s in target_servers}
            if missing:
                raise ValueError(f"Unknown local server_id(s): {sorted(missing)}")
        else:
            target_servers = all_vless

        provisioned = []
        for server in target_servers:
            client_name = f"user-{uid}"
            result = self.add_vless_client(server["id"], client_name, duration_code, user_id=uid)
            if result:
                client_cfg, link, renewed = result
                provisioned.append({
                    "server_id": server["id"],
                    "server_name": server.get("name"),
                    "country_code": server.get("country_code", ""),
                    "client_id": client_cfg["id"],
                    "uuid": client_cfg["uuid"],
                    "expires_at": client_cfg.get("expires_at"),
                    "renewed": renewed,
                    "link": link,
                })

        # Federation fan-out (only when ``server_ids`` filter is absent — operator
        # asked for "everything" — keeping per-satellite filtering for a later iteration).
        if not server_ids:
            self._fanout_provision_to_satellites(uid, duration_code, user_record, provisioned)

        return user_record, provisioned, f"/api/sub/user/{user_record['token']}"

    def extend_user(self, user_id, duration_code):
        """Extend every existing client of the user (local + remote)."""
        uid = self._normalize_user_id(user_id)
        normalized_duration = self._normalize_duration_code(duration_code)
        extended = []
        for server, client in self._get_user_clients(uid):
            new_client, err = self.extend_client(server["id"], client["id"], normalized_duration)
            if err or not new_client:
                continue
            extended.append({
                "server_id": server["id"],
                "client_id": client["id"],
                "expires_at": new_client.get("expires_at"),
            })

        # Extend remote clients on each satellite.
        record = self.config.get("users", {}).get(uid)
        if record:
            sats = self.config.get("satellites", {})
            for remote in record.get("remote_clients", []):
                sat = sats.get(remote.get("satellite_id"))
                if not sat:
                    continue
                try:
                    ext = self._satellite_request(
                        sat["base_url"], sat["api_key"], "POST",
                        f"/api/satellite/servers/{remote['remote_server_id']}/clients/{remote['remote_client_id']}/extend",
                        {"duration_code": normalized_duration},
                        basic_auth=self._satellite_basic_auth(sat),
                    )
                    remote["expires_at"] = ext.get("expires_at")
                    extended.append({
                        "server_id": remote["remote_server_id"],
                        "client_id": remote["remote_client_id"],
                        "satellite_id": remote["satellite_id"],
                        "expires_at": remote["expires_at"],
                    })
                except ValueError as e:
                    print(f"extend: satellite {remote['satellite_id']} failed: {e}")
            with self.config_lock:
                self.save_config()
        return extended

    def delete_user(self, user_id, *, purge_clients=True):
        """Delete the user record and every client they own (local + remote)."""
        uid = self._normalize_user_id(user_id)
        removed_clients = []
        if purge_clients:
            for server, client in self._get_user_clients(uid):
                if self.delete_client(server["id"], client["id"], reason="user_deleted"):
                    removed_clients.append(client["id"])

            # Remove the user's clients on satellites too.
            record = self.config.get("users", {}).get(uid)
            if record:
                sats = self.config.get("satellites", {})
                for remote in record.get("remote_clients", []):
                    sat = sats.get(remote.get("satellite_id"))
                    if not sat:
                        continue
                    try:
                        self._satellite_request(
                            sat["base_url"], sat["api_key"], "DELETE",
                            f"/api/satellite/servers/{remote['remote_server_id']}/clients/{remote['remote_client_id']}",
                            basic_auth=self._satellite_basic_auth(sat),
                        )
                        removed_clients.append(remote["remote_client_id"])
                    except ValueError as e:
                        print(f"delete: satellite {remote['satellite_id']} failed: {e}")

        with self.config_lock:
            users = self.config.setdefault("users", {})
            tokens = self.config.setdefault("user_tokens", {})
            record = users.pop(uid, None)
            if record:
                token = record.get("token")
                if token and tokens.get(token) == uid:
                    tokens.pop(token, None)
                self.save_config()
        return {"deleted_clients": removed_clients, "user_existed": record is not None}

    def get_user_summary(self, user_id):
        """Public-facing snapshot of a user — what the bot polls between renewals."""
        uid = self._normalize_user_id(user_id)
        record = self.config.get("users", {}).get(uid)
        if record is None:
            return None
        clients_view = []
        for server, client in self._get_user_clients(uid):
            clients_view.append({
                "server_id": server["id"],
                "server_name": server.get("name"),
                "country_code": server.get("country_code", ""),
                "flag_emoji": server.get("flag_emoji", ""),
                "display_location": server.get("display_location", ""),
                "client_id": client["id"],
                "expires_at": client.get("expires_at"),
                "duration_label": client.get("duration_label"),
                "is_expired": self._is_client_expired(client),
                "scope": "local",
            })
        # Remote clients (federation) are first-class in the summary too.
        for remote in record.get("remote_clients", []):
            clients_view.append({
                "server_id": remote.get("remote_server_id"),
                "server_name": remote.get("display_location") or remote.get("satellite_label"),
                "country_code": remote.get("country_code", ""),
                "flag_emoji": remote.get("flag_emoji", ""),
                "display_location": remote.get("display_location", ""),
                "client_id": remote.get("remote_client_id"),
                "expires_at": remote.get("expires_at"),
                "duration_label": None,
                "is_expired": (remote.get("expires_at") is not None
                               and time.time() >= float(remote["expires_at"])),
                "scope": "satellite",
                "satellite_id": remote.get("satellite_id"),
            })
        max_expiry = max((c["expires_at"] for c in clients_view if c.get("expires_at")), default=None)
        return {
            "user_id": uid,
            "name": record.get("name"),
            "token": record.get("token"),
            "created_at": record.get("created_at"),
            "subscription_url_path": f"/api/sub/user/{record['token']}",
            "clients": clients_view,
            "client_count": len(clients_view),
            "expires_at": max_expiry,
            "remote_errors": record.get("remote_errors", []),
        }

    def list_users(self):
        return [self.get_user_summary(uid) for uid in self.config.get("users", {}).keys()]

    # ─────────────────────────────────────────────────────────────────────
    # Federation — hub-side: registry, RPC helper, fan-out for user actions.
    # ─────────────────────────────────────────────────────────────────────

    def _validate_satellite_url(self, base_url):
        text = str(base_url or "").strip().rstrip("/")
        if not text:
            raise ValueError("base_url is required")
        if not (text.startswith("http://") or text.startswith("https://")):
            raise ValueError("base_url must start with http:// or https://")
        if len(text) > 256:
            raise ValueError("base_url is too long")
        return text

    def _satellite_request(self, base_url, api_key, method, path, json_body=None,
                           timeout=None, basic_auth=None):
        """Authenticated outbound call to a satellite. ``basic_auth`` lets the
        caller pass nginx basic-auth credentials (the satellite is usually
        behind nginx in this project)."""
        url = base_url.rstrip("/") + path
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            r = requests.request(
                method, url,
                headers=headers,
                json=json_body,
                timeout=timeout or SATELLITE_HTTP_TIMEOUT,
                auth=basic_auth,
            )
        except requests.RequestException as e:
            raise ValueError(f"satellite unreachable: {e}") from e
        if r.status_code >= 400:
            try:
                detail = r.json().get("error") or r.text
            except Exception:
                detail = r.text
            raise ValueError(f"satellite returned {r.status_code}: {detail}")
        try:
            return r.json()
        except Exception:
            return {}

    def _satellite_basic_auth(self, record):
        u = (record or {}).get("nginx_user") or ""
        p = (record or {}).get("nginx_password") or ""
        if u and p:
            return (u, p)
        return None

    def register_satellite(self, base_url, api_key, label=None,
                           nginx_user=None, nginx_password=None):
        url = self._validate_satellite_url(base_url)
        key = str(api_key or "").strip()
        if not key:
            raise ValueError("api_key is required")

        sat_id = "sat-" + str(uuid.uuid4())[:8]
        record = {
            "id": sat_id,
            "label": (str(label).strip() if label else url),
            "base_url": url,
            "api_key": key,
            "nginx_user": (str(nginx_user).strip() if nginx_user else ""),
            "nginx_password": (str(nginx_password).strip() if nginx_password else ""),
            "created_at": time.time(),
            "servers": [],
            "last_sync_at": None,
            "last_error": None,
        }

        # Validate by pinging the remote first.
        try:
            self._satellite_request(
                url, key, "GET", "/api/satellite/ping",
                basic_auth=self._satellite_basic_auth(record),
            )
        except ValueError as e:
            raise ValueError(f"satellite ping failed: {e}")

        # Pull initial server list.
        try:
            data = self._satellite_request(
                url, key, "GET", "/api/satellite/servers",
                basic_auth=self._satellite_basic_auth(record),
            )
            record["servers"] = data.get("servers", [])
            record["last_sync_at"] = time.time()
        except ValueError as e:
            record["last_error"] = str(e)

        with self.config_lock:
            self.config.setdefault("satellites", {})[sat_id] = record
            self.save_config()
        return self._satellite_public_view(record)

    def delete_satellite(self, sat_id):
        with self.config_lock:
            sats = self.config.setdefault("satellites", {})
            record = sats.pop(sat_id, None)
            if record is None:
                return False
            # Best-effort cleanup of any remote clients we've provisioned there.
            for uid, user in self.config.get("users", {}).items():
                kept = []
                for remote in user.get("remote_clients", []):
                    if remote.get("satellite_id") != sat_id:
                        kept.append(remote)
                        continue
                    try:
                        self._satellite_request(
                            record["base_url"], record["api_key"], "DELETE",
                            f"/api/satellite/servers/{remote['remote_server_id']}/clients/{remote['remote_client_id']}",
                            basic_auth=self._satellite_basic_auth(record),
                        )
                    except ValueError as e:
                        print(f"delete_satellite: orphaned remote client on {sat_id}: {e}")
                user["remote_clients"] = kept
            self.save_config()
            return True

    def sync_satellite(self, sat_id):
        record = self.config.get("satellites", {}).get(sat_id)
        if not record:
            raise ValueError("satellite not found")
        try:
            data = self._satellite_request(
                record["base_url"], record["api_key"], "GET", "/api/satellite/servers",
                basic_auth=self._satellite_basic_auth(record),
            )
        except ValueError as e:
            with self.config_lock:
                record["last_error"] = str(e)
                self.save_config()
            raise
        with self.config_lock:
            record["servers"] = data.get("servers", [])
            record["last_sync_at"] = time.time()
            record["last_error"] = None
            self.save_config()
        return {"satellite_id": sat_id, "server_count": len(record["servers"])}

    def list_satellites(self):
        return [self._satellite_public_view(s) for s in self.config.get("satellites", {}).values()]

    def _satellite_public_view(self, record):
        """Hide the api_key/basic-auth password from API responses."""
        return {
            "id": record["id"],
            "label": record.get("label"),
            "base_url": record.get("base_url"),
            "created_at": record.get("created_at"),
            "last_sync_at": record.get("last_sync_at"),
            "last_error": record.get("last_error"),
            "server_count": len(record.get("servers", [])),
            "servers": record.get("servers", []),
        }

    def test_sni_reachability(self, host_port_list, timeout=4, max_workers=10):
        """For each ``"host:port"`` in the list, attempt a TCP connect + TLS
        handshake from this VPS, then return whether it succeeded, the
        negotiated TLS version, and the round-trip latency.

        Why it matters: REALITY masks under a real public website's TLS
        handshake. If the destination is unreachable from your server (gov-
        blocked, geo-blocked, firewall, …) clients will silently fail to
        bootstrap. A "✅ TLS 1.3, 128 ms" result means it's safe to use.
        Useful both on the hub and when it's mounted on a satellite — the
        operator can probe whatever VPS they're configuring.
        """
        def _probe(host_port):
            host_port = (host_port or "").strip()
            if not host_port:
                return {"host": host_port, "ok": False, "error": "empty host"}
            host, _, port_str = host_port.partition(":")
            try:
                port = int(port_str) if port_str else 443
            except ValueError:
                return {"host": host_port, "ok": False, "error": "invalid port"}
            host = host.strip().lower()
            if not host:
                return {"host": host_port, "ok": False, "error": "empty host"}

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                start = time.time()
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        latency_ms = int((time.time() - start) * 1000)
                        cipher = ssock.cipher()
                        return {
                            "host": host_port,
                            "ok": True,
                            "tls_version": ssock.version(),
                            "cipher": cipher[0] if cipher else None,
                            "latency_ms": latency_ms,
                        }
            except socket.timeout:
                return {"host": host_port, "ok": False, "error": f"timeout after {timeout}s"}
            except (socket.gaierror, OSError) as e:
                return {"host": host_port, "ok": False, "error": str(e)[:120]}
            except Exception as e:
                return {"host": host_port, "ok": False, "error": f"{type(e).__name__}: {str(e)[:120]}"}

        # Cap concurrency to avoid hammering DNS / outbound when many presets pass through.
        workers = max(1, min(max_workers, len(host_port_list) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(_probe, host_port_list))

    def set_promo_lines(self, lines):
        cleaned = []
        for line in lines or []:
            text = str(line or "").strip()
            if not text:
                continue
            # Only allow vless:// (or vmess://) lines so we don't smuggle anything weird.
            if not (text.startswith("vless://") or text.startswith("vmess://")):
                continue
            if len(text) > 4096:
                continue
            cleaned.append(text)
        with self.config_lock:
            self.config["promo_lines"] = cleaned
            self.save_config()
        return cleaned

    # ─────────────────────────────────────────────────────────────────────
    # Satellite-mode helpers (used by the satellite-side API). The satellite
    # instance only stores native VLESS servers and the clients the hub
    # provisions on it; it has no concept of users or tokens.
    # ─────────────────────────────────────────────────────────────────────

    def satellite_servers_view(self):
        """Public-safe list of VLESS servers exposed to the hub.

        Reality private keys, internal port mappings, and other secrets are
        deliberately omitted — the hub only needs identity + display fields.
        """
        out = []
        for s in self.get_active_vless_servers():
            v = s.get("vless") or {}
            out.append({
                "id": s["id"],
                "name": s.get("name"),
                "country_code": s.get("country_code", ""),
                "flag_emoji": s.get("flag_emoji", ""),
                "display_location": s.get("display_location", ""),
                "description": s.get("description", ""),
                "public_ip": s.get("public_ip"),
                "domain": v.get("domain"),
                "client_port": v.get("client_port") or v.get("port"),
                "use_stream": v.get("use_stream"),
            })
        return out

    def satellite_create_client(self, server_id, client_name, duration_code="1m"):
        """Provision a VLESS client on this satellite. Wraps add_vless_client."""
        result = self.add_vless_client(server_id, client_name, duration_code)
        if result is None:
            raise ValueError("server not found")
        client, link, renewed = result
        return {
            "client_id": client["id"],
            "server_id": server_id,
            "uuid": client["uuid"],
            "expires_at": client.get("expires_at"),
            "duration_code": client.get("duration_code"),
            "duration_label": client.get("duration_label"),
            "link": link,
            "renewed": renewed,
        }

    def satellite_extend_client(self, server_id, client_id, duration_code):
        client, err = self.extend_client(server_id, client_id, duration_code)
        if err:
            raise ValueError(err)
        return {
            "client_id": client_id,
            "expires_at": client.get("expires_at"),
            "duration_code": client.get("duration_code"),
        }

    def satellite_delete_client(self, server_id, client_id):
        ok = self.delete_client(server_id, client_id, reason="hub_request")
        if not ok:
            raise ValueError("client not found")
        return {"client_id": client_id}

    def broadcast_server_to_users(self, server_id, duration_code="1m", only_active=True):
        """Provision every existing user onto a newly added VLESS server.

        ``only_active=True`` skips users whose latest expiry has already passed
        the grace period (effectively gone) and users with no live clients —
        they will get the new server when they renew.
        """
        server_id = str(server_id or "").strip()
        if not server_id:
            raise ValueError("server_id is required")

        local_server = None
        if ":" not in server_id:
            local_server = next(
                (
                    s for s in self.config.get("servers", [])
                    if s.get("id") == server_id and s.get("protocol") == "vless"
                ),
                None,
            )

        satellite_target = None
        if local_server is None:
            satellite_target = self._find_satellite_server_for_broadcast(server_id)
        if local_server is None and satellite_target is None:
            raise ValueError(
                "VLESS server not found. For satellite servers use satellite_id:server_id"
            )

        added = []
        for uid in list(self.config.get("users", {}).keys()):
            user_record = self.config.get("users", {}).get(uid)
            if not user_record:
                continue
            if only_active and not self._user_has_live_clients_for_broadcast(uid, user_record):
                continue
            user_duration = self._broadcast_duration_for_user(uid, user_record, duration_code)
            if local_server is not None:
                try:
                    _, provisioned, _ = self.provision_user(
                        uid, user_duration, server_ids=[server_id]
                    )
                except Exception as e:
                    print(f"broadcast: skipping user {uid} due to {e}")
                    continue
                for entry in provisioned:
                    added.append({"user_id": uid, **entry, "scope": "local"})
                continue

            sat_id, sat, srv = satellite_target
            try:
                entry = self._provision_single_satellite_server_for_user(
                    uid, user_duration, user_record, sat_id, sat, srv
                )
                added.append({"user_id": uid, **entry})
            except Exception as e:
                user_record.setdefault("remote_errors", []).append({
                    "satellite_id": sat_id,
                    "server_id": srv.get("id"),
                    "error": str(e),
                })
                print(f"broadcast: skipping user {uid} due to {e}")
        if satellite_target is not None:
            with self.config_lock:
                self.save_config()
        return added

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

    def generate_obfuscation_params(self, mtu=1280, version='3'):
        return generate_params(mtu, version)

    def validate_obfuscation_params(self, params, mtu):
        return normalize_params(params, mtu)

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
        seen_sections = set()
        for raw_line in str(config_text).splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section_name = line[1:-1].strip()
                if section_name in sections and section_name in seen_sections:
                    raise ValueError("Imported config must contain exactly one Interface and one Peer")
                seen_sections.add(section_name)
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

    def build_imported_upstream_config(
        self,
        *,
        server_id,
        upstream_interface,
        upstream_data,
        mtu,
        table_base=200,
        include_fwmark=False,
    ):
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
        keepalive_value = normalize_keepalive(peer_cfg.get("PersistentKeepalive", 25))

        try:
            imported_mtu = int(interface_cfg.get("MTU", mtu))
        except (TypeError, ValueError) as exc:
            raise ValueError("MTU in imported config must be integer") from exc
        if imported_mtu < 1280 or imported_mtu > 1440:
            raise ValueError("MTU in imported config must be between 1280 and 1440")
        mtu = imported_mtu

        imported_obfuscation = import_params(interface_cfg, mtu)

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

        upstream_keys = self.generate_wireguard_keys()
        upstream_private_key = (
            interface_cfg.get("PrivateKey", "")
            or str(upstream_data.get("private_key", "")).strip()
            or upstream_keys["private_key"]
        )
        upstream_client_public_key = str(upstream_data.get("client_public_key", "")).strip()
        if not upstream_client_public_key:
            if upstream_private_key:
                upstream_client_public_key = self.execute_command(f"echo '{upstream_private_key}' | wg pubkey") or ""
            else:
                upstream_client_public_key = upstream_keys["public_key"]

        upstream_config = {
            "interface": upstream_interface,
            "config_path": os.path.join(WIREGUARD_CONFIG_DIR, f"{upstream_interface}.conf"),
            "endpoint": f"{endpoint_host}:{endpoint_port}",
            "public_key": public_key_value,
            "private_key": upstream_private_key,
            "client_public_key": upstream_client_public_key,
            "preshared_key": peer_cfg.get("PresharedKey", ""),
            "allowed_ips": allowed_ips_value,
            "local_address": local_address_value,
            "persistent_keepalive": keepalive_value,
            "obfuscation_enabled": True,
            "obfuscation_params": imported_obfuscation,
            "table_id": self._allocate_upstream_table_id(base=table_base),
            "split_ru_local": split_ru_local,
        }
        if include_fwmark:
            upstream_config["fwmark"] = self._allocate_upstream_fwmark()
        return upstream_config, failover_mode, mtu, imported_obfuscation

    def generate_upstream_config_content(self, upstream, mtu):
        config = f"""[Interface]
PrivateKey = {upstream['private_key']}
Address = {upstream['local_address']}
MTU = {mtu}
Table = off
"""

        params = upstream.get("obfuscation_params")
        if upstream.get("obfuscation_enabled") and params:
            config += render_params(params)

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
        if server.get("protocol") == "vless":
            return self.configure_vless_upstream_routing(server)

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

    def _vless_upstream_route_context(self, server):
        upstream = server.get("upstream") or {}
        table_id = int(upstream.get("table_id", 300))
        fwmark = int(upstream.get("fwmark") or table_id)
        upstream_interface = upstream.get("interface")
        endpoint_host, endpoint_port = self.parse_endpoint(upstream.get("endpoint"), DEFAULT_PORT)
        endpoint_ip = self.resolve_ipv4(endpoint_host) if endpoint_host else None
        endpoint_ip = endpoint_ip or endpoint_host
        gateway, default_device = self.get_default_route_info()
        return upstream, table_id, fwmark, upstream_interface, endpoint_host, endpoint_port, endpoint_ip, gateway, default_device

    def _install_vless_mark_rule(self, fwmark, table_id):
        priority = 10000 + int(table_id)
        self.execute_command(
            f"ip rule add fwmark {int(fwmark)} table {int(table_id)} priority {priority} 2>/dev/null || true"
        )

    def _install_vless_endpoint_route(self, endpoint_ip, gateway, default_device):
        if not endpoint_ip:
            return
        if default_device:
            if gateway:
                self.execute_command(f"ip route replace {endpoint_ip}/32 via {gateway} dev {default_device}")
            else:
                self.execute_command(f"ip route replace {endpoint_ip}/32 dev {default_device}")
        elif gateway:
            self.execute_command(f"ip route replace {endpoint_ip}/32 via {gateway}")

    def _install_vless_ru_split_routes(self, table_id, gateway, default_device, split_ru_local):
        ru_route_count = 0
        if split_ru_local and default_device and self.ru_split_cidrs:
            for cidr in self.ru_split_cidrs:
                if gateway:
                    self.execute_command(f"ip route replace {cidr} via {gateway} dev {default_device} table {int(table_id)}")
                else:
                    self.execute_command(f"ip route replace {cidr} dev {default_device} table {int(table_id)}")
                ru_route_count += 1
        return ru_route_count

    def configure_vless_upstream_routing(self, server):
        """Route Xray-marked VLESS egress through the imported AWG upstream."""
        (
            upstream, table_id, fwmark, upstream_interface, endpoint_host,
            endpoint_port, endpoint_ip, gateway, default_device
        ) = self._vless_upstream_route_context(server)
        if not upstream_interface or not endpoint_host:
            return False

        self._install_vless_mark_rule(fwmark, table_id)
        self.execute_command(f"ip route replace default dev {upstream_interface} table {table_id}")
        self._install_vless_endpoint_route(endpoint_ip, gateway, default_device)

        split_ru_local = self._to_bool(upstream.get("split_ru_local"), True)
        ru_route_count = self._install_vless_ru_split_routes(
            table_id, gateway, default_device, split_ru_local
        )

        # Marked packets are created by Xray itself, not by a WG client subnet.
        # Masquerade them on the AWG uplink so the EU peer sees the tunnel IP.
        self.execute_command(
            "iptables -t nat -C POSTROUTING "
            f"-m mark --mark {fwmark} -o {upstream_interface} -j MASQUERADE "
            "2>/dev/null || "
            "iptables -t nat -A POSTROUTING "
            f"-m mark --mark {fwmark} -o {upstream_interface} -j MASQUERADE"
        )
        print(
            f"VLESS upstream routing configured: server={server.get('name')}, "
            f"table={table_id}, mark={fwmark}, endpoint={endpoint_host}:{endpoint_port}, "
            f"iface={upstream_interface}, split_ru_local={split_ru_local}, ru_routes={ru_route_count}"
        )
        return True

    def configure_vless_fail_closed_routing(self, server):
        """Keep linked VLESS from leaking direct if the AWG upstream is down."""
        (
            upstream, table_id, fwmark, upstream_interface, endpoint_host,
            endpoint_port, endpoint_ip, gateway, default_device
        ) = self._vless_upstream_route_context(server)
        if not upstream_interface:
            return False
        self._install_vless_mark_rule(fwmark, table_id)
        self.execute_command(f"ip route replace blackhole default table {table_id}")
        self._install_vless_endpoint_route(endpoint_ip, gateway, default_device)
        split_ru_local = self._to_bool(upstream.get("split_ru_local"), True)
        ru_route_count = self._install_vless_ru_split_routes(
            table_id, gateway, default_device, split_ru_local
        )
        print(
            f"VLESS fail-close routing configured: server={server.get('name')}, "
            f"table={table_id}, mark={fwmark}, split_ru_local={split_ru_local}, "
            f"ru_routes={ru_route_count}"
        )
        return True

    def cleanup_upstream_routing(self, server):
        if server.get("protocol") == "vless":
            return self.cleanup_vless_upstream_routing(server)

        upstream = server.get("upstream") or {}
        table_id = int(upstream.get("table_id", 200))
        server_subnet = server.get("subnet")
        if server_subnet:
            self.execute_command(f"ip rule del from {server_subnet} table {table_id} priority {10000 + table_id} 2>/dev/null || true")
        self.execute_command(f"ip route flush table {table_id} 2>/dev/null || true")
        return True

    def cleanup_vless_upstream_routing(self, server):
        upstream = server.get("upstream") or {}
        table_id = int(upstream.get("table_id", 300))
        fwmark = int(upstream.get("fwmark") or table_id)
        upstream_interface = upstream.get("interface")
        self.execute_command(
            f"ip rule del fwmark {fwmark} table {table_id} priority {10000 + table_id} 2>/dev/null || true"
        )
        self.execute_command(f"ip route flush table {table_id} 2>/dev/null || true")
        if upstream_interface:
            self.execute_command(
                "iptables -t nat -D POSTROUTING "
                f"-m mark --mark {fwmark} -o {upstream_interface} -j MASQUERADE "
                "2>/dev/null || true"
            )
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

    @synchronized_config
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

        awg_version = str(server_data.get('awg_version', '3'))
        if awg_version not in ('2', '3'):
            raise ValueError('awg_version must be 2 or 3')

        # Generate and use provided obfuscation parameters if enabled
        obfuscation_params = None
        if enable_obfuscation:
            if 'obfuscation_params' in server_data:
                supplied = server_data['obfuscation_params']
                if not isinstance(supplied, dict):
                    raise ValueError('Obfuscation params must be an object')
                if awg_version == '3':
                    # Older API callers still submit the nine legacy fields.
                    # Fill only absent AWG3 fields; reject explicitly invalid values.
                    supplied = dict(supplied)
                    defaults = upgrade_params({}, mtu)
                    for key in ('S3', 'S4') + V3_KEYS:
                        supplied.setdefault(key, defaults[key])
                elif any(key in supplied for key in V3_KEYS):
                    raise ValueError('AWG 3 parameters require awg_version=3')
                obfuscation_params = self.validate_obfuscation_params(supplied, mtu)
            else:
                obfuscation_params = self.generate_obfuscation_params(mtu, awg_version)

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
            keepalive_value = normalize_keepalive(peer_cfg.get("PersistentKeepalive", 25))
            imported_private_key = interface_cfg.get("PrivateKey", "")
            imported_preshared_key = peer_cfg.get("PresharedKey", "")
            try:
                imported_mtu = int(interface_cfg.get("MTU", mtu))
            except (TypeError, ValueError) as exc:
                raise ValueError("MTU in imported config must be integer") from exc
            if imported_mtu < 1280 or imported_mtu > 1440:
                raise ValueError("MTU in imported config must be between 1280 and 1440")
            mtu = imported_mtu
            imported_obfuscation = import_params(interface_cfg, mtu)

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

            # Entry and egress are separate interfaces: retain the selected entry
            # version while preserving the imported EU protocol independently.

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
            server_config_content += render_params(obfuscation_params)

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
            "awg_version": protocol_version(obfuscation_params, enable_obfuscation),
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
    
    def upgrade_server_awg3(self, server_id):
        """Explicit, recoverable upgrade of a stopped entry interface and its clients."""
        with self.config_lock:
            server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
            if server is None:
                return None
            if server.get('protocol') == 'vless' or not server.get('obfuscation_enabled'):
                raise ValueError('Only AmneziaWG servers can be upgraded')
            if protocol_version(server.get('obfuscation_params')) == '3':
                return server
            if server.get('status') != 'stopped':
                raise ValueError('Stop the server before upgrading to AWG 3')
            # Check real interface presence; an old UI status is not enough.
            probe = subprocess.run(['ip', 'link', 'show', 'dev', server['interface']],
                                   capture_output=True, text=True)
            if probe.returncode == 0:
                raise ValueError('The interface is still active; stop it before upgrading')
            if probe.returncode != 1 or 'does not exist' not in probe.stderr.lower():
                raise ValueError('Cannot verify that the interface is stopped')

            config_path = server['config_path']
            with open(config_path, encoding='utf-8') as f:
                old_config_text = f.read()
            # Use actual on-disk fields as the source, retaining manual AWG2 additions.
            interface_text = old_config_text.split('[Peer]', 1)[0]
            on_disk = {}
            for line in interface_text.splitlines():
                key, sep, value = line.split('#', 1)[0].partition('=')
                if sep:
                    on_disk[key.strip()] = value.strip()
            old_params = import_params(on_disk, server['mtu'])
            new_params = upgrade_params(old_params, server['mtu'])
            new_config_text = replace_interface_params(old_config_text, new_params)
            backup_dir = os.path.join(CONFIG_DIR, 'backups',
                                      f"awg3-{server_id}-{time.time_ns()}")
            os.makedirs(backup_dir, mode=0o700)
            backup_config = os.path.join(backup_dir, os.path.basename(config_path))
            backup_json = os.path.join(backup_dir, 'web_config.json')
            old_state = copy.deepcopy(self.config)
            self._atomic_config_write(backup_config, old_config_text)
            self._atomic_config_write(backup_json, json.dumps(old_state, indent=2))
            journal = os.path.join(CONFIG_DIR, 'awg3-upgrade.pending.json')
            if os.path.exists(journal):
                raise ValueError('An incomplete AWG upgrade needs recovery; restart the container')
            self._atomic_config_write(journal, json.dumps({'files': {
                config_path: backup_config, CONFIG_FILE: backup_json}}))
            try:
                server['obfuscation_params'] = new_params
                server['awg_version'] = '3'
                server['awg3_backup_path'] = backup_dir
                # Both indexes are persisted separately in older web_config.json files.
                clients = server.get('clients', []) + [
                    c for c in self.config.get('clients', {}).values()
                    if c.get('server_id') == server_id]
                for client in clients:
                    client['obfuscation_enabled'] = True
                    client['obfuscation_params'] = dict(new_params)
                    global_client = self.config.get('clients', {}).get(client['id'])
                    if global_client is not None:
                        global_client['obfuscation_enabled'] = True
                        global_client['obfuscation_params'] = dict(new_params)
                self._atomic_config_write(config_path, new_config_text)
                self.save_config()
                os.unlink(journal)
            except Exception:
                self.config = old_state
                self._atomic_config_write(config_path, old_config_text)
                self.save_config()
                os.unlink(journal)
                raise
            return server

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

    @synchronized_config
    def delete_server(self, server_id):
        """Delete a server and all its clients"""
        server = next((s for s in self.config['servers'] if s['id'] == server_id), None)
        if not server:
            return False

        if server.get("protocol") == "vless":
            if self._server_has_linked_upstream(server):
                self.stop_upstream_link(server)
            upstream_conf_path = ((server.get("upstream") or {}).get("config_path"))
            if upstream_conf_path and os.path.exists(upstream_conf_path):
                os.remove(upstream_conf_path)
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

    @synchronized_config
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
        persistent_keepalive = ("15-30" if protocol_version(server.get("obfuscation_params"),
                                                        server.get("obfuscation_enabled")) == "3"
                                else random.randint(15, 30))

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

    @synchronized_config
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
        """Extend client expiration by duration from current expiry or now.

        For relative durations (e.g. ``30d``, ``6m``) the new expiry is the
        request added to ``max(current_expiry, now)`` so that active clients
        keep their unused time and expired clients restart from today.

        For absolute durations (``abs:<ts>`` / ISO dates) the new expiry is
        the specified date itself — but never earlier than the current expiry,
        so an operator cannot accidentally shorten a paying client by picking
        a past date.
        """
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

            if self._duration_is_absolute(normalized_duration):
                requested_expires_at = self._calculate_expires_at(normalized_duration, base_ts)
                # Never silently downgrade a "forever" client to a fixed date,
                # and never roll a paying client backwards in time.
                if requested_expires_at is None:
                    new_expires_at = None
                elif current_expires_at is None:
                    # Already permanent — keep it permanent.
                    new_expires_at = None
                else:
                    new_expires_at = max(float(current_expires_at), requested_expires_at)
            else:
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
            config += render_params(params)

        # Per-client keepalive if stored (new clients); fall back to 25 for legacy entries.
        keepalive = client_config.get('persistent_keepalive', 25)
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
        if not self._server_has_linked_upstream(server):
            return False, "Failover mode can be changed only for linked servers"

        mode_value = str(new_mode or "").strip().lower()
        if mode_value not in ("fail_close", "fail_open"):
            return False, "Mode must be fail_close or fail_open"

        server["linked_failover_mode"] = mode_value

        # Apply immediately for running WireGuard servers and always-on VLESS.
        if server.get("protocol") == "vless" or self.is_interface_running(server.get("interface")):
            healthy, _ = self.is_upstream_healthy(server)
            if mode_value == "fail_close":
                if healthy:
                    self.switch_server_egress(server, "upstream")
                elif server.get("protocol") == "vless":
                    self.configure_vless_fail_closed_routing(server)
                    server["routing_state"] = "upstream"
                    server["egress_interface"] = (server.get("upstream") or {}).get("interface")
                    self._write_xray_config()
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

    @synchronized_config
    def start_server(self, server_id):
        """Start a WireGuard server using awg-quick with iptables setup"""
        if os.path.exists(os.path.join(CONFIG_DIR, 'awg3-upgrade.pending.json')):
            print('Cannot start AWG while an interrupted upgrade needs recovery; restart the container')
            return False
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

    @synchronized_config
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

@app.route('/api/servers/<server_id>/upgrade-awg3', methods=['POST'])
def upgrade_server_awg3(server_id):
    try:
        server = amnezia_manager.upgrade_server_awg3(server_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except OSError:
        return jsonify({'error': 'Upgrade failed; check server logs and the AWG backup before retrying'}), 500
    if server is None:
        return jsonify({'error': 'Server not found'}), 404
    return jsonify(server)

@app.route('/api/servers/<server_id>/metadata', methods=['PATCH'])
def update_server_metadata(server_id):
    """Edit display fields on a VLESS server (country, flag, location, name)."""
    data = request.json or {}
    try:
        server = amnezia_manager.update_vless_server_metadata(server_id, data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not server:
        return jsonify({"error": "Server not found"}), 404
    return jsonify({
        "status": "updated",
        "server_id": server_id,
        "name": server.get("name"),
        "country_code": server.get("country_code", ""),
        "flag_emoji": server.get("flag_emoji", ""),
        "display_location": server.get("display_location", ""),
        "description": server.get("description", ""),
    })

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
            "mode": server.get("mode", "standalone"),
            "egress_interface": server.get("egress_interface", "eth+"),
            "linked_failover_mode": server.get("linked_failover_mode"),
            "routing_state": server.get("routing_state"),
            "upstream": server.get("upstream"),
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
    vless_sni_conflicts = amnezia_manager._vless_stream_sni_conflicts()

    # Update server status based on actual interface state
    for server in amnezia_manager.config["servers"]:
        if server.get("protocol") == "vless":
            if "status" not in server:
                server["status"] = "ready"
            if amnezia_manager._server_has_linked_upstream(server):
                if "linked_failover_mode" not in server or server["linked_failover_mode"] not in ("fail_close", "fail_open"):
                    server["linked_failover_mode"] = "fail_close"
                if "routing_state" not in server or server["routing_state"] not in ("upstream", "local"):
                    server["routing_state"] = "upstream"
                expected_egress = "eth+" if server["routing_state"] == "local" else ((server.get("upstream") or {}).get("interface"))
                server["egress_interface"] = expected_egress or "eth+"
            else:
                server["mode"] = "standalone"
                server["upstream"] = None
                server["linked_failover_mode"] = None
                server["routing_state"] = None
                server["egress_interface"] = "eth+"
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
    servers_view = []
    for server in amnezia_manager.config["servers"]:
        view = dict(server)
        if server.get("protocol") == "vless":
            view["vless_warnings"] = amnezia_manager.vless_server_warnings(
                server, vless_sni_conflicts
            )
        servers_view.append(view)
    return jsonify(servers_view)

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


@app.route('/api/vless/test-sni', methods=['POST'])
def vless_test_sni():
    """Probe one or many SNI host:port targets from this VPS.

    Body: ``{"hosts": ["vkvideo.ru:443", "www.microsoft.com:443"]}``  or
          ``{"host": "vkvideo.ru:443"}``. Returns one result per host with
    `ok / tls_version / latency_ms / error`. Use to validate that a Reality
    `dest` you're about to pick is actually reachable from the server VPS
    before saving — otherwise REALITY can't fall back to the masked
    handshake and the whole inbound silently dies under any probe.

    `?all=1` (or empty body) probes every preset returned by
    `/api/vless/sni-presets`. Useful for the "test all SNIs from this VPS"
    button.
    """
    data = request.json or {}
    if request.args.get('all') == '1' or (not data.get('host') and not data.get('hosts')):
        hosts = [p["host"] for p in REALITY_SNI_PRESETS]
    elif data.get('hosts'):
        if not isinstance(data['hosts'], list):
            return jsonify({"error": "hosts must be a list"}), 400
        hosts = [str(h) for h in data['hosts']]
    else:
        hosts = [str(data['host'])]

    if len(hosts) > 100:
        return jsonify({"error": "too many hosts (max 100)"}), 400

    results = amnezia_manager.test_sni_reachability(hosts)
    summary = {
        "ok": sum(1 for r in results if r.get("ok")),
        "fail": sum(1 for r in results if not r.get("ok")),
        "tested_from": amnezia_manager.public_ip,
    }
    return jsonify({"results": results, "summary": summary})


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

    body_lines = _happ_subscription_management_comments() + lines
    body = "\n".join(body_lines) + ("\n" if body_lines else "")
    response = app.response_class(body, mimetype="text/plain")
    return _apply_happ_subscription_management_headers(response)


# ─────────────────────────────────────────────────────────────────────────────
# Multi-server (per-user) subscription endpoints.
#
# Bot flow:
#   1. POST /api/users/<user_id>/provision   → creates clients on all VLESS servers,
#      returns the user's permanent subscription URL.
#   2. POST /api/users/<user_id>/extend      → extends every client of the user.
#   3. DELETE /api/users/<user_id>           → removes the user and all their clients.
#   4. GET    /api/users/<user_id>           → status snapshot for renewal logic.
#   5. GET    /api/sub/user/<token>          → the URL handed to HAPP/v2rayN.
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
def list_users_route():
    return jsonify({
        "brand": MEMEVPN_BRAND,
        "users": amnezia_manager.list_users(),
    })


@app.route('/api/users/<user_id>', methods=['GET'])
def get_user_route(user_id):
    try:
        summary = amnezia_manager.get_user_summary(user_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if summary is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(summary)


@app.route('/api/users/<user_id>/provision', methods=['POST'])
def provision_user_route(user_id):
    """Create or top-up clients for this user on the requested VLESS servers."""
    data = request.json or {}
    duration = data.get('duration', '1m')
    server_ids = data.get('server_ids')  # list of ids, or omitted for all
    name = data.get('name')
    try:
        record, provisioned, sub_path = amnezia_manager.provision_user(
            user_id, duration_code=duration, server_ids=server_ids, name=name
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "status": "ok",
        "user_id": record["user_id"],
        "name": record.get("name"),
        "subscription_url_path": sub_path,
        "subscription_token": record["token"],
        "provisioned": provisioned,
    })


@app.route('/api/users/<user_id>/extend', methods=['POST'])
def extend_user_route(user_id):
    data = request.json or {}
    duration = data.get('duration', '1m')
    try:
        extended = amnezia_manager.extend_user(user_id, duration)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not extended:
        return jsonify({"error": "User has no live clients to extend"}), 404
    return jsonify({"status": "extended", "user_id": user_id, "extended": extended})


@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user_route(user_id):
    try:
        result = amnezia_manager.delete_user(user_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not result.get("user_existed"):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"status": "deleted", "user_id": user_id, **result})


@app.route('/api/users/broadcast', methods=['POST'])
def broadcast_route():
    """Provision a newly added VLESS server onto all existing users.

    Body: {"server_id": "<id>", "duration": "1m", "only_active": true}
    ``duration`` is only a fallback. Existing users are provisioned with their
    current subscription expiry preserved as ``abs:<expires_at>``.
    """
    data = request.json or {}
    server_id = data.get('server_id')
    duration = data.get('duration', '1m')
    only_active = bool(data.get('only_active', True))
    if not server_id:
        return jsonify({"error": "server_id is required"}), 400
    try:
        added = amnezia_manager.broadcast_server_to_users(
            server_id, duration_code=duration, only_active=only_active
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"status": "ok", "server_id": server_id, "added": added, "count": len(added)})


def _b64(value):
    """Base64 with no padding — what HAPP expects for header values."""
    return base64.urlsafe_b64encode(str(value).encode("utf-8")).decode("ascii").rstrip("=")


# ─────────────────────────────────────────────────────────────────────────────
# Satellite-side API. Enabled on a VPS by setting SATELLITE_API_KEY. Other
# instances act as the "hub" and call these endpoints to provision clients
# directly on this satellite's local Xray.
# ─────────────────────────────────────────────────────────────────────────────

def _require_satellite_auth():
    """Return None on success, or a ``(json, status)`` tuple on failure."""
    if not SATELLITE_API_KEY:
        return jsonify({"error": "satellite mode disabled"}), 403
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Bearer token required"}), 401
    if auth.removeprefix("Bearer ").strip() != SATELLITE_API_KEY:
        return jsonify({"error": "invalid api key"}), 403
    return None


def _apply_happ_subscription_management_headers(response):
    """Attach HAPP app-management headers to subscription responses."""
    if HAPP_PROVIDER_ID:
        response.headers["providerid"] = HAPP_PROVIDER_ID
    if HAPP_HIDE_SERVER_SETTINGS:
        response.headers["hide-settings"] = "1"
    return response


def _happ_subscription_management_comments():
    """Plain-text HAPP metadata comments for non-base64 subscriptions."""
    comments = []
    if HAPP_PROVIDER_ID:
        comments.append(f"#providerid {HAPP_PROVIDER_ID}")
    if HAPP_HIDE_SERVER_SETTINGS:
        comments.append("#hide-settings: 1")
    return comments


@app.route('/api/satellite/ping', methods=['GET'])
def satellite_ping():
    err = _require_satellite_auth()
    if err is not None:
        return err
    return jsonify({
        "ok": True,
        "brand": MEMEVPN_BRAND,
        "public_ip": amnezia_manager.public_ip,
        "vless_servers": len(amnezia_manager.get_active_vless_servers()),
    })


@app.route('/api/satellite/servers', methods=['GET'])
def satellite_servers():
    err = _require_satellite_auth()
    if err is not None:
        return err
    return jsonify({"servers": amnezia_manager.satellite_servers_view()})


@app.route('/api/satellite/clients', methods=['POST'])
def satellite_create_client_route():
    err = _require_satellite_auth()
    if err is not None:
        return err
    data = request.json or {}
    try:
        result = amnezia_manager.satellite_create_client(
            data.get("server_id"),
            data.get("client_name") or "hub-client",
            data.get("duration_code") or "1m",
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route('/api/satellite/servers/<server_id>/clients/<client_id>/extend', methods=['POST'])
def satellite_extend_client_route(server_id, client_id):
    err = _require_satellite_auth()
    if err is not None:
        return err
    data = request.json or {}
    try:
        result = amnezia_manager.satellite_extend_client(
            server_id, client_id, data.get("duration_code") or "1m"
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route('/api/satellite/servers/<server_id>/clients/<client_id>', methods=['DELETE'])
def satellite_delete_client_route(server_id, client_id):
    err = _require_satellite_auth()
    if err is not None:
        return err
    try:
        result = amnezia_manager.satellite_delete_client(server_id, client_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# Hub-side: register / list / sync / delete satellites.
# Promo lines: short curated list of arbitrary vless:// strings appended to
# every user's subscription (e.g. "Renew at @bot" billboard entries).
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/satellites', methods=['GET'])
def list_satellites_route():
    return jsonify({"satellites": amnezia_manager.list_satellites()})


@app.route('/api/satellites', methods=['POST'])
def register_satellite_route():
    data = request.json or {}
    try:
        sat = amnezia_manager.register_satellite(
            base_url=data.get("base_url"),
            api_key=data.get("api_key"),
            label=data.get("label"),
            nginx_user=data.get("nginx_user"),
            nginx_password=data.get("nginx_password"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(sat)


@app.route('/api/satellites/<sat_id>', methods=['DELETE'])
def delete_satellite_route(sat_id):
    if amnezia_manager.delete_satellite(sat_id):
        return jsonify({"status": "deleted", "satellite_id": sat_id})
    return jsonify({"error": "Satellite not found"}), 404


@app.route('/api/satellites/<sat_id>/sync', methods=['POST'])
def sync_satellite_route(sat_id):
    try:
        result = amnezia_manager.sync_satellite(sat_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route('/api/promo-lines', methods=['GET', 'PUT'])
def promo_lines_route():
    if request.method == 'PUT':
        data = request.json or {}
        lines = data.get("lines") or []
        if not isinstance(lines, list):
            return jsonify({"error": "lines must be a list of strings"}), 400
        amnezia_manager.set_promo_lines([str(s) for s in lines])
    return jsonify({"lines": amnezia_manager.config.get("promo_lines", [])})


@app.route('/api/sub/user/<token>')
def user_subscription(token):
    """Single subscription URL aggregating one user's VLESS clients across all servers.

    Response is base64-encoded plain text (one ``vless://`` per line) — this is
    the format HAPP, v2rayN, NekoBox, Hiddify all accept by default.
    HAPP-specific headers add the profile title, expiry, and auto-update interval.
    """
    amnezia_manager.prune_expired_clients()
    user_id, record = amnezia_manager._resolve_user_token(token)
    if not user_id or not record:
        return jsonify({"error": "Subscription not found"}), 404

    lines = []
    latest_expiry = None
    for server, client in amnezia_manager._get_user_clients(user_id):
        try:
            lines.append(amnezia_manager.generate_vless_client_link(
                server, client, label_style="memevpn"
            ))
        except Exception as e:
            print(f"user_subscription: skipping {server.get('id')}/{client.get('id')}: {e}")
            continue
        ce = client.get("expires_at")
        if ce is not None and (latest_expiry is None or ce > latest_expiry):
            latest_expiry = ce

    # Federation: append cached vless:// links produced when this user was
    # provisioned on each registered satellite. The link points directly at the
    # satellite VPS — HAPP connects there without going through the hub.
    # We re-write the URI fragment (#label) in MemeVPN format so HAPP shows a
    # coherent list (otherwise satellite links carry their own legacy
    # "<server>-<client>" label, e.g. "Netherlands-1-user-test").
    for remote in record.get("remote_clients", []):
        link = remote.get("link")
        if not link:
            continue
        # Skip remotes whose grace window already elapsed (the hub will purge
        # them on the next provision/extend call; until then, just hide them).
        re_exp = remote.get("expires_at")
        if re_exp is not None:
            grace = max(0.0, CLIENT_DELETE_GRACE_DAYS) * 24 * 60 * 60
            if time.time() >= float(re_exp) + grace:
                continue
        new_label = amnezia_manager._format_memevpn_label_from_remote(remote)
        link = amnezia_manager._replace_vless_link_label(link, new_label)
        lines.append(link)
        if re_exp is not None and (latest_expiry is None or re_exp > latest_expiry):
            latest_expiry = re_exp

    # Promo / billboard entries — last so they sit at the bottom in HAPP.
    for promo in amnezia_manager.config.get("promo_lines", []):
        promo = str(promo).strip()
        if promo:
            lines.append(promo)

    body_text = "\n".join(lines) + ("\n" if lines else "")
    encoded = base64.b64encode(body_text.encode("utf-8")).decode("ascii")
    response = app.response_class(encoded, mimetype="text/plain; charset=utf-8")
    _apply_happ_subscription_management_headers(response)

    # HAPP / v2rayN / Hiddify standard subscription headers.
    profile_title = f"{MEMEVPN_BRAND} | {record.get('name') or user_id}"
    response.headers["Profile-Title"] = "base64:" + _b64(profile_title)
    response.headers["Profile-Update-Interval"] = str(MEMEVPN_SUB_UPDATE_HOURS)
    response.headers["Subscription-Userinfo"] = (
        f"upload=0; download=0; total=0; "
        f"expire={int(latest_expiry) if latest_expiry else 0}"
    )
    response.headers["Content-Disposition"] = (
        f'inline; filename="{MEMEVPN_BRAND}.txt"'
    )
    response.headers["Cache-Control"] = "no-store"
    return response


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
