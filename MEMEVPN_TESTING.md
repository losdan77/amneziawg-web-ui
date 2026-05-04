# MemeVPN: multi-server VLESS subscription — manual testing guide

This guide walks you through deploying the new build, creating a few VLESS
servers with country labels, provisioning a test user, and importing the
single subscription URL into HAPP on your phone.

It assumes you already use this project to manage AmneziaWG and have at least
one VPS where Docker is installed.

---

## 0. What changed in this build

1. **Grace period for expired clients** — clients are now physically deleted
   `CLIENT_DELETE_GRACE_DAYS` (default **3**) days *after* `expires_at`. Within
   that window the user can still pay and seamlessly continue. Existing AmneziaWG
   clients are not affected — only the deletion timer is delayed.
2. **VLESS server location fields** — `country_code` (ISO alpha-2),
   `flag_emoji`, `display_location`. They show up in HAPP labels.
3. **MemeVPN multi-server subscription** — one URL per user that aggregates
   their VLESS clients across every server, with HAPP-friendly headers
   (`Profile-Title`, `Subscription-Userinfo`, `Profile-Update-Interval`).
4. **Old subscription URLs (`/api/sub/vless/<sub_id>`) keep working** —
   nothing breaks for existing AmneziaWG/VLESS users.

Environment variables (all optional):

| Var | Default | What it does |
|---|---|---|
| `CLIENT_DELETE_GRACE_DAYS` | `3` | Grace window before expired clients are deleted |
| `MEMEVPN_BRAND` | `MemeVPN` | Profile title shown in HAPP/v2rayN |
| `MEMEVPN_SUB_UPDATE_HOURS` | `24` | How often the client should auto-refresh the subscription |

---

## 1. Deploy on a VPS (single-instance, several VLESS servers)

For the first round of testing, the simplest setup is **one admin VPS** that
runs both the web UI and Xray; you create *several VLESS servers* in this one
admin instance, each pretending to live in a different country (set
`country_code` / `display_location` per server). HAPP will see them as
different exits even if physically they're on the same VPS.

> Real geographic distribution requires the bridge/chain mode that already
> exists in the project — covered briefly at the end. Start with the
> simpler single-VPS setup; once everything works you'll know exactly what
> to verify when you point bridges to remote relays.

### 1.1 Pull the new code

```bash
ssh root@your-vps
cd /opt/amneziawg-web-ui   # or wherever you cloned it
git fetch
git checkout claude/clever-thompson-914453   # this branch
docker compose down
docker compose build --no-cache
docker compose up -d
docker compose logs -f web-ui   # watch for "AmneziaWG Web UI starting..."
```

If you don't already have it cloned, see `README.md`.

> **Important**: existing `web_config.json` is auto-migrated on startup —
> location fields are backfilled with empty strings, the `users` and
> `user_tokens` maps are seeded. Old AmneziaWG clients keep their
> `expires_at` and start using the new 3-day grace period automatically.

### 1.2 Verify the migration ran

```bash
docker compose exec web-ui cat /etc/amnezia/web_config.json | head -40
```

You should see top-level `"users": {}` and `"user_tokens": {}`. Existing VLESS
servers should have `"country_code": ""`, `"flag_emoji": ""`, `"display_location": ""`.
WG servers are untouched.

---

## 2. Create two test VLESS servers with locations

For a real test you need to be able to reach the VPS on port 443 (or
8443+ if you don't use stream mode). DNS A-record `vpn.example.com → your VPS IP`
is required — REALITY needs the SNI to match the destination domain you set.

### 2.1 In the web UI (recommended)

1. Open `https://your-vps-domain/` and log in with basic auth.
2. **Tab "Servers" → "Create New VPN Server"**:
   - Protocol: **VLESS + REALITY + XHTTP**
   - Server name: `Germany #1`
   - In the green **🌍 Локация** block:
     - Country code: `DE` (the flag 🇩🇪 auto-fills)
     - Display name: `Germany #1`
   - Domain: `de1.example.com` (must point to this VPS)
   - XHTTP path: click **Generate**
   - Reality dest: pick a preset (e.g. `vkvideo.ru:443` for RU whitelist bypass)
   - Click **Create Server**.
3. Repeat for a second pseudo-location:
   - Country code: `NL`, display name: `Netherlands #1`
   - Domain: `nl1.example.com` (you can point a second subdomain to the same IP)
   - Different secret path
4. The server cards now show `🇩🇪 Germany #1 (DE)` and `🇳🇱 Netherlands #1 (NL)` next to
   the standard VLESS info.

### 2.2 Or via curl (for the bot)

```bash
curl -u admin:changeme -X POST https://your-vps-domain/api/servers \
  -H 'Content-Type: application/json' \
  -d '{
    "protocol": "vless",
    "name": "Germany #1",
    "country_code": "DE",
    "display_location": "Germany #1",
    "domain": "de1.example.com",
    "host": "de1.example.com",
    "path": "/api/v1/sync/abc123",
    "xhttp_mode": "packet-up",
    "reality_dest": "vkvideo.ru:443",
    "fingerprint": "chrome",
    "use_stream": true
  }'
```

The response includes the `id` you'll need for broadcast later.

---

## 3. Create a test user and get the subscription URL

```bash
curl -u admin:changeme -X POST \
  https://your-vps-domain/api/users/test_42/provision \
  -H 'Content-Type: application/json' \
  -d '{"duration": "1m", "name": "Test"}'
```

Response:

```json
{
  "status": "ok",
  "user_id": "test_42",
  "name": "Test",
  "subscription_url_path": "/api/sub/user/AbCdEfGh...",
  "subscription_token": "AbCdEfGh...",
  "provisioned": [
    { "server_id": "...", "server_name": "Germany #1",     "country_code": "DE", ... },
    { "server_id": "...", "server_name": "Netherlands #1", "country_code": "NL", ... }
  ]
}
```

Or do it in the web UI: **Tab "Users (MemeVPN)"** → fill `User ID` =
`test_42`, `Display name` = `Test`, `Duration` = `1 month`, click **Provision**.
The card that appears has a copy-able subscription URL.

The subscription URL is permanent for that user. Save it.

---

## 4. Import into HAPP on your phone

1. Install **HAPP** from the App Store / Google Play.
2. Tap **+** → **Add subscription** (or "Import from URL").
3. Paste the full URL: `https://your-vps-domain/api/sub/user/<token>`.
4. HAPP fetches it and shows:
   - Profile title: **MemeVPN | Test**
   - Two servers: `MemeVPN | 🇩🇪 Germany #1`, `MemeVPN | 🇳🇱 Netherlands #1`
   - Expiry date taken from the `Subscription-Userinfo` header.
5. Tap a server, then **Connect**. You should get internet through the VPS.
6. Pull-to-refresh on the subscription — HAPP will re-fetch and you should
   see no changes. The `Profile-Update-Interval` header tells HAPP to auto-refresh
   every 24h.

### Verifying the subscription content manually

```bash
curl -i https://your-vps-domain/api/sub/user/<token>
```

You should see:
- `Content-Type: text/plain; charset=utf-8`
- `Profile-Title: base64:...` (decode it: `echo <value> | base64 -d` → `MemeVPN | Test`)
- `Subscription-Userinfo: upload=0; download=0; total=0; expire=<unix-timestamp>`
- `Profile-Update-Interval: 24`
- Body: a base64 blob. Decode it: `curl ... | base64 -d` → two `vless://` lines,
  each ending in `#MemeVPN%20%7C%20%F0%9F%87%A9%F0%9F%87%AA%20Germany%20%231` etc.

---

## 5. Add a third server and broadcast it to the user

This is the killer feature: existing users automatically pick up the new server.

1. **Servers tab** → create another VLESS server, e.g. country `FI`, display
   `Finland #1`, on a third subdomain.
2. Note its `id` (visible in the server card under "ID: …" or returned by the API).
3. **Users tab** → in the purple "📡 Раскатать новый сервер всем активным
   пользователям" block, paste the new server's ID, choose duration (`1m`
   matches what your test user already has), click **Broadcast**. Or via curl:

   ```bash
   curl -u admin:changeme -X POST https://your-vps-domain/api/users/broadcast \
     -H 'Content-Type: application/json' \
     -d '{"server_id": "<new_id>", "duration": "1m", "only_active": true}'
   ```
4. **In HAPP** — pull-to-refresh on the subscription, or wait 24h. A third
   server `MemeVPN | 🇫🇮 Finland #1` shows up automatically.

This is the workflow you'll use whenever you launch a new node.

---

## 6. Test the 3-day grace period

To test quickly, set `CLIENT_DELETE_GRACE_DAYS=0.001` (about 90 seconds) in
`docker-compose.yml`, recreate the container, then:

1. Provision a user with `duration: 1m`.
2. Manually edit `expires_at` of one of their clients to `time.time() - 60`
   (or just create the user with a duration that's already passed by tweaking
   the system clock — easier path: just wait).
3. The expiration worker runs every `CLIENT_EXPIRATION_CHECK_INTERVAL` (60s
   default). With grace=0.001 days, expired clients get deleted ~90s after
   their `expires_at`. With grace=3 days (the default), they stay for 3 days.
4. Reset `CLIENT_DELETE_GRACE_DAYS=3` for production.

Production verification: pick any AmneziaWG client whose `expires_at` is past
but ≤ 3 days ago — it should still be in `web_config.json` and still be served.

---

## 7. Bot integration (when you wire this into your TG bot)

Endpoints the bot should call:

```text
POST   /api/users/{user_id}/provision      body: {"duration":"1m","name":"<TG name>"}
                                            → returns subscription_url_path

POST   /api/users/{user_id}/extend         body: {"duration":"1m"}
                                            → extends every client of the user

DELETE /api/users/{user_id}                 → deletes the user and their clients

GET    /api/users/{user_id}                 → snapshot for status / expiry checks

GET    /api/bot/reminders/expiring-clients?days=3
                                            → existing reminder list (already shipped)
```

Subscription URL handed to the user:

```
https://<your-vps-domain>/api/sub/user/{subscription_token}
```

Bot logic boils down to:

| User action | Bot call |
|---|---|
| Bought 1 month | `POST /api/users/<tg_id>/provision {"duration":"1m"}`; send `subscription_url` to user |
| Renewed 1 month | `POST /api/users/<tg_id>/extend {"duration":"1m"}` |
| Refunded / banned | `DELETE /api/users/<tg_id>` |
| Daily renewal reminder cron | `GET /api/bot/reminders/expiring-clients?days=3` |

---

## 8. Where each piece lives in the code

So you can rationally make changes after the test:

| Concern | File:line |
|---|---|
| Grace-period logic | `web-ui/app.py:_should_delete_expired_client`, `prune_expired_clients` |
| Country → flag, label format | `web-ui/app.py:_country_code_to_flag`, `_format_memevpn_subscription_label` |
| Server location fields | `web-ui/app.py:create_vless_server`, `migrate_vless_metadata`, `update_vless_server_metadata` |
| User records & tokens | `web-ui/app.py:_get_or_create_user`, `_resolve_user_token` |
| Provision / extend / delete user | `web-ui/app.py:provision_user`, `extend_user`, `delete_user` |
| Multi-server subscription | `web-ui/app.py:user_subscription` (route `/api/sub/user/<token>`) |
| Broadcast | `web-ui/app.py:broadcast_server_to_users` |
| UI VLESS location form | `web-ui/templates/index.html` (the green 🌍 Локация block) |
| UI Users tab | `web-ui/templates/index.html` (`#usersSection`) + `web-ui/static/js/app.js` (`app.loadUsers`, `provisionUser`, …) |

---

## 9. Real geographic distribution (for later)

To put each VLESS server on a different physical VPS:

- **Option A — single admin / many bridges**: keep one admin web UI + one
  exit Xray. Use the existing **bridge / chain** mode (✅ already implemented,
  see `create_bridge_config`) to relay clients through Russian (or any other)
  VPSes. The relay VPS only needs Xray + the generated `config.json` —
  no web UI. Each bridge is one HAPP server entry. Country labels are
  whatever you set for the bridge UUID's parent VLESS server in the admin.
- **Option B — independent admin instances + manual subscription merge**:
  run a full stack on each VPS, and your bot fetches each instance's
  `/api/sub/user/<token>` separately and concatenates them. Simple but the
  "broadcast new server to all users" UX is gone.

Pick A for production once the single-VPS test passes — it's what the bridge
modal in the UI was designed for.

---

## 10. Quick troubleshooting

| Symptom | Likely cause |
|---|---|
| Subscription URL returns 404 | Typo in token; or user was deleted |
| HAPP shows no servers | The user has no VLESS clients yet — re-run `provision` |
| HAPP shows ascii instead of flags | Old emoji font on the device; try a different country and check that the raw `vless://` ends with the right `#…` label |
| New server doesn't appear after broadcast | HAPP cached the previous response; pull-to-refresh in the subscription view |
| `xray` keeps restarting | The watchdog in `docker-compose.yml` restarts on every config write — that's normal. If it loops every 2s, your generated `config.json` is invalid; check `docker compose logs xray` |
| WG client still works after expiration | Within the 3-day grace — that's the new intended behaviour |

If anything looks wrong, share `docker compose logs web-ui --tail=200` and the
output of `curl -i .../api/sub/user/<token>`; that's enough to diagnose 99% of
issues.
