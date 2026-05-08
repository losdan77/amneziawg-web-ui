# Подключение к VLESS-серверу есть, но интернет не работает

В HAPP сервер «зелёный» (handshake прошёл), а сайты не открываются. Чек-лист
по убыванию частоты причин.

---

## 1. Reality `dest` (SNI) недоступен с самой VPS

Самая частая причина. REALITY-сервер на VPS должен уметь сходить на `dest`
(например `vkvideo.ru:443`) и сделать к нему обычный TLS-handshake — иначе
маска не работает, а в момент любой DPI-проверки сессия рушится.

Это происходит, если:
- VPS зарубежная, а вы выбрали **российский домен** (vkvideo.ru, gosuslugi.ru,
  www.tbank.ru и т.д.) — почти все они **гео-блокируют** не-RU IP. С VPS в
  Германии/Нидерландах/США такой `dest` будет TIMEOUT.
- Между VPS и `dest` стоит файрвол / outbound-блокировка по `iptables` /
  оператор VPS режет egress-трафик к данному домену.

### Как проверить

В админке откройте форму создания сервера → нажмите **Пресеты SNI** →
кнопка **🔍 Test all SNI from this VPS**. Каждый пресет получит метку:

- `✅ TLSv1.3 95ms` — рабочий, можно использовать.
- `❌ timeout after 4s` — VPS не может достучаться до домена (гео-блок или
  файрвол).
- `❌ [Errno 111] Connection refused` — сервер не отвечает на 443 порт.

Выбирайте только зелёные.

Альтернатива в SSH:
```bash
docker compose exec web-ui sh -c "echo Q | openssl s_client -connect vkvideo.ru:443 -servername vkvideo.ru -tls1_3 2>&1 | head -5"
```
Если `CONNECTED` — ок. Если `connect: Connection refused / timeout` — мимо.

### Что использовать вместо

С зарубежной VPS гарантированно работают:

| Домен | Где используется | Причина |
|---|---|---|
| `www.microsoft.com:443` | Windows Update | глобальный CDN, нигде не блокируется |
| `www.apple.com:443` | Apple Software Update | глобальный |
| `addons.mozilla.org:443` | Firefox extensions | Cloudflare |
| `dl.google.com:443` | Chrome / Android updates | глобальный |
| `cdn.jsdelivr.net:443` | jsDelivr CDN | TLS 1.3, повсеместно |
| `releases.ubuntu.com:443` | Ubuntu | глобальный |
| `www.cloudflare.com:443` | Cloudflare | глобальный |

С российской VPS работают и российские «whitelist» домены — `vkvideo.ru`,
`rutube.ru`, `yandex.ru` — потому что VPS внутри РФ имеет доступ к ним.

### Как поменять SNI на уже созданном сервере

Сейчас в UI редактирования `reality_dest` нет — нужно **удалить сервер и
создать заново** с правильным SNI. Подписочные ссылки у пользователей
обновятся автоматически после Provision (повторного).

---

## 2. Доменное имя сервера резолвится не на этот VPS

Хост в `vless://...@de.memevpn.ru:443` должен резолвиться в IP именно этой
VPS. Если вы перенесли VPS / поменяли A-запись / используете `nip.io` с
неправильным IP — клиент конектится «куда-то ещё».

### Как проверить

С телефона (любого устройства, не VPN):
```bash
nslookup de.memevpn.ru
```
В ответе должен быть IP именно этой VPS. Если другой — поправьте DNS.

С VPS:
```bash
curl -v https://api.ipify.org
```
Сравните с A-записью домена.

---

## 3. Конфликт порта 443: nginx HTTP vs nginx stream vs xray

В этом проекте порт 443 расшарен:

- **nginx stream** (если `use_stream=true`) ловит трафик по SNI и проксирует
  REALITY-handshake'и на `xray:9443+` по внутренней сети docker.
- **nginx HTTP** (для админки) тоже слушает 443, но если SNI совпадает с
  доменом сервера — должен «пройти мимо» в stream.

Если конфигурация stream'а сломана (например после ручного редактирования) —
client коннектится к nginx HTTP, тот не понимает REALITY и сессия молча
зависает.

### Как проверить

```bash
docker compose exec web-ui cat /etc/nginx/stream_reality.conf
docker compose logs web-ui --tail=50 | grep -i nginx
docker compose logs xray --tail=50
```

Если в `stream_reality.conf` пусто или нет вашего `server_names` (включая
SNI-маску `vkvideo.ru` и его варианты) — пересоздайте VLESS-сервер; web-ui
перепишет конфиг.

---

## 4. xray в crash-loop из-за плохого config.json

```bash
docker compose ps        # xray должен быть Up, а не Restarting
docker compose logs xray --tail=80
```

Если каждые 2 секунды видите `[xray] config changed, restarting xray`
бесконечно — config битый. Web-ui в этой ситуации **тоже** должен ругаться
в логах. Откройте `/etc/amnezia/xray/config.json` через
`docker compose exec web-ui cat /etc/amnezia/xray/config.json | python3 -m json.tool`
— если падает на парсинге, сервер создан с битыми параметрами; удалите и
создайте заново.

---

## 5. iptables MASQUERADE не настроен на host

VLESS-трафик внутри контейнера выходит через `eth0`. Для NAT в интернет
нужен iptables MASQUERADE на хосте. В нашем образе это автоматизировано
скриптом `scripts/setup_iptables.sh`, но иногда не отрабатывает после
ребута VPS.

Проверка:
```bash
sudo iptables -t nat -L POSTROUTING -n | grep MASQUERADE
sysctl net.ipv4.ip_forward    # должно быть 1
```

Если `MASQUERADE` пусто:
```bash
sudo iptables -t nat -A POSTROUTING -s 172.17.0.0/16 -o eth0 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1
```

И добавьте перманентно через `/etc/sysctl.d/99-vpn.conf` + `iptables-persistent`.

---

## 6. У клиента (телефона) DNS-leak / DNS не работает

REALITY+XHTTP туннелирует TCP/UDP, но не DNS-запросы автоматически. HAPP
по умолчанию использует системные DNS. Если у оператора связи DNS отравлен —
сайты не резолвятся даже под VPN.

### Проверка

В HAPP откройте настройки этого сервера / профиля → пункт `DNS` или
`Remote DNS`. Поставьте `1.1.1.1` или `8.8.8.8`.

---

## 7. xhttp Host-mismatch (для bridge / chain режима)

Если использовали кнопку **🔗 Цепочка (обход WL)** для российского relay,
но потом изменили на сервере `host` или `domain` — chain-конфиг на bridge VPS
показывает 404 / connection refused. Перегенерируйте bridge-config.

---

## Быстрая диагностика

Запустите на VPS:

```bash
# Под капотом проверяет всё сразу
docker compose ps
docker compose exec web-ui curl -s https://localhost/api/system/status | python3 -m json.tool
docker compose logs xray --tail=50 | grep -E 'rejected|failed|error'
docker compose logs web-ui --tail=50 | grep -E 'error|failed'
```

Если в xray-логах есть `accepted ... -> direct` строки при попытке клиента
коннектиться, но клиент висит — это либо #1 (SNI), либо #5 (iptables).

Если xray не видит `accepted` вовсе — клиент даже не доходит до xray, дело
в #2 (DNS), #3 (nginx-stream) или #4 (xray не запустился).
