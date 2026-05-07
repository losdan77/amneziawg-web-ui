# Federation / Satellite mode — настройка двух VPS под одну подписку

Документ объясняет, как развернуть две (или больше) VPS так, чтобы у клиента
была **одна subscription URL** на все ваши сервера — как у популярных VPN-сервисов
(пример на скриншоте PSNreality из задачи).

> Если коротко: одна VPS назначается **хабом** (там админка + БД пользователей),
> остальные — **спутниками** (там только Xray + наш API). Хаб общается со
> спутниками по защищённому HTTP, а пользователю отдаёт единую подписку, в
> которой подмешаны строки `vless://` со всех спутников.

---

## 0. Архитектура одним абзацем

```
            ┌──────────────────────┐
            │      Хаб (VPS-1)     │
   user ──► │ web-ui + Xray + БД   │ ──► xray inbound (VLESS-сервер #1, 🇩🇪)
            │  /api/sub/user/<t>   │
            └─────────┬────────────┘
                      │ HTTPS, Bearer auth (SATELLITE_API_KEY)
                      ▼
            ┌──────────────────────┐
            │  Спутник 1 (VPS-2)   │ ──► xray inbound (VLESS-сервер #2, 🇳🇱)
            │ web-ui (только API)  │
            │       + Xray         │
            └──────────────────────┘
            ┌──────────────────────┐
            │  Спутник 2 (VPS-3)   │ ──► xray inbound (VLESS-сервер #3, 🇫🇮)
            │      web-ui+Xray     │
            └──────────────────────┘
```

Клиенты подключаются **напрямую** к VPS, на которой стоит конкретный VLESS
inbound (не через хаб). Хаб ходит на спутник только в момент create / extend / delete.
Если хаб упадёт — уже импортированные подписки в HAPP продолжат работать; новые
пользователи временно не смогут получить ссылки. Если упадёт спутник — его узел
из подписки пропадёт (HAPP покажет n/a), остальные продолжат работать.

---

## 1. Требования

- 2+ VPS (Ubuntu/Debian, Docker)
- 2+ поддомена (DNS A → IP соответствующей VPS), например:
  - `de.memevpn.ru` → VPS-1 (хаб)
  - `nl.memevpn.ru` → VPS-2 (спутник)
- Открытые порты на каждой VPS: **80** (HTTP / Let's Encrypt), **443** (web-ui + REALITY-stream).
  AmneziaWG-порты — по необходимости.
- На каждой VPS: **разные** `NGINX_PASSWORD`, чтобы случайно не пустить хаб
  в админку спутника по basic-auth.

---

## 2. Развернуть хаб (VPS-1)

1. SSH на VPS-1 → ставим Docker, если ещё нет:
   ```bash
   curl -fsSL https://get.docker.com | sh
   ```
2. Клонируем и переключаемся на ветку:
   ```bash
   git clone https://github.com/losdan77/amneziawg-web-ui.git /opt/memevpn
   cd /opt/memevpn
   git checkout claude/clever-thompson-914453
   ```
3. В `docker-compose.yml`, в секции `web-ui → environment`, оставляем как есть
   (без `SATELLITE_API_KEY` — это значит «эта VPS работает как обычная админка»;
   спутник-API на ней выключен).

   Опционально установите `MEMEVPN_BRAND=MemeVPN`, `SSL_DOMAIN=de.memevpn.ru`,
   `NGINX_PASSWORD=<надёжный пароль>`.

4. Запускаем:
   ```bash
   docker compose build --no-cache
   docker compose up -d
   docker compose logs -f web-ui   # ждём "AmneziaWG Web UI starting…"
   ```
5. Открываем `https://de.memevpn.ru/`, заходим под `admin / <NGINX_PASSWORD>`.
6. Вкладка **Servers** → создаём VLESS-сервер на VPS-1 (например, country `DE`,
   display name `Germany #1`, domain `de.memevpn.ru`). Шаги те же, что в
   `MEMEVPN_TESTING.md`.

В итоге у хаба есть свой VLESS-сервер #1.

---

## 3. Развернуть спутник (VPS-2)

1. SSH на VPS-2, ставим Docker, клонируем тот же репо:
   ```bash
   curl -fsSL https://get.docker.com | sh
   git clone https://github.com/losdan77/amneziawg-web-ui.git /opt/memevpn
   cd /opt/memevpn
   git checkout claude/clever-thompson-914453
   ```
2. Сгенерируем длинный API-ключ:
   ```bash
   openssl rand -hex 32
   # пример: 8ef9c2…  ← это значение ставится в SATELLITE_API_KEY и на хабе, и здесь
   ```
3. Открываем `docker-compose.yml`, в `web-ui → environment` добавляем:
   ```yaml
       - SATELLITE_API_KEY=8ef9c2…   # тот самый ключ
       - NGINX_PASSWORD=<пароль_спутника>  # отличный от хаба
       - SSL_DOMAIN=nl.memevpn.ru
       - MEMEVPN_BRAND=MemeVPN
   ```
4. Запускаем:
   ```bash
   docker compose build --no-cache
   docker compose up -d
   ```
5. Открываем `https://nl.memevpn.ru/`, заходим под локальной учёткой спутника,
   создаём ровно один VLESS-сервер (country `NL`, display name `Netherlands #1`,
   domain `nl.memevpn.ru`).

   Этот спутник полноценный — у него тоже есть админка. **Но** для federation
   важно, что у него теперь активен спутниковый API (`/api/satellite/...`).

> На этом спутнике вы можете не создавать пользователей и не публиковать его
> подписочную URL — пользователей будет провижонить хаб. Спутник тут только
> хостит VLESS-инстансы и принимает команды от хаба.

---

## 4. Регистрируем спутник на хабе (через веб)

1. Возвращаемся на хаб (`https://de.memevpn.ru/`), вкладка **Users (MemeVPN)**.
2. Скроллим до секции **🛰️ Спутники (federation)**.
3. В блоке «➕ Зарегистрировать спутник» заполняем:
   - **Label**: `Netherlands relay`
   - **Base URL**: `https://nl.memevpn.ru`
   - **API key**: тот самый `SATELLITE_API_KEY` со спутника (`8ef9c2…`)
   - **nginx user / password**: **оставьте пустыми**. С нашим nginx-конфигом
     `/api/satellite/*` НЕ закрыт basic-auth — аутентификация идёт только через
     Bearer-токен `SATELLITE_API_KEY`, проверяет сам Flask. Поля нужны лишь
     если вы вручную закрыли federation-эндпоинты дополнительной basic-auth.
4. Жмём **Register**. Хаб дёрнет `/api/satellite/ping` и `/api/satellite/servers`,
   подтянет список VLESS-серверов спутника. Если всё ок — карточка спутника
   появится ниже с зелёной строкой «Registered: Netherlands relay (1 VLESS server)».

> Если ошибка `satellite unreachable` — проверьте DNS / SSL / firewall на VPS-2.
> Если `401 Authorization Required` от nginx — на спутнике ещё не подтянут
> новый nginx-конфиг (нужно `git pull && docker compose up -d --build web-ui`).
> Если `403 invalid api key` — ключ разный на хабе и спутнике.
> Если `403 satellite mode disabled` — на спутнике не задан `SATELLITE_API_KEY` в `.env`.

5. Аналогично можно зарегистрировать VPS-3, VPS-4 и т.д.

---

## 5. Создаём тестового пользователя на хабе (через веб)

1. На хабе, вкладка **Users (MemeVPN)** → секция «➕ Создать / продлить пользователя».
2. **User ID**: `test_42`, **Display name**: `Test`, **Duration**: `1 month`.
3. Жмём **Provision**.

Что происходит под капотом:
- Хаб создаёт VLESS-клиента у себя (на сервере 🇩🇪 Germany #1).
- Хаб делает RPC к каждому зарегистрированному спутнику и создаёт VLESS-клиента
  на каждом его сервере (🇳🇱 Netherlands #1 и т.д.). Возвращённые `vless://`
  ссылки сохраняются в БД хаба.
- Пользователю выдаётся **одна** subscription URL вида
  `https://de.memevpn.ru/api/sub/user/<token>`.

Карточка пользователя в UI покажет все клиенты (с бейджами `local` или `satellite`)
и одну subscription URL. Любые ошибки RPC видны в карточке красным текстом
рядом с пользователем — например, если спутник лёг на середине provision.

---

## 6. Импорт в HAPP

1. Скопируйте subscription URL пользователя.
2. В HAPP: **+** → **Add subscription** → вставить URL → подтвердить.
3. HAPP покажет:
   - Profile title: **MemeVPN | Test**
   - Список серверов: 🇩🇪 Germany #1, 🇳🇱 Netherlands #1, и любые promo-строки
     (см. ниже).
   - «Истекает» через 1 месяц.

Подключайтесь к любому узлу — трафик пойдёт **напрямую к соответствующей VPS**,
никак не через хаб. Это и даёт отказоустойчивость: если хаб упадёт, рабочие
узлы продолжают работать.

---

## 7. Promo-строки (для красоты как на скриншоте)

В подписку можно подмешать декоративные `vless://` строки, которые в HAPP
выглядят как «серверы», но фактически серверами не являются — это просто способ
вывести текст в списке (например «👉 Продлите в боте»).

1. Сначала сгенерируем «фейковый» vless-URL с нужным лейблом — он не должен
   куда-либо подключаться. Самый простой способ: возьмите любой настоящий
   `vless://` из подписки и замените `host:port` на `127.0.0.1:1`, а `#…` —
   на нужный текст в URL-encode:

   ```
   vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=tls#%F0%9F%91%89%20%D0%9F%D1%80%D0%BE%D0%B4%D0%BB%D0%B8%D1%82%D0%B5%20%D0%B2%20%40memevpn_bot
   ```

   `%F0%9F%91%89` — emoji 👉; `%D0%9F%D1%80%D0%BE%D0%B4%D0%BB%D0%B8%D1%82%D0%B5%20%D0%B2%20%40memevpn_bot` — «Продлите в @memevpn_bot».
2. На вкладке **Users (MemeVPN)** → секция **📣 Promo lines** → вставьте эти
   строки (по одной на строку) в textarea и нажмите **Save promo lines**.
3. Перечитайте подписку в HAPP (pull-to-refresh) — внизу появятся ваши строки
   как отдельные «серверы» с указанными лейблами.

Только `vless://` и `vmess://` строки принимаются — это чтобы случайно не положить
в подписку что-то странное.

---

## 8. Что делать, когда добавляешь новый спутник позже

- Зарегистрируйте его (раздел 4).
- Для каждого активного пользователя нажмите **Provision** ещё раз с тем же
  duration (например, ставите **1 month** для пользователя, у которого осталось
  20 дней — на спутнике провижится клиент с 1-месячным сроком, остальные
  серверы не пострадают).
- Альтернатива: написать массовое provision-через-curl скриптом по списку
  пользователей из `GET /api/users`.

При следующем pull-to-refresh в HAPP у пользователя появится новый сервер.

---

## 9. Команды для бота / Swagger (если хочется автоматизации)

```bash
# Создать пользователя на месяц (хаб + все спутники)
curl -u admin:<hub_password> -X POST \
  https://de.memevpn.ru/api/users/test_42/provision \
  -H 'Content-Type: application/json' \
  -d '{"duration":"1m","name":"Test"}'

# Продлить пользователя на месяц на всех серверах сразу
curl -u admin:<hub_password> -X POST \
  https://de.memevpn.ru/api/users/test_42/extend \
  -H 'Content-Type: application/json' \
  -d '{"duration":"1m"}'

# Удалить пользователя со всех серверов разом
curl -u admin:<hub_password> -X DELETE \
  https://de.memevpn.ru/api/users/test_42

# Получить статус (включая клиентов на спутниках)
curl -u admin:<hub_password> https://de.memevpn.ru/api/users/test_42

# Зарегистрировать спутник через API
curl -u admin:<hub_password> -X POST \
  https://de.memevpn.ru/api/satellites \
  -H 'Content-Type: application/json' \
  -d '{
    "label":"Netherlands relay",
    "base_url":"https://nl.memevpn.ru",
    "api_key":"<SATELLITE_API_KEY>",
    "nginx_user":"admin",
    "nginx_password":"<satellite_password>"
  }'
```

---

## 10. Безопасность

- **`SATELLITE_API_KEY` — это полный ключ от Xray этой VPS.** Не публикуйте,
  ротируйте при компрометации (поменяли env → пересоздали контейнер →
  `Delete satellite` на хабе → зарегистрировали заново с новым ключом).
- Spaceship-API спутника **дополнительно** прикрыт nginx basic-auth — то есть
  без знания и `(nginx user, password)`, и `SATELLITE_API_KEY` к нему не пробиться.
- Хаб хранит ключ и пароль basic-auth в `web_config.json` (volume `amnezia-data`).
  Бэкапы этого тома обращайтесь как с секретами.

---

## 11. Что НЕ сделано / что улучшить позже

- Health-check спутников и автоматическая ротация ключей.
- Автоматический re-provision новых спутниковых серверов на всех уже активных
  пользователях (сейчас — массовый Provision вручную).
- Per-satellite фильтр при provision: «выдать только NL, не выдавать DE».
  Сейчас provision раскатывается на все спутники.
- Графический индикатор «спутник недоступен» в карточке пользователя
  (есть только текстовое сообщение об ошибке последнего provision/extend).

Если что-то из этого нужно — скажите, докручу.
