# VLESS -> AmneziaWG bridge

Схема для проблемных мобильных сетей:

```text
HAPP / VLESS client
  -> RU VPS: VLESS + REALITY inbound (Xray)
  -> RU VPS: imported AmneziaWG client tunnel
  -> EU VPS: AmneziaWG server / internet egress
```

## Как создать

1. На EU VPS создайте обычного AmneziaWG-клиента для RU bridge.
2. Скопируйте полный client config, включая `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1..H4`.
3. На RU VPS откройте **Servers** и создайте **VLESS** server.
4. Включите **Route this VLESS server through upstream AmneziaWG**.
5. Вставьте EU AmneziaWG client config в **Import EU client config**.
6. Оставьте **Route Russian destination IP ranges via local RU egress** включенным, если российские IP должны выходить напрямую с RU VPS.

## Что делает панель

- Поднимает отдельный `vl-<server>-up` AmneziaWG interface.
- Xray помечает outbound-сокеты этого VLESS inbound через `sockopt.mark`.
- Linux policy routing отправляет marked-трафик в таблицу upstream.
- Default route в этой таблице идет через EU AmneziaWG interface.
- RU CIDR routes в этой же таблице идут через обычный local egress RU VPS.
- Для marked-трафика через AWG добавляется `MASQUERADE`.

## Failover

- `fail_close`: если EU tunnel недоступен, non-RU VLESS traffic blackhole'ится и не утекает напрямую. RU split routes остаются локальными.
- `fail_open`: если EU tunnel недоступен, VLESS временно переключается на обычный local egress RU VPS.

## Docker requirement

Для этой схемы Xray должен видеть тот же network namespace, где поднят AmneziaWG interface. В штатном `docker-compose.yml` Xray запускается с:

```yaml
network_mode: "service:web-ui"
```

а web-ui использует:

```yaml
XRAY_UPSTREAM_HOST=127.0.0.1
```

Если вернуть Xray в отдельную Docker-сеть, VLESS -> AmneziaWG bridge не сможет работать: Xray будет ставить `fwmark` в другой network namespace и не увидит AWG routes.
