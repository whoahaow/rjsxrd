# Генерируемые файлы

Папка `githubmirror/` содержит результаты работы генератора. Конфиги обновляются **каждый час** с VPS (основной канал) и **раз в 2 дня** через GitHub Actions (резервный).

> **Примечание:** по умолчанию генерируется только папка `bypass/`. Остальные наборы (`default/`, `bypass-unsecure/`, `split-by-protocols/`, `tg-proxy/`, raw-файлы) включаются feature-флагами `--enable-*`.

## Структура

```
githubmirror/
├── default/                   # Основные конфиги
│   ├── 1.txt                  # Номерные файлы (по источникам, до 300 строк)
│   ├── 2.txt
│   ├── ...
│   ├── all.txt                # Все уникальные конфиги в одном файле
│   └── all-secure.txt         # Только безопасные (без insecure-параметров)
│
├── bypass/                    # SNI/CIDR-фильтрованные, безопасные
│   ├── raw/                   # Нетестированные raw-конфиги
│   ├── bypass-all.txt         # Все в одном файле, отсортированы по пингу
│   ├── bypass-1.txt           # Разделение по 300 конфигов
│   └── ...
│
├── bypass-unsecure/           # SNI/CIDR-фильтрованные, все конфиги
│   ├── raw/                   # Нетестированные raw-конфиги
│   ├── bypass-unsecure-all.txt  # Все в одном файле
│   ├── bypass-unsecure-1.txt    # Разделение по 300 конфигов
│   └── ...
│
├── split-by-protocols/        # Разделение по протоколам
│   ├── vless.txt              # VLESS
│   ├── vless-secure.txt       # VLESS (только безопасные)
│   ├── vmess.txt              # VMess
│   ├── vmess-secure.txt
│   ├── trojan.txt             # Trojan
│   ├── trojan-secure.txt
│   ├── ss.txt                 # Shadowsocks
│   ├── ss-secure.txt
│   ├── ssr.txt                # ShadowsocksR
│   ├── ssr-secure.txt
│   ├── tuic.txt               # TUIC
│   ├── tuic-secure.txt
│   ├── hysteria.txt           # Hysteria v1
│   ├── hysteria-secure.txt
│   ├── hysteria2.txt          # Hysteria v2
│   ├── hysteria2-secure.txt
│   ├── hy2.txt                # Hysteria v2 (альтернативный префикс)
│   └── hy2-secure.txt
│
└── tg-proxy/                  # Telegram-прокси
    ├── all.txt                # Все прокси (MTProto + SOCKS5)
    ├── MTProto.txt            # Только MTProto
    └── socks.txt              # Только SOCKS5
```

Также генерируются QR-коды в папке `qr-codes/` для мобильного импорта.

## Типы файлов

### Основные (`default/`)

Конфиги из всех источников, прошедшие базовую дедупликацию и фильтрацию. Номерные файлы (1.txt, 2.txt, ...) соответствуют разным источникам — можно подписаться на один конкретный источник.

- `all.txt` — слияние всех номерных, 0 дубликатов
- `all-secure.txt` — то же самое, но удалены конфиги с insecure-параметрами

### SNI/CIDR (`bypass/` и `bypass-unsecure/`)

Конфиги, отфильтрованные по доменам из whitelist-файлов. Используются для обхода мобильных белых списков (Россия и другие страны, где мобильные операторы блокируют VPN по SNI/IP-адресам).

- `bypass/` — безопасные конфиги (двойная фильтрация: SNI/CIDR + security)
- `bypass-unsecure/` — все конфиги (только SNI/CIDR-фильтрация)
- `raw/` — конфиги до верификации (не проверены Xray)
- Основные файлы — после Xray-верификации, отсортированы по пингу

**Почему разделение по 300 строк?** GitHub имеет ограничение на размер файла (~49 MB). Разделение также улучшает производительность при импорте на мобильных устройствах.

### По протоколам (`split-by-protocols/`)

Удобны, если вы знаете, какой протокол вам нужен:

- **Secure** (например `vless-secure.txt`) — только безопасные конфиги
- **Unsecure** (например `vless.txt`) — все конфиги протокола

Поддерживаемые протоколы: VLESS, VMess, Trojan, Shadowsocks, ShadowsocksR, TUIC, Hysteria v1, Hysteria v2.

### Telegram-прокси (`tg-proxy/`)

Автоматически собранные, верифицированные и отсортированные по пингу прокси для Telegram. Подходят для использования в настройках мессенджера.

## Формат файлов

Все сгенерированные файлы содержат subscription-заголовок для совместимости с VPN-клиентами:

```
#profile-title: all t.me/rjsxrd
#profile-update-interval: 48
#support-url: https://t.me/rjsxrd
#announce: t.me/rjsxrd
#subscription-userinfo: upload=0; download=0; total=0; expire=0
```

Каждому конфигу добавляется remark-суффикс `%20t.me%2Frjsxrd` (URL-кодированная ссылка на канал проекта).

## Ограничение размера

GitHub ограничивает файлы ~49 MB. При превышении лимита файл автоматически разделяется через `split_file_by_size()`:

- Сначала оценивается размер `all.txt` и `all-secure.txt` — при превышении лимита конфиги распределяются по нескольким файлам без лишней записи
- Протокол-специфичные файлы также проходят проверку и автоматическое разделение

Разделение по 300 строк — это secondary limit, используемый для bypass-файлов в `split_configs_to_files()`. Основной механизм — проверка размера в байтах с 10% запасом безопасности.

## Какую папку выбрать?

| Ваша задача | Рекомендуемый файл |
|-------------|--------------------|
| Быстрый старт, не знаете что выбрать | `default/6.txt` или `default/1.txt` |
| Мобильный интернет (белые списки) | `bypass/bypass-all.txt` |
| Максимальная безопасность | `default/all-secure.txt` |
| Хотите только VLESS | `split-by-protocols/vless-secure.txt` |
| Все источники в одном файле | `default/all.txt` |
| Telegram заблокирован | `tg-proxy/all.txt` |
