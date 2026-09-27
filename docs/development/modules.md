> **Language:** [Русский](modules.md) · [English](modules.en.md)

# Модули и ключевые функции

## main.py — точка входа

Обрабатывает аргументы CLI, настраивает прокси (одиночный, цепочка, авто-детекция), запускает ResourceMonitor и вызывает `process_all_configs()`.

**Аргументы CLI** — см. [CLI-справочник](../operation/cli-reference.md).

**Поток выполнения:**
1. Health check (интернет, Xray, GitHub API)
2. Настройка прокси (если указан)
3. Запуск мониторинга ресурсов
4. `process_all_configs()` — полный цикл
5. Выгрузка в GitHub
6. Остановка мониторинга → отчёт

## config_processor.py — оркестратор пайплайна

Центральный модуль, который координирует все фазы обработки.

### `download_all_configs(output_dir, scan_for_telegram_proxies)`

Параллельная загрузка из всех источников. Возвращает кортеж из 5 массивов: основные конфиги, extra-bypass, номерные с URL, MTProto-прокси, SOCKS5-прокси.

**Автоопределение base64:**
Прежде чем декодировать, функция проверяет 4 эвристики:
- Соотношение новых строк (base64 однострочен)
- Наличие `://` (уже декодировано — не base64)
- Соотношение пробелов (в base64 их почти нет)
- Состав символов (только A-Z, a-z, 0-9, +, /, =)

### `create_protocol_split_files(all_configs, output_dir)`

Классифицирует конфиги по протоколам из URL-префикса и создаёт отдельные файлы с secure/unsecure вариантами.

### Вспомогательные функции (из `file_writer.py`)

Эти функции определены в `file_writer.py` и импортируются в `config_processor.py`:

- `append_remark_suffix(config)` — добавляет `%20t.me%2Frjsxrd` к remark каждого конфига
- `get_subscription_header(filename)` — генерирует subscription-заголовок (`#profile-title`, `#profile-update-interval: 48`, и т.д.)
- `split_configs_to_files(configs, dir, prefix, max=300)` — разделяет конфиги на номерные файлы (параллельная запись, до 8 workers)
- `_write_config_chunk(args)` — module-level worker для параллельной записи chunk'ов

## fetchers — модули загрузки

### fetcher.py — базовый загрузчик

**Ключевые особенности:**

- `FetchResult` — dataclass с полями `text`, `status_code`, `error`, `success`. Функция `fetch_data()` **никогда не выбрасывает исключений** — всегда проверяйте `.success` перед использованием
- использует curl_cffi Session с Chrome 124 impersonation — в 2-3x быстрее requests, обходит анти-бот системы
- `build_session()` — создаёт сессию с прокси из `--proxy` или `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` окружения
- retry: до 3 попыток (по умолчанию) с 1s wait между ними, и каждая — тот же запрос, что записан в URL, с проверкой сертификата для https: ошибка повторяется, а не ослабляется. Таймаут 5 с (настраивается через `FETCH_TIMEOUT`/`FETCH_MAX_ATTEMPTS`). `ALLOW_TLS_DOWNGRADE=1` возвращает старый порядок (attempt 2 без проверки сертификата, attempt 3 по plaintext HTTP) — на сети, которая мешает TLS, именно он держит выход загрузки. Что это даёт и чем рискует — в [SECURITY.md](../../SECURITY.md)
- даунгрейды видны и посчитаны: `_log_downgrade()` пишет в лог хост и номер попытки, счётчик `INSECURE_FETCHES` копит попытки и хосты, `report_insecure_fetches()` печатает итог в конце прогона рядом с отчётом о здоровье URL. Предупреждение клиента о непроверенном TLS глушится только вокруг самой insecure-попытки, а не на весь процесс (`_silence_client_tls_warning`). `ALLOW_TLS_DOWNGRADE=1` возвращает попытки 2 и 3; без них даунгрейдов нет вообще, а отчёт прогона называет, какой режим работал. Источник, не прошедший проверенные попытки, — ошибка источника: он стареет и удаляется из `URLS.txt`, как любой недоступный. Об исходе прогона, а не источника, говорят только случаи, когда запрос не уходил вовсе: вызов без попыток даёт `RUN_CONDITION_PREFIX`, считается `RUN_CONDITIONS` и называется в отчёте (`report_run_conditions()`), и URL за него не стареет
- приватные адреса не загружаются: `_destination_refusal()` проверяет **разрешённый** адрес, а не текст URL, до соединения; тело ответа, пришедшего после редиректа с запрещённого адреса, отбрасывается; отказ — это ошибка с предупреждением, а не пустой успешный результат. Единственное исключение — явный список `FETCH_PRIVATE_ALLOWLIST` (по умолчанию пуст): IP-литерал, CIDR или `host` / `host:port`, где v6-хост записывается в скобках, как в URL (`[::1]`, `[::1]:1080`); запись, покрывающая всё семейство адресов (`0.0.0.0/0`, `::/0`), отклоняется при чтении настройки — такая запись отключает гард, а не расширяет его. Запись с портом покрывает тот порт, который будет использовать запрос, и никакой другой. Отказ считается отдельно от мёртвых ссылок: `fetchers/destination_guard.py` ведёт счётчик `DESTINATION_REFUSALS`, а `report_destination_refusals()` (вызывается из `report_fetch_security()` в конце прогона) называет хост и адрес каждого отказа. `utils/url_stats.py` узнаёт отказ по маркеру `DESTINATION_REFUSAL_PREFIX` из `utils/fetch_outcomes.py` и **не** увеличивает счётчик ошибок URL: источник, которому трижды подряд отказали, остаётся в `URLS.txt` и виден в отчёте каждого прогона, а строку удаляют только три настоящие ошибки загрузки. Адрес внутри трансляционного префикса судится по тому, что он несёт: `is_global` считает весь NAT64 well-known prefix (`64:ff9b::/96`) глобальным, поэтому `64:ff9b::7f00:1` — это 127.0.0.1 в v6-костюме, и адрес метаданных кодируется так же. Вложенный адрес читается по RFC 6052 (NAT64), RFC 3056 (`2002::/16`, 6to4) и для устаревшей формы `::a.b.c.d`, и разворачивание только **добавляет** отказы: диапазон, который не проходит обычную проверку целиком (например `64:ff9b:1::/48` или весь `2002::/16`), остаётся отказанным, поэтому ничего из ранее разрешённого не открывается
- `fetch_data()` принимает `token` — заголовок `Authorization: token <token>` уходит только на хосты из `GITHUB_TOKEN_HOSTS` (`github.com`, `raw.githubusercontent.com`, `api.github.com` — последний запрашивает API-fallback), сравнение идёт по **имени хоста** из URL, поэтому имя GitHub в пути или в query-строке токена не получает. Это повышает лимиты GitHub с ~60/ч до 5000/ч
- `_extract_status(exc)` — извлекает HTTP-статус из разных типов исключений

### daily_repo_fetcher.py — ежедневные репозитории

Ищет конфиги в репозиториях с датовой схемой именования:

- генерирует имена `v2YYYYMMDD1`, `v2YYYYMMDD2` на основе текущей даты
- `fetch_configs_from_daily_repo()` — проверяет 7 дней назад (параметр `lookback_days=7`, было 30), 100 параллельных workers
- глобальная дедупликация через `seen`/`seen_lock` (общий set с основным пайплайном)

### yaml_converter.py — Clash/Surge YAML

`convert_yaml_to_vpn_configs(yaml_content)`:

1. Парсит YAML через `yaml.safe_load()`
2. Рекурсивно обрабатывает словари и списки (`_extract_configs_from_dict()`)
3. Извлекает прокси-секции (`proxies:`, `Proxy:`, `proxy-providers:`)
4. Конвертирует каждый прокси-объект в VPN-URL нужного формата
5. Валидирует результат через `is_valid_vpn_config_url()`

### sstap_scraper.py — скрапинг sstap.org

Извлекает VPN-конфиги со страницы https://sstap.org/node-real-time-update/ через регулярные выражения.

**Поддерживаемые протоколы:** VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC.

**Пайплайн:** Fetch → regex → дедупликация → prepare_config_content.
Встроен в `download_all_configs()` как дополнительный источник.

### upstream_aggregator.py — агрегатор динамических источников

Загружает списки URL из mermeroo/V2RAY-CLASH-BASE64-Subscription.Links и Leon406/jsdelivr, отфильтровывает только yudou226.top и guidongone ссылки, затем параллельно (20 workers) загружает конфиги.

**Особенности:**
- Двухэтапный: сначала список URL, потом загрузка каждого
- Base64-автоопределение для каждого URL
- Глобальная дедупликация через `seen`/`seen_lock`
- 20 параллельных workers через ExecutorCache

### telegram_proxy_scraper.py — скрапинг прокси

Извлекает MTProto и SOCKS5 прокси из текстового контента через 10 регулярных выражений:

**MTProto** (4 паттерна): `https://t.me/proxy?...`, `http://t.me/proxy?...`, `t.me/proxy?...` (bare), `tg://proxy?...`

**SOCKS5** (7 паттернов): `https://t.me/socks?...`, `http://t.me/socks?...`, `t.me/socks?...`, `tg://socks?...`, `socks5://host:port`, `http://IP:PORT`, `IP:PORT` (bare format)

`_clean_proxy_url()` — удаляет эмодзи и не-ASCII символы. `deduplicate_proxies()` — O(n) дедупликация через set.

## file_utils.py — файловые операции и фильтрация

### `apply_sni_cidr_filter(configs, filter_secure) -> list`

Фильтрует конфиги по whitelist-файлам:
1. Загружает домены из `whitelist-all.txt`
2. Загружает CIDR из `cidrwhitelist.txt`
3. Извлекает host:port из каждого конфига
4. Оставляет только те, чей host **и есть** домен из списка или его поддомен — сравнение
   по границе метки. Aho-Corasick отвечает на вхождения подстрок, а `xmail.ru` содержит
   `mail.ru`, не будучи достижим через whitelist, который перечисляет `mail.ru`
5. Оставляет те, чей host — литеральный IP из CIDR-белого списка
6. Если `filter_secure=True` — дополнительно отфильтровывает insecure

Проверка идёт по адресу соединения, а не по параметру `sni`/`peer`, который нода и
положит в handshake, — а это вторая половина того, что видит мобильный whitelist.

### `extract_host_port(config_line) -> (host, port)`

Извлекает хост и порт из URL любого поддерживаемого протокола. Дедупликация использует кэш `lru_cache` в `_get_dedup_key()`.

Три обработчика разбирают то, чего `urlparse` не видит: JSON vmess, payload SSR и Blob SIP003 `ss://base64(method:password@host:port)`, у которого адрес целиком лежит в одном токене и в URL нет ни одного `@`. Пропустить такую форму — значит молча потерять публикацию: конфиг остаётся во всех остальных файлах и выглядит отфильтрованным, а не потерянным. Что бы ни вернул обработчик, проходит одну нормализацию IPv6: `[2001:db8::1]` — это как написано в URL, а `2001:db8::1` — то, с чем работают `ipaddress.ip_address()` и TCP-пинг, и проверка CIDR-белого списка вызывает именно её.

Известный пробел, и он касается только `ss://`: URL без порта (`ss://method:pw@host`) возвращает `None` здесь, хотя `parse_shadowsocks_to_outbound()` подставляет для той же строки `443` — такую ноду тестируют и публикуют, но в bypass-файлы она не попадает. У portless `trojan://` этого нет: проверено, `parse_trojan_to_outbound()` тоже возвращает `None`, и нода просто никогда не верифицируется. Закрыть ss-пробел — значит выбрать между угадыванием порта в экстракторе и отказом парсера от URL без порта; решение не принято.

### `deduplicate_configs(configs) -> list`

Удаляет дубликаты на основе содержимого (без учёта имени/remark). O(n) по памяти.

### `filter_secure_configs(configs) -> list`

Параллельная (8 workers) фильтрация через `has_insecure_setting()`.

## security_filter.py — фильтрация безопасности

Вынесен из `file_utils.py`. Содержит:

- **`has_insecure_setting(config_line) -> bool`** — проверяет один конфиг на наличие небезопасных параметров. Защищён `lru_cache` (65536 записей). Внутренняя логика по протоколам описана в [Система безопасности](security-system.md). Включает валидацию длины ключа для 2022-blake3 шифров (`_SS_2022_KEY_LENGTHS`).
- **`filter_secure_configs(configs) -> list`** — параллельная фильтрация через ProcessPoolExecutor (8 workers).
- **`SS_XRAY_CIPHERS` / `SS_WEAK_CIPHERS` / `SS_PLAINTEXT_CIPHERS` / `SS_SECURE_CIPHERS`** — единый источник истины по шифрам Shadowsocks: что загружает xray, что считается слабым, что означает «без шифрования». `SS_SECURE_CIPHERS` вычитается из первого списка. Читают это `protocol_parsers.py`, `vpn_config.py` и `xray_compat.py` — через `is_xray_cipher()`.
- **`is_xray_cipher(method) -> bool`** — принимает метод, который `cipherFromString` в xray знает; всё остальное для xray `unknown cipher method`, то есть падение загрузки конфига.
- **`extract_ss_credentials(config_line) -> tuple | None`** — один декодер четырёх форм (`method:pass@host`, `b64(method:pass)@host`, `b64(method:pass@host:port)`, где адрес лежит внутри токена, и payload SSR), чтобы парсеры и оба фильтра читали один и тот же шифр. `None` — «вердикта нет», а не «небезопасно»: именно поэтому третья форма должна была быть прочитана, потому что непрочитанный шифр записывается как чистый.
- **`_SS_2022_KEY_LENGTHS`** — маппинг 2022-blake3 шифров на ожидаемую длину ключа (16/32 байт); он же список методов 2022, которые принимает xray.

## xray_tester.py — верификация через Xray-core

### `test_batch(configs) -> list`

Конкурентное тестирование пачки конфигов.

**Пайплайн на конфиг:**
1. `_quick_validate_url()` — быстрая валидация URL
2. `create_single_outbound_config()` — генерация Xray-конфига
3. `start_xray_instance()` — запуск процесса Xray с уникальным портом (60 строк, делегирует в жизненный цикл)
4. `test_through_socks()` — HTTP-запрос через SOCKS5 (`socks5h://`)
5. `stop_xray_process()` — завершение процесса

**Извлечённые методы жизненного цикла (из `start_xray_instance`, 147→60 строк):**
- `_write_xray_config_file()` — запись конфига в secure tempfile
- `_launch_xray_process()` — запуск subprocess Xray
- `_is_xray_spam()` — фильтр спам-сообщений (баннеры, runtime info)
- `_cleanup_config_file()` — удаление temp файла

**Платформенная диспетчеризация:**
- Linux/WSL: асинхронный путь, до 300 параллельных конфигов
- Windows: ThreadPoolExecutor, до 50 параллельных конфигов

**Retry:** максимум 2 попытки на конфиг, экспоненциальная задержка.

### Парсеры протоколов (`_url_to_outbound()` → `protocol_parsers.py`)

| Протокол | Метод (xray_tester) | Возможности парсера |
|----------|---------------------|---------------------|
| VLESS | `_parse_vless_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| VMess | `_parse_vmess_to_outbound()` | TLS, WS, gRPC, httpupgrade, xhttp (h2 удалён из xray; reality отклоняется) |
| Trojan | `_parse_trojan_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| Shadowsocks | `_parse_shadowsocks_to_outbound()` | Только AEAD |
| SSR | `_parse_ssr_to_outbound()` | Конвертация → Shadowsocks |
| Hysteria2 | `parse_hysteria2_to_outbound()` | outbound `hysteria`, `version: 2`, TLS, finalmask |
| Hysteria v1 | — | парсера нет: xray отвергает `version != 2`, отказ до верификации |
| TUIC | — | парсера нет: в xray нет реализации TUIC (используйте sing-box) |

### `create_chain_config(proxy_urls, socks_port)`

Создаёт конфиг для прокси-цепочки. Реверсирует порядок hop'ов, валидирует транспорт (требуется WS/HTTPUpgrade + TLS).

## xray_batch.py — BatchRunner

Вынесен из `xray_tester.py`. Оркестрирует конкурентное тестирование конфигов:

- `test_batch()` — асинхронный batch (async wrapper с sync fallback)
- `test_single_config()` — одиночный конфиг с retry и парсингом
- `_run_single_config_test()` — extracted test loop с progress tracking (извлечена из внутренней closure)
- `_test_batch_single()` — синхронный fallback через ThreadPoolExecutor

Владеет ETA-трекингом, прогресс-барами и агрегацией результатов.

## xray_compat.py — отбраковка несовместимых с Xray конфигов

Вынесена из `xray_tester.py` (тот модуль был поверх потолка размера). Чистая
проверка строк URL, три вызывающих: `bypass_builder.verify_config_file()` перед
верификацией, `create_multi_config()` при сборке batch-конфига и
`XrayTester._quick_validate_url()` — чтобы одиночный режим отклонял те же URL по
той же причине, а не выдавал «не удалось разобрать конфиг».

- `filter_xray_compatible(configs)` — делит список на (совместимые,
  отклонённые с причиной) и пишет в лог счётчик по причинам
- `_xray_incompatible_reason(cfg)` — одна причина на конфиг: пустая строка
  означает «проверить можно»

Отклоняются конфиги, которые парсятся, но валят xray на загрузке конфига:
нерабочий UUID, мусорное значение `encryption=`, `flow=` у VLESS вне трёх значений,
которые xray разбирает, непустой `flow=` у trojan, Hysteria v1, Hysteria2 с
`insecure=1` без `pinSHA256` — или с pin, который не является 32 байтами hex, —
`type=`, который транспортный билдер не разрешает (удалённые `h2`, `h3`, `http`,
`quic` и любое незарегистрированное имя; `splithttp` и `mkcp` в список не входят,
потому что это псевдонимы, которые он разрешает), неизвестное стримовое
`security=`, шифр Shadowsocks/SSR вне `SS_XRAY_CIPHERS`, и `pbk`/`sid` Reality,
которые не проходят его декодеры. В batch-режиме один процесс xray держит до
`XRAY_BATCH_SIZE` конфигов, поэтому сорванный запуск стоит результатов всего
чанка — отсюда проверка по строке до построения конфига. Ровно на границе двух
фильтров стоят `none` и `plain`: `xray_compat.py` отклоняет то, что xray не
загрузит, а `security_filter.py` помечает то, что загружается без шифрования.

Что НЕ отклоняется: Hysteria2 и Reality поверх WebSocket или gRPC. outbound
Hysteria2 xray добавил в v26.1.13, а пайплайн берёт `releases/latest`; клиентский
билдер Reality транспорт не рассматривает вовсе. Отказываться от них — значит
терять конфиги, которые xray загружает и по которым соединяется.

## xray_helpers.py — чистые хэлперы Xray

- `wait_for_port(host, port, timeout)` — ожидание TCP-порта (используется и xray_tester, и ip_verifier)

## bypass_builder.py — верификация bypass-конфигов

- `_verify_and_write_bypass()` — Xray-верификация с сортировкой по пингу
- `_verify_and_write_bypass_unsecure()` — то же для unsecure-варианта
- Консолидированы из дублированной логики в config_processor.py

## file_writer.py — запись конфигов

Вынесен из `config_processor.py`. Содержит:

- `append_remark_suffix()` — добавление remark-суффикса `%20t.me%2Frjsxrd`
- `get_subscription_header()` — генерация subscription-заголовка
- `write_configs_file()` / `stream_write_configs_file()` — запись файла
- `_write_config_chunk()` — параллельный worker для чанковой записи
- `split_configs_to_files()` — разделение на номерные файлы
- `_write_numbered_file()` — запись номерных файлов (1.txt, 2.txt, ...)
- `create_numbered_default_files()` — создание номерных файлов default/
- `_write_protocol_file()` — запись протокол-специфичных файлов

## system_specs.py — автодетекция ресурсов

`SystemSpecs.detect()` — однократное обнаружение при старте: total RAM, CPU cores, WSL, container cgroup limits.

**Методы:**
- `safe_xray_workers()` — RAM-based: `(total - 200) / 24`, capped at `cpu * 40`.
- `safe_url_workers()` — I/O-bound, generous: до 20.
- `safe_fetch_workers()` — CPU-bound (TLS handshake), auto-detect. Low-CPU: `cpu * 4 + 4`, min 10. 4+ cores: `cpu * 10 + 10`, clamped [20, 50].
- `safe_tcp_workers()` — очень лёгкий: до 150.
- `safe_http_workers()` — умеренный: до 20.
- `summary()` — однострочный отчёт (`"956 MB RAM, 1 CPU cores (container)"`).

Кэшированный singleton через `get_specs()` — import-safe lazy init.

## url_payload.py — где заканчивается base64-payload

`base64_payload(url)` возвращает URL до первого `#` или `?` — что встретится раньше.
Так читать можно только base64-формы: у `vless://` и `trojan://` `?` вводит параметры,
которые и *есть* конфигурация.

Декодеры здесь снисходительные: `b64decode` и `urlsafe_b64decode` выбрасывают символы
вне своего алфавита вместо ошибки, а `#` и `?` в этом алфавите не было. Поэтому имя
ноды попадало в payload до подсчёта паддинга, и битый декод давал пять разных ответов
об одной ноде: нет хоста для SNI-белого списка, нет outbound для верификатора, нет
шифра для allowlist, нет `allowInsecure` для фильтра безопасности, и ключ дедупликации
из сырого blob вместо адреса сервера. Какие ноды ломались, зависело от длины
оставшихся символов — поэтому сбой выглядел нестабильным.

Используют `file_utils.py` (хост/порт, ключ дедупликации, кодированная форма `ss://`),
`security_filter.py` (вердикт vmess, шифр SSR), `protocol_parsers.py` и `vpn_config.py`
(оба строителя outbound).

## protocol_parsers.py — парсеры протоколов

Вынесены из `utils/xray_tester.py` для уменьшения god-module. Все шесть парсеров живут здесь:

- `parse_vless_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (97→33 строк, использует shared helpers)
- `parse_trojan_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (103→32 строк, использует shared helpers)
- `parse_vmess_to_outbound()` — TLS, WS, gRPC, httpupgrade, xhttp через общий builder; `tls: true` (булево из старых экспортов) нормализуется в `"tls"`, ветки h2 нет — xray удалил этот транспорт
- `parse_shadowsocks_to_outbound()` — только шифры из `SS_XRAY_CIPHERS`, метод отдаётся в нижнем регистре
- `parse_ssr_to_outbound()` — конвертация → Shadowsocks (использует `_clean_url_part`), тот же список шифров
- `parse_hysteria2_to_outbound()` — outbound ровно в том виде, в котором его документирует xray: `protocol: "hysteria"`, `version: 2`, TLS, `finalmask.udp` для obfuscation salamander
- для Hysteria v1 парсера нет вовсе: xray не умеет эту версию, поэтому фильтр совместимости отклоняет такие URL
- для TUIC парсера нет: xray не реализует исходящий TUIC-протокол, поэтому `tuic://` не даёт никакого конфига вообще

**URL helpers (извлечены из VLESS/Trojan/SSR для устранения дублирования):**
- `_clean_url_part(url)` — case-insensitive удаление протокола
- `_split_fragment_query(url_part)` — разделение `#fragment`, `?query`, `base`
- `_parse_user_host_port(base)` — парсинг `user@host:port`

Блоки `streamSettings` собираются в `xray_stream_settings.py` — раздел ниже.

Импортирует `is_xray_cipher()` из `security_filter.py`. Каждый парсер обязан вернуть None вместо исключения — контракт, а не надежда: форма SSR-пароля, на которой декод поднимал `UnboundLocalError` наружу, закреплена тестом.

## xray_stream_settings.py — сборщики streamSettings

Вынесены из `protocol_parsers.py`, когда тот перешагнул потолок размера модуля.
Чистые строители: никакого разбора URL и никаких знаний о протоколах, одна задача —
выдать ключи, которые читает `StreamConfig` xray (проверено по
`infra/conf/transport_internet.go` на v26.3.27). `utils/vpn_config.py` строит те же
блоки на typed-пути, и `test_stream_settings_builders.py` сверяет их ключ в ключ.

- `_make_stream_settings(network, security, params, host)` — весь блок: tls или reality плюс настройки транспорта
- `_make_tls_settings()`, `_make_reality_settings()`, `_make_ws_settings()`, `_make_grpc_settings()`, `_make_httpupgrade_settings()`, `_make_xhttp_settings()` — строители секций
- `apply_tls_fragment(stream)` — навешивает стадию `finalmask.tcp`, которая и делает `ENABLE_FRAGMENT` настоящим; вызывает её верификатор, а не парсер URL
- `_WS_NAMES` / `_XHTTP_NAMES` — пары транспортов, которые `TransportProtocol.Build()` сводит к одному протоколу; диспетч по литералу `"ws"` оставлял `type=websocket` без блока настроек, и path с host не попадали в handshake
- `vmess_security(raw)` — читает поле `tls` объекта vmess, куда клиенты пишут `"tls"`, `"none"`, голое `true` или `"reality"`; `StreamConfig` сравнивает `security` со строкой, поэтому `true` в outward означал `Unknown security "true"` — падение загрузки, а не неудачное соединение

Две формы выбраны сознательно. `wsSettings`, `httpupgradeSettings` и
`xhttpSettings` несут `host`, а не карту `headers`: xray принимает host, спрятанный
в `headers`, только как запасной вариант и печатает предупреждение о deprecated. И
`fingerprint` принадлежит `tlsSettings`/`realitySettings` — у `StreamConfig` нет
ключа fingerprint, поэтому `streamSettings.fingerprint`, который здесь раньше
писали, просто терялся; при этом пустое или неизвестное значение в том месте, где
xray его действительно читает, рвёт загрузку конфига.

## config_helpers.py — хэлперы пайплайна

Извлечены из `config_processor.py`. Чистые функции:

- `natural_sort_key(path)` — сортировка файлов с числовыми суффиксами
- `resolve_flag(name, overrides, default)` — разрешение feature-флагов
- `add_unique(configs, target, seen, seen_lock)` — потокобезопасная дедупликация
- `path_in_output(output_dir, *parts)` — построение путей через os.path.join
- `try_decode_base64_content(content)` — эвристическое определение base64

## merged_config_generator.py — объединённые конфиги

**УДАЛЁН** в рамках рефакторинга (2026-06). Функциональность не использовалась в основном пайплайне.

## logger.py — потокобезопасное логирование

- `log(message, level)` — добавляет сообщение в глобальный `LOGS_BY_FILE[file_index]`
- **File index extraction:** через regex `githubmirror/(\d+)\.txt` — логи группируются по номеру файла
- `print(formatted, file=sys.stderr, flush=True)` — вывод в stderr (чтобы не мешать tqdm)
- **Уровни:** DEBUG, INFO, WARNING, ERROR, CRITICAL (по умолчанию INFO, переключается `--verbose`)
- `print_logs()` — упорядоченный вывод по file index, затем общие сообщения
- `extract_source_name(url)` — извлекает читаемое имя источника из URL

## simple_tester.py — TCP-пинг

Быстрая альтернатива Xray для --tcp-ping режима. Использует asyncio для TCP-соединений. Тот же интерфейс возврата, что и `XrayTester.test_batch()`.

## smart_eta.py — умный ETA

Решает проблему завышенной оценки скорости из-за того, что быстрые конфиги завершаются первыми.

**Алгоритм:**
1. **Трёхкомпонентная оценка** — макс из трёх подходов: скользящее окно (быстрая реакция на изменения), глобальная скорость (стабильная на всём прогоне), EMA длительности (не зависит от очередности быстрых/медленных)
2. **EMA длительности** — экспоненциальное скользящее среднее, обновляется на каждом конфиге. Быстро адаптируется к изменению распределения
3. **Timeout floor** — физическая нижняя граница: `ceil(осталось / concurrency) * timeout` (без дисконта 0.8)
4. **Динамическое окно** — размер зависит от общего числа конфигов: `max(500, min(total // 10, 5000))`

Интегрирован во все тестеры: XrayTester, SimpleTester, TelegramProxyVerifier.

## url_stats.py — статистика URL

Собирает персистентную статистику в `data/url_stats.json`:

- `record_fetch(url, success)` — результат загрузки URL (fetch)
- `record_config_yield(url, raw_count, secure_count)` — выход конфигов (по источнику)
- `record_verified_yield(config_url, worked)` — результат верификации (обратное маппирование)
- `get_dead_urls()` — URL с 3+ последовательными ошибками
- `get_dead_configs()` — servers.txt конфиги с 3+ провалами верификации
- `remove_dead_from_urls_txt()` — авто-удаление мёртвых URL
- `remove_dead_from_servers_txt()` — авто-удаление мёртвых конфигов

## proxy_detector.py — авто-детекция прокси

Сканирует localhost на распространённых портах прокси:

| Порт | Обычно используется |
|------|---------------------|
| 10808 | v2rayN, Hiddify |
| 2080 | NekoRay |
| 7890, 7891 | Clash |
| 1080 | SOCKS-стандарт |
| 8080 | HTTP-прокси |

## ip_verifier.py — проверка IP, настройка прокси

Слит с `ip_checker.py` (удалён). Содержит:

- `get_real_ip()` / `get_proxy_ip()` — определение внешнего IP (без прокси / через прокси)
- `setup_global_proxy(url)` — запуск Xray для одиночного прокси
- `setup_proxy_chain(urls)` — запуск Xray с dialerProxy цепочкой
- `verify_protection(port)` — проверка, что прокси действительно скрывает IP
- `_make_request()` — HTTP-запрос с curl_cffi (fallback requests)
- `IP_CHECK_URLS` — список URL для проверки IP
- `_clear_proxy_env_vars()` — очистка HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (зарегистрирована в ProcessRegistry)
- `_json_payload()` / `_json_str_field()` / `_json_nested_str_field()` — чтение полей ответа с проверкой формы: ответ, который не является JSON-объектом (массив, скаляр), читается как отсутствие полей, а не падает с `AttributeError`
- `setup_proxy_chain()` — провайдер, не назвавший IP (ответ не JSON-объект, нет поля `ip`, пустое тело), считается неудачей: перебор идёт к следующему провайдеру, и цепочка не может быть признана рабочей с пустым exit-адресом; если IP не назвал никто, возвращается ошибка «Failed to get IP through proxy chain»
- Читатели поверх `_json_payload()`: `_json_ip_field()`, `_json_org_field()`, `_plain_text_body()` — тот же контракт: нет поля или тело не того типа — значит значения нет, а не исключение

## resource_monitor.py — мониторинг ресурсов

Фоновый поток (sample_interval=2 с), собирает через psutil:
- CPU загрузка (процесс + система)
- RAM (RSS, VMS, процент)
- Сетевой трафик (отправлено/получено за сессию)

По окончании выводит сводный отчёт.

## github_handler.py — GitHub API

- `_GitHubClient` — абстрактный протокол для изоляции тестов. Реализации: `_PyGithubClient` (реальный, PyGithub) и `FakeGitHubClient` (in-memory для тестов)
- `upload_multiple_files(file_pairs)` — параллельная загрузка файлов (ThreadPoolExecutor)
- `upload_file(local_path, remote_path)` — загрузка одного файла с разрешением SHA-конфликтов
- SHA-конфликты разрешаются экспоненциальной задержкой (базово 0.5 с, до 5 попыток)
- Сравнение содержимого перед загрузкой — избегает пустых коммитов
- `_check_rate_limit()` — предупреждает при < 100 запросов, ждёт reset если лимит исчерпан
- Rate limit проверка при инициализации: `g.rate_limiting`
- Тесты через `FakeGitHubClient` in-memory file tree — счётчик в [таблице тестов](testing.md)

## git_updater.py — Git-команды

- `commit_and_push_files(file_pairs)` — полный цикл: configure → squash auto → stage → commit → push
- Для VPS cron (основной) и GitHub Actions (резервный); не требует токена GitHub API
- `configure_git()` — устанавливает `user.name` и `user.email` для коммитов
- `pull(branch)` — pull с rebase; при unstaged changes делает `reset --hard` + `clean -fd`
- Retry при push-конфликте: `pull --rebase` вместо слепого ожидания (до 3 попыток)
- Все команды с таймаутом 60 с
- Перед stage_files() вызывает `git_auto_cleaner.squash_auto_commits()` для авто-очистки

## git_auto_cleaner.py — авто-очистка истории

Автоматически удаляет старые `auto: update ...` коммиты перед созданием нового, чтобы git история не засорялась.

### `squash_auto_commits(repo_dir) -> int`

- Ходит от HEAD назад, собирает contiguous auto-коммиты (сообщение начинается с `auto: update `)
- Делает `git reset --soft` до последнего реального коммита — все изменения остаются в index
- Только при 2+ auto-коммитах подряд (одиночный auto не трогает)
- Возвращает количество схлопнутых коммитов (0 = ничего не сделано)
- Вызывается из `GitUpdater.commit_and_push_files()` автоматически, перед stage_files()
- **Не трогает** коммиты других типов (fix:, feat:, chore:, merge: и старые форматы Update bypass-, update configs)
- **Требует `fetch-depth: 0`** в GitHub Actions (полная история) — настроено в `frequent_update.yml`
- Тесты, все mock-based на `subprocess.run`; счётчик в [таблице тестов](testing.md)

### Сколько истории занимают авто-коммиты

История `main` — это в основном авто-обновления. Замер сделан 18 сентября 2026
на ветке `main` в коммите `71972831`: 6894 коммита, из них 6700 (**≈ 97,2 %**)
начинаются с `auto: update`, а остальные 194 (≈ 2,8 %) — весь прочий текст
истории (`reinit`, `feat:`, `fix:`, `docs:`, `chore:` и старые подписи вроде
`Update bypass-`). Отсюда и вид `git log`: часовая машина обновления коммитит
каждое изменение, а `squash_auto_commits()` схлопывает только подряд идущие
авто-коммиты — свежие остаются видны по одному.

Доля привязана к коммиту, а не к HEAD: каждый ручной коммит её немного
опускает (за две предыдущие правки она ушла с 97,5 % на 97,2 %),
поэтому цифра без привязки устаревает через один коммит. `71972831` — вершина
`main` на момент замера; `source/tests/test_docs_figures.py` проверяет, что
привязка и обе доли остались на месте.

Повторить замер:

```bash
git rev-list --count 71972831                              # 6894
git log --format=%s 71972831 | grep -c '^auto: update'     # 6700
git log --format=%s 71972831 | grep -vc '^auto: update'    # 194
```

## config_helpers.py — общие хэлперы пайплайна

Извлечённые из config_processor.py вспомогательные функции:

- `natural_sort_key()` — сортировка файлов с числовыми суффиксами
- `resolve_flag()` — разрешение feature-флагов из CLI override или настроек
- `add_unique()` — потокобезопасная дедупликация конфигов
- `path_in_output()` — построение путей в output-директории
- `try_decode_base64_content()` — попытка декодировать контент из base64
