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

### Вспомогательные функции

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
|- retry: до 3 попыток (по умолчанию) с 1s wait между попытками. Стратегия: attempt 1 — `verify=True`, attempt 2 — `verify=False` (SSL skip), attempt 3 — HTTPS→HTTP downgrade. Таймаут 5 с (настраивается через `FETCH_TIMEOUT`/`FETCH_MAX_ATTEMPTS`)
|- `fetch_data()` принимает `token` — если передан и URL содержит `github.com`/`raw.githubusercontent.com`, в сессию добавляется заголовок `Authorization: Bearer <token>`. Это повышает лимиты GitHub с ~60/ч до 5000/ч
|- `_extract_status(exc)` — извлекает HTTP-статус из разных типов исключений

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

**SOCKS5** (6 паттернов): `https://t.me/socks?...`, `http://t.me/socks?...`, `t.me/socks?...`, `tg://socks?...`, `socks5://host:port`, `IP:PORT` (bare format)

`_clean_proxy_url()` — удаляет эмодзи и не-ASCII символы. `deduplicate_proxies()` — O(n) дедупликация через set.

## file_utils.py — файловые операции и фильтрация

### `apply_sni_cidr_filter(configs, filter_secure) -> list`

Фильтрует конфиги по whitelist-файлам:
1. Загружает домены из `whitelist-all.txt`
2. Загружает CIDR из `cidrwhitelist.txt`
3. Извлекает host:port из каждого конфига
4. Оставляет только те, чей host/ip совпадает с whitelist
5. Если `filter_secure=True` — дополнительно отфильтровывает insecure

### `extract_host_port(config_line) -> (host, port)`

Извлекает хост и порт из URL любого поддерживаемого протокола. Использует кэширование результатов через `lru_cache`.

### `deduplicate_configs(configs) -> list`

Удаляет дубликаты на основе содержимого (без учёта имени/remark). O(n) по памяти.

### `filter_secure_configs(configs) -> list`

Параллельная (8 workers) фильтрация через `has_insecure_setting()`.

## security_filter.py — фильтрация безопасности

Вынесен из `file_utils.py`. Содержит:

- **`has_insecure_setting(config_line) -> bool`** — проверяет один конфиг на наличие небезопасных параметров. Защищён `lru_cache` (65536 записей). Внутренняя логика по протоколам описана в [Система безопасности](security-system.md). Включает валидацию длины ключа для 2022-blake3 шифров (`_SS_2022_KEY_LENGTHS`).
- **`filter_secure_configs(configs) -> list`** — параллельная фильтрация через ProcessPoolExecutor (8 workers).
- **`SS_WEAK_CIPHERS` / `SS_SECURE_CIPHERS`** — единый источник истины для шифров Shadowsocks. Импортируется `xray_tester.py` и `protocol_parsers.py`.
- **`_SS_2022_KEY_LENGTHS`** — маппинг 2022-blake3 шифров на ожидаемую длину ключа (16/32 байт).

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
- Linux/WSL: асинхронный путь, до 150 параллельных конфигов
- Windows: ThreadPoolExecutor, до 50 параллельных конфигов

**Retry:** максимум 2 попытки на конфиг, экспоненциальная задержка.

### Парсеры протоколов (`_url_to_outbound()` → `protocol_parsers.py`)

| Протокол | Метод (xray_tester) | Возможности парсера |
|----------|---------------------|---------------------|
| VLESS | `_parse_vless_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| VMess | `_parse_vmess_to_outbound()` | TLS, WS, gRPC, h2 |
| Trojan | `_parse_trojan_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| Shadowsocks | `_parse_shadowsocks_to_outbound()` | Только AEAD |
| SSR | `_parse_ssr_to_outbound()` | Конвертация → Shadowsocks |
| Hysteria v2 | `_parse_hysteria2_to_outbound()` | QUIC, TLS |
| Hysteria v1 | `_parse_hysteria_to_outbound()` | Ограниченно |
| TUIC | `_parse_tuic_to_outbound()` | Не поддерживается Xray (возвращает None) |

### `create_chain_config(proxy_urls, socks_port)`

Создаёт конфиг для прокси-цепочки. Реверсирует порядок hop'ов, валидирует транспорт (требуется WS/HTTPUpgrade + TLS).

## xray_batch.py — BatchRunner

Вынесен из `xray_tester.py`. Оркестрирует конкурентное тестирование конфигов:

- `test_batch()` — асинхронный batch (async wrapper с sync fallback)
- `test_single_config()` — одиночный конфиг с retry и парсингом
- `_run_single_config_test()` — extracted test loop с progress tracking (извлечена из внутренней closure)
- `_test_batch_single()` — синхронный fallback через ThreadPoolExecutor

Владеет ETA-трекингом, прогресс-барами и агрегацией результатов.

## xray_helpers.py — чистые хэлперы Xray

- `wait_for_port(host, port, timeout)` — ожидание TCP-порта (используется и xray_tester, и ip_verifier)

## bypass_builder.py — верификация bypass-конфигов

- `_verify_and_write_bypass()` — Xray-верификация с сортировкой по пингу
- `_verify_and_write_bypass_unsecure()` — то же для unsecure-варианта
- Консолидированы из дублированной логики в config_processor.py

## file_writer.py — запись конфигов

Вынесен из `config_processor.py`. Содержит:

- `_write_config_chunk()` — параллельный worker для чанковой записи
- `_write_numbered_file()` — запись номерных файлов (1.txt, 2.txt, ...)
- `_write_protocol_file()` — запись протокол-специфичных файлов

## system_specs.py — автодетекция ресурсов

`SystemSpecs.detect()` — однократное обнаружение при старте: total RAM, CPU cores, WSL, container cgroup limits.

**Методы:**
- `safe_xray_workers()` — RAM-based: `(total - 200) / 24`, capped at `cpu * 40`.
- `safe_url_workers()` — I/O-bound, generous: до 20.
- `safe_tcp_workers()` — очень лёгкий: до 150.
- `safe_http_workers()` — умеренный: до 20.
- `summary()` — однострочный отчёт (`"956 MB RAM, 1 CPU cores (container)"`).

Кэшированный singleton через `get_specs()` — import-safe lazy init.

## protocol_parsers.py — парсеры протоколов

Вынесены из `utils/xray_tester.py` для уменьшения god-module. Все 8 парсеров живут здесь:

- `parse_vless_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (97→33 строк, использует shared helpers)
- `parse_trojan_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (103→32 строк, использует shared helpers)
- `parse_vmess_to_outbound()` — TLS, WS, gRPC, h2 (93 строк, base64 JSON)
- `parse_shadowsocks_to_outbound()` — AEAD only, слабые шифры отвергаются
- `parse_ssr_to_outbound()` — конвертация → Shadowsocks (использует `_clean_url_part`)
- `parse_hysteria2_to_outbound()` — QUIC, TLS (43 строки)
- `parse_hysteria_to_outbound()` — ограниченно (v1)
- `parse_tuic_to_outbound()` — возвращает None (не поддерживается Xray)

**Shared helpers (извлечены из VLESS/Trojan/SSR для устранения дублирования):**
- `_clean_url_part(url)` — case-insensitive удаление протокола
- `_split_fragment_query(url_part)` — разделение `#fragment`, `?query`, `base`
- `_parse_user_host_port(base)` — парсинг `user@host:port`
- `_make_stream_settings(network, security, params, host)` — сборка streamSettings (tls, reality, ws, grpc, httpupgrade)
- `_make_tls_settings()`, `_make_reality_settings()`, `_make_ws_settings()`, `_make_grpc_settings()`, `_make_httpupgrade_settings()` — низкоуровневые строители секций

Импортирует `SS_WEAK_CIPHERS` из `security_filter.py`. Каждый парсер защищён try/except и возвращает None при ошибке.

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
- **22 теста** через `FakeGitHubClient` in-memory file tree

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
- 24 теста, все mock-based на `subprocess.run`

## config_helpers.py — общие хэлперы пайплайна

Извлечённые из config_processor.py вспомогательные функции:

- `natural_sort_key()` — сортировка файлов с числовыми суффиксами
- `resolve_flag()` — разрешение feature-флагов из CLI override или настроек
- `add_unique()` — потокобезопасная дедупликация конфигов
- `path_in_output()` — построение путей в output-директории
- `try_decode_base64_content()` — попытка декодировать контент из base64
