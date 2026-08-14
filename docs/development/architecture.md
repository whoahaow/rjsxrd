> **Language:** [Русский](architecture.md) · [English](architecture.en.md)

# Архитектура

## Обзор

Проект построен по модульной схеме с разделением ответственности. Каждый компонент выполняет строго одну задачу: загрузка, фильтрация, верификация, генерация файлов, выгрузка.

## Схема модулей

```
main.py                          # Точка входа, CLI, оркестрация
  │
  ├── config/                    # Настройки и конфигурация
  │   ├── settings.py           #   Параметры, токены, URL-источники (включая бывшие constants.py)
  │   ├── URLS.txt               #   Список URL-источников (секции)
  │   ├── servers.txt            #   Ручные VPN-серверы
  │   ├── tg_proxies.txt         #   Ручные Telegram-прокси
  │   ├── whitelist-all.txt      #   SNI-домены для обхода
  │   └── cidrwhitelist.txt      #   CIDR-диапазоны для обхода
  │
  ├── fetchers/                  # Загрузка данных из источников
  │   ├── fetcher.py             #   curl_cffi-загрузчик
  │   ├── daily_repo_fetcher.py  #   Ежедневные репозитории
  │   ├── yaml_converter.py      #   Clash/Surge YAML → VPN URL
  │   ├── telegram_proxy_scraper.py  # MTProto/SOCKS5 из контента
  │   ├── sstap_scraper.py       #   sstap.org скрапинг
  │   └── upstream_aggregator.py #   yudou226.top + guidongone
  │
  ├── processors/                # Обработка и генерация
  │   ├── config_processor.py    #   ConfigPipeline (оркестратор)
  │   └── telegram_proxy_processor.py  # Прокси-обработчик
  │
  ├── utils/                     # Вспомогательные модули
  │   ├── file_utils.py          #   I/O, SNI/CIDR, протоколы
  │   ├── security_filter.py     #   has_insecure_setting (вынесен)
  │   ├── vpn_config.py          #   VPNConfig dataclass иерархия
  │   ├── managed_process.py     #   ManagedProcess lifecycle
  │   ├── process_registry.py    #   Единый реестр процессов
  │   ├── config_tagger.py       #   ConfigTagger (source+protocol)
  │   ├── logger.py              #   Логирование (thread-safe)
  │   ├── progress.py            #   Консолидированный tqdm импорт
  │   ├── executor_cache.py      #   Пул тредов с WSL-детекцией
  │   ├── ip_verifier.py         #   Настройка прокси + проверка IP (слит с ip_checker)
  │   ├── bypass_builder.py      #   Верификация bypass-конфигов
  │   ├── file_writer.py         #   Параллельная запись конфигов
  │   ├── xray_batch.py          #   BatchRunner — конкурентное тестирование + batch-режим (shared Xray, v2rayN-стиль)
  │   ├── xray_helpers.py        #   Хэлперы Xray (wait_for_port)
  │   ├── proxy_detector.py      #   Авто-детекция прокси
  │   ├── proxy_monitor.py       #   Мониторинг цепочек
  │   ├── resource_monitor.py    #   Мониторинг CPU/RAM/сети
  │   ├── download_xray.py       #   Установщик Xray-core
  │   ├── url_stats.py           #   Статистика URL (typed dataclass)
  │   ├── health_check.py        #   Health check перед запуском
  │   ├── _sni_worker.py         # SNI/CIDR worker (внутренний)
  │   ├── system_specs.py        # SystemSpecs — автодетект ресурсов
  │   ├── psutil_available.py    # единый import psutil
  │   ├── protocol_parsers.py    # Парсеры протоколов (из xray_tester)
  │   ├── config_helpers.py      # Хэлперы пайплайна
  │   ├── curl_import.py         # Единый import curl_cffi
  │   ├── xray_tester.py         # Xray-core верификация
  │   ├── simple_tester.py       #   TCP-пинг верификация
  │   ├── smart_eta.py           #   Оценка времени (3-way + EMA + timeout floor)
  │   ├── telegram_proxy_verifier.py  # Верификация прокси
  │   ├── github_handler.py      #   GitHub API (PyGithub)
  │   ├── git_updater.py         #   Git-команды (VPS/GitHub Actions)
  │   └── git_auto_cleaner.py    #   Авто-очистка auto:update коммитов при коммите
  │
  ├── scripts/                   # Утилиты (однократный запуск)
  │   ├── purge_dead_urls.py
  │   ├── purge_stale_urls.py
  │   ├── analyze_url_stats.py
  │   ├── benchmark_configs.py
  │   ├── test_telegram_proxies.py
  │   └── setup-vps.sh
  └── tests/                     # 658 тестов в 26 файлах
```

## Пайплайн обработки

### Фаза 1. Загрузка

Параллельная загрузка из всех источников с использованием ThreadPoolExecutor (50 workers по умолчанию, настраивается через MAX_WORKERS):

1. URL из секции `# default` — базовые конфиги
2. URL из секции `# extra_bypass` — дополнительный набор для bypass
3. URL из секции `# yaml` — парсинг Clash/Surge через PyYAML
4. Ежедневно обновляемые репозитории — поиск по дате
5. Ручные серверы из `servers.txt`
6. Сканирование всего контента на наличие Telegram-прокси (MTProto/SOCKS5)
7. Base64-автоопределение для каждого URL

Результат: 4 массива (`all_configs`, `extra_bypass_configs`, `mtproto_proxies`, `socks5_proxies`) + массив кортежей для номерных файлов.

### Фаза 2. Генерация default-файлов

```
create_numbered_default_files() → 1.txt, 2.txt, ... (по источникам)
create_all_configs_file()      → all.txt (дедупликация)
create_secure_configs_file()   → all-secure.txt (фильтрация insecure)
```

### Фаза 3. Генерация bypass-файлов

```
apply_sni_cidr_filter() → выборка по доменам/CIDR
  + extra_bypass_configs (без SNI/CIDR-фильтрации)
  → дедупликация + security-фильтр
  → запись raw-файлов
  → верификация (Xray или TCP)
  → сортировка по пингу
  → bypass-all.txt, bypass-unsecure-all.txt
```

### Фаза 4. Разделение по протоколам

Классификация по типу протокола → создание secure/unsecure файлов → параллельная запись (8 workers).

### Фаза 5. Telegram-прокси

Слияние скрапированных и ручных → верификация → сортировка → all.txt, MTProto.txt, socks.txt.

### Фаза 6. URL Health Report

Анализ статистики → удаление мёртвых URL и конфигов → отчёт.

### Фаза 7. Выгрузка

Два режима:
- **GitHub API:** PyGithub, параллельная загрузка (8 workers), разрешение SHA-конфликтов
- **Git-команды:** `--use-git`, для VPS cron (основной) и GitHub Actions (резервный)

## Обработка сигналов

При получении SIGINT/SIGTERM срабатывает `_signal_handler()` в `main.py`:

1. **Остановка ResourceMonitor** — фоновый сбор CPU/RAM/сети прекращается
2. **Очистка реестра процессов** — `default_registry.cleanup(force=True)` из `process_registry.py`. Реестр сначала останавливает ProxyMonitor'ы (они зависят от SOCKS-порта Xray), затем завершает все Xray-процессы и восстанавливает proxy env vars
3. **Ожидание 2 с** — `time.sleep(2)`, даёт время процессам завершиться
4. **`sys.exit(0)`** — чистое завершение

**Почему именно такой порядок:** ProxyMonitor зависит от SOCKS-порта Xray. Убить Xray до остановки монитора = паника в мониторе. Signal handler сначала останавливает все watcher'ы, затем чистит процессы.

Сигнал-хендлер Xray больше не регистрируется отдельно — весь cleanup централизован в `main.py`. `ProcessRegistry` — единый реестр для всех Xray-процессов (заменил старые `_active_testers`, `_xray_process_registry`).
