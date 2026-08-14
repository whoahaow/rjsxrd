> **Language:** [Русский](testing.md) · [English](testing.en.md)

# Тестирование

## Запуск тестов

```bash
cd source
pip install pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock

pytest                       # Все тесты
pytest -v                    # Подробный вывод
pytest -n auto               # Параллельный запуск
```

### Фильтрация

```bash
pytest -m unit                # Быстрые unit-тесты (без сети)
pytest -m integration         # Интеграционные (требуют сеть)
pytest --cov=fetchers --cov=utils  # С отчётом о покрытии
```

## Структура тестов

Всего **658 тестов** в 26 файлах (полный прогон ~40 с):

| Файл | Тестов | Область |
|------|--------|---------|
| `test_config_processor.py` | 78 | Пайплайн обработки, `prepare_config_content`, `_add_unique`, `write_configs_file` |
| `test_file_utils.py` | 70 | `extract_host_port`, `deduplicate_configs`, `is_valid_vpn_config_url`, `filter_secure_configs` |
| `test_xray_tester.py` | 44 | Парсеры, сигналы, startup-timeout, security edge-кейсы |
| `test_security_filter.py` | 35 | `has_insecure_setting`, все протоколы и edge-кейсы, 2022 key length validation |
| `test_vpn_config.py` | 35 | VPNConfig typed dataclass'ы |
| `test_logger.py` | 30 | Логирование, уровни, формат |
| `test_yaml_converter.py` | 28 | Конвертация Clash/Surge YAML в VPN URL |
| `test_smart_eta.py` | 27 | SmartETA: 3-way estimate (window, global, EMA) + timeout floor |
| `test_git_updater.py` | 26 | GitUpdater: init, pull, stage, commit, push, retry |
| `test_simple_tester.py` | 25 | `extract_host_port` + `SimpleTester` (TCP-пинг) |
| `test_process_registry.py` | 25 | ProcessRegistry, cleanup, callbacks |
| `test_git_auto_cleaner.py` | 24 | Авто-очистка auto-коммитов |
| `test_github_handler.py` | 22 | GitHub API, rate limits, 409 conflicts, batch |
| `test_health_check.py` | 21 | Health check: DNS fallback, диск, память, токен |
| `test_telegram_proxy_scraper.py` | 21 | Извлечение MTProto и SOCKS5 из контента |
| `test_proxy_monitor.py` | 19 | Мониторинг цепочек, stop-событие |
| `test_xray_batch.py` | 18 | BatchRunner, shared xray, port allocation |
| `test_config_tagger.py` | 17 | ConfigTagger: source+protocol tagging |
| `test_fetcher.py` | 15 | Загрузка, парсинг ответов, обработка ошибок |
| `test_executor_cache.py` | 15 | Пул тредов, shutdown, WSL-детекция |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_ip_checker.py` | 14 | Проверка IP, `_make_request` |
| `test_telegram_proxy_verifier.py` | 12 | Верификация MTProto/SOCKS5 прокси |
| `test_url_stats.py` | 11 | `record_fetch`, `get_dead_urls`, персистентность |
| `test_ip_verifier.py` | 6 | env vars, TCP port polling |
| `test_progress.py` | 6 | tqdm-консолидация |

Покрытие: ~46% (измеряется через `pytest --cov=fetchers --cov=utils`).

## Утилиты для ручного тестирования

Расположены в `source/scripts/`:

```bash
# Очистка URLS.txt от мёртвых ссылок (dry-run: без --apply ничего не удаляет)
python scripts/purge_dead_urls.py
python scripts/purge_dead_urls.py --apply

# Очистка по git timestamp (только GitHub URL)
python scripts/purge_stale_urls.py --days 60 --apply

# Анализ источников: топ по отдаче
python scripts/analyze_url_stats.py
python scripts/analyze_url_stats.py --top 30
python scripts/analyze_url_stats.py --dead  # только мёртвые

# Бенчмарк конфигов (TCP ping или Xray)
python scripts/benchmark_configs.py --mode tcp --count 500
python scripts/benchmark_configs.py --mode xray --count 200

# Тестирование Telegram-прокси
python scripts/test_telegram_proxies.py
```

## Локальное тестирование генератора

```bash
python main.py --dry-run
```

Выполняет все фазы, кроме загрузки в GitHub. Полезно для проверки изменений перед коммитом.

## GitHub Workflow

`.github/workflows/frequent_update.yml` — запуск каждые 2 дня в 00:00 UTC.
- Ubuntu latest
- 80 минут таймаут
- Флаги: `--use-git --no-proxy-check`
- Concurrency group для предотвращения overlapping
- Ручной запуск через `workflow_dispatch`
