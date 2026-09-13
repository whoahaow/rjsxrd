> **Language:** [Русский](testing.md) · [English](testing.en.md)

# Тестирование

## Запуск тестов

Тестовый тулчейн ставится один раз через `uv` — создание окружения и команда установки описаны в [Окружении для разработки](development-environment.md). Bare `pip` в проекте не используется.

```bash
cd source
../.venv/Scripts/python.exe -m pytest -q        # полный прогон

pytest -v                    # Подробный вывод
pytest -n auto               # Параллельный запуск
```

### Фильтрация

```bash
pytest -m unit                # Быстрые unit-тесты (без сети)
pytest -m integration         # Интеграционные (требуют сеть)
pytest --cov=fetchers --cov=utils  # С отчётом о покрытии
```

Маркеры проставлены на каждом тестовом модуле (`pytestmark`), поэтому `-m unit`
и `-m integration` действительно что-то выбирают: 694 и 30 тестов из 724
(замер — `pytest --collect-only -q` с тем и другим маркером). Два
модуля, которые обращаются к сети и сами пропускаются при её отсутствии
(`test_fetcher.py`, `test_ip_checker.py`), помечены `integration`.

## Структура тестов

Всего **724 теста** в 31 файле. Полный прогон на машине разработки (Windows,
Python 3.12) занимает около 70–80 секунд; время зависит от диска и загрузки
машины, поэтому ориентируйтесь на `pytest -q` у себя.

| Файл | Тестов | Область |
|------|--------|---------|
| `test_config_processor.py` | 81 | Пайплайн обработки, `prepare_config_content`, `_add_unique`, `write_configs_file` |
| `test_file_utils.py` | 70 | `extract_host_port`, `deduplicate_configs`, `is_valid_vpn_config_url`, `filter_secure_configs` |
| `test_xray_tester.py` | 45 | Парсеры, сигналы, startup-timeout, security edge-кейсы |
| `test_vpn_config.py` | 35 | VPNConfig typed dataclass'ы |
| `test_security_filter.py` | 35 | `has_insecure_setting`, все протоколы и edge-кейсы, 2022 key length validation |
| `test_logger.py` | 30 | Логирование, уровни, формат |
| `test_yaml_converter.py` | 28 | Конвертация Clash/Surge YAML в VPN URL |
| `test_smart_eta.py` | 27 | SmartETA: 3-way estimate (window, global, EMA) + timeout floor |
| `test_git_updater.py` | 26 | GitUpdater: init, pull, stage, commit, push, retry |
| `test_simple_tester.py` | 25 | `extract_host_port` + `SimpleTester` (TCP-пинг) |
| `test_process_registry.py` | 25 | ProcessRegistry, cleanup, callbacks |
| `test_git_auto_cleaner.py` | 24 | Авто-очистка auto-коммитов |
| `test_health_check.py` | 22 | Health check: DNS fallback, диск, память, токен |
| `test_github_handler.py` | 22 | GitHub API, rate limits, 409 conflicts, batch |
| `test_xray_batch.py` | 21 | BatchRunner, shared xray, port allocation |
| `test_telegram_proxy_scraper.py` | 21 | Извлечение MTProto и SOCKS5 из контента |
| `test_proxy_monitor.py` | 19 | Мониторинг цепочек, stop-событие |
| `test_pipeline_e2e.py` | 18 | Прогон всего пайплайна офлайн, с заглушёнными швами |
| `test_config_tagger.py` | 18 | ConfigTagger: source+protocol tagging; `utils/__init__.py` не импортирует ничего |
| `test_fetcher.py` | 16 | Загрузка, парсинг ответов, обработка ошибок |
| `test_executor_cache.py` | 16 | Пул тредов, shutdown, WSL-детекция |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_ip_verifier.py` | 15 | env vars, TCP port polling |
| `test_telegram_proxy_verifier.py` | 14 | Верификация MTProto/SOCKS5 прокси |
| `test_ip_checker.py` | 14 | Проверка IP, `_make_request` |
| `test_url_stats.py` | 13 | `record_fetch`, `get_dead_urls`, персистентность |
| `test_scripts_import.py` | 12 | Импорт-смоук тесты точек входа в `scripts/`, загрузчик бенчмарка |
| `test_progress.py` | 6 | tqdm-консолидация |
| `test_main.py` | 5 | Гварды путей загрузки в точке входа пайплайна |
| `test_telegram_proxy_processor.py` | 3 | Запись MTProto/SOCKS5 прокси в файлы |
| `test_purge_stale_urls.py` | 3 | Загрузка кэша в `scripts/purge_stale_urls.py` |

Покрытие зависит от того, что считать, и эти два числа нельзя сравнивать
напрямую:

| Команда | Область | Покрытие |
|---------|---------|----------|
| `pytest --cov=fetchers --cov=utils` | два пакета | **56 %** (5567 операторов, 2433 не покрыто) |
| `pytest --cov=.` (то, что запускает CI) | весь `source/` | **72 %** (12452 оператора, 3436 не покрыто) |

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

## Проверка типов

```bash
cd source
../.venv/Scripts/python.exe -m mypy .   # полный отчёт по текущему дереву
```

В CI `mypy` работает как блокирующий гейт по явному списку модулей с **нулём**
ошибок (`Type check (ratchet)` в `.github/workflows/ci.yml`). Этот список —
храповик: он может только расти. Модуль попадает в него, когда становится
чистым, и после этого CI падает, если в нём появляется новая ошибка. Гейт
запускается с `--follow-imports=silent`, чтобы каждый модуль из списка
оценивался по своему коду, а не наследовал ошибки своих импортов.

`strict`, `disallow_untyped_defs` и `check_untyped_defs` намеренно не включены:
каждый из них умножает число ошибок, а не выявляет новые дефекты, поэтому
строгость включается поэтапно. Остаток по всему дереву — это семейства гигиены
(`assignment`, `arg-type`, `var-annotated`, `no-any-return`, `return-value`);
находки `name-defined`, стоявшие рядом с ними, оказались реальными дефектами и
исправлены. Число ошибок и файлов меняется от карточки к карточке — измеряйте
его командой выше, а не переносите цифру из документа.

## Предупреждения

Глобальных `ignore` для предупреждений в конфиге pytest нет: первое
`DeprecationWarning` из своего кода — это ранний сигнал к следующему обновлению
зависимостей, и подавлять его категорией нельзя. Если у сторонней библиотеки
появится шум, фильтр привязывается к её модулю
(`ignore::DeprecationWarning:<модуль>.*`), а не к категории целиком.

`default::ResourceWarning` включён намеренно: он показывает незакрытые файлы и
сокеты. После последнего замера таких предупреждений 8, и все они вызваны
тестами: `test_config_processor.py` — 6, `test_file_utils.py` — 1,
`test_pipeline_e2e.py` — 1. Ни одно не выделяется в продакшн-коде — раньше их
было 10, и два приходили из `check_internet_connectivity`
(`utils/health_check.py`): сокет открывался и не закрывался. Теперь сокет
закрывается (`contextlib.closing`), поэтому счёт упал до 8. Прогон остаётся
зелёным, предупреждения только печатаются.
