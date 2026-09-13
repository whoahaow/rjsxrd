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
и `-m integration` действительно что-то выбирают: 705 и 30 тестов из 735
(замер — `pytest --collect-only -q` с тем и другим маркером). Два
модуля, которые обращаются к сети и сами пропускаются при её отсутствии
(`test_fetcher.py`, `test_ip_checker.py`), помечены `integration`.

## Структура тестов

Всего **735 тестов** в 32 файлах. Полный прогон на машине разработки (Windows,
Python 3.12) занимает около 70–80 секунд; время зависит от диска и загрузки
машины, поэтому ориентируйтесь на `pytest -q` у себя.

| Файл | Тестов | Область |
|------|--------|---------|
| `test_config_processor.py` | 85 | Пайплайн обработки, `prepare_config_content`, `_add_unique`, `write_configs_file` |
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
| `test_pipeline_e2e.py` | 19 | Прогон всего пайплайна офлайн, с заглушёнными швами |
| `test_config_tagger.py` | 18 | ConfigTagger: source+protocol tagging; `utils/__init__.py` не импортирует ничего |
| `test_fetcher.py` | 16 | Загрузка, парсинг ответов, обработка ошибок |
| `test_executor_cache.py` | 17 | Пул тредов, shutdown, WSL-детекция |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_ip_verifier.py` | 15 | env vars, TCP port polling |
| `test_telegram_proxy_verifier.py` | 14 | Верификация MTProto/SOCKS5 прокси |
| `test_ip_checker.py` | 14 | Проверка IP, `_make_request` |
| `test_url_stats.py` | 13 | `record_fetch`, `get_dead_urls`, персистентность |
| `test_scripts_import.py` | 12 | Импорт-смоук тесты точек входа в `scripts/`, загрузчик бенчмарка |
| `test_progress.py` | 6 | tqdm-консолидация |
| `test_docs_figures.py` | 5 | Фигуры в документации сверяются с собранным набором тестов |
| `test_main.py` | 5 | Гварды путей загрузки в точке входа пайплайна |
| `test_telegram_proxy_processor.py` | 3 | Запись MTProto/SOCKS5 прокси в файлы |
| `test_purge_stale_urls.py` | 3 | Загрузка кэша в `scripts/purge_stale_urls.py` |

Покрытие зависит от того, что и в каком режиме считать: эти числа несравнимы
напрямую. Режим — ветви (`branch = true` в `[tool.coverage]` в
`pyproject.toml`), а не одни операторы: оператор, выполненный один раз, скрывает
ветку `if`, которая не выполнялась ни разу, — а падения пайплайна жили именно
там.

| Команда | Область | Покрытие |
|---------|---------|----------|
| `pytest --cov=fetchers --cov=utils` | два пакета | **55 %** (5587 операторов, 2312 не покрыто, 1880 ветвей) |
| `pytest --cov=.` — полный прогон, как в CI | весь `source/` | **69 %** (12754 оператора, 3320 не покрыто, 2790 ветвей) |
| `pytest -m "not integration" --cov=.` — офлайн-пол | весь `source/` | **67 %** (12754 оператора, 3593 не покрыто, 2790 ветвей) |

Порог `fail_under = 65` задан для области CI — всего `source/`. Он не про узкие
области: команда `pytest --cov=fetchers --cov=utils` показывает 55 % и порог не
проходит, потому что два пакета и дерево — разные знаменатели. Такой прогон —
иллюстрация того, что покрытие зависит от области, а не гейт.

Ниже порога CI падает: `fail_under = 65` в `[tool.coverage]`, и это число взято
из офлайн-пола (67,5 % — прогон без 30 сетевых тестов и без покрытия, которое
дают только они), округлённого вниз. Запас в 2,5 процентных пункта — это около
320 операторов. Офлайн-пол — замер на машине разработки (Windows): раннер работает
на Linux и выполняет другие стороны веток `sys.platform` в
`utils/download_xray.py`, `utils/xray_batch.py` и `utils/xray_tester.py`, так что
число раннера ещё ни разу не наблюдалось. Оно будет записано здесь, когда CI
впервые пройдёт успешно; до этого порог остаётся оценкой на основе Windows-замера
и не двигается — сдвигать его сейчас значило бы калиброваться по неизмеренному.

Любая команда с покрытием несёт `--cov-config=../pyproject.toml`, включая шаг CI.
pytest-cov по умолчанию ищет `.coveragerc` в каталоге запуска (`source/`), а не
в корне репозитория, поэтому без флага `[tool.coverage]` не читается: режим
ветвей и порог молча пропадают, и отчёт остаётся просто отчётом.

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

В CI `mypy` — блокирующий гейт по **всему дереву** (`Type check` в
`.github/workflows/ci.yml`): ошибка в любом модуле валит шаг. Раньше здесь стоял
список модулей, и он слабее по устройству: список покрывает файлы, которые в нём
перечислены, и не видит модуль, которого в списке нет.

Храповик существовал, чтобы вывезти остаток ошибок, — остатка больше нет (0
ошибок по дереву), поэтому гейт проверяет дерево целиком. Доказательство
воспроизводимо: на ревизии `60a69368`, с которой начиналась вычистка, список из
27 модулей завершался успешно (`Success: no issues found in 27 source files`) в
тот момент, когда `mypy .` находил **87 ошибок в 22 файлах**.

`strict`, `disallow_untyped_defs` и `check_untyped_defs` намеренно не включены:
каждый из них умножает число ошибок, а не выявляет новые дефекты, поэтому
строгость включается поэтапно. Находки `name-defined`, стоявшие среди остатка,
оказались реальными дефектами и исправлены. Число ошибок и файлов меняется от
карточки к карточке — измеряйте его командой выше, а не переносите цифру из
документа.

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
