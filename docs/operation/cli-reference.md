# CLI-справочник

## Синтаксис

```bash
python main.py [OPTIONS]
```

## Флаги

### Режимы выполнения

| Флаг | Описание |
|------|----------|
| `--dry-run` | Скачать и обработать конфиги локально, без загрузки в GitHub |
| `--use-git` | Использовать git-команды вместо GitHub API (для GitHub Actions) |

### Управление выходными файлами (feature flags)

Эти флаги переопределяют значения из `config/settings.py` для одного запуска (не изменяя файл):

| Флаг | Описание |
|------|----------|
| `--enable-default-files` | Генерировать default/ (1.txt, all.txt, all-secure.txt) |
| `--disable-default-files` | Пропустить генерацию default/ |
| `--enable-bypass-unsecure` | Генерировать bypass-unsecure/ |
| `--disable-bypass-unsecure` | Пропустить bypass-unsecure/ |
| `--enable-protocol-split` | Генерировать split-by-protocols/ |
| `--disable-protocol-split` | Пропустить split-by-protocols/ |
| `--enable-tg-proxy` | Генерировать tg-proxy/ |
| `--disable-tg-proxy` | Пропустить tg-proxy/ |
| `--publish-raw-files` | Загружать /raw/ подпапки |
| `--no-publish-raw-files` | Не загружать /raw/ подпапки |

### Режимы верификации

| Флаг | Описание |
|------|----------|
| _(без флага)_ | Xray-core: запуск отдельного процесса Xray на каждый конфиг, HTTP-тест через SOCKS5. Максимальная точность. |
| `--tcp-ping` | TCP-пинг: быстрое тестирование через TCP-соединение к host:port. В 10-20x быстрее Xray. Неявно включает `--skip-xray`. |
| `--skip-xray` | Пропуск верификации — только raw-файлы без проверки |
| `--batch-mode` | Batch-режим: один Xray на N конфигов (shared Xray, меньше RAM). Переопределяет XRAY_BATCH_MODE. |
| `--single-mode` | Single-режим: один Xray на конфиг (больше изоляции). Переопределяет XRAY_BATCH_MODE. |

**Сравнение режимов верификации:**

| Режим | Точность | Время (на ~700 конфигов) | Зависимости |
|-------|----------|--------------------------|-------------|
| Xray-core (по умолчанию) | Высокая | 60-120 с | Xray-core бинарник |
| `--tcp-ping` | Средняя | ~5 с | Нет |
| `--skip-xray` | Нет | 0 с | Нет |

### Прокси

| Флаг | Описание |
|------|----------|
| `--proxy=<URL>` | Одиночный прокси для всего генератора. Формат: `vless://`, `socks5://` и т.д. |
| `--proxy-chain=<URL1,URL2,URL3>` | Цепочка прокси (минимум 2). Через запятую, без пробелов. |
| `--no-proxy-check` | Отключить детекцию и проверку прокси. |

### Отладка

| Флаг | Описание |
|------|----------|
| `--verbose` | Подробный лог: показывает пропущенные конфиги, детали фильтрации |

## Примеры

```bash
# Локальное тестирование
python main.py --dry-run

# Быстрая проверка без Xray
python main.py --tcp-ping --dry-run

# Полный запуск с загрузкой
python main.py --use-git

# Через собственный прокси
python main.py --proxy="vless://uuid@host:443?security=tls&..."

# Цепочка из двух прокси
python main.py --proxy-chain="vless://hop1@a.com:443,vless://hop2@b.com:443"

# Без прокси, подробный лог
python main.py --dry-run --no-proxy-check --verbose
```

## Переменные окружения

Все переменные можно задать через `.env` файл в корне проекта (см. `.env.example`).

| Переменная | По умолч. | Описание |
|------------|-----------|----------|
| `GITHUB_TOKEN` | — | GitHub-токен с доступом repo (из `.env`) |
| `REPO_NAME` | whoahaow/rjsxrd | Репозиторий для загрузки (из `.env`) |
| `TELEGRAM_BOT_TOKEN` | — | Токен бота для уведомлений (из `.env`) |
| `MAX_WORKERS` | 50 | Количество потоков для загрузок |
| `FETCH_TIMEOUT` | 5 | Таймаут HTTP запроса (с) |
| `FETCH_MAX_ATTEMPTS` | 2 | Количество попыток загрузки URL |
| `VALIDATION_TCP_CONCURRENCY` | 100 | Параллельность TCP-пинга |
| `VALIDATION_HTTP_CONCURRENCY` | 20 | Параллельность HTTP-проверок |
| `VALIDATION_MAX_WORKERS` | 200 | Максимум потоков верификации |
| `ASYNC_CONCURRENCY_WIN32` | 50 | Параллельность Xray на Windows |
| `ASYNC_CONCURRENCY_LINUX` | 300 | Параллельность Xray на Linux |
| `VALIDATION_TCP_TIMEOUT` | 3 | Таймаут TCP-соединения (с) |
| `VALIDATION_HTTP_TIMEOUT` | 5 | Таймаут HTTP-запроса (с) |
| `XRAY_BATCH_MODE` | single | Режим тестирования: single или batch |
| `XRAY_BATCH_SIZE` | 100 | Конфигов на один Xray в batch-режиме |
| `XRAY_BATCH_PROCESSES` | 10 | Параллельных Xray процессов в batch-режиме |
| `XRAY_BATCH_STARTUP_DELAY_MS` | 200 | Задержка перед пингом после старта Xray (мс) |
| `XRAY_BATCH_PORT_RANGE_SIZE` | 300 | Диапазон портов на chunk в batch-режиме |
