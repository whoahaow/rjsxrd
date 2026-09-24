> **Language:** [Русский](development-environment.md) · [English](development-environment.en.md)

# Окружение для разработки

Как развернуть репозиторий для работы над кодом и прогнать проверки. Установщик один — `uv`: команды с bare `pip` не используются ни в документации, ни в CI, ни в cron на VPS.

## Требования

- [uv](https://docs.astral.sh/uv/) — интерпретатор Python uv скачивает и версионирует сам, системный Python не нужен
- Git

## Создание окружения

```bash
uv venv --python 3.12 .venv
```

## Установка зависимостей

Файлов два: `source/requirements.txt` — рантайм-зависимости (их ставит VPS и GitHub Actions), `source/requirements-dev.txt` — линтеры и тестовый тулчейн; он подключает рантайм-файл первой строкой.

```bash
uv pip install --python .venv/Scripts/python.exe -r source/requirements-dev.txt
```

Путь к интерпретатору зависит от ОС: `.venv/Scripts/python.exe` — Windows, `.venv/bin/python` — Linux и macOS.

## Проверки перед коммитом

```bash
# тесты — из каталога source/
cd source && ../.venv/Scripts/python.exe -m pytest -q

# линтер — из корня репозитория
./.venv/Scripts/python.exe -m ruff check .
```

Полный прогон — 1017 тестов, около 70–80 секунд на машине разработки (Windows, Python 3.12). Структура набора и сценарии проверки описаны в [Тестировании](testing.md).

## Зафиксированные версии

`source/requirements.lock` — lock рантайм-зависимостей с хешами. Пересобрать его после правки `source/requirements.txt`:

```bash
uv pip compile source/requirements.txt --generate-hashes --python-version 3.12 --python-platform windows -o source/requirements.lock
```
