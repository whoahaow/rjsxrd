# Установка и запуск генератора

## Требования

- Python 3.8+
- Git (для `--use-git`)
- (Опционально) Xray-core — скачивается автоматически

## Установка

```bash
git clone https://github.com/whoahaow/rjsxrd
cd rjsxrd/source
python -m pip install -r requirements.txt
```

## Базовая конфигурация

Настройки задаются через `.env` файл в корне проекта. Скопируйте шаблон и заполните:

```bash
cp .env.example ../.env   # .env в корне проекта
nano ../.env              # укажите GITHUB_TOKEN и REPO_NAME
```

### Основные переменные

| Переменная | Обязательная | Описание |
|------------|-------------|----------|
| `GITHUB_TOKEN` | да | GitHub Personal Access Token (доступ repo) |
| `REPO_NAME` | да | Репозиторий в формате `owner/repo` |
| `TELEGRAM_BOT_TOKEN` | нет | Токен бота для уведомлений |
| `TELEGRAM_CHAT_ID` | нет | ID чата для уведомлений |

## Запуск

```bash
python main.py
```

Конфиги появятся в `../githubmirror/`.

**Локальное тестирование без загрузки:**

```bash
python main.py --dry-run
```

**Для VPS (cron, основной):**

```bash
python main.py --use-git --no-proxy-check
```

**Для GitHub Actions (резервный):**

```bash
python main.py --use-git
```

## Развёртывание на VPS

Для ежечасного обновления конфигов используется VPS со скриптом `source/scripts/setup-vps.sh`:

1. Запустите скрипт setup-vps.sh на чистой Ubuntu/Debian VPS
2. Скрипт установит Python, зависимости, Xray-core и настроит cron
3. Cron-запуск: `python main.py --use-git --no-proxy-check` каждый час

**Примечание:** GitHub Actions используется как резервный канал (каждые 2 дня). Основной pipeline работает на VPS.

**Ссылки по теме:**
- [GitHub Actions limits](https://docs.github.com/en/actions/reference/limits) — бесплатный лимит 2000 минут/месяц
- [GitHub Acceptable Use Policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies) — Actions предназначены для CI/CD, а не для постоянного хостинга задач
- [Scheduled workflows disablement](https://stackoverflow.com/questions/67184368/prevent-scheduled-github-actions-from-becoming-disabled) — GitHub отключает scheduled workflows после 60 дней без активности в репозитории

## Проверка здоровья

Перед запуском генератор выполняет 5 проверок через `health_check.py`:

| Проверка | Что проверяет | Критичность |
|----------|---------------|-------------|
| интернет | TCP-соединение с DNS-серверами (1.1.1.1, 8.8.8.8, 77.88.8.8 и др., таймаут 2 с каждый) | 🟡 предупреждение |
| дисковое пространство | `shutil.disk_usage` — минимум 100 MB свободно | 🟡 предупреждение |
| память | `psutil.virtual_memory` — минимум 256 MB | 🟡 предупреждение |
| Xray-core | существует ли бинарник, исполняемый ли | 🟡 предупреждение |
| GitHub-токен | не пустой, длиннее 10 символов | 🟡 предупреждение |

Проверка интернета не блокирует запуск — при её неудаче генератор продолжает работу с предупреждением.

При `--tcp-ping` или `--skip-xray` генератор не требует Xray-core.

## Источники конфигов

Основной список URL находится в `source/config/URLS.txt`. Файл парсится функцией `parse_urls_file()` — секции определяются по маркерам `#`:

| Секция | Маркер | Назначение |
|--------|--------|------------|
| `# default` | `# yaml` / `# telegram` / `# extra_bypass` не найдены | Основные источники |
| `# extra_bypass` | `extra` или `bypass` в строке | Дополнительные для bypass-наборов |
| `# yaml` | `yaml` в строке | Clash/Surge — конвертируются через `yaml_converter.py` |
| `# telegram` | `telegram` или `tg` в строке | Источники Telegram-прокси |

**Autodetect base64:** каждый URL проверяется на base64-кодировку. Эвристики: соотношение newline (<10%), отсутствие `://`, соотношение пробелов (<5%), состав символов (только A-Za-z0-9+/=).

Чтобы добавить источник, просто поместите URL под соответствующим заголовком. Мёртвые URL удаляются автоматически после 3 последовательных ошибок загрузки (через `URLStats`).

## Зависимости

**Основные:**

| Пакет | Назначение |
|-------|------------|
| `curl_cffi` | HTTP-клиент с TLS-фingerprint (в 2-3x быстрее requests) |
| `PyGithub` | GitHub API |
| `PyYAML` | Парсинг Clash/Surge YAML |
| `requests[socks]` | HTTP через прокси (резервный) |
| `tqdm` | Прогресс-бары |
| `psutil` | Управление процессами Xray |

**Опционально:**

| Пакет | Назначение |
|-------|------------|
| `aiodns` | Асинхронный DNS (ускорение верификации) |
| `dnspython` | DNS-утилиты |

**Для разработки:**

```
pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock
```
