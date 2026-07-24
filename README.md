# rjsxrd - Автоматически обновляемые VPN-конфиги

tgc: [t.me/rjsxrd](https://t.me/rjsxrd)

---

Если вы хотите поддержать меня, то вот мои крипто-кошельки:

SOL: `DcvcsapMBqbLdA2GRhGQXPq5F74AkLQ4eh8yyTxEtsVj`

USDT (TRC20): `TTgMgXWZKFpzqXL7mPfchvjovMHKaGyea4`

BTC: `bc1q8s5snc95w3696taw5du9gnz6uf33wjz3yrq5e6`

ETH: `0x17D7206EBfba1F0b6b65E99ACbd294827D9A79B1`

---

Автоматически обновляемая коллекция публичных VPN-конфигов (`V2Ray` / `VLESS` / `Trojan` / `VMess` / `Reality` / `Shadowsocks` / `ShadowsocksR` / `Hysteria` / `Hysteria2` / `TUIC`) для быстрого обхода блокировок. Обход белых списков на мобильном интернете.

Каждый конфиг — это TXT-подписка, которую можно импортировать практически в любой современный клиент (`v2rayNG`, `NekoRay`, `Throne`, `v2rayN`, `V2Box`, `v2RayTun`, `Hiddify` и др.).

Конфиги обновляются **каждый час** с VPS (основной канал) и **раз в 2 дня** через GitHub Actions (резервный).

## Особенности
- Автоматическая фильтрация и дедупликация конфигов
- Разделение больших файлов для лучшей производительности (максимум 300 конфигов на файл)
- Поддержка различных типов протоколов (V2Ray, VLESS, Trojan, VMess, и др.)
- Поддержка обработки base64-кодированных подписок с фильтрацией по доменным именам
- **Улучшенная фильтрация безопасности**: комплексная проверка insecure параметров для повышения безопасности
  - **VMess**: проверка `insecure`, `allowInsecure`, `security=none`, `alterId > 0` + валидация TLS SNI
  - **VLESS**: проверка `allowInsecure`, `insecure`, `security=none`, `encryption=none` + валидация Reality publicKey
  - **Trojan**: проверка `allowInsecure`, `insecure` + валидация Reality publicKey/SNI
  - **Shadowsocks**: проверка слабых шифров (RC4, DES, CFB, Salsa20, Chacha20 non-IETF) + отвергаются пустые пароли
  - **ShadowsocksR**: проверка слабых шифров + конвертация в Shadowsocks + отвергаются пустые пароли
  - **Hysteria2**: валидация TLS SNI
  - **Hysteria v1**: предупреждение при `insecure=1`
  - **TUIC**: не поддерживается Xray-core (возвращает `None`)
  - **Общие**: проверка `verify=0`, `verify=false`, `insecure=1`
- Специальные конфиги для обхода SNI/CIDR белых списков
- Небезопасные конфиги для обхода SNI/CIDR
- Конфиги, разделенные по протоколам
- Создание файлов all.txt и all-secure.txt
- **Автоматическая верификация конфигов**: тестирование через Xray-core с сортировкой по скорости (fastest first), либо быстрая TCP верификация через `--tcp-ping`
- **Двухуровневая система верификации**:
  - **Raw файлы**: нетестированные конфиги в `/raw/` подпапках
  - **Верифицированные файлы**: протестированы через Xray-core, отсортированы по пингу
- **Telegram прокси**: автоматический сбор, верификация и обработка MTProto и SOCKS5 прокси для Telegram с сортировкой по пингу
- **Прокси цепочки**: поддержка цепочек прокси (--proxy-chain) для многоуровневого маршрутизирования
- **Прогресс-бары**: стабильные индикаторы прогресса при верификации конфигов и Telegram прокси с умным ETA (скользящее окно + timeout floor) и скоростью обработки
- **URL Health Report**: автоматический сбор статистики по каждому URL-источнику — количество конфигов, результаты верификации, мёртвые URL
- **Авто-очистка мёртвых URL**: URL с 3+ последовательными неудачными загрузками автоматически удаляются из URLS.txt
- **Авто-очистка мёртвых конфигов**: конфиги из servers.txt с 3+ последовательными провалами верификации автоматически удаляются
- Улучшенная валидация конфигов: теперь учитываются только строки, начинающиеся с поддерживаемого протокола (vless://, vmess://, trojan:// и др.) для предотвращения включения неподходящих строк в итоговые файлы
- Поддержка ежедневно обновляемых репозиториев с автоматическим поиском конфигов по дате
- Поддержка YAML-конфигов с конвертацией в формат VPN URL
- **Ручное добавление конфигов**: возможность добавлять собственные серверы через файл `source/config/servers.txt`, которые будут автоматически фильтроваться и объединяться с другими источниками
- Параллельные загрузки для ускорения процесса
- Потокобезопасное логирование с сортировкой сообщений по файлам
- Улучшенная архитектура с четким разделением ответственности между модулями

## Документация

Полная документация — **[docs/readme.md](docs/readme.md)**. Быстрый переход:

| Раздел | Описание |
|--------|----------|
| [Быстрый старт](docs/quickstart.md) | 2 шага до подключения |
| [Генерируемые файлы](docs/user/config-files.md) | Папки, типы, формат файлов |
| [Импорт в клиенты](docs/user/import-guide.md) | Android, iOS, Windows, macOS |
| [Свои серверы](docs/user/custom-servers.md) | Добавление VPN и Telegram-прокси |
| [Установка генератора](docs/operation/installation.md) | Запуск, health check, источники |
| [Архитектура](docs/development/architecture.md) | Модули, пайплайн, сигналы |
| [Безопасность](docs/development/security-system.md) | Фильтрация, SNI/CIDR, верификация |
| [FAQ](docs/faq.md) | Частые вопросы |

## Содержание
- [Особенности](#особенности)
- [Документация](#документация)
- [Видео гайд](#видео-гайд)
- [Конфигурации](#конфигурации)
- [Установка и использование](#установка-и-использование)
- [Дополнительно](#дополнительно)

## Быстрый старт

1. Скопируйте нужную ссылку из раздела [Конфигурации](#конфигурации) (bypass/bypass-all.txt)
2. Импортируйте её в ваш **VPN-клиент**
3. Выберите сервер с минимальным пингом и подключайтесь

---

## Видео гайд

> **Внимание!** Видео гайд актуален только для Android, Android TV, Windows, Linux, MacOS. Для iOS и iPadOS используйте текстовые инструкции ниже.

[Смотреть на YouTube](https://youtu.be/sagz2YluM70)

[Смотреть на Dzen](https://dzen.ru/video/watch/680d58f28c6d3504e953bd6d)

[Смотреть на VK Video](https://vk.com/video-200297343_456239303)

[Смотреть в Telegram](https://t.me/avencoreschat/56595)

---

## Конфигурации

### Конфиги для обхода SNI/CIDR белых списков (bypass/)

> **Для пользователей мобильных устройств**: при возникновении проблем с производительностью рекомендуется использовать файлы по отдельности, а не bypass-all.txt

**[bypass-all](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt)** - все безопасные конфиги для обхода SNI/CIDR в одном файле

Ссылка для обновления при бс: **[bypass-all](https://translate.yandex.ru/translate?url=https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt&lang=en-en)**. Если конфиги ломаются, то открыть ссылку в браузере, скопировать все конфиги и вставить в клиент.

**Файлы разделенные по 300 конфигов**:
- **[bypass-1](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-1.txt)**
- **[bypass-2](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-2.txt)**
- **[bypass-3](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-3.txt)**
- **[bypass-4](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-4.txt)**
- **[bypass-5](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-5.txt)**
- **[bypass-6](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-6.txt)**
- **[bypass-7](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-7.txt)**
- **[bypass-8](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-8.txt)**
- **[bypass-9](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-9.txt)**
- **[bypass-10](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-10.txt)**
- **[bypass-11](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-11.txt)**
- **[bypass-12](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-12.txt)**
- **[bypass-13](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-13.txt)**
- **[bypass-14](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-14.txt)**
- **[bypass-15](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-15.txt)**

### Небезопасные конфиги для обхода SNI/CIDR (bypass-unsecure/)

**[bypass-unsecure-all](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt)** - все конфиги для обхода SNI/CIDR в одном файле (включая небезопасные)

**Файлы разделенные по 300 конфигов**:
- **[bypass-unsecure-1](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-1.txt)**
- **[bypass-unsecure-2](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-2.txt)**
- **[bypass-unsecure-3](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-3.txt)**
- **[bypass-unsecure-4](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-4.txt)**
- **[bypass-unsecure-5](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-5.txt)**
- **[bypass-unsecure-6](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-6.txt)**
- **[bypass-unsecure-7](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-7.txt)**
- **[bypass-unsecure-8](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-8.txt)**
- **[bypass-unsecure-9](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-9.txt)**
- **[bypass-unsecure-10](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-10.txt)**
- **[bypass-unsecure-11](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-11.txt)**
- **[bypass-unsecure-12](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-12.txt)**
- **[bypass-unsecure-13](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-13.txt)**
- **[bypass-unsecure-14](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-14.txt)**
- **[bypass-unsecure-15](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-15.txt)**
- **[bypass-unsecure-16](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-16.txt)**

### Обычные конфиги (default/)
Обычные конфиги для обхода стандартных блокировок.
- **[1](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/1.txt)**
- **[6](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/6.txt)**
- **[22](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/22.txt)**
- **[23](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/23.txt)**
- **[24](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/24.txt)**
- **[25](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/25.txt)**

#### Дополнительные файлы в default/
- **[all.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all.txt)** - все уникальные конфиги из папки default в одном файле
- **[all-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure.txt)** - все безопасные (без insecure параметров) уникальные конфиги из папки default в одном файле

### Конфиги, разделенные по протоколам (split-by-protocols/)

**Безопасные протокол-специфичные файлы**:
- **[vless-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless-secure.txt)** - только безопасные VLESS конфиги
- **[vmess-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vmess-secure.txt)** - только безопасные VMess конфиги
- **[trojan-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/trojan-secure.txt)** - только безопасные Trojan конфиги
- **[ss-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ss-secure.txt)** - только безопасные Shadowsocks конфиги
- **[ssr-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ssr-secure.txt)** - только безопасные ShadowsocksR конфиги
- **[tuic-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic-secure.txt)** - только безопасные TUIC конфиги
- **[hysteria-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria-secure.txt)** - только безопасные Hysteria конфиги
- **[hysteria2-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria2-secure.txt)** - только безопасные Hysteria2 конфиги
- **[hy2-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hy2-secure.txt)** - только безопасные Hysteria2 (hy2) конфиги

**Все протокол-специфичные файлы (включая небезопасные)**:
- **[vless.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless.txt)** - все VLESS конфиги
- **[vmess.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vmess.txt)** - все VMess конфиги
- **[trojan.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/trojan.txt)** - все Trojan конфиги
- **[ss.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ss.txt)** - все Shadowsocks конфиги
- **[ssr.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ssr.txt)** - все ShadowsocksR конфиги
- **[tuic.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic.txt)** - все TUIC конфиги
- **[hysteria.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria.txt)** - все Hysteria конфиги
- **[hysteria2.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria2.txt)** - все Hysteria2 конфиги
- **[hy2.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hy2.txt)** - все Hysteria2 (hy2) конфиги

### Telegram прокси (tg-proxy/)

**Файлы с Telegram прокси для обхода блокировок мессенджера**:
- **[all.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/all.txt)** - все Telegram прокси (MTProto + SOCKS5, отсортированы по пингу)
- **[MTProto.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/MTProto.txt)** - только MTProto прокси
- **[socks.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/socks.txt)** - только SOCKS5 прокси

[Ссылка на QR-коды конфигов](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes)


---
## Установка и использование

<details>

<summary>Гайд для Android</summary>

**1.** Скачиваем **«v2rayNG»** universal.apk - [Ссылка](https://github.com/2dust/v2rayNG/releases)

Можно использовать **«Happ»** - [Ссылка](https://play.google.com/store/apps/details?id=com.happproxy&hl=ru), но в настройках: Подписки -> сортировать по пингу

**2.** Копируем в буфер обмена ссылку на конфиг из раздела [Конфигурации](#конфигурации)

**3.** Заходим в приложение **«v2rayNG»** и в правом верхнем углу нажимаем на +, а затем выбираем **«Импорт из буфера обмена»**.

**4.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверка профилей группы»**, после окончания проверки в этом же меню нажмите на **«Сортировка по результатам теста»**.

**5.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

</details>

<details>

<summary>Гайд для Android TV</summary>

**1.** Скачиваем **«v2rayNG»** universal.apk - [Ссылка](https://github.com/2dust/v2rayNG/releases)

**2.** Скачиваем **«QR-коды»** вечно актуальных конфигов - [Ссылка](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes)

**3**. Заходим в приложение **«v2rayNG»** и в правом верхнем углу нажимаем на +, а затем выбираем **«Импорт из QR-кода»**, выбираем картинку нажав на иконку фото в правом верхнем углу.

**4.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверка профилей группы»**, после окончания проверки в этом же меню нажмите на **«Сортировка по результатам теста»**.

**5.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

</details>

<details>

<summary>Дополнительные решения проблем</summary>

**Если нету интернета при подключении к VPN в v2rayNG**

Ссылка на видео с демонстрацией фикса - [Ссылка](https://t.me/avencoreschat/25254)

**Если не появились конфиги при добавлении VPN в v2rayNG**

1. Нажмите на **«три полоски»** в **«левом верхнем углу»**.
2. Нажимаем на кнопку **«Группы»**.
3. Нажимаем на **«иконку кружка со стрелкой»** в **«верхнем правом углу»** и дожидаемся окончания обновления.

**Фикс ошибки "Cбой проверки интернет-соединения: net/http: 12X handshake timeout"**

1. На рабочем столе зажимаем на иконке **«v2rayNG»** и нажимаем на пункт **«О приложении»**.
2. Нажимаем на кнопку **«Остановить»** и заново запускаем **«v2rayNG»**.

**Фикс ошибки "Fail to detect internet connection: io: read/write closed pipe"**

1. На рабочем столе зажимаем на иконке **«v2rayNG»** и нажимаем на пункт **«О приложении»**.
2. Нажимаем на кнопку **«Остановить»** и заново запускаем **«v2rayNG»**.
3. Нажимаем **«справа сверху на три точки»**, а затем **«Проверка профилей группы»**, после окончания проверки в этом же меню нажмите на **«Сортировка по результатам теста»**.
4. Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

**Обновление конфигов в v2rayNG**

1. Нажимаем на **«иконку трех полосок»** в **«левом верхнем углу»**.
2. Выбираем вкладку **«Группы»**.
3. Нажимаем на **«иконку кружка со стрелкой»** в **«правом верхнем углу»**.

</details>


---
<details>

<summary>Гайд для Windows, Linux</summary>

**1.** Скачиваем **«v2rayN»** - [Ссылка](https://github.com/2dust/v2rayN/releases)

Можно использовать **«nekoray»** - [Ссылка](https://github.com/MatsuriDayo/nekoray/releases)

Можно использовать **«Throne»** - [Ссылка](https://github.com/throneproj/Throne/releases)

**2.** Копируем в буфер обмена ссылку на конфиг из раздела [Конфигурации](#конфигурации)

**3.** Нажимаем на **«Профили»**, а затем **«Добавить профиль из буфера обмена»**.

**4.** Выделяем все конфиги комбинацией клавиш **«Ctrl + A»**, нажимаем **«Профили»** в верхнем меню, а затем **«Тест задержки (пинга) выбранного профиля»** и дожидаемся окончания теста (во вкладке **«Логи»** появится надпись **«Тест задержек (пинга) завершён!»**)

**5.** Наживаем на кнопку колонки **«Задержка (пинг)»**.

**6.** В верхней части окна программы активируйте опцию **«Режим TUN»**, установив галочку.

**7.** Выбираем один из конфигов с наименьшим **«Задержка (пинг)»**, а затем нажимаем **«ЛКМ»** и **«Запустить»**.

</details>

<details>

<summary>Дополнительные руководства для Windows</summary>

**Исправляем ошибку MSVCP и VCRUNTIME на Windows 10/11**

1. Нажимаем **«Win+R»** и пишем **«control»**.
2. Выбираем **«Программы и компоненты»**.
3. В поиск (справа сверху) пишем слово **«Visual»** и удалям все что касается **«Microsoft Visual»**.
4. Скачиваем архив и распаковываем - [Ссылка](https://cf.comss.org/download/Visual-C-Runtimes-All-in-One-Jul-2025.zip)
5. Запускаем от *имени Администратора* **«install_bat.all»** и ждем пока все установиться.

**Обновление конфигов в NekoRay**

1. Нажимаем на кнопку **«Настройки»**.
2. Выбираем **«Группы»**.
3. Нажимаем на кнопку **«Обновить все подписки»**.

</details>


---
<details>

<summary>Гайд для iOS, iPadOS</summary>

**1.** Скачиваем **«V2Box - V2ray Client»** - [Ссылка](https://apps.apple.com/ru/app/v2box-v2ray-client/id6446814690)

Можно использовать **«Happ»** - [Ссылка](https://apps.apple.com/us/app/happ-proxy-utility/id6504287215), в настройках: Подписки -> сортировать по пингу

**2.** Копируем в буфер обмена ссылку на конфиг из раздела [Конфигурации](#конфигурации)

**3.** Заходим в приложение **«V2Box - V2ray Client»** и переходим во вкладку **«Config»**, нажимаем на плюсик в правом верхнем углу, затем - **«Добавить подписку»**, вводим любое **«Название»** и вставляем ссылку на конфиг в поле **«URL»**.

**4.** После добавления конфига дожидаемся окончания проверки и выбираем нужный, просто нажав на его название.

**5.** В нижней панели программы нажимаем кнопку **«Подключиться»**.

</details>

<details>

<summary>Обновление конфигов в V2Box - V2ray Client</summary>

**1.** Переходим во вкладку **«Config»**.

**2.** Нажимаем на иконку обновления слева от названия группы подписки.

</details>


---
<details>

<summary>Гайд для MacOS</summary>

**1.** Скачиваем **«Hiddify»** - [Ссылка](https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-MacOS.dmg)

Можно использовать **«v2rayN»** - [Ссылка](https://github.com/2dust/v2rayN/releases)

**2.** Нажимаем **«Новый профиль»**.

**3.** Копируем в буфер обмена ссылку на конфиг из раздела [Конфигурации](#конфигурации)

**4.** Нажимаем на кнопку **«Добавить из буфера обмена»**.

**5.** Перейдите в **«Настройки»**, измените **«Вариант маршрутизации»** на **«Индонезия»**.

**6.** Нажмите в левом верхнем меню на иконку настроек и выберите **«VPN сервис»**.

**7.** Включаем **«VPN»** нажав на иконку по середине.

**8.** Для смены сервера включите **«VPN»** и перейдите во вкладку **«Прокси»**.

</details>

<details>

<summary>Обновление конфигов в Hiddify</summary>

**1.** Заходим в приложение **«Hiddify»** и выбираем нужный вам профиль.

**2.** Нажимаем **«слева от названия профиля на иконку обновления»**.

</details>

---

## Дополнительно

### Структура репозитория
```text
githubmirror/         - сгенерированные .txt файлы конфигов
 ├─ default/          - основные конфиги (1.txt, 2.txt, ..., all.txt, all-secure.txt)
 ├─ bypass/           - безопасные конфиги для обхода SNI/CIDR
 │   ├─ raw/          - нетестированные конфиги (перед верификацией)
 │   └─ bypass-all.txt, bypass-1.txt, ... (протестированы, отсортированы по пингу)
 ├─ bypass-unsecure/  - все конфиги для обхода SNI/CIDR (включая небезопасные)
 │   ├─ raw/          - нетестированные конфиги (перед верификацией)
 │   └─ bypass-unsecure-all.txt, bypass-unsecure-1.txt, ...
 ├─ split-by-protocols/ - протокол-специфичные файлы (vless.txt, vmess.txt, ...)
 ├─ tg-proxy/         - Telegram прокси (all.txt, MTProto.txt, socks.txt)
qr-codes/             - PNG-версии конфигов для импорта по QR
source/               - исходный код генератора
 ├─ __init__.py
 ├─ main.py           - основная точка входа в приложение
 ├─ config/           - настройки и конфигурационные параметры
 │   ├─ __init__.py
 │   ├─ settings.py   - глобальные настройки, токены, URL-источники, часовые пояса
 │   ├─ URLS.txt      - список URL для основных конфигов
 │   ├─ servers.txt   - список ручных серверов для добавления в конфигурации
 │   ├─ tg_proxies.txt - список ручных Telegram прокси
 │   ├─ whitelist-all.txt - список доменов для SNI фильтрации
 │   └─ cidrwhitelist.txt - список CIDR для IP фильтрации
 ├─ data/             - постоянная статистика URL (gitignored, накапливается между запусками)
 ├─ fetchers/         - модули для загрузки конфигов из внешних источников
 │   ├─ __init__.py
 │   ├─ fetcher.py    - базовый загрузчик конфигов с curl_cffi
 │   ├─ daily_repo_fetcher.py - загрузка из ежедневно обновляемого репозитория
 │   ├─ telegram_proxy_scraper.py - скрапер Telegram прокси (MTProto и SOCKS5)
 │   ├─ yaml_converter.py - конвертер YAML-конфигов (Clash/Surge) в VPN URL
 │   ├─ sstap_scraper.py - скрапинг sstap.org/node-real-time-update/
 │   └─ upstream_aggregator.py - агрегатор yudou226.top + guidongone
 ├─ processors/       - основная обработка и фильтрация конфигов
 │   ├─ __init__.py
 │   ├─ config_processor.py - ConfigPipeline — оркестратор пайплайна
 │   └─ telegram_proxy_processor.py - обработчик Telegram прокси
 ├─ scripts/          - служебные скрипты
 │   ├─ analyze_url_stats.py - анализ статистики URL
 │   ├─ benchmark_configs.py - бенчмарк конфигов (--mode xray|tcp)
 │   ├─ purge_dead_urls.py - очистка URLS.txt от нерабочих ссылок
 │   ├─ purge_stale_urls.py - очистка по git timestamp
 │   ├─ setup-vps.sh   - скрипт развёртывания на VPS
 │   └─ test_telegram_proxies.py - тестирование Telegram прокси
 ├─ tests/            - unit-тесты (640+ тестов, 25 файлов)
 │   ├─ __init__.py
 │   ├─ conftest.py   - фикстуры и конфигурация pytest
 │   ├─ README.md     - документация по тестам
 │   ├─ test_config_processor.py
 │   ├─ test_config_tagger.py
 │   ├─ test_executor_cache.py
 │   ├─ test_fetcher.py
 │   ├─ test_file_utils.py
 │   ├─ test_git_auto_cleaner.py
 │   ├─ test_git_updater.py
 │   ├─ test_github_handler.py
 │   ├─ test_health_check.py
 │   ├─ test_ip_checker.py
 │   ├─ test_ip_verifier.py
 │   ├─ test_logger.py
 │   ├─ test_managed_process.py
 │   ├─ test_process_registry.py
 │   ├─ test_progress.py
 │   ├─ test_proxy_monitor.py
 │   ├─ test_security_filter.py
 │   ├─ test_simple_tester.py
 │   ├─ test_smart_eta.py
 │   ├─ test_telegram_proxy_scraper.py
 │   ├─ test_telegram_proxy_verifier.py
 │   ├─ test_url_stats.py
 │   ├─ test_vpn_config.py
 │   ├─ test_xray_batch.py
 │   ├─ test_xray_tester.py
 │   └─ test_yaml_converter.py
 ├─ utils/            - вспомогательные функции и утилиты
 │   ├─ __init__.py
 │   ├─ _sni_worker.py - SNI/CIDR worker (внутренний)
 │   ├─ bypass_builder.py - сборщик bypass-конфигов
 │   ├─ config_helpers.py - хэлперы пайплайна
 │   ├─ config_tagger.py - ConfigTagger (source+protocol)
 │   ├─ curl_import.py - условный импорт curl_cffi
 │   ├─ download_xray.py - загрузка и установка Xray-core
 │   ├─ executor_cache.py - кэш ThreadPoolExecutor с WSL-детекцией
 │   ├─ file_utils.py - I/O, SNI/CIDR, дедупликация, prepare_config_content
 │   ├─ file_writer.py - асинхронная запись результирующих файлов
 │   ├─ git_auto_cleaner.py - авто-очистка истории git
 │   ├─ git_updater.py - Git-коммиты (режим VPS cron)
 │   ├─ github_handler.py - работа с GitHub API (PyGithub)
 │   ├─ health_check.py - health check (интернет/Xray/GitHub API)
 │   ├─ ip_verifier.py - проверка IP и настройка прокси цепочек
 │   ├─ logger.py - потокобезопасное логирование
 │   ├─ managed_process.py - ManagedProcess lifecycle
 │   ├─ process_registry.py - единый реестр процессов
 │   ├─ progress.py - консолидированный tqdm импорт
 │   ├─ protocol_parsers.py - парсеры протоколов
 │   ├─ proxy_detector.py - авто-детекция активных прокси
 │   ├─ proxy_monitor.py - мониторинг здоровья прокси-цепочек
 │   ├─ psutil_available.py - единый import psutil (HAS_PSUTIL)
 │   ├─ resource_monitor.py - мониторинг CPU/RAM/сети
 │   ├─ security_filter.py - has_insecure_setting + cipher sets
 │   ├─ simple_tester.py - TCP пинг конфигов (без Xray)
 │   ├─ smart_eta.py - умный ETA для batch-тестирования
 │   ├─ system_specs.py - SystemSpecs — автодетект RAM/CPU/WSL/cgroups
 │   ├─ telegram_notifier.py - уведомления в Telegram
 │   ├─ telegram_proxy_verifier.py - верификация Telegram прокси
 │   ├─ url_stats.py - сбор статистики и авто-очистка мёртвых URL
 │   ├─ vpn_config.py - VPNConfig dataclass иерархия
 │   ├─ xray_batch.py - batch-режим тестирования (shared Xray)
 │   ├─ xray_helpers.py - вспомогательные функции Xray
 │   └─ xray_tester.py - Xray-core тестирование с сортировкой по скорости
 ├─ xray/             - Xray-core бандл (xray, geoip.dat, geosite.dat, LICENSE)
 └─ requirements.txt  - зависимости проекта
.github/workflows/    - CI/CD (авто-обновление ежедневно)
.env                  - переменные окружения (gitignored)
.env.example          - шаблон переменных окружения
pyproject.toml        - метаданные и инструменты проекта
README.md             - этот файл
LICENSE               - лицензия MIT
docs/                 - документация проекта (см. docs/readme.md)
```

---

### Локальный запуск генератора
```bash
git clone https://github.com/whoahaow/rjsxrd
cd rjsxrd
cp .env.example .env          # создайте и заполните .env своими настройками
nano .env                      # укажите GITHUB_TOKEN и REPO_NAME
cd source
python -m pip install -r requirements.txt
python main.py                 # конфиги появятся в ../githubmirror
```

> **Важно:** Скопируйте `.env.example` в `.env` и заполните `GITHUB_TOKEN` (токен с доступом repo) и `REPO_NAME` (формат `owner/repo`). Telegram-уведомления и тюнинг производительности — опционально.

#### Запуск тестов

Проект включает набор unit-тестов для проверки корректности работы основных модулей (640 тестов, 25 файлов):

```bash
cd source
pip install pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock
pytest                              # Запустить все тесты
pytest -v                           # Подробный вывод
pytest --cov=fetchers --cov=utils   # С отчетом о покрытии
pytest -m unit                      # Только быстрые unit-тесты
pytest -n auto                      # Параллельный запуск
```

Подробнее см. [`source/tests/README.md`](source/tests/README.md)

#### Режимы запуска

**Локальное тестирование без загрузки в GitHub:**
```bash
python main.py --dry-run
```

**Запуск в режиме git (рекомендуется для VPS):**
```bash
python main.py --use-git --no-proxy-check
```

**Пропустить Xray верификацию (конфиги без проверки):**
```bash
python main.py --skip-xray
```

**TCP пинг вместо Xray (быстрее, но менее точно):**
```bash
python main.py --tcp-ping
```

**Batch-режим (shared Xray, экономия RAM для тысяч конфигов):**
```bash
python main.py --batch-mode              # через CLI-флаг
XRAY_BATCH_MODE=batch python main.py     # через переменную окружения
```

**Использовать один прокси:**
```bash
python main.py --proxy="vless://uuid@host:port?..."
```

**Использовать цепочку прокси (EXPERIMENTAL):**
```bash
python main.py --proxy-chain="vless://hop1,hop2,hop3"
```

**Пропустить проверку прокси:**
```bash
python main.py --no-proxy-check
```

**Feature-флаги (переопределяют settings.py для одного запуска):**
```bash
python main.py --enable-default-files          # Генерировать default/ (1.txt, all.txt)
python main.py --disable-default-files         # Пропустить default/
python main.py --enable-bypass-unsecure        # Генерировать bypass-unsecure/
python main.py --disable-bypass-unsecure       # Пропустить bypass-unsecure/
python main.py --enable-protocol-split         # Генерировать split-by-protocols/
python main.py --disable-protocol-split        # Пропустить split-by-protocols/
python main.py --enable-tg-proxy               # Генерировать tg-proxy/
python main.py --disable-tg-proxy              # Пропустить tg-proxy/
python main.py --publish-raw-files             # Загружать /raw/ подпапки
python main.py --no-publish-raw-files          # Не загружать /raw/ подпапки
```

**Подробный лог (показывает пропущенные конфиги):**
```bash
python main.py --verbose
```

#### Зависимости

Основные зависимости:
- `curl_cffi` - быстрый HTTP клиент с TLS fingerprinting (2-3x быстрее requests)
- `PyGithub` - работа с GitHub API
- `PyYAML` - парсинг YAML конфигов (Clash/Surge)
- `requests[socks]` - HTTP запросы через прокси (fallback)
- `ahocorasick-rs` - быстрый Aho-Corasick для SNI-фильтрации
- `aiofiles` - асинхронная запись файлов
- `aiodns` - асинх DNS резолвинг (опционально, для скорости)
- `PySocks` - SOCKS прокси поддержка
- `psutil` - мониторинг ресурсов и управление процессами Xray
- `tqdm` - прогресс бары для верификации конфигов и Telegram прокси
- `pytdbot[tdjson]` - Telegram бот API

Для разработки и тестирования:
- `pytest` - фреймворк для тестирования
- `pytest-cov` - отчет о покрытии кода
- `pytest-asyncio` - поддержка async тестов
- `pytest-xdist` - параллельный запуск тестов
- `pytest-mock` - mocking утилиты

---

### Лицензия

Проект распространяется под лицензией MIT License. Полный текст лицензии содержится в файле [`LICENSE`](LICENSE).

---

### Источники и вдохновение

Основной репозиторий, который вдохновил данный проект: https://github.com/AvenCores/goida-vpn-configs

---

### ДИСКЛЕЙМЕР

> *Автор не является владельцем/разработчиком/поставщиком перечисленных VPN-конфигураций. Это независимый информационный обзор и результаты тестирования.*
>
> *Данный репозиторий не является рекламой VPN. Материал предназначен исключительно в информационных целях, и только для граждан тех стран, где эта информация легальна, как минимум - в научных целях.*
> *Автор не имеет никаких намерений, не побуждает, не поощряет и не оправдывает использование VPN ни при каких обстоятельствах.*
> *Ответственность за любое применение данных VPN-конфигураций — на их пользователе.*
> *Отказ от ответственности: автор не несёт ответственность за действия третьих лиц и не поощряет противоправное использование VPN.*
> *Используйте в соответствии с местным законодательством.*
>
> *Используйте VPN только в законных целях: в частности - для обеспечения вашей безопасности в сети и защищённого удалённого доступа, и ни в коем случае не применяйте данную технологию для обхода блокировок.*
