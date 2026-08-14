> **Language:** [Русский](import-guide.md) · [English](import-guide.en.md)

# Импорт в VPN-клиенты

## Android (v2rayNG)

**Рекомендуемый клиент:** [v2rayNG (GitHub Releases)](https://github.com/2dust/v2rayNG/releases)

1. Скопируйте ссылку на конфиг в буфер обмена
2. Откройте v2rayNG
3. Нажмите `+` в правом верхнем углу → «Импорт из буфера обмена»
4. Нажмите «три точки» справа сверху → «Проверка профилей группы»
5. Дождитесь окончания проверки → «Сортировка по результатам теста»
6. Выберите сервер с минимальным пингом → кнопка ▶️ в правом нижнем углу

**Альтернативы:** [Happ (Google Play)](https://play.google.com/store/apps/details?id=com.happproxy&hl=ru) — в настройках включите сортировку по пингу.

### Частые проблемы

**Нет интернета после подключения:**
[Видеофикс](https://t.me/avencoreschat/25254)

**Конфиги не отображаются после импорта:**
1. Нажмите «три полоски» в левом верхнем углу
2. Выберите «Группы»
3. Нажмите «иконку кружка со стрелкой» в правом верхнем углу

**Ошибка «Cбой проверки интернет-соединения»:**
Зажмите иконку v2rayNG на рабочем столе → «О приложении» → «Остановить» → запустите заново.

**Обновление конфигов:**
«три полоски» → «Группы» → «иконка кружка со стрелкой» в правом верхнем углу.

## Android TV (v2rayNG)

1. Скачайте [v2rayNG universal.apk](https://github.com/2dust/v2rayNG/releases)
2. Скачайте [QR-коды](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes) на USB-флешку
3. В v2rayNG нажмите `+` → «Импорт из QR-кода» → выберите изображение
4. Проверка и сортировка — как в обычной версии Android

## iOS / iPadOS (V2Box)

**Рекомендуемый клиент:** [V2Box (App Store)](https://apps.apple.com/ru/app/v2box-v2ray-client/id6446814690)

1. Скопируйте ссылку на конфиг
2. Откройте V2Box → вкладка «Config»
3. Нажмите `+` в правом верхнем углу → «Добавить подписку»
4. Введите название и вставьте ссылку в поле «URL»
5. Дождитесь проверки → выберите конфиг нажатием
6. В нижней панели нажмите «Подключиться»

**Альтернатива:** [Happ (App Store)](https://apps.apple.com/us/app/happ-proxy-utility/id6504287215)

**Обновление:** вкладка «Config» → иконка обновления слева от группы подписки.

## Windows (Throne)

**Рекомендуемый клиент:** [Throne (GitHub Releases)](https://github.com/throneproj/Throne/releases)
- Windows 10/11: `windows64.zip`
- Windows 7/8: `windowslegacy64.zip`

1. Скопируйте ссылку на конфиг
2. Откройте Throne → «Профили» → «Добавить профиль из буфера обмена»
3. Выделите все конфиги (Ctrl+A)
4. «Профили» → «Тест задержки (пинга) выбранного профиля»
5. Дождитесь надписи «Тест задержек завершён!» во вкладке «Логи»
6. Нажмите на заголовок колонки «Задержка (пинг)» для сортировки
7. Активируйте «Режим TUN» (галочка в верхней части окна)
8. Выберите конфиг с наименьшим пингом → «Запустить»

**Альтернативы:** [nekoray](https://github.com/MatsuriDayo/nekoray/releases), [v2rayN](https://github.com/2dust/v2rayN/releases)

### Исправление ошибок MSVCP/VCRUNTIME на Windows

1. Нажмите Win+R → `control`
2. «Программы и компоненты» → в поиске введите «Visual»
3. Удалите всё, связанное с «Microsoft Visual C++»
4. Скачайте и установите [Visual C++ Runtimes All-in-One](https://cf.comss.org/download/Visual-C-Runtimes-All-in-One-Jul-2025.zip)

### Обновление конфигов в NekoRay

«Настройки» → «Группы» → «Обновить все подписки».

## macOS (Hiddify)

**Рекомендуемый клиент:** [Hiddify (GitHub Releases)](https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-MacOS.dmg)

1. Откройте Hiddify → «Новый профиль»
2. Скопируйте ссылку на конфиг
3. Нажмите «Добавить из буфера обмена»
4. «Настройки» → «Вариант маршрутизации» → «Индонезия»
5. Меню настроек (иконка) → «VPN сервис»
6. Включите VPN нажатием на иконку
7. Для смены сервера — вкладка «Прокси»

**Альтернатива:** [v2rayN](https://github.com/2dust/v2rayN/releases)

**Обновление:** выберите профиль → иконка обновления слева от названия.

## Linux (Throne)

**Клиент:** [Throne](https://github.com/throneproj/Throne/releases) — `linux-amd64.zip`

Инструкция та же, что для Windows. Альтернатива — [nekoray](https://github.com/MatsuriDayo/nekoray/releases).
