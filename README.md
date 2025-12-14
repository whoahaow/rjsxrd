# Описание проекта

Автоматически обновляемая коллекция публичных VPN-конфигов (`V2Ray` / `VLESS` / `Trojan` / `VMess` / `Reality` / `Shadowsocks`) для быстрого обхода блокировок.
Обход блокировок. Обход белых списков на мобильном интернете.

Каждый конфиг — это TXT-подписка, которую можно импортировать практически в любой современный клиент (`v2rayNG`, `NekoRay`, `Throne`, `v2rayN`, `V2Box`, `v2RayTun`, `Hiddify` и др.).

Конфиги обновляются каждые **12 часов** с помощью GitHub Actions, поэтому ссылки из раздела **«Общий список всех вечно актуальных конфигов»** всегда актуальны.

## Содержание
- [Описание проекта](#описание-проекта)
  - [Содержание](#содержание)
  - [Быстрый старт](#быстрый-старт)
  - [Статус конфигов](#статус-конфигов)
  - [Как это работает](#как-это-работает)
  - [Структура репозитория](#структура-репозитория)
  - [Локальный запуск генератора](#локальный-запуск-генератора)
- [Видео гайд по установке и решению проблем](#видео-гайд-по-установке-и-решению-проблем)
- [Общее меню гайдов репозитория](#общее-меню-гайдов-репозитория)
- [Лицензия](#лицензия)

---

## Быстрый старт
1. Скопируйте нужную ссылку из раздела **«Общий список всех вечно актуальных конфигов»**.
2. Импортируйте её в ваш **VPN-клиент** (см. инструкции ниже).
3. Выберите сервер с минимальным пингом и подключайтесь.

---

# Видео гайд по установке и решению проблем

> **Внимание!** Для iOS и iPadOS актуален только текстовый гайд ниже. Видео гайд актуален только для Android, Android TV, Windows, Linux, MacOS.

[Смотреть на YouTube](https://youtu.be/sagz2YluM70)

[Смотреть на Dzen](https://dzen.ru/video/watch/680d58f28c6d3504e953bd6d)

[Смотреть на VK Video](https://vk.com/video-200297343_456239303)

[Смотреть в Telegram](https://t.me/avencoreschat/56595)

---

# Общее меню гайдов репозитория

<details>

<summary>Исходный код для генерации вечно актуальных конфигов</summary>

Ссылка на исходный код - [Ссылка](https://github.com/whoahaow/rjsxrd/tree/main/source)

</details>

<details>
<summary>Советы по производительности и оптимизации</summary>

Если у вас возникают проблемы с производительностью при импорте большого файла 26.txt, особенно на мобильных устройствах, рекомендуется разделить импорт на несколько более мелких конфигов. Основной файл 26.txt был разделен на несколько файлов (26.txt, 27.txt, 28.txt и т.д.) по 300 серверов в каждом, чтобы избежать проблем с производительностью. Импортируйте файлы 26.txt, 27.txt и последующие по отдельности для лучшего опыта и избегания возможных лагов на мобильных устройствах.

</details>

<details>

<summary>Общий список всех вечно актуальных конфигов</summary>

> Рекомендованные списки: **[6](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt)**, **[22](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt)**, **[23](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt)**, **[24](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt)** и **[25](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt)**.

> Обход SNI/CIDR белых списков: файлы **[26](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt)** и **[27](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt)** и т.д.

 - [ ] **Вечно актуальные**

1) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/1.txt`
2) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/2.txt`
3) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/3.txt`
4) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/4.txt`
5) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/5.txt`
6) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt`
7) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/7.txt`
8) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/8.txt`
9) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/9.txt`
10) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/10.txt`
11) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/11.txt`
12) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/12.txt`
13) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/13.txt`
14) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/14.txt`
15) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/15.txt`
16) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/16.txt`
17) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/17.txt`
18) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/18.txt`
19) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/19.txt`
20) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/20.txt`
21) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/21.txt`
22) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt`
23) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt`
24) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt`
25) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt`
26) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt`
27) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt`
28) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/28.txt`
29) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/29.txt`
30) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/30.txt`
31) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/31.txt`
32) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/32.txt`
33) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/33.txt`
34) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/34.txt`
35) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/35.txt`

🔗 [Ссылка на QR-коды вечно актуальных конфигов](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes)
</details>


---
<details>

<summary>Гайд для Android</summary>

**1.** Скачиваем **«v2rayNG»** - [Ссылка](https://github.com/2dust/v2rayNG/releases/download/1.10.28/v2rayNG_1.10.28_universal.apk)

**2.** Копируем в буфер обмена:

> Рекомендованные списки: **[6](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt)**, **[22](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt)**, **[23](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt)**, **[24](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt)** и **[25](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt)**.

> Обход SNI/CIDR белых списков: файлы **[26](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt)**, **[27](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt)** и т.д.

 - [ ] **Вечно актуальные**

1) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/1.txt`
2) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/2.txt`
3) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/3.txt`
4) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/4.txt`
5) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/5.txt`
6) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt`
7) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/7.txt`
8) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/8.txt`
9) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/9.txt`
10) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/10.txt`
11) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/11.txt`
12) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/12.txt`
13) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/13.txt`
14) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/14.txt`
15) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/15.txt`
16) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/16.txt`
17) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/17.txt`
18) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/18.txt`
19) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/19.txt`
20) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/20.txt`
21) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/21.txt`
22) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt`
23) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt`
24) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt`
25) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt`
26) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt`
27) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt`
28) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/28.txt`
29) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/29.txt`
30) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/30.txt`
31) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/31.txt`
32) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/32.txt`
33) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/33.txt`
34) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/34.txt`
35) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/35.txt`

**3.** Заходим в приложение **«v2rayNG»** и в правом верхнем углу нажимаем на +, а затем выбираем **«Импорт из буфера обмена»**.

**4.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверка профилей группы»**, после окончания проверки в этом же меню нажмите на **«Сортировка по результатам теста»**.

**5.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

</details>

<details>

<summary>Гайд для Android TV</summary>

**1.** Скачиваем **«v2rayNG»** - [Ссылка](https://github.com/2dust/v2rayNG/releases/download/1.10.28/v2rayNG_1.10.28_universal.apk)

> Рекомендованные **«QR-коды»**: **[6](https://github.com/whoahaow/rjsxrd/blob/main/qr-codes/6.png)**, **[22](https://github.com/whoahaow/rjsxrd/blob/main/qr-codes/22.png)**, **[23](https://github.com/whoahaow/rjsxrd/blob/main/qr-codes/23.png)**, **[24](https://github.com/whoahaow/rjsxrd/blob/main/qr-codes/24.png)** и **[25](https://github.com/whoahaow/rjsxrd/blob/main/qr-codes/25.png)**.

> Обход SNI/CIDR белых списков: **[26](https://github.com/whoahaow/rjsxrd/blob/main/qr-codes/26.png)**.

**2.** Скачиваем **«QR-коды»** вечно актуальных конфигов - [Ссылка](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes)

**3**. Заходим в приложение **«v2rayNG»** и в правом верхнем углу нажимаем на +, а затем выбираем **«Импорт из QR-кода»**, выбираем картинку нажав на иконку фото в правом верхнем углу.

**4.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверка профилей группы»**, после окончания проверки в этом же меню нажмите на **«Сортировка по результатам теста»**.

**5.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

</details>

<details>

<summary>Если нету интернета при подключении к VPN в v2rayNG</summary>

Ссылка на видео с демонстрацией фикса - [Ссылка](https://t.me/avencoreschat/25254)

</details>

<details>

<summary>Если не появились конфиги при добавлении VPN в v2rayNG</summary>

**1.** Нажмите на **«три полоски»** в **«левом верхнем углу»**.

**2.** Нажимаем на кнопку **«Группы»**.

**3.** Нажимаем на **«иконку кружка со стрелкой»** в **«верхнем правом углу»** и дожидаемся окончания обновления.

</details>

<details>

<summary>Фикс ошибки "Cбой проверки интернет-соединения: net/http: 12X handshake timeout"</summary>

**1.** На рабочем столе зажимаем на иконке **«v2rayNG»** и нажимаем на пункт **«О приложении»**.

**2.** Нажимаем на кнопку **«Остановить»** и заново запускаем **«v2rayNG»**.

</details>

<details>

<summary>Фикс ошибки "Fail to detect internet connection: io: read/write closed pipe"</summary>

**1.** На рабочем столе зажимаем на иконке **«v2rayNG»** и нажимаем на пункт **«О приложении»**.

**2.** Нажимаем на кнопку **«Остановить»** и заново запускаем **«v2rayNG»**.

**3.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверка профилей группы»**, после окончания проверки в этом же меню нажмите на **«Сортировка по результатам теста»**.

**4.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

</details>

<details>

<summary>Обновление конфигов в v2rayNG</summary>

**1.** Нажимаем на **«иконку трех полосок»** в **«левом верхнем углу»**.

**2.** Выбираем вкладку **«Группы»**.

**3.** Нажимаем на **«иконку кружка со стрелкой»** в **«правом верхнем углу»**.

</details>


---
<details>

<summary>Гайд для Windows, Linux</summary>

**1.** Скачиваем **«Throne»** - [Windows 10/11](https://github.com/throneproj/Throne/releases/download/1.0.10/Throne-1.0.10-windows64.zip) / [Windows 7/8/8.1](https://github.com/throneproj/Throne/releases/download/1.0.10/Throne-1.0.10-windowslegacy64.zip) / [Linux](https://github.com/throneproj/Throne/releases/download/1.0.10/Throne-1.0.10-linux-amd64.zip)

**2.** Копируем в буфер обмена:

> Рекомендованные списки: **[6](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt)**, **[22](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt)**, **[23](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt)**, **[24](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt)** и **[25](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt)**.

> Обход SNI/CIDR белых списков: файлы **[26](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt)**, **[27](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt)** и т.д.

 - [ ] **Вечно актуальные**

1) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/1.txt`
2) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/2.txt`
3) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/3.txt`
4) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/4.txt`
5) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/5.txt`
6) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt`
7) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/7.txt`
8) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/8.txt`
9) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/9.txt`
10) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/10.txt`
11) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/11.txt`
12) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/12.txt`
13) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/13.txt`
14) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/14.txt`
15) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/15.txt`
16) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/16.txt`
17) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/17.txt`
18) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/18.txt`
19) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/19.txt`
20) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/20.txt`
21) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/21.txt`
22) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt`
23) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt`
24) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt`
25) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt`
26) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt`
27) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt`
28) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/28.txt`
29) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/29.txt`
30) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/30.txt`
31) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/31.txt`
32) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/32.txt`
33) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/33.txt`
34) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/34.txt`
35) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/35.txt`

**3.** Нажимаем на **«Профили»**, а затем **«Добавить профиль из буфера обмена»**.

**4.** Выделяем все конфиги комбинацией клавиш **«Ctrl + A»**, нажимаем **«Профили»** в верхнем меню, а затем **«Тест задержки (пинга) выбранного профиля»** и дожидаемся окончания теста (во вкладке **«Логи»** появится надпись **«Тест задержек (пинга) завершён!»**)

**5.** Наживаем на кнопку колонки **«Задержка (пинг)»**.

**6.** В верхней части окна программы активируйте опцию **«Режим TUN»**, установив галочку.

**7.** Выбираем один из конфигов с наименьшим **«Задержка (пинг)»**, а затем нажимаем **«ЛКМ»** и **«Запустить»**.

</details>

<details>

<summary>Исправляем ошибку MSVCP и VCRUNTIME на Windows 10/11</summary>

**1.** Нажимаем **«Win+R»** и пишем **«control»**.

**2.** Выбираем **«Программы и компоненты»**.

**3.** В поиск (справа сверху) пишем слово **«Visual»** и удалям все что касается **«Microsoft Visual»**.

**4.** Скачиваем архив и распаковываем - [Ссылка](https://cf.comss.org/download/Visual-C-Runtimes-All-in-One-Jul-2025.zip)

**5.** Запускаем от *имени Администратора* **«install_bat.all»** и ждем пока все установиться.

</details>

<details>

<summary>Обновление конфигов в NekoRay</summary>

**1.** Нажимаем на кнопку **«Настройки»**.

**2.** Выбираем **«Группы»**.

**3.** Нажимаем на кнопку **«Обновить все подписки»**.

</details>


---
<details>

<summary>Гайд для iOS, iPadOS</summary>

**1.** Скачиваем **«V2Box - V2ray Client»** - [Ссылка](https://apps.apple.com/ru/app/v2box-v2ray-client/id6446814690)

**2.** Копируем в буфер обмена:

> Рекомендованные списки: **[6](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt)**, **[22](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt)**, **[23](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt)**, **[24](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt)** и **[25](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt)**.

> Обход SNI/CIDR белых списков: файлы **[26](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt)**, **[27](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt)** и т.д.

 - [ ] **Вечно актуальные**

1) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/1.txt`
2) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/2.txt`
3) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/3.txt`
4) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/4.txt`
5) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/5.txt`
6) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt`
7) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/7.txt`
8) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/8.txt`
9) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/9.txt`
10) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/10.txt`
11) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/11.txt`
12) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/12.txt`
13) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/13.txt`
14) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/14.txt`
15) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/15.txt`
16) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/16.txt`
17) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/17.txt`
18) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/18.txt`
19) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/19.txt`
20) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/20.txt`
21) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/21.txt`
22) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt`
23) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt`
24) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt`
25) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt`
26) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt`
27) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt`
28) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/28.txt`
29) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/29.txt`
30) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/30.txt`
31) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/31.txt`
32) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/32.txt`
33) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/33.txt`
34) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/34.txt`
35) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/35.txt`

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

**2.** Нажимаем **«Новый профиль»**.

**3.** Копируем в буфер обмена:

> Рекомендованные списки: **[6](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt)**, **[22](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt)**, **[23](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt)**, **[24](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt)** и **[25](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt)**.

> Обход SNI/CIDR белых списков: файлы **[26](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt)**, **[27](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt)** и т.д.

 - [ ] **Вечно актуальные**

1) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/1.txt`
2) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/2.txt`
3) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/3.txt`
4) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/4.txt`
5) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/5.txt`
6) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt`
7) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/7.txt`
8) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/8.txt`
9) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/9.txt`
10) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/10.txt`
11) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/11.txt`
12) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/12.txt`
13) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/13.txt`
14) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/14.txt`
15) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/15.txt`
16) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/16.txt`
17) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/17.txt`
18) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/18.txt`
19) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/19.txt`
20) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/20.txt`
21) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/21.txt`
22) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt`
23) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt`
24) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt`
25) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt`
26) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt`
27) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/27.txt`
28) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/28.txt`
29) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/29.txt`
30) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/30.txt`
31) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/31.txt`
32) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/32.txt`
33) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/33.txt`
34) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/34.txt`
35) `https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/35.txt`

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

## Статус конфигов

> **Внимание!** Эта таблица показывает только **источники** и статус обновления конфигов. **Не копируйте ссылки отсюда!**
> Для использования копируйте ссылки из раздела **«Общий список всех вечно актуальных конфигов»** ниже.

| № | Файл | Источник | Время | Дата |
|--|--|--|--|--|
| 1 | [`1.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/1.txt) | [sakha1370/OpenRay](https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt) | 14:27 | 29.11.2025 |
| 2 | [`2.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/2.txt) | [sevcator/5ubscrpt10n](https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt) | 14:35 | 29.11.2025 |
| 3 | [`3.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/3.txt) | [yitong2333/proxy-mingen](https://raw.githubusercontent.com/yitong2333/proxy-mingen/refs/heads/main/v2ray.txt) | 14:35 | 29.11.2025 |
| 4 | [`4.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/4.txt) | [acymz/AutoVPN](https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt) | 14:27 | 29.11.2025 |
| 5 | [`5.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/5.txt) | [miladtahanian/V2RayCFGDumper](https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt) | 14:35 | 29.11.2025 |
| 6 | [`6.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/6.txt) | [roosterkid/openproxylist](https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt) | 14:15 | 29.11.2025 |
| 7 | [`7.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/7.txt) | [Epodonios/v2ray-configs](https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt) | 13:14 | 29.11.2025 |
| 8 | [`8.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/8.txt) | [YasserDivaR/pr0xy](https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt) | 18:26 | 12.11.2025 |
| 9 | [`9.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/9.txt) | [mohamadfg-dev/telegram-v2ray-configs-collector](https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt) | 13:58 | 29.11.2025 |
| 10 | [`10.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/10.txt) | [mheidari98/.proxy](https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless) | 14:35 | 29.11.2025 |
| 11 | [`11.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/11.txt) | [youfoundamin/V2rayCollector](https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt) | 13:34 | 29.11.2025 |
| 12 | [`12.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/12.txt) | [mheidari98/.proxy](https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all) | 14:35 | 29.11.2025 |
| 13 | [`13.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/13.txt) | [Kwinshadow/TelegramV2rayCollector](https://github.com/Kwinshadow/TelegramV2rayCollector/raw/refs/heads/main/sublinks/mix.txt) | 21:46 | 11.11.2025 |
| 14 | [`14.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/14.txt) | [LalatinaHub/Mineral](https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes) | 14:35 | 29.11.2025 |
| 15 | [`15.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/15.txt) | [miladtahanian/multi-proxy-config-fetcher](https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt) | 05:40 | 28.11.2025 |
| 16 | [`16.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/16.txt) | [Pawdroid/Free-servers](https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub) | 14:15 | 29.11.2025 |
| 17 | [`17.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/17.txt) | [MhdiTaheri/V2rayCollector_Py](https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt) | 14:27 | 29.11.2025 |
| 18 | [`18.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/18.txt) | [Epodonios/v2ray-configs](https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt) | 14:15 | 29.11.2025 |
| 19 | [`19.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/19.txt) | [MhdiTaheri/V2rayCollector](https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix) | 14:15 | 29.11.2025 |
| 20 | [`20.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/20.txt) | [Argh94/Proxy-List](https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt) | 13:14 | 29.11.2025 |
| 21 | [`21.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/21.txt) | [shabane/kamaji](https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt) | 14:35 | 29.11.2025 |
| 22 | [`22.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/22.txt) | [wuqb2i4f/xray-config-toolkit](https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri) | 13:34 | 29.11.2025 |
| 23 | [`23.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/23.txt) | [AzadNetCH/Clash](https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt) | 08:45 | 22.10.2025 |
| 24 | [`24.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/24.txt) | [STR97/STRUGOV](https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE) | 08:15 | 25.11.2025 |
| 25 | [`25.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/25.txt) | [V2RayRoot/V2RayConfig](https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt) | 14:27 | 29.11.2025 |
| 26 | [`26.txt`](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt) | [Обход SNI/CIDR белых списков](https://github.com/whoahaow/rjsxrd/raw/refs/heads/main/githubmirror/26.txt) | 14:35 | 29.11.2025 |

## Структура репозитория
```text
githubmirror/        - сгенерированные .txt конфиги (25+ файлов)
qr-codes/            - PNG-версии конфигов для импорта по QR
source/              - Python-скрипт и зависимости генератора
 ├─ main.py
 ├─ config/
 │   └─ settings.py
 ├─ fetchers/
 │   └─ fetcher.py
 ├─ processors/
 │   └─ config_processor.py
 ├─ utils/
 │   ├─ logger.py
 │   ├─ file_utils.py
 │   └─ github_handler.py
 └─ requirements.txt
.github/workflows/   - CI/CD (авто-обновление каждые 12 часов)
README.md            - этот файл
```

---

## Локальный запуск генератора
```bash
git clone https://github.com/whoahaow/rjsxrd
cd goida-vpn-configs/source
python -m pip install -r requirements.txt
export MY_TOKEN=<GITHUB_TOKEN>   # токен с правом repo, чтобы пушить изменения
python main.py                   # конфиги появятся в ../githubmirror
```

> **Важно!** В файле `source/main.py` вручную задайте `REPO_NAME = "<username>/<repository>"`, если запускаете скрипт из форка.

---

# Лицензия

Проект распространяется под лицензией MIT License. Полный текст лицензии содержится в файле [`LICENSE`](LICENSE).

---

# Источники и вдохновение

Основной репозиторий, который вдохновил данный проект: https://github.com/AvenCores/goida-vpn-configs

## ДИСКЛЕЙМЕР

> *Автор не является владельцем/разработчиком/поставщиком перечисленных VPN-конфигураций. Это независимый информационный обзор и результаты тестирования.*
>
> *Данный пост не является рекламой VPN. Материал предназначен исключительно в информационных целях, и только для граждан тех стран, где эта информация легальна, как минимум - в научных целях.* 
>
> *Автор не имеет никаких намерений, не побуждает, не поощряет и не оправдывает использование VPN ни при каких обстоятельствах.*
>
> *Ответственность за любое применение данных VPN-конфигураций — на их пользователе.*
>
> *Отказ от ответственности: автор не несёт ответственность за действия третьих лиц и не поощряет противоправное использование VPN.*
>
> *Используйте в соответствии с местным законодательством.* 
>
> *Используйте VPN только в законных целях: в частности - для обеспечения вашей безопасности в сети и защищённого удалённого доступа, и ни в коем случае не применяйте данную технологию для обхода блокировок.*
