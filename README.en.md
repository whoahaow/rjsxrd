> **Language:** [Русский](README.md) · [English](README.en.md)

# rjsxrd - Automatically updated VPN configs

tgc: [t.me/rjsxrd](https://t.me/rjsxrd)

---

If you want to support me, here are my crypto wallets:

SOL: `DcvcsapMBqbLdA2GRhGQXPq5F74AkLQ4eh8yyTxEtsVj`

USDT (TRC20): `TTgMgXWZKFpzqXL7mPfchvjovMHKaGyea4`

BTC: `bc1q8s5snc95w3696taw5du9gnz6uf33wjz3yrq5e6`

ETH: `0x17D7206EBfba1F0b6b65E99ACbd294827D9A79B1`

---

An automatically updated collection of public VPN configs (`V2Ray` / `VLESS` / `Trojan` / `VMess` / `Reality` / `Shadowsocks` / `ShadowsocksR` / `Hysteria` / `Hysteria2` / `TUIC`) for quickly bypassing blocks. Bypassing whitelists on mobile internet.

Each config is a TXT subscription that can be imported into almost any modern client (`v2rayNG`, `NekoRay`, `Throne`, `v2rayN`, `V2Box`, `v2RayTun`, `Hiddify`, etc.).

Configs are updated **every hour** from a VPS (primary channel) and **once every 2 days** via GitHub Actions (fallback).

## Features
- Automatic filtering and deduplication of configs
- Splitting large files for better performance (max 300 configs per file)
- Support for various protocol types (V2Ray, VLESS, Trojan, VMess, etc.)
- Support for processing base64-encoded subscriptions with filtering by domain names
- **Improved security filtering**: comprehensive check of insecure parameters to improve security
  - **VMess**: checks `insecure`, `allowInsecure`, `security=none`, `alterId > 0` + TLS SNI validation
  - **VLESS**: checks `allowInsecure`, `insecure`, `security=none`, `encryption=none` + Reality publicKey validation
  - **Trojan**: checks `allowInsecure`, `insecure` + Reality publicKey/SNI validation
  - **Shadowsocks**: check for weak ciphers (RC4, DES, CFB, Salsa20, Chacha20 non-IETF) + empty passwords are rejected
  - **ShadowsocksR**: check for weak ciphers + conversion to Shadowsocks + empty passwords are rejected
  - **Hysteria2**: TLS SNI validation
  - **Hysteria v1**: warning when `insecure=1`
  - **TUIC**: not supported by Xray-core (returns `None`)
  - **Common**: checks `verify=0`, `verify=false`, `insecure=1`
- Dedicated configs for bypassing SNI/CIDR whitelists
- Insecure configs for bypassing SNI/CIDR
- Configs split by protocol
- Creation of all.txt and all-secure.txt files
- **Automatic config verification**: testing via Xray-core with sorting by speed (fastest first), or fast TCP verification via `--tcp-ping`
- **Two-tier verification system**:
  - **Raw files**: untested configs in `/raw/` subfolders
  - **Verified files**: tested via Xray-core, sorted by ping
- **Telegram proxies**: automatic collection, verification, and processing of MTProto and SOCKS5 proxies for Telegram, sorted by ping
- **Proxy chains**: support for proxy chains (--proxy-chain) for multi-level routing
- **Progress bars**: stable progress indicators when verifying configs and Telegram proxies with smart ETA (sliding window + timeout floor) and processing speed
- **URL Health Report**: automatic statistics collection for each URL source — number of configs, verification results, dead URLs
- **Auto-cleanup of dead URLs**: URLs with 3+ consecutive failed fetches are automatically removed from URLS.txt
- **Auto-cleanup of dead configs**: configs from servers.txt with 3+ consecutive verification failures are automatically removed
- Improved config validation: now only lines starting with a supported protocol (vless://, vmess://, trojan://, etc.) are considered, to prevent unsuitable lines from being included in the resulting files
- Support for daily-updated repositories with automatic config search by date
- Support for YAML configs with conversion to VPN URL format
- **Manual config addition**: the ability to add your own servers via the `source/config/servers.txt` file, which will be automatically filtered and merged with other sources
- Parallel downloads to speed up the process
- Thread-safe logging with message sorting by files
- Improved architecture with a clear separation of responsibilities between modules

## Documentation

Full documentation — **[docs/readme.en.md](docs/readme.en.md)**. Quick links:

| Section | Description |
|--------|----------|
| [Quick start](docs/quickstart.en.md) | 2 steps to connect |
| [Generated files](docs/user/config-files.en.md) | Folders, types, file format |
| [Import into clients](docs/user/import-guide.en.md) | Android, iOS, Windows, macOS |
| [Your own servers](docs/user/custom-servers.en.md) | Adding VPN and Telegram proxies |
| [Installing the generator](docs/operation/installation.en.md) | Running, health check, sources |
| [Architecture](docs/development/architecture.en.md) | Modules, pipeline, signals |
| [Security](docs/development/security-system.en.md) | Filtering, SNI/CIDR, verification |
| [FAQ](docs/faq.en.md) | Frequently asked questions |

## Table of contents
- [Features](#features)
- [Documentation](#documentation)
- [Video guide](#video-guide)
- [Configurations](#configurations)
- [Installation and usage](#installation-and-usage)
- [Additional](#additional)

## Quick start

1. Copy the desired link from the [Configurations](#configurations) section (bypass/bypass-all.txt)
2. Import it into your **VPN client**
3. Select the server with the lowest ping and connect

---

## Video guide

> **Attention!** The video guide is only relevant for Android, Android TV, Windows, Linux, macOS. For iOS and iPadOS use the text instructions below.

[Watch on YouTube](https://youtu.be/sagz2YluM70)

[Watch on Dzen](https://dzen.ru/video/watch/680d58f28c6d3504e953bd6d)

[Watch on VK Video](https://vk.com/video-200297343_456239303)

[Watch in Telegram](https://t.me/avencoreschat/56595)

---

## Configurations

> **Note:** by default, the generator only creates verified configs in `bypass/`. The other sets (`default/`, `bypass-unsecure/`, `split-by-protocols/`, `tg-proxy/`, raw files) are enabled with `--enable-*` feature flags (see [Run modes](#run-modes)). All links below are current — the files are published on GitHub.

### Configs for bypassing SNI/CIDR whitelists (bypass/)

> **For mobile device users**: if you experience performance issues, it is recommended to use the files individually rather than bypass-all.txt

**[bypass-all](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt)** - all secure configs for bypassing SNI/CIDR in one file

Update link for when blocked: **[bypass-all](https://translate.yandex.ru/translate?url=https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt&lang=en-en)**. If the configs break, open the link in the browser, copy all the configs and paste them into the client.

**Files split by 300 configs**:
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

### Insecure configs for bypassing SNI/CIDR (bypass-unsecure/)

**[bypass-unsecure-all](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt)** - all configs for bypassing SNI/CIDR in one file (including insecure ones)

**Files split by 300 configs**:
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

### Regular configs (default/)
Regular configs for bypassing standard blocks.
- **[1](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/1.txt)**
- **[6](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/6.txt)**
- **[22](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/22.txt)**
- **[23](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/23.txt)**
- **[24](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/24.txt)**
- **[25](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/25.txt)**

#### Additional files in default/
- **[all.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all.txt)** - all unique configs from the default folder in one file
- **[all-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure.txt)** - all secure (without insecure parameters) unique configs from the default folder in one file

### Configs split by protocol (split-by-protocols/)

**Secure protocol-specific files**:
- **[vless-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless-secure.txt)** - only secure VLESS configs
- **[vmess-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vmess-secure.txt)** - only secure VMess configs
- **[trojan-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/trojan-secure.txt)** - only secure Trojan configs
- **[ss-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ss-secure.txt)** - only secure Shadowsocks configs
- **[ssr-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ssr-secure.txt)** - only secure ShadowsocksR configs
- **[tuic-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic-secure.txt)** - only secure TUIC configs
- **[hysteria-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria-secure.txt)** - only secure Hysteria configs
- **[hysteria2-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria2-secure.txt)** - only secure Hysteria2 configs
- **[hy2-secure.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hy2-secure.txt)** - only secure Hysteria2 (hy2) configs

**All protocol-specific files (including insecure)**:
- **[vless.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless.txt)** - all VLESS configs
- **[vmess.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vmess.txt)** - all VMess configs
- **[trojan.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/trojan.txt)** - all Trojan configs
- **[ss.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ss.txt)** - all Shadowsocks configs
- **[ssr.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/ssr.txt)** - all ShadowsocksR configs
- **[tuic.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic.txt)** - all TUIC configs
- **[hysteria.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria.txt)** - all Hysteria configs
- **[hysteria2.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hysteria2.txt)** - all Hysteria2 configs
- **[hy2.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hy2.txt)** - all Hysteria2 (hy2) configs

### Telegram proxies (tg-proxy/)

**Files with Telegram proxies for bypassing messenger blocks**:
- **[all.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/all.txt)** - all Telegram proxies (MTProto + SOCKS5, sorted by ping)
- **[MTProto.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/MTProto.txt)** - only MTProto proxies
- **[socks.txt](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/socks.txt)** - only SOCKS5 proxies

[Link to config QR codes](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes)


---
## Installation and usage

<details>

<summary>Android guide</summary>

**1.** Download **«v2rayNG»** universal.apk - [Link](https://github.com/2dust/v2rayNG/releases)

You can use **«Happ»** - [Link](https://play.google.com/store/apps/details?id=com.happproxy&hl=ru), but in the settings: Subscriptions -> sort by ping

**2.** Copy the config link from the [Configurations](#configurations) section to the clipboard

**3.** Open the **«v2rayNG»** app and tap the + in the top right corner, then select **«Import config from clipboard»**.

**4.** Tap **«the three dots in the top right corner»**, then **«Group profile test»**; after the test finishes, in the same menu tap **«Sort by test results»**.

**5.** Select the server you need and then tap the ▶️ button in the bottom right corner.

</details>

<details>

<summary>Android TV guide</summary>

**1.** Download **«v2rayNG»** universal.apk - [Link](https://github.com/2dust/v2rayNG/releases)

**2.** Download **«QR codes»** of always-current configs - [Link](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes)

**3**. Open the **«v2rayNG»** app and tap + in the top right corner, then select **«Import from QR code»**, choose the image by tapping the photo icon in the top right corner.

**4.** Tap **«the three dots in the top right corner»**, then **«Group profile test»**; after the test finishes, in the same menu tap **«Sort by test results»**.

**5.** Select the server you need and then tap the ▶️ button in the bottom right corner.

</details>

<details>

<summary>Additional troubleshooting</summary>

**If there is no internet when connecting to the VPN in v2rayNG**

Link to the video demonstrating the fix - [Link](https://t.me/avencoreschat/25254)

**If the configs do not appear after adding the VPN in v2rayNG**

1. Tap **«the three lines»** in the **«top left corner»**.
2. Tap the **«Groups»** button.
3. Tap the **«circular arrow icon»** in the **«top right corner»** and wait for the update to finish.

**Fix for the error "Internet connection check failed: net/http: 12X handshake timeout"**

1. On the home screen, long-press the **«v2rayNG»** icon and tap **«About»**.
2. Tap the **«Stop»** button and launch **«v2rayNG»** again.

**Fix for the error "Fail to detect internet connection: io: read/write closed pipe"**

1. On the home screen, long-press the **«v2rayNG»** icon and tap **«About»**.
2. Tap the **«Stop»** button and launch **«v2rayNG»** again.
3. Tap **«the three dots in the top right corner»**, then **«Group profile test»**; after the test finishes, in the same menu tap **«Sort by test results»**.
4. Select the server you need and then tap the ▶️ button in the bottom right corner.

**Updating configs in v2rayNG**

1. Tap the **«three lines icon»** in the **«top left corner»**.
2. Select the **«Groups»** tab.
3. Tap the **«circular arrow icon»** in the **«top right corner»**.

</details>


---
<details>

<summary>Windows, Linux guide</summary>

**1.** Download **«v2rayN»** - [Link](https://github.com/2dust/v2rayN/releases)

You can use **«nekoray»** - [Link](https://github.com/MatsuriDayo/nekoray/releases)

You can use **«Throne»** - [Link](https://github.com/throneproj/Throne/releases)

**2.** Copy the config link from the [Configurations](#configurations) section to the clipboard

**3.** Tap **«Profiles»**, then **«Add profile from clipboard»**.

**4.** Select all the configs with the **«Ctrl + A»** key combination, tap **«Profiles»** in the top menu, then **«Test selected profile's latency (ping)»** and wait for the test to finish (the **«Logs»** tab will show the message **«Latency (ping) test completed!»**)

**5.** Tap the column button **«Latency (ping)»**.

**6.** In the upper part of the program window, enable the **«TUN mode»** option by checking the box.

**7.** Select one of the configs with the lowest **«Latency (ping)»**, then tap **«LMB»** and **«Run»**.

</details>

<details>

<summary>Additional Windows guides</summary>

**Fixing the MSVCP and VCRUNTIME error on Windows 10/11**

1. Press **«Win+R»** and type **«control»**.
2. Select **«Programs and Features»**.
3. In the search (top right) type the word **«Visual»** and delete everything related to **«Microsoft Visual»**.
4. Download the archive and unpack it - [Link](https://cf.comss.org/download/Visual-C-Runtimes-All-in-One-Jul-2025.zip)
5. Run **«install_bat.all»** *as Administrator* and wait for everything to install.

**Updating configs in NekoRay**

1. Tap the **«Settings»** button.
2. Select **«Groups»**.
3. Tap the **«Update all subscriptions»** button.

</details>


---
<details>

<summary>iOS, iPadOS guide</summary>

**1.** Download **«V2Box - V2ray Client»** - [Link](https://apps.apple.com/ru/app/v2box-v2ray-client/id6446814690)

You can use **«Happ»** - [Link](https://apps.apple.com/us/app/happ-proxy-utility/id6504287215), in the settings: Subscriptions -> sort by ping

**2.** Copy the config link from the [Configurations](#configurations) section to the clipboard

**3.** Open the **«V2Box - V2ray Client»** app and go to the **«Config»** tab, tap the plus sign in the top right corner, then - **«Add subscription»**, enter any **«Name»** and paste the config link into the **«URL»** field.

**4.** After adding the config, wait for the check to finish and select the one you need by simply tapping its name.

**5.** In the bottom panel of the app, tap the **«Connect»** button.

</details>

<details>

<summary>Updating configs in V2Box - V2ray Client</summary>

**1.** Go to the **«Config»** tab.

**2.** Tap the update icon to the left of the subscription group name.

</details>


---
<details>

<summary>macOS guide</summary>

**1.** Download **«Hiddify»** - [Link](https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-MacOS.dmg)

You can use **«v2rayN»** - [Link](https://github.com/2dust/v2rayN/releases)

**2.** Tap **«New profile»**.

**3.** Copy the config link from the [Configurations](#configurations) section to the clipboard

**4.** Tap the **«Add from clipboard»** button.

**5.** Go to **«Settings»**, change **«Routing mode»** to **«Indonesia»**.

**6.** Tap the settings icon in the top left menu and select **«VPN service»**.

**7.** Enable **«VPN»** by tapping the icon in the middle.

**8.** To change the server, enable **«VPN»** and go to the **«Proxy»** tab.

</details>

<details>

<summary>Updating configs in Hiddify</summary>

**1.** Open the **«Hiddify»** app and select the profile you need.

**2.** Tap **«the update icon to the left of the profile name»**.

</details>

---

## Additional

### Repository structure
```text
githubmirror/         - generated .txt config files
 ├─ default/          - main configs (1.txt, 2.txt, ..., all.txt, all-secure.txt)
 ├─ bypass/           - secure configs for bypassing SNI/CIDR
 │   ├─ raw/          - untested configs (before verification)
 │   └─ bypass-all.txt, bypass-1.txt, ... (tested, sorted by ping)
 ├─ bypass-unsecure/  - all configs for bypassing SNI/CIDR (including insecure)
 │   ├─ raw/          - untested configs (before verification)
 │   └─ bypass-unsecure-all.txt, bypass-unsecure-1.txt, ...
 ├─ split-by-protocols/ - protocol-specific files (vless.txt, vmess.txt, ...)
 ├─ tg-proxy/         - Telegram proxies (all.txt, MTProto.txt, socks.txt)
qr-codes/             - PNG versions of configs for QR import
source/               - generator source code
 ├─ __init__.py
 ├─ main.py           - main application entry point
 ├─ config/           - settings and configuration parameters
 │   ├─ __init__.py
 │   ├─ settings.py   - global settings, tokens, URL sources, time zones
 │   ├─ URLS.txt      - URL list for main configs
 │   ├─ servers.txt   - list of manual servers to add to the configurations
 │   ├─ tg_proxies.txt - list of manual Telegram proxies
 │   ├─ whitelist-all.txt - list of domains for SNI filtering
 │   └─ cidrwhitelist.txt - list of CIDR for IP filtering
 ├─ data/             - persistent URL statistics (gitignored, accumulates between runs)
 ├─ fetchers/         - modules for downloading configs from external sources
 │   ├─ __init__.py
 │   ├─ fetcher.py    - basic config fetcher with curl_cffi
 │   ├─ daily_repo_fetcher.py - download from a daily-updated repository
 │   ├─ telegram_proxy_scraper.py - Telegram proxy scraper (MTProto and SOCKS5)
 │   ├─ yaml_converter.py - YAML config converter (Clash/Surge) to VPN URL
 │   ├─ sstap_scraper.py - sstap.org/node-real-time-update/ scraping
 │   └─ upstream_aggregator.py - yudou226.top + guidongone aggregator
 ├─ processors/       - main config processing and filtering
 │   ├─ __init__.py
 │   ├─ config_processor.py - ConfigPipeline — pipeline orchestrator
 │   └─ telegram_proxy_processor.py - Telegram proxy handler
 ├─ scripts/          - utility scripts
 │   ├─ analyze_url_stats.py - URL statistics analysis
 │   ├─ benchmark_configs.py - config benchmark (--mode xray|tcp)
 │   ├─ purge_dead_urls.py - cleaning URLS.txt from dead links
 │   ├─ purge_stale_urls.py - cleaning by git timestamp
 │   ├─ setup-vps.sh   - VPS deployment script
 │   └─ test_telegram_proxies.py - testing Telegram proxies
 ├─ tests/            - unit tests (658 tests, 26 files)
 │   ├─ __init__.py
 │   ├─ conftest.py   - pytest fixtures and configuration
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
 ├─ utils/            - helper functions and utilities
 │   ├─ __init__.py
 │   ├─ _sni_worker.py - SNI/CIDR worker (internal)
 │   ├─ bypass_builder.py - bypass config builder
 │   ├─ config_helpers.py - pipeline helpers
 │   ├─ config_tagger.py - ConfigTagger (source+protocol)
 │   ├─ curl_import.py - conditional curl_cffi import
 │   ├─ download_xray.py - Xray-core download and installation
 │   ├─ executor_cache.py - ThreadPoolExecutor cache with WSL detection
 │   ├─ file_utils.py - I/O, SNI/CIDR, deduplication, prepare_config_content
 │   ├─ file_writer.py - async writing of resulting files
 │   ├─ git_auto_cleaner.py - auto-cleaning of git history
 │   ├─ git_updater.py - git commits (VPS cron mode)
 │   ├─ github_handler.py - GitHub API work (PyGithub)
 │   ├─ health_check.py - health check (internet/Xray/GitHub API)
 │   ├─ ip_verifier.py - IP check and proxy chain setup
 │   ├─ logger.py - thread-safe logging
 │   ├─ managed_process.py - ManagedProcess lifecycle
 │   ├─ process_registry.py - unified process registry
 │   ├─ progress.py - consolidated tqdm import
 │   ├─ protocol_parsers.py - protocol parsers
 │   ├─ proxy_detector.py - auto-detection of active proxies
 │   ├─ proxy_monitor.py - proxy chain health monitoring
 │   ├─ psutil_available.py - unified psutil import (HAS_PSUTIL)
 │   ├─ resource_monitor.py - CPU/RAM/network monitoring
 │   ├─ security_filter.py - has_insecure_setting + cipher sets
 │   ├─ simple_tester.py - TCP ping of configs (without Xray)
 │   ├─ smart_eta.py - smart ETA for batch testing
 │   ├─ system_specs.py - SystemSpecs — RAM/CPU/WSL/cgroups auto-detection
 │   ├─ telegram_notifier.py - Telegram notifications
 │   ├─ telegram_proxy_verifier.py - Telegram proxy verification
 │   ├─ url_stats.py - statistics collection and dead URL auto-cleanup
 │   ├─ vpn_config.py - VPNConfig dataclass hierarchy
 │   ├─ xray_batch.py - batch testing mode (shared Xray)
 │   ├─ xray_helpers.py - Xray helper functions
 │   └─ xray_tester.py - Xray-core testing sorted by speed
 ├─ xray/             - Xray-core bundle (xray, geoip.dat, geosite.dat, LICENSE)
 └─ requirements.txt  - project dependencies
.github/workflows/    - CI/CD (auto-update daily)
.env                  - environment variables (gitignored)
.env.example          - environment variable template
pyproject.toml        - project metadata and tools
README.md             - this file
LICENSE               - MIT license
docs/                 - project documentation (see docs/readme.md)
```

---

### Running the generator locally
```bash
git clone https://github.com/whoahaow/rjsxrd
cd rjsxrd
cp .env.example .env          # create and fill in .env with your settings
nano .env                      # specify GITHUB_TOKEN and REPO_NAME
cd source
python -m pip install -r requirements.txt
python main.py                 # configs will appear in ../githubmirror
```

> **Important:** Copy `.env.example` to `.env` and fill in `GITHUB_TOKEN` (a token with repo access) and `REPO_NAME` (in `owner/repo` format). Telegram notifications and performance tuning are optional.

#### Running the tests

The project includes a set of unit tests to verify the correctness of the main modules (658 tests, 26 files):

```bash
cd source
pip install pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock
pytest                              # Run all tests
pytest -v                           # Verbose output
pytest --cov=fetchers --cov=utils   # With coverage report
pytest -m unit                      # Only fast unit tests
pytest -n auto                      # Parallel run
```

Detailed test documentation — in [`docs/development/testing.en.md`](docs/development/testing.en.md).

#### Run modes

**Local testing without uploading to GitHub:**
```bash
python main.py --dry-run
```

**Running in git mode (recommended for VPS):**
```bash
python main.py --use-git --no-proxy-check
```

**Skip Xray verification (configs without testing):**
```bash
python main.py --skip-xray
```

**TCP ping instead of Xray (faster, but less accurate):**
```bash
python main.py --tcp-ping
```

**Batch mode (shared Xray, RAM savings for thousands of configs):**
```bash
python main.py --batch-mode              # via CLI flag
XRAY_BATCH_MODE=batch python main.py     # via environment variable
```

**Use a single proxy:**
```bash
python main.py --proxy="vless://uuid@host:port?..."
```

**Use a proxy chain (EXPERIMENTAL):**
```bash
python main.py --proxy-chain="vless://hop1,hop2,hop3"
```

**Skip proxy check:**
```bash
python main.py --no-proxy-check
```

**Feature flags (override settings.py for one run):**
```bash
python main.py --enable-default-files          # Generate default/ (1.txt, all.txt)
python main.py --disable-default-files         # Skip default/
python main.py --enable-bypass-unsecure        # Generate bypass-unsecure/
python main.py --disable-bypass-unsecure       # Skip bypass-unsecure/
python main.py --enable-protocol-split         # Generate split-by-protocols/
python main.py --disable-protocol-split        # Skip split-by-protocols/
python main.py --enable-tg-proxy               # Generate tg-proxy/
python main.py --disable-tg-proxy              # Skip tg-proxy/
python main.py --publish-raw-files             # Upload /raw/ subfolders
python main.py --no-publish-raw-files          # Don't upload /raw/ subfolders
```

**Verbose log (shows skipped configs):**
```bash
python main.py --verbose
```

#### Dependencies

Main dependencies:
- `curl_cffi` - fast HTTP client with TLS fingerprinting (2-3x faster than requests)
- `PyGithub` - GitHub API work
- `PyYAML` - YAML config parsing (Clash/Surge)
- `requests[socks]` - HTTP requests through a proxy (fallback)
- `ahocorasick-rs` - fast Aho-Corasick for SNI filtering
- `aiofiles` - async file writing
- `aiodns` - async DNS resolving (optional, for speed)
- `PySocks` - SOCKS proxy support
- `psutil` - resource monitoring and Xray process management
- `tqdm` - progress bars for config and Telegram proxy verification
- `pytdbot[tdjson]` - Telegram bot API

For development and testing:
- `pytest` - testing framework
- `pytest-cov` - code coverage report
- `pytest-asyncio` - async test support
- `pytest-xdist` - parallel test run
- `pytest-mock` - mocking utilities

---

### License

The project is distributed under the MIT License. The full license text is contained in the [`LICENSE`](LICENSE) file.

---

### Sources and inspiration

The main repository that inspired this project: https://github.com/AvenCores/goida-vpn-configs

---

### DISCLAIMER

> *The author is not the owner/developer/provider of the listed VPN configurations. This is an independent informational review and test results.*
>
> *This repository is not VPN advertising. The material is intended exclusively for informational purposes, and only for citizens of those countries where this information is legal, at least for scientific purposes.*
> *The author has no intentions, does not encourage, promote, or justify the use of VPN under any circumstances.*
> *Responsibility for any use of these VPN configurations lies with their user.*
> *Disclaimer: the author is not responsible for the actions of third parties and does not encourage unlawful use of VPN.*
> *Use in accordance with local legislation.*
>
> *Use VPN only for lawful purposes: in particular, to ensure your security online and secure remote access, and in no case use this technology to bypass blocks.*
