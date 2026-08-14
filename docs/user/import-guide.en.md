> **Language:** [Русский](import-guide.md) · [English](import-guide.en.md)

# Import into VPN clients

## Android (v2rayNG)

**Recommended client:** [v2rayNG (GitHub Releases)](https://github.com/2dust/v2rayNG/releases)

1. Copy the config link to the clipboard
2. Open v2rayNG
3. Tap `+` in the top right corner → "Import config from clipboard"
4. Tap "three dots" in the top right → "Group profile test"
5. Wait for the test to finish → "Sort by test results"
6. Select the server with the lowest ping → the ▶️ button in the bottom right corner

**Alternatives:** [Happ (Google Play)](https://play.google.com/store/apps/details?id=com.happproxy&hl=ru) — enable sorting by ping in the settings.

### Common problems

**No internet after connecting:**
[Video fix](https://t.me/avencoreschat/25254)

**Configs do not appear after importing:**
1. Tap "three lines" in the top left corner
2. Select "Groups"
3. Tap the "circular arrow icon" in the top right corner

**Error "Internet connection check failed":**
Long-press the v2rayNG icon on the home screen → "About" → "Stop" → launch it again.

**Updating configs:**
"three lines" → "Groups" → "circular arrow icon" in the top right corner.

## Android TV (v2rayNG)

1. Download [v2rayNG universal.apk](https://github.com/2dust/v2rayNG/releases)
2. Download [QR codes](https://github.com/whoahaow/rjsxrd/tree/main/qr-codes) to a USB drive
3. In v2rayNG tap `+` → "Import from QR code" → select the image
4. Checking and sorting — as in the regular Android version

## iOS / iPadOS (V2Box)

**Recommended client:** [V2Box (App Store)](https://apps.apple.com/ru/app/v2box-v2ray-client/id6446814690)

1. Copy the config link
2. Open V2Box → "Config" tab
3. Tap `+` in the top right corner → "Add subscription"
4. Enter a name and paste the link into the "URL" field
5. Wait for the check → select the config by tapping it
6. In the bottom panel tap "Connect"

**Alternative:** [Happ (App Store)](https://apps.apple.com/us/app/happ-proxy-utility/id6504287215)

**Updating:** "Config" tab → update icon to the left of the subscription group.

## Windows (Throne)

**Recommended client:** [Throne (GitHub Releases)](https://github.com/throneproj/Throne/releases)
- Windows 10/11: `windows64.zip`
- Windows 7/8: `windowslegacy64.zip`

1. Copy the config link
2. Open Throne → "Profiles" → "Add profile from clipboard"
3. Select all the configs (Ctrl+A)
4. "Profiles" → "Test selected profile's latency (ping)"
5. Wait for the "Latency (ping) test completed!" message in the "Logs" tab
6. Tap the "Latency (ping)" column header to sort
7. Enable "TUN mode" (check the box at the top of the window)
8. Select the config with the lowest ping → "Run"

**Alternatives:** [nekoray](https://github.com/MatsuriDayo/nekoray/releases), [v2rayN](https://github.com/2dust/v2rayN/releases)

### Fixing MSVCP/VCRUNTIME errors on Windows

1. Press Win+R → `control`
2. "Programs and Features" → type "Visual" in the search
3. Delete everything related to "Microsoft Visual C++"
4. Download and install [Visual C++ Runtimes All-in-One](https://cf.comss.org/download/Visual-C-Runtimes-All-in-One-Jul-2025.zip)

### Updating configs in NekoRay

"Settings" → "Groups" → "Update all subscriptions".

## macOS (Hiddify)

**Recommended client:** [Hiddify (GitHub Releases)](https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-MacOS.dmg)

1. Open Hiddify → "New profile"
2. Copy the config link
3. Tap "Add from clipboard"
4. "Settings" → "Routing mode" → "Indonesia"
5. Settings menu (icon) → "VPN service"
6. Enable the VPN by tapping the icon
7. To change the server — the "Proxy" tab

**Alternative:** [v2rayN](https://github.com/2dust/v2rayN/releases)

**Updating:** select the profile → update icon to the left of the name.

## Linux (Throne)

**Client:** [Throne](https://github.com/throneproj/Throne/releases) — `linux-amd64.zip`

The instructions are the same as for Windows. Alternative — [nekoray](https://github.com/MatsuriDayo/nekoray/releases).
