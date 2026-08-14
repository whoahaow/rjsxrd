> **Language:** [Русский](faq.md) · [English](faq.en.md)

# Frequently asked questions

## About the project

**What is rjsxrd?**  
An automatically updated collection of public VPN configs. The project collects, filters, and verifies configs from open sources, updating them **every hour from a VPS** (primary, cron) and **once every 2 days** via GitHub Actions (fallback).

**Where do the configs come from?**  
From public sources listed in `source/config/URLS.txt`. The project does not create its own servers — it only aggregates and verifies existing ones.

**How safe is it?**  
The configs go through filtering of insecure parameters and verification. But these are public configs — use them with an understanding of the risks. For confidential data, your own VPN is recommended.

## Usage

**Why are configs split by 300 lines per file?**  
GitHub file size limit (~49 MB). Splitting also speeds up import on mobile devices.

**What to choose: default or bypass?**  
- `default/` — for regular blocks
- `bypass/` — if the mobile operator blocks VPN by SNI/IP

**What is the difference between bypass and bypass-unsecure?**  
- `bypass/` — only secure configs (passed the insecure filter)
- `bypass-unsecure/` — all configs, including insecure ones

**Why is the split-by-protocols folder needed?**  
If you know which protocol you need (for example, only VLESS), you can take the file from there instead of downloading all configs.

**How to add your own server?**  
Place it in `source/config/servers.txt`. On the next generator run, it will be processed and merged with the rest.

**How to add a Telegram proxy?**  
Place them in `source/config/tg_proxies.txt`. Supported formats: `https://t.me/proxy?...`, `https://t.me/socks?...`, `tg://proxy?...`, `tg://socks?...`.

## Generator modes

**What is the difference between --skip-xray, --tcp-ping and a regular run?**  
- **Regular:** Xray-core launches a process for each config and makes an HTTP request. Maximum accuracy, but the slowest (60-120 s).
- **--tcp-ping:** TCP connection to host:port. Fast (~5 s), only checks whether the port is open. Does not require Xray.
- **--skip-xray:** No verification at all. The fastest, but the configs may be non-working.

**How to run the generator without uploading to GitHub?**  
```bash
python main.py --dry-run
```

**What is --use-git?**  
A mode for GitHub Actions. Uses git commands instead of the GitHub API to upload files.

## Problems

**No config works. What to do?**  
1. Restart the app and the device
2. Check the firewall and antivirus
3. Update the config list in the app
4. Try a different file (for example, bypass-all.txt instead of 1.txt)

**Slow connection**  
Choose a config with a lower ping. Try a different protocol. Check the quality of your internet connection.

**Import problems on mobile**  
- First try `bypass-all.txt`
- If it is slow — use split files (bypass-1.txt, etc.)
- Update the VPN client to the latest version

**Configs do not appear when importing**  
In v2rayNG: "three lines" → "Groups" → "circular arrow icon" (update subscription).
