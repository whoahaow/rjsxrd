> **Language:** [Русский](custom-servers.md) · [English](custom-servers.en.md)

# Adding your own servers and proxies

The project allows you to add your own VPN servers and Telegram proxies through configuration files. They will be processed, filtered, and merged with other sources automatically.

## VPN servers

Edit the `source/config/servers.txt` file:

```
vless://uuid@host:52496?... # own VLESS server
vmess://eyJhZGQiOiI...      # VMess in base64 format
trojan://password@host:443?...
```

**Format:** one line = one config. All protocols are supported:

- `vless://`, `vmess://`, `trojan://` — main
- `ss://`, `ssr://` — Shadowsocks
- `tuic://` — TUIC
- `hysteria://`, `hysteria2://`, `hy2://` — Hysteria

**What will happen when the generator runs:**

1. Your configs will be merged with the configs from the URL sources
2. They will go through security filtering (insecure parameters will be marked)
3. They will go through SNI/CIDR filtering for the bypass sets
4. They will get into all output files: numbered, all.txt, all-secure.txt, bypass, split-by-protocols

**Important:** after 3 consecutive failed verifications in a row, the config is automatically removed from `servers.txt`.

## Telegram proxies

Edit the `source/config/tg_proxies.txt` file:

**Supported formats:**

| Format | Example |
|--------|--------|
| MTProto | `https://t.me/proxy?server=1.2.3.4&port=443&secret=...` |
| SOCKS5 | `https://t.me/socks?server=1.2.3.4&port=1080&user=...&pass=...` |
| tg:// MTProto | `tg://proxy?server=1.2.3.4&port=443&secret=...` |
| tg:// SOCKS5 | `tg://socks?server=1.2.3.4&port=1080` |
| Direct SOCKS5 | `socks5://1.2.3.4:1080` |

**What will happen:**

1. Your proxies will be merged with the ones scraped from the sources
2. They will go through verification (a working check)
3. They will be sorted by ping (the fastest first)
4. They will get into `tg-proxy/all.txt`, `MTProto.txt`, and `socks.txt`

## Scraping Telegram proxies from URLs

Proxies are extracted from the content of URL sources via `TelegramProxyScraper`. Regular expressions are used for 4 MTProto formats and 7 SOCKS5 formats:

| Type | Pattern |
|-----|---------|
| MTProto | `https://t.me/proxy?...`, `http://t.me/proxy?...`, `t.me/proxy?...` (bare), `tg://proxy?...` |
| SOCKS5 | `https://t.me/socks?...`, `http://t.me/socks?...`, `t.me/socks?...`, `tg://socks?...`, `socks5://host:port`, `http://IP:PORT`, `IP:PORT` bare format |

Extracted proxies go through deduplication and cleaning from emoji/garbage.

## How it works

All files are processed by the same pipeline as external sources — all filters, deduplication, and verification are applied to them.
