> **Language:** [Русский](config-files.md) · [English](config-files.en.md)

# Generated files

The `githubmirror/` folder contains the results of the generator's work. Configs are updated **every hour** from a VPS (primary channel) and **once every 2 days** via GitHub Actions (fallback).

> **Note:** by default, only the `bypass/` folder is generated. The other sets (`default/`, `bypass-unsecure/`, `split-by-protocols/`, `tg-proxy/`, raw files) are enabled with `--enable-*` feature flags.

## Structure

```
githubmirror/
├── default/                   # Main configs
│   ├── 1.txt                  # Numbered files (by source, up to 300 lines)
│   ├── 2.txt
│   ├── ...
│   ├── all.txt                # All unique configs in one file
│   └── all-secure.txt         # Only secure (without insecure parameters)
│
├── bypass/                    # SNI/CIDR-filtered, secure
│   ├── raw/                   # Untested raw configs
│   ├── bypass-all.txt         # All in one file, sorted by ping
│   ├── bypass-1.txt           # Split by 300 configs
│   └── ...
│
├── bypass-unsecure/           # SNI/CIDR-filtered, all configs
│   ├── raw/                   # Untested raw configs
│   ├── bypass-unsecure-all.txt  # All in one file
│   ├── bypass-unsecure-1.txt    # Split by 300 configs
│   └── ...
│
├── split-by-protocols/        # Split by protocol
│   ├── vless.txt              # VLESS
│   ├── vless-secure.txt       # VLESS (only secure)
│   ├── vmess.txt              # VMess
│   ├── vmess-secure.txt
│   ├── trojan.txt             # Trojan
│   ├── trojan-secure.txt
│   ├── ss.txt                 # Shadowsocks
│   ├── ss-secure.txt
│   ├── ssr.txt                # ShadowsocksR
│   ├── ssr-secure.txt
│   ├── tuic.txt               # TUIC
│   ├── tuic-secure.txt
│   ├── hysteria.txt           # Hysteria v1
│   ├── hysteria-secure.txt
│   ├── hysteria2.txt          # Hysteria v2
│   ├── hysteria2-secure.txt
│   ├── hy2.txt                # Hysteria v2 (alternative prefix)
│   └── hy2-secure.txt
│
└── tg-proxy/                  # Telegram proxies
    ├── all.txt                # All proxies (MTProto + SOCKS5)
    ├── MTProto.txt            # Only MTProto
    └── socks.txt              # Only SOCKS5
```

QR codes are also generated in the `qr-codes/` folder for mobile import.

## File types

### Main (`default/`)

Configs from all sources that have gone through basic deduplication and filtering. Numbered files (1.txt, 2.txt, ...) correspond to different sources — you can subscribe to one specific source.

- `all.txt` — a merge of all numbered files, 0 duplicates
- `all-secure.txt` — the same, but configs with insecure parameters are removed

### SNI/CIDR (`bypass/` and `bypass-unsecure/`)

Configs filtered by domains from the whitelist files. Used to bypass mobile whitelists (Russia and other countries where mobile operators block VPN by SNI/IP addresses).

- `bypass/` — secure configs (double filtering: SNI/CIDR + security)
- `bypass-unsecure/` — all configs (only SNI/CIDR filtering)
- `raw/` — configs before verification (not checked by Xray)
- Main files — after Xray verification, sorted by ping

**Why split by 300 lines?** GitHub has a file size limit (~49 MB). Splitting also improves import performance on mobile devices.

### By protocol (`split-by-protocols/`)

Convenient if you know which protocol you need:

- **Secure** (for example `vless-secure.txt`) — only secure configs
- **Unsecure** (for example `vless.txt`) — all configs of the protocol

Supported protocols: VLESS, VMess, Trojan, Shadowsocks, ShadowsocksR, TUIC, Hysteria v1, Hysteria v2.

### Telegram proxies (`tg-proxy/`)

Automatically collected, verified, and sorted by ping proxies for Telegram. Suitable for use in the messenger's settings.

## File format

All generated files contain a subscription header for compatibility with VPN clients:

```
#profile-title: all t.me/rjsxrd
#profile-update-interval: 48
#support-url: https://t.me/rjsxrd
#announce: t.me/rjsxrd
#subscription-userinfo: upload=0; download=0; total=0; expire=0
```

Each config gets a remark suffix `%20t.me%2Frjsxrd` (URL-encoded link to the project channel).

## Size limit

GitHub limits files to ~49 MB. When the limit is exceeded, the file is automatically split via `split_file_by_size()`:

- First, the size of `all.txt` and `all-secure.txt` is estimated — if the limit is exceeded, the configs are distributed across several files without redundant writes
- Protocol-specific files also go through the check and automatic splitting

The 300-line split is a secondary limit used for bypass files in `split_configs_to_files()`. The main mechanism is the byte size check with a 10% safety margin.

## Which folder to choose?

| Your task | Recommended file |
|-------------|--------------------|
| Quick start, don't know what to choose | `default/6.txt` or `default/1.txt` |
| Mobile internet (whitelists) | `bypass/bypass-all.txt` |
| Maximum security | `default/all-secure.txt` |
| Want only VLESS | `split-by-protocols/vless-secure.txt` |
| All sources in one file | `default/all.txt` |
| Telegram is blocked | `tg-proxy/all.txt` |
