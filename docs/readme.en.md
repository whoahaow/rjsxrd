> **Language:** [Русский](readme.md) · [English](readme.en.md)

# rjsxrd

An automatically updated collection of public VPN configurations for bypassing blocks.

**Repository:** [github.com/whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd)  
**Telegram channel:** [t.me/rjsxrd](https://t.me/rjsxrd)

## About the project

rjsxrd collects, filters, and verifies thousands of VPN configs from open sources. The result is files ready for import into any modern VPN client.

**Key characteristics:**

- **Update:** hourly from VPS via cron (primary) + every 48 hours via GitHub Actions (fallback)
- **Protocols:** VLESS, VMess, Trojan, Shadowsocks, ShadowsocksR, Hysteria v1/v2, TUIC
- **Verification:** Xray-core or TCP ping, sorting by latency
- **Filtering:** automatic removal of insecure and non-working configs
- **SNI/CIDR:** dedicated sets for bypassing mobile whitelists
- **Telegram proxies:** collection and verification of MTProto and SOCKS5 proxies

---

## Documentation contents

### For users

| Section | Description |
|--------|----------|
| [Quick start](quickstart.en.md) | How to start using the configs in 2 steps |
| [Generated files](user/config-files.en.md) | Description of all folders and file types |
| [Import into clients](user/import-guide.en.md) | Instructions for Android, iOS, Windows, macOS, Linux |
| [Your own servers](user/custom-servers.en.md) | Adding your own VPN servers and Telegram proxies |

### For administrators

| Section | Description |
|--------|----------|
| [Installing the generator](operation/installation.en.md) | Running the generator locally |
| [CLI reference](operation/cli-reference.en.md) | All flags and run modes |
| [Proxy chains](operation/proxy-chains.en.md) | Multi-level routing |

### For developers

| Section | Description |
|--------|----------|
| [Architecture](development/architecture.en.md) | Modular structure and processing pipeline |
| [Modules](development/modules.en.md) | Description of all components and key functions |
| [Security](development/security-system.en.md) | Filtering of insecure configs and SNI/CIDR |
| [Performance](development/performance.en.md) | Parallelism, batch mode, Xray compatibility |
| [Testing](development/testing.en.md) | Set of tests and verification scenarios |

---

## Quick navigation through files

```
githubmirror/
├── default/             # Main configs (1.txt, all.txt, all-secure.txt)
├── bypass/              # SNI/CIDR-filtered, secure
├── bypass-unsecure/     # SNI/CIDR-filtered, all (including insecure)
├── split-by-protocols/  # Split by protocols (vless.txt, vmess.txt, ...)
└── tg-proxy/            # Telegram proxies (all.txt, MTProto.txt, socks.txt)
```

## License

MIT. Full text — in the [LICENSE](../../LICENSE) file.

## Disclaimer

The author is not the owner or provider of the listed VPN configurations. The project is an independent informational review and test results of public sources. Responsibility for any use of the configurations lies with the user.
