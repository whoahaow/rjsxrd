> **Language:** [Русский](security-system.md) · [English](security-system.en.md)

# Security and filtering system

The project implements a multi-level system for filtering insecure configs and generating sets for bypassing mobile whitelists.

## Filtering insecure configs

The `has_insecure_setting()` function checks each config for parameters that reduce security. It is used to generate the `-secure.txt` files.

### VMess

| Check | Parameter | Reason |
|----------|----------|---------|
| TLS disabled | `security=none` | Traffic is not encrypted |
| Forced insecure | `insecure=true`, `allowInsecure=true` | The certificate is not verified |
| Legacy mode | `alterId`/`aid` > 0 | MD5 vulnerability (VMess legacy) |

The parser also validates: TLS requires a non-empty SNI, the h2 host must be a valid array.

### VLESS

| Check | Parameter | Reason |
|----------|----------|---------|
| No encryption | `encryption=none` (without TLS/Reality) | Traffic is open |
| Insecure | `allowInsecure=true`, `insecure=true` | TLS certificate is not verified |

Reality parser: requires the simultaneous presence of `sni` and `publicKey`.

### Trojan

| Check | Parameter |
|----------|----------|
| Insecure | `allowInsecure=true`, `insecure=true` |

Reality parser: the same requirements as VLESS.

### Shadowsocks

| Check | Criterion |
|----------|----------|
| Weak cipher | Unified list in `security_filter.py` — `rc4`, `des`, `rc4-md5`, all `aes-*-cfb`/`-cfb8`/`-cfb1`/`-ctr`, `bf-cfb`, `camellia-*-cfb`, `cast5-cfb`, `des-cfb`, `idea-cfb`, `rc2-cfb`, `seed-cfb`, `salsa20`, `chacha20`, `xsalsa20`, `xchacha20`, etc. |
| Empty password | Password length = 0 |
| Plugin | Any plugin parameter (not supported) |
| **2022 key length** | The base64 key for `2022-blake3-aes-128-gcm` must decode to 16 bytes, for `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305` — to 32 bytes. The multi-key `key1:key2` format (3x-ui) is skipped — this is an Xray-core feature, not an error. |

**Secure ciphers (AEAD):**
```
aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305,
chacha20-poly1305, xchacha20-ietf-poly1305,
2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm,
2022-blake3-chacha20-poly1305
```

The constants are defined in `source/utils/security_filter.py:11-29` — the single source of truth, imported in `xray_tester.py` and `protocol_parsers.py`.

### ShadowsocksR

Converted to Shadowsocks (SSR protocol and obfuscation are lost). The same cipher and empty password validation is used.

### TUIC

Not supported by Xray-core — the parser returns `None`. The `skip-cert-verify` parameter is considered insecure.

### Hysteria

- Hysteria v2: TLS SNI validation
- Hysteria v1: warning when `insecure=1`

### Common checks

```
verify=0 | verify=false | insecure=1/true/yes/on
```

> **Important:** `verify=0` is checked as a separate URL parameter (regex `[\?&]verify=0`), not as a simple substring. This prevents false positives (for example, `skip-cert-verify=0` does not trigger as insecure).

### Checks without TLS

For VLESS without TLS/Reality: if the `vless://` config does not contain `security=tls` or `security=reality`, it is considered insecure (plaintext traffic).

## SNI/CIDR filtering

Designed to bypass mobile whitelists (Russia, Uzbekistan, etc.), where operators block VPN by SNI and IP addresses.

**Principle:** configs aimed at "white" domains/IPs (Avito, Yandex, Mail.ru, etc.) are not blocked by the mobile operator, because they look like normal traffic to allowed resources.

**Process:**
1. Loading domains from `config/whitelist-all.txt` (hundreds of domains)
2. Loading CIDR ranges from `config/cidrwhitelist.txt`
3. Extracting host:port from each config
4. Check: does the host/ip match the whitelist?
5. Filtering non-matching configs

**Result:**
- `bypass/` — SNI/CIDR + security filtering
- `bypass-unsecure/` — only SNI/CIDR (without security)

## Config verification

### Two-tier architecture

```
Raw files → Verification → Verified files
  (raw/)                    (bypass-*.txt)
```

1. **Raw** — untested configs, the result of filtering without checking
2. **Verified** — those that passed verification, sorted by ping

### Verification modes

| Mode | Mechanism | Speed | Accuracy |
|-------|----------|----------|----------|
| Xray-core | Launch Xray → HTTP via SOCKS5 | 60-120 s | High |
| TCP ping | Asyncio TCP connection to host:port | ~5 s | Medium |
| skip | No verification | 0 s | — |

### Port pool

Dynamic port allocation in ranges is used for Xray testing:

| Range | Purpose |
|----------|------------|
| 20000-21999 | Parallel batch testing |
| 22000-23999 | Proxy chains (dialerProxy) |
| 24000-24999 | Persistent proxies |

Each config is tested on a unique port, which excludes mutual influence.

## URL Health Report

Automatic report at the end of each run:

- URLs with 3+ consecutive fetch errors are removed from `URLS.txt`
- Configs from `servers.txt` with 3+ verification failures are removed
- Top sources by number of working configs
- Statistics are stored in `data/url_stats.json` (gitignored)

## Error handling

In Xray config parsers, every exception is logged with context. On a parsing error, the config does not crash the testing — it is simply marked as non-working and skipped.

Thread safety everywhere is ensured via `threading.Lock`.

## Failure protection

The system uses a circuit breaker to prevent cascade failures:

- `CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5` — after 5 errors in a row the breaker opens
- `CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 60` — 60 s to recover
- Retry: 2 attempts per config during Xray testing, 5 attempts per GitHub upload
- **CIDR OOM guard:** `load_cidr_whitelist()` automatically skips CIDR ranges with >65536 addresses (prevents OOM from an accidental /8 or /16 entry)

Temporary files are created with `TEMP_FILE_PERMISSIONS = 0o600` — only the owner has access.

## ManagedProcess — subprocess lifecycle

Xray process management is moved to `utils/managed_process.py`:

1. The process is launched with a unique config (`tempfile.mkstemp` + `chmod 0600`)
2. On termination (success, timeout, error) — guaranteed cleanup of the temporary file
3. `ProcessRegistry` (`utils/process_registry.py`) tracks all launched processes
4. On SIGINT/SIGTERM: `default_registry.cleanup(force=True)` terminates all processes and restores the proxy env vars

## Process registry

The single `ProcessRegistry` replaced three old registries:
- `_active_testers` (xray_tester.py)
- `_xray_process_registry` (ip_verifier.py)
- `_active_proxy_monitors` (proxy_monitor.py)

ProxyMonitor instances are tracked in the same registry (`register_monitor()` / `_proxy_monitors`) — during cleanup they are stopped **before** the Xray processes are terminated, because the monitors depend on the SOCKS port.

The signal handler is registered only in `main.py` — xray_tester no longer registers its own SIGINT (prevents a race condition).

## URL validation

The `is_valid_vpn_config_url()` function checks that a string is a valid VPN URL:

```python
^(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://
```

Lines that do not match any protocol are excluded at the content preparation stage.

## Case-insensitive protocols

All parsers and filters use case-insensitive protocol matching. `VLess://`, `VMess://`, `TROJAN://`, etc. are correctly recognized and processed. Deduplication keys are normalized to lowercase, so `vless://host` and `VLess://host` give the same dedup key.

## VPNConfig dataclass

`utils/vpn_config.py` contains a typed hierarchy of dataclasses for all supported protocols:

```python
class VPNConfig(Protocol):
    host: str
    port: int
    def to_xray_outbound(self, tag: str) -> Dict: ...
    def to_url(self) -> str: ...
    def dedup_key(self) -> Tuple: ...
```

This avoids re-parsing URLs (especially for VMess with base64-encoded JSON) and provides a single extension point when adding a new protocol.
