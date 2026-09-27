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
| Legacy mode | `alterId`/`aid` > 0 | The node is on the deprecated MD5 id-cycle. xray's `VMessAccount` has no `alterId` field (it reads `id`/`security`/`experiments`), so the verifier ignores the value and connects with zero alter IDs — the flag judges the deployment, not the handshake |

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
| Plaintext method | `none` or `plain` — xray loads them, and what it loads is a tunnel with no encryption |
| Empty password | Password length = 0 |
| Plugin | Any plugin parameter (not supported) |
| **2022 key length** | The base64 key for `2022-blake3-aes-128-gcm` must decode to 16 bytes, for `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305` — to 32 bytes. The multi-key `key1:key2` format (3x-ui) is skipped — this is an Xray-core feature, not an error. |

**Ciphers xray loads** — `SS_XRAY_CIPHERS`, the cases of `cipherFromString` in
xray's `infra/conf/shadowsocks.go` (checked at v26.3.27):

```
aes-128-gcm, aead_aes_128_gcm, aes-256-gcm, aead_aes_256_gcm,
chacha20-poly1305, chacha20-ietf-poly1305, aead_chacha20_poly1305,
xchacha20-poly1305, xchacha20-ietf-poly1305, aead_xchacha20_poly1305,
2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm,
2022-blake3-chacha20-poly1305, none, plain
```

Anything outside it is `unknown cipher method`, which fails while xray loads the
config — so `utils/xray_compat.py` refuses such a URL before verification rather
than taking the rest of its batch chunk down with it. `none` and `plain` are
inside the allowlist on purpose: they are not a load failure, and catching them
is the security filter's job, which is why both sets appear above.

`SS_SECURE_CIPHERS` is `SS_XRAY_CIPHERS` minus the two plaintext methods. The
sets live in `source/utils/security_filter.py` and are read through
`is_xray_cipher()` by `protocol_parsers.py`, `vpn_config.py` and
`xray_compat.py`; `xray_tester.py` imports none of them and delegates to the
parsers. Both the typed parser and the legacy one lowercase the method before
emitting it, because xray looks the 2022 names up case-sensitively.

**Which spelling the cipher arrives in.** `extract_ss_credentials()` is the single
decoder, and there are four spellings to cover: `method:password@host:port`,
`b64(method:password)@host:port`, `b64(method:password@host:port)` — SIP003, where the
address is inside the token and the URL carries no `@` at all — and the SSR payload.
The third went unread until 2026-09-27, and unread is not neutral here: a URL the
decoder cannot read gets no verdict, and no verdict is what the pipeline records as
clean. A `none` tunnel in that form therefore landed in `all-secure.txt` and
`ss-secure.txt` and entered the secure SNI/CIDR tier, while the verifier decoded the
very same string into `method: none` and connected. The compatibility filter reads
through the same decoder, so a blob carrying a cipher xray cannot load is now refused
by name instead of being handed to the batch.

### ShadowsocksR

Converted to Shadowsocks (SSR protocol and obfuscation are lost, and nothing is
logged about it). The cipher is read through `extract_ss_credentials()`, the same
decoder `ss://` uses, so the allowlist above applies here too. That matters:
`aes-256-cfb` is what ssserver defaulted to, so most SSR nodes are refused
verification for that reason alone.

### Parameter names

Every check looks for a parameter: `?` or `&` before the name, then `&`, `#` or the end of the
string after the value. Some of these used to be plain substring searches over the whole URL,
which was wrong in both directions: `#node-security=none` marked a working config insecure and
took it out of the secure files, while `#say-security=tls` in a remark convinced the "is this
encrypted" test that it was. The search still runs over the whole string — a `?security=none`
that follows a fragment counts — because the only mistake allowed here is letting an
unencrypted tunnel into the secure tier, not the other way round.

A `vmess://` node keeps its settings inside base64, where no parameter boundary
applies, so the payload is cut at its first `#` or `?` before decoding
(`utils/url_payload.py`). The decoders discard characters outside the base64 alphabet
instead of raising, so without that cut the node's own name was decoded as part of its
configuration — and a `vmess://` link with `allowInsecure` inside the payload and a
remark after it read as secure. That is the one case where the parameter-boundary rule
above is not enough: for the base64 forms the remark has to be removed before anything
is judged.

### TUIC

Not supported by Xray-core — the parser returns `None`. The `skip-cert-verify` parameter is considered insecure.

### Hysteria

- Hysteria2: verified through xray's `hysteria` outbound with `version: 2`, TLS required. A node with `insecure=1` and no `pinSHA256` is refused before verification: xray removed `allowInsecure`, so there is nothing left to check such a config against. A `pinSHA256` that is not 32 bytes of hex is refused too — xray hex-decodes it after stripping colons, and a short value aborts the config load rather than failing the handshake
- Hysteria v1: not verified — xray rejects `version != 2` while loading the config, so `utils/xray_compat.py` refuses those URLs with that reason

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
- A refusal of a private address, and a call that asked for no attempt at all, are not part of that count and never remove a line: no request left the process, so neither says anything about the source (`utils/fetch_outcomes.py`, `utils/url_stats.py`). Each is named in the run's report — a refusal with its host and address (`fetchers/destination_guard.py`), a curtailed call with its host and reason (`run_condition()` / `report_run_conditions()`). A fetch that made all of its verified attempts and got through none is the source's own failure, and it ages: the TLS downgrades are off by default, so reach is not bought with the credential
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
