> **Language:** [Русский](modules.md) · [English](modules.en.md)

# Modules and key functions

## main.py — entry point

Handles CLI arguments, configures the proxy (single, chain, auto-detection), starts ResourceMonitor, and calls `process_all_configs()`.

**CLI arguments** — see the [CLI reference](../operation/cli-reference.en.md).

**Execution flow:**
1. Health check (internet, Xray, GitHub API)
2. Proxy configuration (if specified)
3. Starting resource monitoring
4. `process_all_configs()` — full cycle
5. Upload to GitHub
6. Stopping monitoring → report

## config_processor.py — pipeline orchestrator

The central module that coordinates all processing phases.

### `download_all_configs(output_dir, scan_for_telegram_proxies)`

Parallel download from all sources. Returns a tuple of 5 arrays: main configs, extra-bypass, numbered with URLs, MTProto proxies, SOCKS5 proxies.

**Base64 auto-detection:**
Before decoding, the function checks 4 heuristics:
- Newline ratio (base64 is single-line)
- Presence of `://` (already decoded — not base64)
- Space ratio (base64 has almost none)
- Character composition (only A-Z, a-z, 0-9, +, /, =)

### `create_protocol_split_files(all_configs, output_dir)`

Classifies configs by protocol from the URL prefix and creates separate files with secure/unsecure variants.

### Helper functions (from `file_writer.py`)

These functions are defined in `file_writer.py` and imported into `config_processor.py`:

- `append_remark_suffix(config)` — adds `%20t.me%2Frjsxrd` to each config's remark
- `get_subscription_header(filename)` — generates the subscription header (`#profile-title`, `#profile-update-interval: 48`, etc.)
- `split_configs_to_files(configs, dir, prefix, max=300)` — splits configs into numbered files (parallel writing, up to 8 workers)
- `_write_config_chunk(args)` — module-level worker for parallel chunk writing

## fetchers — download modules

### fetcher.py — basic fetcher

**Key features:**

- `FetchResult` — a dataclass with `text`, `status_code`, `error`, `success` fields. The `fetch_data()` function **never throws exceptions** — always check `.success` before using
- uses a curl_cffi Session with Chrome 124 impersonation — 2-3x faster than requests, bypasses anti-bot systems
- `build_session()` — creates a session with a proxy from `--proxy` or the `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` environment
- retry: up to 3 attempts (default) with a 1s wait between them, and every one of them the same request as the URL spells it, certificate checked when it is https — a failure is retried, not relaxed. Timeout 5 s (configurable via `FETCH_TIMEOUT`/`FETCH_MAX_ATTEMPTS`). `ALLOW_TLS_DOWNGRADE=1` brings back the older ladder (attempt 2 without the certificate check, attempt 3 over plaintext HTTP), which on a network that interferes with TLS is what keeps the fetch yield up. What it buys and what it risks is in [SECURITY.md](../../SECURITY.md)
- every downgrade is visible and counted: `_log_downgrade()` writes the host and the attempt number to the log, the `INSECURE_FETCHES` counter accumulates attempts and hosts, and `report_insecure_fetches()` prints the total at the end of a run next to the URL health report. The client's unverified-request warning is silenced only around the insecure attempt itself, not for the whole process (`_silence_client_tls_warning`). `ALLOW_TLS_DOWNGRADE=1` brings attempts 2 and 3 back; without it nothing downgrades, and the run's report names the policy that ran. A source that fails its verified attempts is a failure of the source: it ages toward removal from `URLS.txt` like any unreachable one. The outcomes that say nothing about a source are the ones where no request left the process — a call that asked for no attempt carries `RUN_CONDITION_PREFIX`, is counted by `RUN_CONDITIONS` and named in the run's report (`report_run_conditions()`), and the URL is not aged for it
- private addresses are not fetched: `_destination_refusal()` checks the **resolved** address rather than the URL text before connecting; a body that arrives after a redirect from a refused address is discarded; and a refusal is a reported error with a warning, never an empty successful result. The only exception is the explicit `FETCH_PRIVATE_ALLOWLIST` (empty by default): an IP literal, a CIDR, or `host` / `host:port`, with a v6 host bracketed the way a URL writes it (`[::1]`, `[::1]:1080`) — and an entry that covers a whole address family (`0.0.0.0/0`, `::/0`) is refused when the setting is read, because that entry switches the guard off rather than widening it. A port-qualified entry covers the port the request will use and no other. A refusal is counted apart from dead sources: `fetchers/destination_guard.py` keeps the `DESTINATION_REFUSALS` counter, and `report_destination_refusals()` (called from `report_fetch_security()` at the end of a run) names each refused host and address. `utils/url_stats.py` recognizes a refusal by the `DESTINATION_REFUSAL_PREFIX` marker from `utils/fetch_outcomes.py` and does **not** raise the URL's failure count: a source refused three times running stays in `URLS.txt` and is named in every run's report, and only three real fetch failures remove the line. An address inside a translation prefix is judged by what it carries: `is_global` reports the whole NAT64 well-known prefix (`64:ff9b::/96`) as global, so `64:ff9b::7f00:1` is 127.0.0.1 in a v6 costume and the metadata endpoint encodes the same way. The carried address is read out of it per RFC 6052 (NAT64), RFC 3056 (`2002::/16`, 6to4) and for the deprecated `::a.b.c.d` form, and the unwrapping only **adds** refusals: a range the plain rule already fails as a whole (such as `64:ff9b:1::/48`, or all of `2002::/16`) stays refused, so nothing that was allowed before is admitted now
- `fetch_data()` accepts `token` — the `Authorization: token <token>` header goes only to the hosts in `GITHUB_TOKEN_HOSTS` (`github.com`, `raw.githubusercontent.com`, `api.github.com`, the last being what the API fallback requests), compared against the URL's **hostname**, so a GitHub name in a path or a query string receives nothing. This raises GitHub limits from ~60/h to 5000/h
- `_extract_status(exc)` — extracts the HTTP status from different exception types

### daily_repo_fetcher.py — daily repositories

Looks for configs in repositories with a date-based naming scheme:

- generates `v2YYYYMMDD1`, `v2YYYYMMDD2` names based on the current date
- `fetch_configs_from_daily_repo()` — checks 7 days back (parameter `lookback_days=7`, was 30), 100 parallel workers
- global deduplication via `seen`/`seen_lock` (a shared set with the main pipeline)

### yaml_converter.py — Clash/Surge YAML

`convert_yaml_to_vpn_configs(yaml_content)`:

1. Parses YAML via `yaml.safe_load()`
2. Recursively processes dictionaries and lists (`_extract_configs_from_dict()`)
3. Extracts proxy sections (`proxies:`, `Proxy:`, `proxy-providers:`)
4. Converts each proxy object into a VPN URL of the required format
5. Validates the result via `is_valid_vpn_config_url()`

### sstap_scraper.py — sstap.org scraping

Extracts VPN configs from the https://sstap.org/node-real-time-update/ page via regular expressions.

**Supported protocols:** VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC.

**Pipeline:** Fetch → regex → deduplication → prepare_config_content.
Built into `download_all_configs()` as an additional source.

### upstream_aggregator.py — dynamic source aggregator

Loads URL lists from mermeroo/V2RAY-CLASH-BASE64-Subscription.Links and Leon406/jsdelivr, filters out only yudou226.top and guidongone links, then downloads configs in parallel (20 workers).

**Features:**
- Two-stage: first the URL list, then downloading each
- Base64 auto-detection for each URL
- Global deduplication via `seen`/`seen_lock`
- 20 parallel workers via ExecutorCache

### telegram_proxy_scraper.py — proxy scraping

Extracts MTProto and SOCKS5 proxies from text content via 10 regular expressions:

**MTProto** (4 patterns): `https://t.me/proxy?...`, `http://t.me/proxy?...`, `t.me/proxy?...` (bare), `tg://proxy?...`

**SOCKS5** (7 patterns): `https://t.me/socks?...`, `http://t.me/socks?...`, `t.me/socks?...`, `tg://socks?...`, `socks5://host:port`, `http://IP:PORT`, `IP:PORT` (bare format)

`_clean_proxy_url()` — removes emoji and non-ASCII characters. `deduplicate_proxies()` — O(n) deduplication via a set.

## file_utils.py — file operations and filtering

### `apply_sni_cidr_filter(configs, filter_secure) -> list`

Filters configs by whitelist files:
1. Loads domains from `whitelist-all.txt`
2. Loads CIDR from `cidrwhitelist.txt`
3. Extracts host:port from each config
4. Keeps only those whose host/ip matches the whitelist
5. If `filter_secure=True` — additionally filters out insecure ones

### `extract_host_port(config_line) -> (host, port)`

Extracts the host and port from a URL of any supported protocol. Deduplication uses the `lru_cache` in `_get_dedup_key()`.

Three handlers decode what `urlparse` cannot see: the vmess JSON, the SSR payload,
and the SIP003 `ss://base64(method:password@host:port)` blob, whose address sits
behind one token with no `@` in the URL at all. Missing that form costs silent
publication: the config stays in every other file, so it reads as filtered rather
than lost. Whatever a handler returns goes through one IPv6 normalisation —
`[2001:db8::1]` is what the URL says, `2001:db8::1` is what `ipaddress.ip_address()`
and the TCP ping accept, and the CIDR whitelist check calls exactly that.

### `deduplicate_configs(configs) -> list`

Removes duplicates based on content (ignoring the name/remark). O(n) in memory.

### `filter_secure_configs(configs) -> list`

Parallel (8 workers) filtering via `has_insecure_setting()`.

## security_filter.py — security filtering

Moved out of `file_utils.py`. Contains:

- **`has_insecure_setting(config_line) -> bool`** — checks one config for insecure parameters. Protected by `lru_cache` (65536 entries). The internal per-protocol logic is described in [Security system](security-system.en.md). Includes key length validation for 2022-blake3 ciphers (`_SS_2022_KEY_LENGTHS`).
- **`filter_secure_configs(configs) -> list`** — parallel filtering via ProcessPoolExecutor (8 workers).
- **`SS_XRAY_CIPHERS` / `SS_WEAK_CIPHERS` / `SS_PLAINTEXT_CIPHERS` / `SS_SECURE_CIPHERS`** — the single source of truth for Shadowsocks ciphers: what xray loads, what counts as weak, what means "no encryption". `SS_SECURE_CIPHERS` is derived from the first two. Read by `protocol_parsers.py`, `vpn_config.py` and `xray_compat.py` through `is_xray_cipher()`.
- **`is_xray_cipher(method) -> bool`** — true for the methods `cipherFromString` in xray knows; anything else is `unknown cipher method` there, which fails the config load.
- **`extract_ss_credentials(config_line) -> tuple | None`** — one decoder for the three encodings in circulation (`method:pass@host`, `b64(method:pass)@host`, and the SSR payload), so the parsers and both filters read the same method. `None` means "no verdict", not "insecure".
- **`_SS_2022_KEY_LENGTHS`** — mapping of 2022-blake3 ciphers to the expected key length (16/32 bytes); it is also the list of 2022 methods xray accepts.

## xray_tester.py — verification via Xray-core

### `test_batch(configs) -> list`

Concurrent testing of a batch of configs.

**Per-config pipeline:**
1. `_quick_validate_url()` — quick URL validation
2. `create_single_outbound_config()` — Xray config generation
3. `start_xray_instance()` — launching an Xray process with a unique port (60 lines, delegates to the lifecycle)
4. `test_through_socks()` — HTTP request via SOCKS5 (`socks5h://`)
5. `stop_xray_process()` — terminating the process

**Extracted lifecycle methods (from `start_xray_instance`, 147→60 lines):**
- `_write_xray_config_file()` — writing the config to a secure tempfile
- `_launch_xray_process()` — launching the Xray subprocess
- `_is_xray_spam()` — spam message filter (banners, runtime info)
- `_cleanup_config_file()` — deleting the temp file

**Platform dispatch:**
- Linux/WSL: async path, up to 300 parallel configs
- Windows: ThreadPoolExecutor, up to 50 parallel configs

**Retry:** maximum 2 attempts per config, exponential delay.

### Protocol parsers (`_url_to_outbound()` → `protocol_parsers.py`)

| Protocol | Method (xray_tester) | Parser capabilities |
|----------|---------------------|---------------------|
| VLESS | `_parse_vless_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| VMess | `_parse_vmess_to_outbound()` | TLS, WS, gRPC, httpupgrade, xhttp (h2 removed from xray; reality declined) |
| Trojan | `_parse_trojan_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| Shadowsocks | `_parse_shadowsocks_to_outbound()` | AEAD only |
| SSR | `_parse_ssr_to_outbound()` | Conversion → Shadowsocks |
| Hysteria2 | `parse_hysteria2_to_outbound()` | outbound `hysteria`, `version: 2`, TLS, finalmask |
| Hysteria v1 | — | no parser: xray rejects `version != 2`, refused before verification |
| TUIC | — | no parser: xray has no TUIC implementation (use sing-box) |

### `create_chain_config(proxy_urls, socks_port)`

Creates a config for a proxy chain. Reverses the hop order, validates the transport (WS/HTTPUpgrade + TLS required).

## xray_batch.py — BatchRunner

Moved out of `xray_tester.py`. Orchestrates concurrent config testing:

- `test_batch()` — async batch (async wrapper with sync fallback)
- `test_single_config()` — single config with retry and parsing
- `_run_single_config_test()` — extracted test loop with progress tracking (extracted from an inner closure)
- `_test_batch_single()` — sync fallback via ThreadPoolExecutor

Owns ETA tracking, progress bars, and result aggregation.

## xray_compat.py — configs xray cannot load

Extracted from `xray_tester.py`, which sat above the module-size ceiling. Pure
inspection of URL strings, with three callers: `bypass_builder.verify_config_file()`
before verification, `create_multi_config()` while building a batch config, and
`XrayTester._quick_validate_url()` so the single-config path refuses the same URLs
for the same reason instead of reporting a parse failure.

- `filter_xray_compatible(configs)` — splits the list into (compatible,
  rejected-with-reason) and logs a per-reason count
- `_xray_incompatible_reason(cfg)` — one reason per config; an empty string means
  it is testable

Refused are the configs that parse and then fail when xray loads the JSON: a dead
UUID, a garbage `encryption=` value, a VLESS `flow=` outside the three xray
switches on, a non-empty `flow=` on trojan, hysteria v1, Hysteria2 with
`insecure=1` and no `pinSHA256` or with a pin that is not 32 bytes of hex, a
`type=` the transport builder cannot resolve (the deleted `h2`, `h3`, `http`,
`quic` and every unregistered name — but not `splithttp` or `mkcp`, which are
aliases it does resolve), an unknown stream `security=`, a Shadowsocks or SSR
cipher outside `SS_XRAY_CIPHERS`, and a Reality `pbk`/`sid` the client builder's
decoders reject. In batch mode one xray process carries up to `XRAY_BATCH_SIZE`
configs, so a failed load costs the whole chunk — which is why the check reads the
URL before anything is built. `none` and `plain` mark where the two filters part:
`xray_compat.py` refuses what xray cannot load, `security_filter.py` flags what it
loads with no encryption.

Not refused: Hysteria2, and Reality over WebSocket or gRPC. xray added the
Hysteria2 outbound in v26.1.13 and the pipeline runs `releases/latest`, and its
Reality client builder never inspects the transport — refusing either discards
configs xray loads and connects with.

## xray_helpers.py — pure Xray helpers

- `wait_for_port(host, port, timeout)` — TCP port wait (used by both xray_tester and ip_verifier)

## bypass_builder.py — bypass config verification

- `_verify_and_write_bypass()` — Xray verification sorted by ping
- `_verify_and_write_bypass_unsecure()` — the same for the unsecure variant
- Consolidated from duplicated logic in config_processor.py

## file_writer.py — config writing

Moved out of `config_processor.py`. Contains:

- `append_remark_suffix()` — adding the `%20t.me%2Frjsxrd` remark suffix
- `get_subscription_header()` — subscription header generation
- `write_configs_file()` / `stream_write_configs_file()` — file writing
- `_write_config_chunk()` — parallel worker for chunk writing
- `split_configs_to_files()` — splitting into numbered files
- `_write_numbered_file()` — writing numbered files (1.txt, 2.txt, ...)
- `create_numbered_default_files()` — creating default/ numbered files
- `_write_protocol_file()` — writing protocol-specific files

## system_specs.py — resource auto-detection

`SystemSpecs.detect()` — a one-time detection at startup: total RAM, CPU cores, WSL, container cgroup limits.

**Methods:**
- `safe_xray_workers()` — RAM-based: `(total - 200) / 24`, capped at `cpu * 40`.
- `safe_url_workers()` — I/O-bound, generous: up to 20.
- `safe_fetch_workers()` — CPU-bound (TLS handshake), auto-detect. Low-CPU: `cpu * 4 + 4`, min 10. 4+ cores: `cpu * 10 + 10`, clamped [20, 50].
- `safe_tcp_workers()` — very light: up to 150.
- `safe_http_workers()` — moderate: up to 20.
- `summary()` — a one-line report (`"956 MB RAM, 1 CPU cores (container)"`).

Cached singleton via `get_specs()` — import-safe lazy init.

## protocol_parsers.py — protocol parsers

Moved out of `utils/xray_tester.py` to reduce the god-module. All six protocol parsers live here:

- `parse_vless_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (97→33 lines, uses shared helpers)
- `parse_trojan_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (103→32 lines, uses shared helpers)
- `parse_vmess_to_outbound()` — TLS, WS, gRPC, httpupgrade, xhttp through the shared builder; a boolean `"tls": true` from an older export is normalised to `"tls"`; no h2 branch, xray deleted that transport
- `parse_shadowsocks_to_outbound()` — only the ciphers in `SS_XRAY_CIPHERS`, emitted lowercased
- `parse_ssr_to_outbound()` — conversion → Shadowsocks (uses `_clean_url_part`), same cipher allowlist
- `parse_hysteria2_to_outbound()` — the outbound xray documents: `protocol: "hysteria"`, `version: 2`, TLS, `finalmask.udp` for salamander obfuscation
- Hysteria v1 has no parser at all: xray cannot load that version, so the compatibility filter refuses those URLs instead
- TUIC has no parser: xray implements no TUIC outbound, so a `tuic://` URL resolves to no config at all

**URL helpers (extracted from VLESS/Trojan/SSR to eliminate duplication):**
- `_clean_url_part(url)` — case-insensitive protocol removal
- `_split_fragment_query(url_part)` — splitting `#fragment`, `?query`, `base`
- `_parse_user_host_port(base)` — parsing `user@host:port`

The `streamSettings` blocks are built in `xray_stream_settings.py`, described next.

Imports `is_xray_cipher()` from `security_filter.py`. Every parser has to return None rather than raise — that is a contract, not a hope: the SSR password shape that used to leak `UnboundLocalError` out of the decoder is pinned by a test.

## xray_stream_settings.py — streamSettings builders

Split out of `protocol_parsers.py` when that file passed the module-size ceiling.
Pure builders: no URL parsing, no protocol knowledge, one job — emit keys xray's
`StreamConfig` reads (checked against `infra/conf/transport_internet.go` at
v26.3.27). `utils/vpn_config.py` builds the same blocks on the typed path, and
`test_stream_settings_builders.py` asserts the two agree key for key.

- `_make_stream_settings(network, security, params, host)` — the whole block: tls or reality plus the transport settings
- `_make_tls_settings()`, `_make_reality_settings()`, `_make_ws_settings()`, `_make_grpc_settings()`, `_make_httpupgrade_settings()`, `_make_xhttp_settings()` — the section builders
- `apply_tls_fragment(stream)` — the `finalmask.tcp` stage that makes `ENABLE_FRAGMENT` real; the verifier calls it, not a URL parser
- `_WS_NAMES` / `_XHTTP_NAMES` — the transport pairs `TransportProtocol.Build()` resolves to one protocol; dispatching on the literal `"ws"` left `type=websocket` with no settings block, so its path and host never reached the handshake
- `vmess_security(raw)` — reads a vmess object's `tls` field, which arrives as `"tls"`, `"none"`, a bare JSON `true`, or `"reality"`. `StreamConfig` matches `security` as a string, so a `true` reaching the outbound was `Unknown security "true"` — a load failure, not a failed connection

Two shapes are deliberate. `wsSettings`, `httpupgradeSettings` and `xhttpSettings`
carry `host` rather than a `headers` map: xray honors a host hidden in `headers`
only as a fallback and prints a deprecation warning for it. And `fingerprint`
belongs inside `tlsSettings`/`realitySettings` — `StreamConfig` has no fingerprint
key, so the `streamSettings.fingerprint` this repo used to write was dropped in
silence, while a blank or unknown value in the place xray does read aborts the
config load.

## config_helpers.py — pipeline helpers

Extracted from `config_processor.py`. Pure functions:

- `natural_sort_key(path)` — sorting files with numeric suffixes
- `resolve_flag(name, overrides, default)` — feature flag resolution
- `add_unique(configs, target, seen, seen_lock)` — thread-safe deduplication
- `path_in_output(output_dir, *parts)` — building paths via os.path.join
- `try_decode_base64_content(content)` — heuristic base64 detection

## merged_config_generator.py — merged configs

**DELETED** as part of the refactoring (2026-06). The functionality was not used in the main pipeline.

## logger.py — thread-safe logging

- `log(message, level)` — adds a message to the global `LOGS_BY_FILE[file_index]`
- **File index extraction:** via the regex `githubmirror/(\d+)\.txt` — logs are grouped by file number
- `print(formatted, file=sys.stderr, flush=True)` — output to stderr (so as not to interfere with tqdm)
- **Levels:** DEBUG, INFO, WARNING, ERROR, CRITICAL (INFO by default, switched with `--verbose`)
- `print_logs()` — ordered output by file index, then general messages
- `extract_source_name(url)` — extracts a readable source name from the URL

## simple_tester.py — TCP ping

A fast alternative to Xray for the --tcp-ping mode. Uses asyncio for TCP connections. The same return interface as `XrayTester.test_batch()`.

## smart_eta.py — smart ETA

Solves the problem of an overestimated speed due to fast configs finishing first.

**Algorithm:**
1. **Three-component estimate** — max of three approaches: sliding window (fast reaction to changes), global speed (stable over the whole run), duration EMA (independent of the order of fast/slow)
2. **Duration EMA** — exponential moving average, updated on each config. Quickly adapts to distribution changes
3. **Timeout floor** — a physical lower bound: `ceil(remaining / concurrency) * timeout` (without the 0.8 discount)
4. **Dynamic window** — the size depends on the total number of configs: `max(500, min(total // 10, 5000))`

Integrated into all testers: XrayTester, SimpleTester, TelegramProxyVerifier.

## url_stats.py — URL statistics

Collects persistent statistics in `data/url_stats.json`:

- `record_fetch(url, success)` — URL fetch result
- `record_config_yield(url, raw_count, secure_count)` — config yield (by source)
- `record_verified_yield(config_url, worked)` — verification result (reverse mapping)
- `get_dead_urls()` — URLs with 3+ consecutive errors
- `get_dead_configs()` — servers.txt configs with 3+ verification failures
- `remove_dead_from_urls_txt()` — auto-removal of dead URLs
- `remove_dead_from_servers_txt()` — auto-removal of dead configs

## proxy_detector.py — proxy auto-detection

Scans localhost on common proxy ports:

| Port | Usually used by |
|------|---------------------|
| 10808 | v2rayN, Hiddify |
| 2080 | NekoRay |
| 7890, 7891 | Clash |
| 1080 | SOCKS standard |
| 8080 | HTTP proxy |

## ip_verifier.py — IP check, proxy setup

Merged with `ip_checker.py` (deleted). Contains:

- `get_real_ip()` / `get_proxy_ip()` — determining the external IP (without a proxy / through a proxy)
- `setup_global_proxy(url)` — launching Xray for a single proxy
- `setup_proxy_chain(urls)` — launching Xray with a dialerProxy chain
- `verify_protection(port)` — checking that the proxy actually hides the IP
- `_make_request()` — HTTP request with curl_cffi (requests fallback)
- `IP_CHECK_URLS` — list of URLs for IP checking
- `_clear_proxy_env_vars()` — clearing HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (registered in ProcessRegistry)
- `_json_payload()` / `_json_str_field()` / `_json_nested_str_field()` — validated reads of a provider response: a body that is not a JSON object (an array, a scalar) reads as no fields instead of raising `AttributeError`
- `setup_proxy_chain()` — a provider that names no IP (a body that is not a JSON object, no `ip` field, an empty body) counts as a failure: the loop moves on to the next provider, and a chain is never reported as working with an empty exit address; when no provider names an IP, the result is the `Failed to get IP through proxy chain` error
- Readers on top of `_json_payload()`: `_json_ip_field()`, `_json_org_field()`, `_plain_text_body()` — the same contract: a missing field or a body of the wrong type means no value, not an exception

## resource_monitor.py — resource monitoring

A background thread (sample_interval=2 s), collects via psutil:
- CPU load (process + system)
- RAM (RSS, VMS, percentage)
- Network traffic (sent/received per session)

At the end, prints a summary report.

## github_handler.py — GitHub API

- `_GitHubClient` — an abstract protocol for test isolation. Implementations: `_PyGithubClient` (real, PyGithub) and `FakeGitHubClient` (in-memory for tests)
- `upload_multiple_files(file_pairs)` — parallel file upload (ThreadPoolExecutor)
- `upload_file(local_path, remote_path)` — single file upload with SHA conflict resolution
- SHA conflicts are resolved with an exponential delay (base 0.5 s, up to 5 attempts)
- Content comparison before upload — avoids empty commits
- `_check_rate_limit()` — warns at < 100 requests, waits for reset if the limit is exhausted
- Rate limit check at initialization: `g.rate_limiting`
- Tests via the `FakeGitHubClient` in-memory file tree — the count is in the [test table](testing.en.md)

## git_updater.py — Git commands

- `commit_and_push_files(file_pairs)` — full cycle: configure → squash auto → stage → commit → push
- For VPS cron (primary) and GitHub Actions (fallback); does not require a GitHub API token
- `configure_git()` — sets `user.name` and `user.email` for commits
- `pull(branch)` — pull with rebase; with unstaged changes does `reset --hard` + `clean -fd`
- Retry on a push conflict: `pull --rebase` instead of blind waiting (up to 3 attempts)
- All commands with a 60 s timeout
- Before stage_files() calls `git_auto_cleaner.squash_auto_commits()` for auto-cleaning

## git_auto_cleaner.py — history auto-cleaning

Automatically removes old `auto: update ...` commits before creating a new one, so the git history does not get cluttered.

### `squash_auto_commits(repo_dir) -> int`

- Walks back from HEAD, collecting contiguous auto-commits (messages starting with `auto: update `)
- Does `git reset --soft` to the last real commit — all changes stay in the index
- Only with 2+ auto-commits in a row (a single auto is left alone)
- Returns the number of squashed commits (0 = nothing done)
- Called from `GitUpdater.commit_and_push_files()` automatically, before stage_files()
- **Does not touch** other commit types (fix:, feat:, chore:, merge:, and the old formats Update bypass-, update configs)
- **Requires `fetch-depth: 0`** in GitHub Actions (full history) — configured in `frequent_update.yml`
- Tests, all mock-based on `subprocess.run`; the count is in the [test table](testing.en.md)

### How much of the history the auto-commits account for

`main`'s history is mostly auto-updates. Measured on 18 September 2026 on branch
`main` at commit `71972831`: 6894 commits, 6700 of them (**≈ 97.2 %**) start
with `auto: update`, and the remaining 194 (≈ 2.8 %) are every other piece of
text the history carries (`reinit`, `feat:`, `fix:`, `docs:`, `chore:` and the
old labels such as `Update bypass-`). That is why `git log` reads the way it
does: the hourly update job commits every change, and `squash_auto_commits()`
only squashes *runs* of consecutive auto-commits, so the fresh ones stay visible
one by one.

The share is anchored to a commit rather than to HEAD: every hand-written commit
lowers it a little (it moved from 97.5 % to 97.2 % across the two previous
commits), so a HEAD-relative figure is wrong one commit after it is
written. `71972831` was the tip of `main` when this was measured, and
`source/tests/test_docs_figures.py` checks that the anchor and both shares stay
in place.

To re-measure:

```bash
git rev-list --count 71972831                              # 6894
git log --format=%s 71972831 | grep -c '^auto: update'     # 6700
git log --format=%s 71972831 | grep -vc '^auto: update'    # 194
```

## config_helpers.py — common pipeline helpers

Helper functions extracted from config_processor.py:

- `natural_sort_key()` — sorting files with numeric suffixes
- `resolve_flag()` — feature flag resolution from a CLI override or settings
- `add_unique()` — thread-safe config deduplication
- `path_in_output()` — building paths in the output directory
- `try_decode_base64_content()` — trying to decode content from base64
