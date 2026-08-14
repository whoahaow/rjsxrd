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
- retry: up to 3 attempts (default) with a 1s wait between attempts. Strategy: attempt 1 — `verify=True`, attempt 2 — `verify=False` (SSL skip), attempt 3 — HTTPS→HTTP downgrade. Timeout 5 s (configurable via `FETCH_TIMEOUT`/`FETCH_MAX_ATTEMPTS`)
- `fetch_data()` accepts `token` — if passed and the URL contains `github.com`/`raw.githubusercontent.com`, the `Authorization: Bearer <token>` header is added to the session. This raises GitHub limits from ~60/h to 5000/h
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

### `deduplicate_configs(configs) -> list`

Removes duplicates based on content (ignoring the name/remark). O(n) in memory.

### `filter_secure_configs(configs) -> list`

Parallel (8 workers) filtering via `has_insecure_setting()`.

## security_filter.py — security filtering

Moved out of `file_utils.py`. Contains:

- **`has_insecure_setting(config_line) -> bool`** — checks one config for insecure parameters. Protected by `lru_cache` (65536 entries). The internal per-protocol logic is described in [Security system](security-system.en.md). Includes key length validation for 2022-blake3 ciphers (`_SS_2022_KEY_LENGTHS`).
- **`filter_secure_configs(configs) -> list`** — parallel filtering via ProcessPoolExecutor (8 workers).
- **`SS_WEAK_CIPHERS` / `SS_SECURE_CIPHERS`** — the single source of truth for Shadowsocks ciphers. Imported by `xray_tester.py` and `protocol_parsers.py`.
- **`_SS_2022_KEY_LENGTHS`** — mapping of 2022-blake3 ciphers to the expected key length (16/32 bytes).

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
| VMess | `_parse_vmess_to_outbound()` | TLS, WS, gRPC, h2 |
| Trojan | `_parse_trojan_to_outbound()` | TLS, Reality, WS, gRPC, HTTPUpgrade |
| Shadowsocks | `_parse_shadowsocks_to_outbound()` | AEAD only |
| SSR | `_parse_ssr_to_outbound()` | Conversion → Shadowsocks |
| Hysteria v2 | `_parse_hysteria2_to_outbound()` | QUIC, TLS |
| Hysteria v1 | `_parse_hysteria_to_outbound()` | Limited |
| TUIC | `_parse_tuic_to_outbound()` | Not supported by Xray (returns None) |

### `create_chain_config(proxy_urls, socks_port)`

Creates a config for a proxy chain. Reverses the hop order, validates the transport (WS/HTTPUpgrade + TLS required).

## xray_batch.py — BatchRunner

Moved out of `xray_tester.py`. Orchestrates concurrent config testing:

- `test_batch()` — async batch (async wrapper with sync fallback)
- `test_single_config()` — single config with retry and parsing
- `_run_single_config_test()` — extracted test loop with progress tracking (extracted from an inner closure)
- `_test_batch_single()` — sync fallback via ThreadPoolExecutor

Owns ETA tracking, progress bars, and result aggregation.

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

Moved out of `utils/xray_tester.py` to reduce the god-module. All 8 parsers live here:

- `parse_vless_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (97→33 lines, uses shared helpers)
- `parse_trojan_to_outbound()` — TLS, Reality, WS, gRPC, HTTPUpgrade (103→32 lines, uses shared helpers)
- `parse_vmess_to_outbound()` — TLS, WS, gRPC, h2 (93 lines, base64 JSON)
- `parse_shadowsocks_to_outbound()` — AEAD only, weak ciphers are rejected
- `parse_ssr_to_outbound()` — conversion → Shadowsocks (uses `_clean_url_part`)
- `parse_hysteria2_to_outbound()` — QUIC, TLS (43 lines)
- `parse_hysteria_to_outbound()` — limited (v1)
- `parse_tuic_to_outbound()` — returns None (not supported by Xray)

**Shared helpers (extracted from VLESS/Trojan/SSR to eliminate duplication):**
- `_clean_url_part(url)` — case-insensitive protocol removal
- `_split_fragment_query(url_part)` — splitting `#fragment`, `?query`, `base`
- `_parse_user_host_port(base)` — parsing `user@host:port`
- `_make_stream_settings(network, security, params, host)` — assembling streamSettings (tls, reality, ws, grpc, httpupgrade)
- `_make_tls_settings()`, `_make_reality_settings()`, `_make_ws_settings()`, `_make_grpc_settings()`, `_make_httpupgrade_settings()` — low-level section builders

Imports `SS_WEAK_CIPHERS` from `security_filter.py`. Each parser is protected by try/except and returns None on error.

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
- **22 tests** via the `FakeGitHubClient` in-memory file tree

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
- 24 tests, all mock-based on `subprocess.run`

## config_helpers.py — common pipeline helpers

Helper functions extracted from config_processor.py:

- `natural_sort_key()` — sorting files with numeric suffixes
- `resolve_flag()` — feature flag resolution from a CLI override or settings
- `add_unique()` — thread-safe config deduplication
- `path_in_output()` — building paths in the output directory
- `try_decode_base64_content()` — trying to decode content from base64
