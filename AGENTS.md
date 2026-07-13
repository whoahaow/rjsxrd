# AGENTS.md - AI Coding Agent Instructions for rjsxrd

## Project Overview

**rjsxrd** is an automatically updated collection of public VPN configurations (V2Ray/VLESS/Trojan/VMess/Reality/Shadowsocks/Hysteria2/TUIC). The project generates and maintains config files that update every hour via VPS cron (primary) and every 2 days via GitHub Actions (fallback).

**Key Features:**
- Automatic config verification via Xray-core (sorted by ping speed)
- Two-tier file system: Raw files (`/raw/`) + Verified files (tested & sorted)
- Security filtering (removes insecure configs with `allowInsecure`, weak ciphers, etc.)
- SNI/CIDR filtering for mobile whitelist bypass
- Telegram proxy scraping and verification (MTProto/SOCKS5)
- Protocol-specific file splitting
- Proxy chain support (--proxy-chain flag)
- Parallel processing with platform-aware concurrency

---

## Repository Structure

```
rjsxrd/
├── githubmirror/           # Generated config files (output)
│   ├── default/            # Main configs (1.txt, 2.txt, all.txt, all-secure.txt)
│   ├── bypass/             # SNI/CIDR filtered configs (secure only)
│   │   ├── raw/            # Untested configs
│   │   └── bypass-all.txt  # Verified, sorted by ping
│   ├── bypass-unsecure/    # SNI/CIDR filtered (includes insecure)
│   │   ├── raw/
│   │   └── bypass-unsecure-all.txt
│   ├── split-by-protocols/ # Protocol-specific files
│   │   ├── vless.txt, vless-secure.txt
│   │   ├── vmess.txt, vmess-secure.txt
│   │   └── ... (trojan, ss, ssr, tuic, hysteria, hy2)
│   └── tg-proxy/           # Telegram proxies
│       ├── all.txt, MTProto.txt, socks.txt
├── qr-codes/               # PNG QR codes for mobile import
├── source/                 # Python source code
│   ├── data/               # Persistent URL stats (gitignored, local only)
│   ├── main.py             # Entry point (orchestration, CLI args)
│   ├── config/
│   │   ├── settings.py     # Global settings, URLs, tokens (includes constants that were in constants.py pre-refactor)
│   │   ├── URLS.txt        # Source URLs (sections: default, extra_bypass, yaml, telegram)
│   │   ├── servers.txt     # Manual VPN servers to add
│   │   ├── tg_proxies.txt  # Manual Telegram proxies
│   │   ├── whitelist-all.txt      # SNI domains for bypass
│   │   └── cidrwhitelist.txt      # CIDR IPs for bypass
│   ├── fetchers/
│   │   ├── fetcher.py             # HTTP fetcher (curl_cffi)
│   │   ├── daily_repo_fetcher.py  # Daily-updated repo scraper
│   │   ├── yaml_converter.py      # Clash/Surge YAML → VPN URLs
│   │   ├── telegram_proxy_scraper.py  # MTProto/SOCKS5 extractor
│   │   ├── sstap_scraper.py       # sstap.org node real-time scrape
│   │   └── upstream_aggregator.py # yudou226.top + guidongone dynamic configs
│   ├── processors/
│   │   ├── config_processor.py        # Pipeline orchestration (ConfigPipeline class)
│   │   └── telegram_proxy_processor.py # Telegram proxy processing
│   ├── utils/
│   │   ├── config_helpers.py    # Helper utilities (extracted from config_processor)
│   │   ├── curl_import.py       # Shared curl_cffi import (single source of truth)
│   │   ├── file_utils.py          # File ops, SNI/CIDR, protocol helpers
│   │   ├── security_filter.py     # has_insecure_setting() + cipher sets (SS_WEAK_CIPHERS/SS_SECURE_CIPHERS)
│   │   ├── vpn_config.py          # VPNConfig typed dataclass hierarchy
│   │   ├── managed_process.py     # ManagedProcess for subprocess lifecycle
│   │   ├── process_registry.py    # Unified ProcessRegistry (replaces 3 old registries)
│   │   ├── config_tagger.py       # ConfigTagger for single-pass protocol/source tagging
│   │   ├── psutil_available.py    # Shared psutil import (single source of truth)
│   │   ├── telegram_notifier.py   # Telegram bot notifications (start/success/error)
│   │   ├── system_specs.py        # SystemSpecs — auto-detect RAM/CPU/cgroups at startup
│   │   ├── protocol_parsers.py    # Standalone protocol parsers (extracted from xray_tester)
│   │   ├── xray_tester.py         # Xray-core concurrent testing
│   │   ├── simple_tester.py       # TCP ping (asyncio, no Xray needed)
│   │   ├── smart_eta.py           # Smart ETA (sliding window, timeout floor, batch drain)
│   │   ├── logger.py              # Thread-safe logging
│   │   ├── progress.py            # Consolidated tqdm import (single try/except)
│   │   ├── executor_cache.py      # ThreadPoolExecutor pooling with WSL-aware sizing
│   │   ├── bypass_builder.py       # Bypass config verification pipeline
│   │   ├── file_writer.py          # Config file writing helpers
│   │   ├── xray_batch.py           # BatchRunner for concurrent Xray testing
│   │   ├── xray_helpers.py         # Pure helper functions for Xray testing
│   │   ├── ip_verifier.py         # IP verify + proxy setup (single+chain), merged from ip_checker
│   │   ├── proxy_detector.py      # Auto-detect active proxies
│   │   ├── proxy_monitor.py       # Background proxy chain health monitoring
│   │   ├── resource_monitor.py    # CPU/RAM/network tracking
│   │   ├── download_xray.py       # Xray binary installer
│   │   ├── url_stats.py           # URL fetch & config yield statistics (typed @dataclass schema)
│   │   ├── health_check.py        # Pre-run internet/Xray/GitHub API health check
│   │   ├── _sni_worker.py         # SNI/CIDR filter chunk worker (internal)
│   │   ├── github_handler.py      # GitHub API uploads
│   │   ├── git_updater.py         # Git commits (Actions mode)
│   │   └── git_auto_cleaner.py    # Auto squash auto commits at HEAD before new ones
│   ├── scripts/
│   │   ├── purge_dead_urls.py      # Remove dead URLs from URLS.txt
│   │   ├── purge_stale_urls.py     # Remove stale URLs (by git timestamp)
│   │   ├── analyze_url_stats.py    # URL statistics analysis
│   │   ├── benchmark_configs.py    # Xray/TCP ping benchmarking (--mode xray|tcp)
│   │   ├── test_telegram_proxies.py # Proxy testing
│   │   └── setup-vps.sh           # VPS setup script
│   ├── tests/
│   │   ├── conftest.py            # Pytest fixtures
│   │   ├── test_fetcher.py        # 16 fetcher tests
│   │   ├── test_file_utils.py     # 26+ file utils tests
│   │   ├── test_config_processor.py # 45+ processor tests
│   │   ├── test_config_tagger.py  # ConfigTagger tests
│   │   ├── test_executor_cache.py # ExecutorCache tests
│   │   ├── test_ip_checker.py     # IP checker tests
│   │   ├── test_ip_verifier.py    # IP verifier tests
│   │   ├── test_logger.py         # Logger tests
│   │   ├── test_managed_process.py # ManagedProcess lifecycle tests
│   │   ├── test_process_registry.py # ProcessRegistry tests
│   │   ├── test_progress.py       # Progress bar tests
│   │   ├── test_proxy_monitor.py  # Proxy monitor tests
│   │   ├── test_security_filter.py # Security filter tests
│   │   ├── test_simple_tester.py  # 25 TCP ping tests
│   │   ├── test_smart_eta.py      # 27 SmartETA tests
│   │   ├── test_telegram_proxy_scraper.py # 27 Telegram tests
│   │   ├── test_telegram_proxy_verifier.py # Telegram proxy verifier tests
│   │   ├── test_url_stats.py      # URL stats tests
│   │   ├── test_vpn_config.py     # VPNConfig typed dataclass tests
│   │   ├── test_github_handler.py # 22 GitHub handler tests (adapter pattern)
│   │   ├── test_git_updater.py    # 26 GitUpdater workflow tests
│   │   ├── test_health_check.py  # 21 health check tests (DNS fallback, disk, memory)
│   │   ├── test_xray_tester.py    # Xray tester + security edge case tests
│   │   ├── test_yaml_converter.py # 28 YAML converter tests
│   │   └── README.md
│   └── requirements.txt
├── docs/                   # Documentation (user, operation, development — see docs/index.md)
├── .github/workflows/
│   └── frequent_update.yml # GitHub Actions (every 2 days)
├── pyproject.toml          # Project config (ruff, mypy, black, pytest)
├── README.md
└── AGENTS.md              # This file
```

---

## Core Architecture

### Pipeline Flow

```
1. DOWNLOAD PHASE (parallel fetching)
   ├─ Fetch from URLS.txt (default section) → all_configs
   ├─ Fetch from URLS.txt (extra_bypass section) → extra_bypass_configs
   ├─ Fetch from URLS.txt (yaml section) → convert YAML → VPN URLs
   ├─ Fetch from daily-updated repo → daily_configs
   ├─ Load manual servers → manual_configs
   ├─ URLStats.record_fetch() per URL (persistent across runs)
   └─ Scan content for Telegram proxies → mtproto_proxies, socks5_proxies

2. DEFAULT FILES GENERATION
   ├─ create_numbered_default_files() → 1.txt, 2.txt, ... (by source)
   ├─ create_all_configs_file() → all.txt (deduplicated)
   └─ create_secure_configs_file() → all-secure.txt (security-filtered)

3. BYPASS FILES GENERATION
   ├─ apply_sni_cidr_filter() → sni_cidr_filtered
   ├─ Add extra bypass configs (no SNI/CIDR filter)
   ├─ Deduplicate + security filter
   ├─ URLStats.record_config_yield() per source (raw + secure counts)
   └─ Create raw files (bypass-all-raw.txt in /raw/)

4. PROTOCOL SPLITTING
   ├─ Classify by protocol (vless, vmess, trojan, ss, ssr, tuic, hysteria, hy2)
   ├─ Create secure variants (filter insecure)
   └─ Create unsecure variants (all configs)

5. TELEGRAM PROXY PROCESSING
   ├─ Merge scraped + manual proxies
   ├─ Verify and sort by latency
   └─ Create all.txt, MTProto.txt, socks.txt

6. PRE-VERIFY UPLOAD (API mode only)
   ├─ Upload all generated files immediately (default, raw, protocols, tg proxies)
   └─ Users see partial results within seconds, not minutes

7. VERIFICATION + PROGRESSIVE UPLOAD
   ├─ _verify_config_file() → Xray-core verification (batches of 300)
   ├─ Every 300 working configs:
   │   ├─ Write bypass-N.txt (bypass-1.txt, bypass-2.txt, ...)
   │   ├─ Upload immediately to GitHub
   │   └─ Same for bypass-unsecure-N.txt
   ├─ URLStats.record_verified_yield() per source (via reverse mapping)
   └─ After all raw files: catch-up progressive write for accumulated results

8. FINAL UPLOAD (API mode only)
   ├─ Upload bypass-all.txt, bypass-unsecure-all.txt (full sorted list)
   ├─ Upload URLS.txt, servers.txt (auto-cleanup persistence)
   └─ Progressive files are overwritten with final sorted versions

9. GIT MODE (Actions, fallback)
   └─ Single commit + push of all file_pairs at the end
```

### Key Modules

#### `main.py` - Entry Point
- Parses CLI args: `--dry-run`, `--skip-xray`, `--tcp-ping`, `--use-git`, `--no-proxy-check`, `--proxy=<url>`, `--proxy-chain=<urls>`, `--verbose`
- Plus 10 feature-flag overrides: `--enable-default-files`, `--disable-default-files`, `--enable-bypass-unsecure`, `--disable-bypass-unsecure`, `--enable-protocol-split`, `--disable-protocol-split`, `--enable-tg-proxy`, `--disable-tg-proxy`, `--publish-raw-files`, `--no-publish-raw-files`
- Manages proxy setup (single, chain, auto-detect)
- Calls `process_all_configs()` via `ConfigPipeline` class from config_processor
- **Progressive upload**: In API mode, creates `upload_fn` that calls `GitHubHandler.upload_file()` and passes it into the pipeline for pre-verify + during-verify uploads
- Handles signal handlers for graceful shutdown (stop monitors → cleanup via ProcessRegistry → exit)
- Activates ResourceMonitor for CPU/RAM/network tracking with end-of-run report
- Runs health check (internet, Xray, GitHub API) before starting

#### `processors/config_processor.py` - Pipeline Orchestrator
- `download_all_configs()` - Parallel fetching from all sources
- `create_numbered_default_files()` - Source-specific files
- `create_all_configs_file()` - Merged unique configs
- `create_secure_configs_file()` - Security-filtered configs
- `apply_sni_cidr_filter()` - SNI/CIDR whitelist filtering
- `create_working_config_files()` - Xray verification & sorting
- `create_protocol_split_files()` - Protocol-specific outputs
- `process_all_configs()` - Main orchestration function (accepts `upload_fn` for progressive upload)
- `ConfigPipeline.run()` - 9-stage pipeline with pre-verify upload (stage 6) before verification (stage 7)

#### `utils/file_utils.py` - Core Utilities
- `apply_sni_cidr_filter()` - SNI/CIDR whitelist filtering
- `extract_host_port()` - Extract (host, port) from any protocol URL (vless, vmess, trojan, ss, ssr, hysteria, hysteria2, tuic)
- `deduplicate_configs()` - Remove duplicates ignoring name/remark
- `prepare_config_content()` - Normalize & split glued configs
- `is_valid_vpn_config_url()` - Validate protocol format

#### `utils/security_filter.py` - Security Filtering
- `has_insecure_setting()` - Security check for all protocols (cached via lru_cache)
- `filter_secure_configs()` - Parallel security filtering via ProcessPoolExecutor
- `SS_WEAK_CIPHERS`/`SS_SECURE_CIPHERS` - Unified cipher sets (single source of truth, imported by xray_tester.py and protocol_parsers.py)

#### `utils/system_specs.py` - System Auto-Detection
- `SystemSpecs.detect()` - Detect total RAM, CPU cores, WSL, container cgroup limits
- `safe_xray_workers()` - Concurrency cap based on available RAM (24MB per process, 200MB headroom)
- `safe_url_workers()` / `safe_tcp_workers()` / `safe_http_workers()` - Per-workload concurrency
- Cached instance via `get_specs()` — import-safe lazy initialization

#### `utils/protocol_parsers.py` - Standalone Protocol Parsers
- Extracted from `utils/xray_tester.py` to reduce god-module size
- All 8 parsers: `parse_vless_to_outbound()`, `parse_vmess_to_outbound()`, `parse_trojan_to_outbound()`, `parse_shadowsocks_to_outbound()`, `parse_hysteria2_to_outbound()`, `parse_hysteria_to_outbound()`, `parse_ssr_to_outbound()`, `parse_tuic_to_outbound()`
- **Shared helpers**: `_clean_url_part()`, `_split_fragment_query()`, `_parse_user_host_port()`, `_make_stream_settings()`, `_make_tls_settings()`, `_make_reality_settings()`, `_make_ws_settings()`, `_make_grpc_settings()` — extracted to shorten parsers (VLESS 97→33, Trojan 103→32 lines)
- Imported by xray_tester.py (`_url_to_outbound()` dispatches to these)
- Uses cipher sets from `security_filter.py` (single source of truth)

#### `utils/smart_eta.py` - Smart ETA Estimator
- `SmartETA` class — 3-way estimate (window rate, global rate, EMA duration) + timeout floor
- Designed for 30k-100k configs at 150-300 concurrency
- `record_completion()` — call per config tested, tracks duration and updates EMA
- `eta` — remaining time in seconds, conservative (max of all 3 estimates)
- `description` — formatted ETA string (`"32s"` / `"2.1m"` / `"1.3h"`)
- Timeout floor: `ceil(remaining/concurrency) * timeout` prevents optimistic ETA early on
- EMA of per-config duration updates every completion (not just per batch)
- Window size scales with total: `max(500, min(total//10, 5000))`
- Injected into all testers: XrayTester (async+sync), SimpleTester, TelegramProxyVerifier

#### `utils/url_stats.py` - URL Statistics & Auto-Cleanup
- `URLStats` class with persistent JSON storage (`data/url_stats.json`)
- `record_fetch()` - Track fetch success/failure per URL (thread-safe)
- `record_config_yield()` - Track raw/secure config counts per source
- `record_verified_yield()` - Track verified config counts per source (reverse mapping)
- `record_config_verification()` - Track per-config health for servers.txt
- `get_dead_urls()` - URLs with 3+ consecutive fetch failures
- `get_dead_configs()` - servers.txt configs with 3+ consecutive verification failures
- `remove_dead_from_urls_txt()` / `remove_dead_from_servers_txt()` - Auto-cleanup
- `print_report()` - Console report at end of pipeline

#### `utils/xray_tester.py` - Xray-Core Testing
- `test_batch()` - Concurrent config testing
- `create_single_outbound_config()` - Single config Xray JSON
- `create_chain_config()` - Proxy chain Xray JSON (dialerProxy)
- `start_xray_instance()` - Launch Xray process (60-line orchestrator, delegates to extracted lifecycle methods)
- `_write_xray_config_file()` - Write config to secure temp file (extracted from start_xray_instance)
- `_launch_xray_process()` - Launch xray subprocess (extracted)
- `_is_xray_spam()` - Filter xray log spam (extracted)
- `_cleanup_config_file()` - Remove temp config file (extracted)
- `test_through_socks()` - HTTP ping through SOCKS
- **Protocol parsers** (dispatched from `_url_to_outbound()` to `protocol_parsers.py`):
  - `parse_vless_to_outbound()` - Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
  - `parse_vmess_to_outbound()` - Full support (TLS, WS, gRPC, h2)
  - `parse_trojan_to_outbound()` - Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
  - `parse_shadowsocks_to_outbound()` - Full support (AEAD only, weak ciphers rejected)
  - `parse_ssr_to_outbound()` - Limited (converted to Shadowsocks)
  - `parse_hysteria2_to_outbound()` - Full support (QUIC, TLS)
  - `parse_hysteria_to_outbound()` - Limited (v1, may not work with all servers)
  - `parse_tuic_to_outbound()` - Returns None (not supported by Xray-core)
- **Security validation**:
  - Cipher sets imported from `security_filter.py` (`SS_SECURE_CIPHERS`, `SS_WEAK_CIPHERS`)
  - Empty password validation (Shadowsocks/SSR)
  - TLS SNI validation (VMess, Trojan, Hysteria)
  - Reality publicKey validation (VLESS, Trojan)
  - Plugin rejection (Shadowsocks)
  - Insecure TLS warnings (Hysteria)
- Platform-aware concurrency (Linux: 300, Windows: 50)

#### `utils/xray_batch.py` - BatchRunner
- `BatchRunner` class — orchestrates concurrent/single-config tests from an XrayTester instance
- `test_batch()` - Concurrent config testing via async wrapper (sync fallback)
- `test_single_config()` - Single config test with retry
- `_run_single_config_test()` - Extracted test loop with progress tracking (extracted from inner closure)
- `_test_batch_single()` - Sync fallback path with ThreadPoolExecutor
- Owns ETA tracking, progress bars, and result aggregation

#### `utils/xray_helpers.py` - Xray Pure Helpers
- `wait_for_port()` - Poll TCP port until listening or timeout

#### `utils/bypass_builder.py` - Bypass Config Verification
- `verify_config_file()` - Xray/TCP verification of configs with optional progress callback
- `write_progressive_bypass_files()` - Write bypass-N.txt files from working set and upload (called every 300 working configs)
- `verify_and_write_bypass()` - Xray verification + sorted output for bypass files (supports progressive upload via callback)
- `verify_and_write_bypass_unsecure()` - Same for unsecure bypass variant
- `create_working_config_files()` - Entry point: orchestrates secure + unsecure verification with progressive upload
- Consolidated from duplicated logic in config_processor.py

#### `utils/file_writer.py` - Config File Writing
- `_write_config_chunk()` - Parallel worker for writing config chunks
- `_write_numbered_file()` - Write numbered split files
- `_write_protocol_file()` - Write protocol-specific files
- Extracted from config_processor.py to reduce god-module size

#### `utils/github_handler.py` - GitHub API
- `_GitHubClient` abstract protocol + `_PyGithubClient` (real) / `FakeGitHubClient` (test adapter)
- `upload_multiple_files()` - Parallel file uploads
- `upload_file()` - Single file upload with conflict resolution (409 retry) and content comparison
- Conflict resolution with exponential backoff
- Content comparison to avoid unnecessary commits

#### `utils/git_updater.py` - Git Commands
- `commit_and_push_files()` - Git-based updates (Actions mode)
- `pull()` with rebase, fallback to `reset --hard` on unstaged changes
- Retry loop: `pull --rebase` on push conflict instead of blind sleep
- Operations timeout at 60s
- Auto-squash auto commits via `git_auto_cleaner.squash_auto_commits()` before staging

#### `utils/git_auto_cleaner.py` - Auto Commit Cleanup
- `squash_auto_commits()` - Walk back from HEAD, squash contiguous `auto: update ...` commits into index via `git reset --soft`
- Only activates when 2+ auto commits at tip (single auto commit is left alone)
- Called from `GitUpdater.commit_and_push_files()` before `stage_files()` — zero boilerplate for callers
- Never touches other commit types (`fix:`, `feat:`, `chore:`, `merge:`, or old formats like `Update bypass-`, `update configs`)
- **Requires `fetch-depth: 0`** in GitHub Actions (full history) — updated in `frequent_update.yml`
- Idempotent — safe to call multiple times, no-op when nothing to squash

---

## Security Filtering (`has_insecure_setting()`)

### VMess
- `insecure`, `allowInsecure` = true/1/'true'/'1'
- `security`/`scy` = 'none'
- `alterId`/`aid` > 0 (MD5 authentication vulnerability)
- **Parser validation**: TLS requires non-empty SNI, h2 host array properly formatted

### VLESS
- `allowInsecure`, `insecure` in URL params
- `security=none`
- `encryption=none` (without TLS/REALITY)
- **Parser validation**: Reality requires non-empty `sni` AND `publicKey`

### Trojan
- `allowInsecure`, `insecure` params
- **Parser validation**: Reality requires non-empty `sni` AND `publicKey`, HTTPUpgrade uses `headers.Host` format

### Shadowsocks
- **Module-level cipher sets** (`SS_WEAK_CIPHERS`, `SS_SECURE_CIPHERS`) — single source of truth in `security_filter.py`, imported by `xray_tester.py` and `protocol_parsers.py`
- Weak ciphers: `rc4`, `des`, `rc4-md5`, `aes-*-cfb`, `aes-*-cfb8`, `aes-*-cfb1`, `aes-*-cfb-fast`, `aes-*-cfb-simple`, `aes-*-ctr`, `bf-cfb`, `camellia-*-cfb`, `cast5-cfb`, `des-cfb`, `idea-cfb`, `rc2-cfb`, `seed-cfb`, `salsa20`, `chacha20`, `xsalsa20`, `xchacha20` (REJECTED)
- Secure AEAD: `aes-*-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-*`
- Empty passwords REJECTED
- Plugins NOT supported (rejected with log message)
- **2022 key length validation**: `2022-blake3-aes-128-gcm` requires 16-byte base64 key, `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305` require 32-byte base64 key. Wrong-length base64 keys are rejected. Multi-key format (`key1:key2` used by 3x-ui) is NOT rejected — it's a legitimate Xray-core feature.

### ShadowsocksR
- Parse SSR format, check encryption method
- **Converted to basic Shadowsocks** (protocol/obfs features lost, warning logged)
- Same cipher validation as Shadowsocks
- Empty passwords REJECTED

### Hysteria2
- Protocol name: `"hysteria2"` (NOT `"hysteria"`)
- `hysteriaSettings` structure with `version: 2`
- SNI validated for TLS

### Hysteria v1
- Limited support (may not work with all Xray-core versions)
- **Warning logged** when `insecure=1` detected

### TUIC
- **NOT supported by Xray-core** (parser returns `None` immediately)
- Use sing-box for TUIC configs

### General
- `verify=0`, `verify=false`
- `insecure=1/true/yes/on`

---

## SNI/CIDR Filtering

**Purpose:** Bypass mobile whitelists (Russia and similar regimes)

**Process:**
1. Load domains from `whitelist-all.txt` (hundreds: Avito, Yandex, Mail.ru, etc.)
2. Load CIDR ranges from `cidrwhitelist.txt`
3. Extract host/port from config
4. Check against whitelist
5. Filter non-matching configs

**Result:**
- `bypass/` - Secure configs (security + SNI/CIDR filtered)
- `bypass-unsecure/` - All configs (SNI/CIDR filtered only)

---

## Proxy Chain Support

**Architecture:** v2rayN-style dialerProxy chaining in SINGLE Xray instance

```
App → Xray (:socks_port) → VLESS hop1 → dialerProxy → VLESS hop2 → Internet
```

**Requirements:**
- Minimum 2 proxies in chain
- All hops MUST use WebSocket (ws) or HTTPUpgrade + TLS
- Reality protocol does NOT work with dialerProxy

**Usage:**
```bash
python main.py --proxy-chain="vless://hop1,vless://hop2,vless://hop3"
```

**Implementation:** `utils/xray_tester.py:create_chain_config()`
- Reverses hop order for correct dialerProxy routing
- Validates transport on each hop
- Monitors connection stability (background thread, 30s checks)

---

## Performance Optimizations

### Parallel Processing
- **ThreadPoolExecutor** for downloads (50 workers default, env MAX_WORKERS to tune)
- **Parallel file writes** via ThreadPoolExecutor (8 workers)
- **Concurrent Xray testing** (Linux: 300, Windows: 50 — each xray ~50MB RAM, swap+earlyoom safety net)
- **Platform-aware concurrency** (higher on Linux due to lower process overhead)

### Caching
- **DNS cache** with 60s TTL (lock-free, aiodns resolver)
- **Host/port extraction cache** to avoid reparsing
- **Connection pooling** in curl_cffi sessions

### Network Optimizations
- **curl_cffi** instead of requests (2-3x faster, TLS fingerprinting, anti-bot bypass)
- **FetchResult** return type — never raises exceptions, always inspect `.success` first
- **SOCKS proxy format** `socks://` for curl_cffi compatibility
- **Remote DNS** via `socks5h://` to prevent DNS leaks
- **Environment proxy** support (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY)

### Resource Management
- **Dynamic port allocation** (BASE_PORT=20000, ranges: batch 20k-22k, chains 22k-24k, persistent 24k-25k)
- **Process cleanup** with signal handlers + atexit hooks + psutil fallback
- **ResourceMonitor** background thread for CPU/RAM/network sampling with end-of-run report
- **ProxyMonitor** background thread for proxy health checks (30s interval) with `_active_proxy_monitors` global registry
- **Signal handler ordering**: stop monitors first → cleanup Xray processes → exit (prevents race conditions on shutdown)
- **Aggressive spam filtering** for Xray logs
- **Secure temp files** with `tempfile.mkstemp()` + `chmod 0600`

---

## CLI Arguments

```bash
python main.py [OPTIONS]

Options:
  --dry-run                  Download and save locally, don't upload/commit
  --skip-xray                Skip Xray-core (no verification, raw configs only)
  --tcp-ping                 Use TCP ping instead of Xray-core (faster but less accurate). Implies --skip-xray.
  --use-git                  Use git commands instead of GitHub API (for GitHub Actions)
  --no-proxy-check           Skip proxy detection and IP protection verification
  --proxy=<url>              Single proxy URL to use (vless://, socks5://, etc.)
  --proxy-chain=<urls>       Comma-separated proxy chain (proxy1,proxy2) for chained routing
  --verbose                  Enable verbose logging (skipped config details, etc.)

Feature flag overrides (override config/settings.py values for this run):
  --enable-default-files     Override ENABLE_DEFAULT_FILES=True
  --disable-default-files    Override ENABLE_DEFAULT_FILES=False
  --enable-bypass-unsecure   Override ENABLE_BYPASS_UNSECURE=True
  --disable-bypass-unsecure  Override ENABLE_BYPASS_UNSECURE=False
  --enable-protocol-split    Override ENABLE_PROTOCOL_SPLIT=True
  --disable-protocol-split   Override ENABLE_PROTOCOL_SPLIT=False
  --enable-tg-proxy          Override ENABLE_TG_PROXY=True
  --disable-tg-proxy         Override ENABLE_TG_PROXY=False
  --publish-raw-files        Override PUBLISH_RAW_FILES=True
  --no-publish-raw-files     Override PUBLISH_RAW_FILES=False
```

---

## Testing

### Run Tests
```bash
cd source
pip install pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock

pytest                              # Run all tests (uses pytest.ini for markers/config)
pytest -v                           # Verbose output
pytest --cov=fetchers --cov=utils   # With coverage report
pytest -m unit                      # Unit tests only (fast, no network)
pytest -m integration               # Integration tests (require network)
pytest -n auto                      # Parallel execution
```

**Pytest config** (`source/pytest.ini`): markers (`unit`, `integration`, `slow`), test paths, warning filters.
**Fixtures** (`source/tests/conftest.py`): sample VLESS/VMess/Trojan/SS configs, MTProto/SOCKS5 proxies, temp files, mock logger.

### Test Coverage
- **640 passing tests** across 25 test files (full suite in ~40s)
- `test_fetcher.py` - 16 tests
- `test_file_utils.py` - 26+ file utils tests
- `test_url_stats.py` - 11+ URL stats tests
- `test_config_processor.py` - 64+ processor tests
- `test_config_tagger.py` - 17+ ConfigTagger tests
- `test_simple_tester.py` - 25 tests (extract_host_port + SimpleTester)
- `test_smart_eta.py` - 27 tests (SmartETA estimator)
- `test_telegram_proxy_scraper.py` - 27 tests
- `test_telegram_proxy_verifier.py` - Telegram proxy verifier tests
- `test_executor_cache.py` - ExecutorCache tests
- `test_ip_checker.py` - IP checker tests
- `test_ip_verifier.py` - IP verifier tests
- `test_logger.py` - Logger tests
- `test_managed_process.py` - ManagedProcess lifecycle tests
- `test_process_registry.py` - ProcessRegistry tests
- `test_progress.py` - Progress bar tests
- `test_proxy_monitor.py` - Proxy monitor tests
- `test_security_filter.py` - Security filter tests
- `test_vpn_config.py` - VPNConfig typed dataclass tests
- `test_github_handler.py` - 22 GitHub handler tests (adapter pattern)
- `test_git_updater.py` - 26 GitUpdater tests (init, pull, commit, push, retry)
- `test_health_check.py` - 21 health check tests (DNS fallback, disk, memory, GitHub token)
- `test_xray_tester.py` - Xray tester + security edge case tests
- `test_yaml_converter.py` - 28 tests

### Utility Scripts
```bash
# Clean dead URLs from URLS.txt
python scripts/cleanup_dead_urls.py

# Test ping speed of configs with Xray
python scripts/test_ping_speed.py --count 1000

# Test TCP ping (faster, no Xray needed)
python scripts/test_tcp_ping.py --count 500

# Test Telegram proxies
python scripts/test_telegram_proxies.py
```

---

## Dependencies

### Core
- `curl_cffi>=0.15.0b3` - Fast HTTP client (2-3x faster than requests)
- `requests[socks]` - Fallback compatibility
- `PyGithub` - GitHub API interactions
- `PyYAML` - YAML config parsing (Clash/Surge)
- `PySocks>=1.7.1` - SOCKS proxy support
- `tqdm>=4.65.0` - Progress bars
- `pytdbot[tdjson]>=0.8.8` - Telegram bot API

### Optional (Performance)
- `aiodns>=3.0.0` - Async DNS resolution
- `dnspython>=2.3.0` - DNS utilities
- `psutil` - Process management (guaranteed cleanup)

### Development
- `pytest>=7.4.0` - Testing framework
- `pytest-cov>=4.1.0` - Coverage reporting
- `pytest-asyncio>=0.21.0` - Async test support
- `pytest-xdist>=3.5.0` - Parallel test execution
- `pytest-mock>=3.12.0` - Mocking utilities

---

## VPS Cron (Primary)

Pipeline runs on a VPS via cron every hour.

**Requirements:**
- Ubuntu/Debian VPS
- Git, Python 3.8+, Xray-core (auto-downloaded)
- GitHub token with repo access in `.env`

**Setup:**
```bash
# Run the setup script on a fresh VPS
bash source/scripts/setup-vps.sh
```

The script installs dependencies, configures the environment, and sets up a cron job that runs:
```bash
cd /path/to/rjsxrd && git pull origin main && python source/main.py --use-git --no-proxy-check
```

## GitHub Actions (Fallback)

**Schedule:** Every 2 days at 00:00 UTC

**Workflow:** `.github/workflows/frequent_update.yml`
- Runs on Ubuntu latest
- 80-minute timeout
- Uses `--use-git --no-proxy-check` flags
- Concurrency group to prevent overlapping runs
- Manual trigger via `workflow_dispatch`
- **Requires `fetch-depth: 0`** (full history) — the auto-commit cleaner needs to walk past HEAD~1

---

## Common Tasks

### Add New Config Source
1. Edit `source/config/URLS.txt`
2. Add URL to appropriate section:
   - `# default` - Main configs
   - `# extra_bypass` - Additional bypass configs
   - `# yaml` - Clash/Surge YAML configs
   - `# telegram` - Telegram proxy sources
3. Test locally: `python main.py --dry-run`

### Add Manual Servers
1. Edit `source/config/servers.txt`
2. Add VPN configs one per line (any supported protocol)
3. Servers auto-merge with fetched configs on next run

### Add Manual Telegram Proxies
1. Edit `source/config/tg_proxies.txt`
2. Add proxies in any format:
   - `https://t.me/proxy?server=...&port=...&secret=...` (MTProto)
   - `https://t.me/socks?server=...&port=...&user=...&pass=...` (SOCKS5)
   - `tg://proxy?...` or `tg://socks?...`
3. Proxies auto-merge and verify on next run

### Modify Security Filtering
Edit `utils/security_filter.py:has_insecure_setting()`:
- Add new insecure patterns for existing protocols
- Add checks for new protocols
- Update docstring with new checks

### Modify Protocol Parsing (Xray testing)
Edit `utils/protocol_parsers.py` — standalone parsers for all 8 protocols.
Edit `utils/xray_tester.py:_url_to_outbound()` — dispatch to the parsers.
When adding a new protocol: add parser to protocol_parsers.py, register in xray_tester's dispatch, add security check in security_filter.py.

### Adjust Concurrency & Timeouts
Edit `source/config/settings.py` or use env vars:
- `MAX_WORKERS` - Download concurrency (default: 50, env overridable)
- `ASYNC_CONCURRENCY_WIN32` - Windows Xray concurrency (default: 50)
- `ASYNC_CONCURRENCY_LINUX` - Linux Xray concurrency (default: 300)
- `FETCH_TIMEOUT` - HTTP request timeout (default: 5s, env overridable)
- `FETCH_MAX_ATTEMPTS` - Retry attempts per URL (default: 2, env overridable)
- `VALIDATION_TCP_TIMEOUT` - TCP ping timeout (default: 3s)
- `VALIDATION_HTTP_TIMEOUT` - Xray HTTP test timeout (default: 5s)
- `TEST_PING_URLS` - Test URL(s) for Xray ping (default: gstatic/generate_204, comma-separated)
- `TLS_FINGERPRINT` - TLS fingerprint (default: chrome, options: firefox/safari/edge/randomized)
- `ENABLE_FRAGMENT` - TLS fragment stealth (default: true)
- `FRAGMENT_PACKETS` - Fragment packet type (default: tlshello)
- `FRAGMENT_LENGTH` - Fragment packet length range (default: 100-200)
- `FRAGMENT_INTERVAL` - Fragment packet interval range (default: 10-20)
- `XRAY_STARTUP_TIMEOUT` - Max seconds to wait for xray to bind port (default: 3)
- Environment overrides: `ASYNC_CONCURRENCY_LINUX=100 FETCH_TIMEOUT=4 python3 main.py`

### Change Update Frequency
Edit `.github/workflows/frequent_update.yml`:
```yaml
on:
  schedule:
    - cron: "0 0 */2 * *"  # Every 2 days at midnight UTC
```

---

## Troubleshooting

### Xray Testing Fails
- Check Xray binary exists: `source/xray/xray` or `source/xray/xray.exe`
- Install manually: run script (auto-downloads)
- Skip Xray: `python main.py --skip-xray` (TCP-only verification)

### GitHub Upload Fails
- Check token: `export MY_TOKEN=<token>` (repo permission required)
- Use git mode: `python main.py --use-git` (for GitHub Actions)
- Check rate limits: GitHub API limited to 5000 requests/hour

### Proxy Detection Fails
- Auto-detect checks ports: 10808, 2080, 7890, 7891, 1080, 8080
- Manual proxy: `python main.py --proxy="vless://..."`
- Skip check: `python main.py --no-proxy-check`

### Tests Fail
- Import errors: Run from `source/` directory
- Network tests: Skip with `pytest -m "not integration"`
- Async errors: Install `pytest-asyncio`

### Config Parsing Issues
- Base64 auto-detection enabled for all URLs
- Glued configs auto-split via regex
- Invalid configs logged and skipped

---

## Code Style & Conventions

### Naming
- Functions: `snake_case` (e.g., `has_insecure_setting()`)
- Classes: `PascalCase` (e.g., `XrayTester`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_CONCURRENCY`)
- Files: `snake_case.py`

### Error Handling
- Log errors with `log()` from `utils/logger.py`
- Use try-except with specific exceptions
- Track error stats in `XrayTester._error_stats`
- Graceful degradation (fallback to TCP if Xray unavailable)

### Logging
- Thread-safe via `utils/logger.py:log()`
- Logs collected by file index for ordered output
- Immediate stdout printing with `flush=True`

### Concurrency
- Use `ThreadPoolExecutor` for I/O-bound tasks
- Use `ProcessPoolExecutor` for CPU-bound tasks
- Lock-free designs preferred (DNS cache)
- Platform-aware limits (Windows lower than Linux)

---

## Security Considerations

### Never Commit
- `.env` files (use `.env.example` as template)
- `MY_TOKEN` or GitHub tokens
- Credentials in code
- Personal proxy configs without permission

### Input Validation
- All URLs validated before fetching
- Config format checked before processing
- JSON/YAML parsed with error handling
- Malformed configs logged and skipped

### Network Security
- Remote DNS via `socks5h://` (prevent DNS leaks)
- TLS verification enabled by default
- Insecure configs filtered from secure outputs
- Proxy chain validation (transport compatibility)

---

## Performance Benchmarks

### Typical Run Times (Ubuntu, ~10k configs)
- **Fetch URLs:** 10-30s (parallel, 50 workers)
- **Create all.txt:** 5-10s (deduplication)
- **SNI/CIDR filter:** 5-15s (parallel, up to 32 chunks)
- **Per-source yield stats:** < 0.5s (batch filter_secure_configs)
- **Xray verification:** 60-180s (concurrent, 150 workers)
- **Protocol splitting:** 5-10s (parallel writes)
- **URL Health Report:** < 0.1s (in-memory)
- **Upload:** 20-40s (GitHub API, parallel)
- **TOTAL:** 2-5 minutes

### Optimization Tips
- Increase concurrency: `ASYNC_CONCURRENCY_LINUX=400` (watch RAM — 50MB per xray process)
- Reduce fetch timeouts: `FETCH_TIMEOUT=4 FETCH_MAX_ATTEMPTS=1`
- Skip Xray for faster runs: `--skip-xray` or `--tcp-ping`
- Use git mode in Actions: `--use-git` (faster than API)
- Reduce daily repo lookback: edit `source/fetchers/daily_repo_fetcher.py` lookback_days
- Reduce batch size if system freezes: lower concurrency

---

### Module-Level Constants

```python
# utils/security_filter.py:11-29 (single source of truth, imported by xray_tester.py and protocol_parsers.py)
SS_SECURE_CIPHERS = {...}  # AEAD шифры
SS_WEAK_CIPHERS = {...}    # Слабые шифры (отвергаются) — единый список
```

---

## Key Design Decisions

### Why curl_cffi over requests?
- 2-3x faster performance
- TLS fingerprinting (bypass anti-bot systems)
- Better SOCKS proxy support
- Chrome impersonation (124)

### Why single Xray process per config?
- Maximum compatibility (no cross-config interference)
- Accurate latency measurement
- Easier debugging (isolated failures)
- Matches v2rayN approach

### Why two-tier file system (raw + verified)?
- Transparency (users see untested configs)
- Faster initial generation (verification is slowest step)
- Fallback if verification fails
- Debugging aid

### Why platform-aware concurrency?
- Windows has higher process overhead
- Linux can handle more concurrent processes
- Prevents system freeze on Windows
- Maximizes throughput on Linux

### Why dialerProxy for chains?
- Single process (simpler than multi-process relay)
- Native Xray feature (maintained by Xray team)
- Same as v2rayN (battle-tested)
- End-to-end encrypted (each hop independent)

---

## Quick Reference

### Most Important Files
- `source/main.py` - Start here for entry point
- `source/processors/config_processor.py` - Pipeline logic
- `source/utils/file_utils.py` - Core utilities
- `source/utils/security_filter.py` - Security filtering (has_insecure_setting + cipher sets)
- `source/utils/protocol_parsers.py` - Protocol parsers for Xray testing
- `source/utils/xray_tester.py` - Xray testing
- `source/utils/system_specs.py` - Auto-detected resource caps
- `source/utils/url_stats.py` - URL statistics & auto-cleanup
- `source/utils/smart_eta.py` - Smart ETA estimator
- `source/utils/resource_monitor.py` - System resource tracking
- `source/utils/ip_verifier.py` - IP leak protection, proxy chains
- `source/config/settings.py` - Configuration
- `source/data/url_stats.json` - Persistent fetch stats

### Most Important Functions
- `process_all_configs()` - Main pipeline
- `has_insecure_setting()` - Security check (all protocols, in security_filter.py)
- `apply_sni_cidr_filter()` - SNI/CIDR filtering
- `test_batch()` - Concurrent Xray testing
- `download_all_configs()` - Parallel fetching
- `parse_vless_to_outbound()` - VLESS parser (in protocol_parsers.py)
- `parse_vmess_to_outbound()` - VMess parser (in protocol_parsers.py)
- `parse_trojan_to_outbound()` - Trojan parser (in protocol_parsers.py)
- `parse_shadowsocks_to_outbound()` - Shadowsocks parser (in protocol_parsers.py)
- `parse_hysteria2_to_outbound()` - Hysteria2 parser (in protocol_parsers.py)

### Configuration Files
- `source/config/URLS.txt` - Add/remove sources (auto-cleaned when dead)
- `source/config/servers.txt` - Manual servers (dead configs auto-removed)
- `source/config/tg_proxies.txt` - Manual Telegram proxies
- `source/config/whitelist-all.txt` - SNI domains
- `source/config/cidrwhitelist.txt` - CIDR ranges
- `source/data/url_stats.json` - Persistent fetch stats (gitignored)

### Test Commands
```bash
cd source
pytest -v                          # Run tests
pytest -m unit -v                  # Unit tests only
pytest --cov=fetchers --cov=utils  # Coverage
```

### Scripts
```bash
cd source
python scripts/purge_dead_urls.py              # dry run
python scripts/purge_dead_urls.py --apply       # remove dead URLs
python scripts/purge_stale_urls.py --days 60   # check stale GitHub URLs
python scripts/analyze_url_stats.py             # source performance report
python scripts/benchmark_configs.py --mode tcp --count 500  # TCP ping
python scripts/benchmark_configs.py --mode xray --count 200 # Xray test
python scripts/test_telegram_proxies.py         # TG proxy verification
```