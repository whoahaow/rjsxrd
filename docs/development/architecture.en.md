> **Language:** [Русский](architecture.md) · [English](architecture.en.md)

# Architecture

## Overview

The project is built on a modular scheme with separation of responsibilities. Each component performs strictly one task: downloading, filtering, verification, file generation, uploading.

## Module scheme

```
main.py                          # Entry point, CLI, orchestration
  │
  ├── config/                    # Settings and configuration
  │   ├── settings.py           #   Parameters, tokens, URL sources (including former constants.py)
  │   ├── URLS.txt               #   List of URL sources (sections)
  │   ├── servers.txt            #   Manual VPN servers
  │   ├── tg_proxies.txt         #   Manual Telegram proxies
  │   ├── whitelist-all.txt      #   SNI domains for bypass
  │   └── cidrwhitelist.txt      #   CIDR ranges for bypass
  │
  ├── fetchers/                  # Downloading data from sources
  │   ├── fetcher.py             #   curl_cffi fetcher
  │   ├── daily_repo_fetcher.py  #   Daily repositories
  │   ├── yaml_converter.py      #   Clash/Surge YAML → VPN URL
  │   ├── telegram_proxy_scraper.py  # MTProto/SOCKS5 from content
  │   ├── sstap_scraper.py       #   sstap.org scraping
  │   └── upstream_aggregator.py #   yudou226.top + guidongone
  │
  ├── processors/                # Processing and generation
  │   ├── config_processor.py    #   ConfigPipeline (orchestrator)
  │   └── telegram_proxy_processor.py  # Proxy handler
  │
  ├── utils/                     # Helper modules
  │   ├── file_utils.py          #   I/O, SNI/CIDR, protocols
  │   ├── security_filter.py     #   has_insecure_setting (moved out)
  │   ├── vpn_config.py          #   VPNConfig dataclass hierarchy
  │   ├── managed_process.py     #   ManagedProcess lifecycle
  │   ├── process_registry.py    #   Unified process registry
  │   ├── config_tagger.py       #   ConfigTagger (source+protocol)
  │   ├── logger.py              #   Logging (thread-safe)
  │   ├── progress.py            #   Consolidated tqdm import
  │   ├── executor_cache.py      #   Thread pool with WSL detection
  │   ├── ip_verifier.py         #   Proxy setup + IP check (merged with ip_checker)
  │   ├── bypass_builder.py      #   Bypass config verification
  │   ├── file_writer.py         #   Parallel config writing
  │   ├── xray_batch.py          #   BatchRunner — concurrent testing + batch mode (shared Xray, v2rayN-style)
  │   ├── xray_helpers.py        #   Xray helpers (wait_for_port)
  │   ├── proxy_detector.py      #   Auto-detection of proxies
  │   ├── proxy_monitor.py       #   Chain monitoring
  │   ├── resource_monitor.py    #   CPU/RAM/network monitoring
  │   ├── download_xray.py       #   Xray-core installer
  │   ├── url_stats.py           #   URL statistics (typed dataclass)
  │   ├── health_check.py        #   Health check before running
  │   ├── _sni_worker.py         # SNI/CIDR worker (internal)
  │   ├── system_specs.py        # SystemSpecs — resource auto-detection
  │   ├── psutil_available.py    # unified psutil import
  │   ├── protocol_parsers.py    # Protocol parsers (from xray_tester)
  │   ├── config_helpers.py      # Pipeline helpers
  │   ├── curl_import.py         # Unified curl_cffi import
  │   ├── xray_tester.py         # Xray-core verification
  │   ├── simple_tester.py       #   TCP ping verification
  │   ├── smart_eta.py           #   Time estimation (3-way + EMA + timeout floor)
  │   ├── telegram_proxy_verifier.py  # Proxy verification
  │   ├── github_handler.py      #   GitHub API (PyGithub)
  │   ├── git_updater.py         #   Git commands (VPS/GitHub Actions)
  │   └── git_auto_cleaner.py    #   Auto-cleaning of auto:update commits on commit
  │
  ├── scripts/                   # Utilities (one-time run)
  │   ├── purge_dead_urls.py
  │   ├── purge_stale_urls.py
  │   ├── analyze_url_stats.py
  │   ├── benchmark_configs.py
  │   ├── test_telegram_proxies.py
  │   └── setup-vps.sh
  └── tests/                     # 658 tests in 26 files
```

## Processing pipeline

### Phase 1. Download

Parallel download from all sources using ThreadPoolExecutor (50 workers by default, configurable via MAX_WORKERS):

1. URLs from the `# default` section — basic configs
2. URLs from the `# extra_bypass` section — additional set for bypass
3. URLs from the `# yaml` section — Clash/Surge parsing via PyYAML
4. Daily-updated repositories — search by date
5. Manual servers from `servers.txt`
6. Scanning all content for Telegram proxies (MTProto/SOCKS5)
7. Base64 auto-detection for each URL

Result: 4 arrays (`all_configs`, `extra_bypass_configs`, `mtproto_proxies`, `socks5_proxies`) + an array of tuples for numbered files.

### Phase 2. Generation of default files

```
create_numbered_default_files() → 1.txt, 2.txt, ... (by sources)
create_all_configs_file()      → all.txt (deduplication)
create_secure_configs_file()   → all-secure.txt (insecure filtering)
```

### Phase 3. Generation of bypass files

```
apply_sni_cidr_filter() → selection by domains/CIDR
  + extra_bypass_configs (without SNI/CIDR filtering)
  → deduplication + security filter
  → writing raw files
  → verification (Xray or TCP)
  → sorting by ping
  → bypass-all.txt, bypass-unsecure-all.txt
```

### Phase 4. Split by protocols

Classification by protocol type → creation of secure/unsecure files → parallel writing (8 workers).

### Phase 5. Telegram proxies

Merging scraped and manual → verification → sorting → all.txt, MTProto.txt, socks.txt.

### Phase 6. URL Health Report

Statistics analysis → removal of dead URLs and configs → report.

### Phase 7. Upload

Two modes:
- **GitHub API:** PyGithub, parallel upload (8 workers), SHA conflict resolution
- **Git commands:** `--use-git`, for VPS cron (primary) and GitHub Actions (fallback)

## Signal handling

On SIGINT/SIGTERM, the `_signal_handler()` in `main.py` fires:

1. **Stopping ResourceMonitor** — background CPU/RAM/network collection stops
2. **Registry cleanup** — `default_registry.cleanup(force=True)` from `process_registry.py`. The registry first stops the ProxyMonitors (they depend on the Xray SOCKS port), then terminates all Xray processes and restores the proxy env vars
3. **2 s wait** — `time.sleep(2)`, gives processes time to finish
4. **`sys.exit(0)`** — clean exit

**Why this exact order:** ProxyMonitor depends on the Xray SOCKS port. Killing Xray before stopping the monitor = a panic in the monitor. The signal handler first stops all watchers, then cleans up the processes.

The Xray signal handler is no longer registered separately — all cleanup is centralized in `main.py`. `ProcessRegistry` is the single registry for all Xray processes (replaced the old `_active_testers`, `_xray_process_registry`).
