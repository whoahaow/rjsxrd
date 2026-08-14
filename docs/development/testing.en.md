> **Language:** [Русский](testing.md) · [English](testing.en.md)

# Testing

## Running the tests

```bash
cd source
pip install pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock

pytest                       # All tests
pytest -v                    # Verbose output
pytest -n auto               # Parallel run
```

### Filtering

```bash
pytest -m unit                # Fast unit tests (no network)
pytest -m integration         # Integration tests (require network)
pytest --cov=fetchers --cov=utils  # With a coverage report
```

## Test structure

Total **658 tests** in 26 files (full run ~40 s):

| File | Tests | Scope |
|------|--------|---------|
| `test_config_processor.py` | 78 | Processing pipeline, `prepare_config_content`, `_add_unique`, `write_configs_file` |
| `test_file_utils.py` | 70 | `extract_host_port`, `deduplicate_configs`, `is_valid_vpn_config_url`, `filter_secure_configs` |
| `test_xray_tester.py` | 44 | Parsers, signals, startup-timeout, security edge cases |
| `test_security_filter.py` | 35 | `has_insecure_setting`, all protocols and edge cases, 2022 key length validation |
| `test_vpn_config.py` | 35 | VPNConfig typed dataclasses |
| `test_logger.py` | 30 | Logging, levels, format |
| `test_yaml_converter.py` | 28 | Clash/Surge YAML to VPN URL conversion |
| `test_smart_eta.py` | 27 | SmartETA: 3-way estimate (window, global, EMA) + timeout floor |
| `test_git_updater.py` | 26 | GitUpdater: init, pull, stage, commit, push, retry |
| `test_simple_tester.py` | 25 | `extract_host_port` + `SimpleTester` (TCP ping) |
| `test_process_registry.py` | 25 | ProcessRegistry, cleanup, callbacks |
| `test_git_auto_cleaner.py` | 24 | Auto-cleaning of auto-commits |
| `test_github_handler.py` | 22 | GitHub API, rate limits, 409 conflicts, batch |
| `test_health_check.py` | 21 | Health check: DNS fallback, disk, memory, token |
| `test_telegram_proxy_scraper.py` | 21 | Extracting MTProto and SOCKS5 from content |
| `test_proxy_monitor.py` | 19 | Chain monitoring, stop event |
| `test_xray_batch.py` | 18 | BatchRunner, shared xray, port allocation |
| `test_config_tagger.py` | 17 | ConfigTagger: source+protocol tagging |
| `test_fetcher.py` | 15 | Fetching, response parsing, error handling |
| `test_executor_cache.py` | 15 | Thread pool, shutdown, WSL detection |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_ip_checker.py` | 14 | IP check, `_make_request` |
| `test_telegram_proxy_verifier.py` | 12 | MTProto/SOCKS5 proxy verification |
| `test_url_stats.py` | 11 | `record_fetch`, `get_dead_urls`, persistence |
| `test_ip_verifier.py` | 6 | env vars, TCP port polling |
| `test_progress.py` | 6 | tqdm consolidation |

Coverage: ~46% (measured via `pytest --cov=fetchers --cov=utils`).

## Manual testing utilities

Located in `source/scripts/`:

```bash
# Cleaning URLS.txt from dead links (dry-run: without --apply nothing is removed)
python scripts/purge_dead_urls.py
python scripts/purge_dead_urls.py --apply

# Cleaning by git timestamp (GitHub URLs only)
python scripts/purge_stale_urls.py --days 60 --apply

# Source analysis: top by yield
python scripts/analyze_url_stats.py
python scripts/analyze_url_stats.py --top 30
python scripts/analyze_url_stats.py --dead  # dead only

# Config benchmark (TCP ping or Xray)
python scripts/benchmark_configs.py --mode tcp --count 500
python scripts/benchmark_configs.py --mode xray --count 200

# Testing Telegram proxies
python scripts/test_telegram_proxies.py
```

## Local generator testing

```bash
python main.py --dry-run
```

Runs all phases except the GitHub upload. Useful for checking changes before committing.

## GitHub Workflow

`.github/workflows/frequent_update.yml` — runs every 2 days at 00:00 UTC.
- Ubuntu latest
- 80 minute timeout
- Flags: `--use-git --no-proxy-check`
- Concurrency group to prevent overlapping
- Manual run via `workflow_dispatch`
