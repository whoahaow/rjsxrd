> **Language:** [Русский](testing.md) · [English](testing.en.md)

# Testing

## Running the tests

The test toolchain is installed once with `uv` — environment creation and the install command are described in [Development environment](development-environment.en.md). Bare `pip` is not used in this project.

```bash
cd source
../.venv/Scripts/python.exe -m pytest -q        # Full run

pytest -v                    # Verbose output
pytest -n auto               # Parallel run
```

### Filtering

```bash
pytest -m unit                # Fast unit tests (no network)
pytest -m integration         # Integration tests (require network)
pytest --cov=fetchers --cov=utils  # With a coverage report
```

Every test module declares its marker (`pytestmark`), so `-m unit` and
`-m integration` actually select something: 676 and 29 tests out of 705. The two
modules that reach the network and skip themselves when it is unavailable
(`test_fetcher.py`, `test_ip_checker.py`) are marked `integration`.

## Test structure

**705 tests** in 30 files. A full run takes around 70–80 seconds on the
development machine (Windows, Python 3.12); the time depends on disk and machine
load, so measure with `pytest -q` on your own machine.

| File | Tests | Scope |
|------|--------|---------|
| `test_config_processor.py` | 81 | Processing pipeline, `prepare_config_content`, `_add_unique`, `write_configs_file` |
| `test_file_utils.py` | 70 | `extract_host_port`, `deduplicate_configs`, `is_valid_vpn_config_url`, `filter_secure_configs` |
| `test_xray_tester.py` | 44 | Parsers, signals, startup-timeout, security edge cases |
| `test_vpn_config.py` | 35 | VPNConfig typed dataclasses |
| `test_security_filter.py` | 35 | `has_insecure_setting`, all protocols and edge cases, 2022 key length validation |
| `test_logger.py` | 30 | Logging, levels, format |
| `test_yaml_converter.py` | 28 | Clash/Surge YAML to VPN URL conversion |
| `test_smart_eta.py` | 27 | SmartETA: 3-way estimate (window, global, EMA) + timeout floor |
| `test_git_updater.py` | 26 | GitUpdater: init, pull, stage, commit, push, retry |
| `test_simple_tester.py` | 25 | `extract_host_port` + `SimpleTester` (TCP ping) |
| `test_process_registry.py` | 25 | ProcessRegistry, cleanup, callbacks |
| `test_git_auto_cleaner.py` | 24 | Auto-cleaning of auto-commits |
| `test_github_handler.py` | 22 | GitHub API, rate limits, 409 conflicts, batch |
| `test_telegram_proxy_scraper.py` | 21 | Extracting MTProto and SOCKS5 from content |
| `test_health_check.py` | 21 | Health check: DNS fallback, disk, memory, token |
| `test_xray_batch.py` | 20 | BatchRunner, shared xray, port allocation |
| `test_proxy_monitor.py` | 19 | Chain monitoring, stop event |
| `test_pipeline_e2e.py` | 18 | Full offline pipeline run with every seam stubbed |
| `test_config_tagger.py` | 18 | ConfigTagger: source+protocol tagging; `utils/__init__.py` declares no imports |
| `test_executor_cache.py` | 16 | Thread pool, shutdown, WSL detection |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_fetcher.py` | 15 | Fetching, response parsing, error handling |
| `test_ip_checker.py` | 14 | IP check, `_make_request` |
| `test_url_stats.py` | 12 | `record_fetch`, `get_dead_urls`, persistence |
| `test_telegram_proxy_verifier.py` | 12 | MTProto/SOCKS5 proxy verification |
| `test_scripts_import.py` | 12 | Import smoke tests for the `scripts/` entry points, benchmark loader |
| `test_progress.py` | 6 | tqdm consolidation |
| `test_ip_verifier.py` | 6 | env vars, TCP port polling |
| `test_main.py` | 5 | Upload-path guards in the pipeline entry point |
| `test_telegram_proxy_processor.py` | 3 | Writing MTProto/SOCKS5 proxies to files |

The coverage number depends on what is measured, and the two are not comparable:

| Command | Scope | Coverage |
|---------|-------|----------|
| `pytest --cov=fetchers --cov=utils` | two packages | **56 %** (5566 statements, 2433 missed) |
| `pytest --cov=.` (what CI runs) | all of `source/` | **72 %** (12441 statements, 3436 missed) |

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

## Type checking

```bash
cd source
../.venv/Scripts/python.exe -m mypy .   # full report for the current tree
```

CI runs `mypy` as a blocking gate over an explicit list of modules that report
**zero** errors (`Type check (ratchet)` in `.github/workflows/ci.yml`). The list
is a ratchet: it may only grow. A module joins it once it is clean, and CI then
fails if a new error appears in a module already on it. The gate passes
`--follow-imports=silent` so a listed module is judged on its own code instead of
inheriting the residual of everything it imports.

`strict`, `disallow_untyped_defs` and `check_untyped_defs` are deliberately not
enabled: each multiplies the error count rather than surfacing new defects, so
strictness is staged. The residual across the tree is the hygiene families
(`assignment`, `arg-type`, `var-annotated`, `no-any-return`, `return-value`); the
`name-defined` findings that used to sit alongside them were defects and are
resolved. The error and file counts move from card to card — measure them with
the command above instead of carrying a number over from a document.

## Warnings

The pytest config carries no global `ignore`: the first `DeprecationWarning`
from our own code is the early signal for the next dependency bump, and
silencing it by category would hide that signal. If a third-party library turns
noisy, the filter is scoped to its module
(`ignore::DeprecationWarning:<module>.*`), never to the category.

`default::ResourceWarning` is on deliberately: it shows unclosed files and
sockets. There are currently 10 such warnings and all of them are in the tests
(`test_config_processor.py`, `test_file_utils.py`, `test_health_check.py`,
`test_pipeline_e2e.py`). The run stays green — the warnings are only printed.
