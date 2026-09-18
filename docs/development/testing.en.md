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
`-m integration` actually select something: 727 and 30 tests out of 757
(measured with `pytest --collect-only -q` under each marker). The two
modules that reach the network and skip themselves when it is unavailable
(`test_fetcher.py`, `test_ip_checker.py`) are marked `integration`.

## Test structure

**757 tests** in 32 files. A full run takes around 70–80 seconds on the
development machine (Windows, Python 3.12); the time depends on disk and machine
load, so measure with `pytest -q` on your own machine.

| File | Tests | Scope |
|------|--------|---------|
| `test_config_processor.py` | 86 | Processing pipeline, `prepare_config_content`, `_add_unique`, `write_configs_file` |
| `test_file_utils.py` | 70 | `extract_host_port`, `deduplicate_configs`, `is_valid_vpn_config_url`, `filter_secure_configs` |
| `test_xray_tester.py` | 45 | Parsers, signals, startup-timeout, security edge cases |
| `test_vpn_config.py` | 35 | VPNConfig typed dataclasses |
| `test_security_filter.py` | 35 | `has_insecure_setting`, all protocols and edge cases, 2022 key length validation |
| `test_logger.py` | 30 | Logging, levels, format |
| `test_yaml_converter.py` | 28 | Clash/Surge YAML to VPN URL conversion |
| `test_smart_eta.py` | 27 | SmartETA: 3-way estimate (window, global, EMA) + timeout floor |
| `test_git_updater.py` | 26 | GitUpdater: init, pull, stage, commit, push, retry |
| `test_simple_tester.py` | 25 | `extract_host_port` + `SimpleTester` (TCP ping) |
| `test_process_registry.py` | 25 | ProcessRegistry, cleanup, callbacks |
| `test_git_auto_cleaner.py` | 24 | Auto-cleaning of auto-commits |
| `test_health_check.py` | 22 | Health check: DNS fallback, disk, memory, token |
| `test_github_handler.py` | 22 | GitHub API, rate limits, 409 conflicts, batch |
| `test_xray_batch.py` | 21 | BatchRunner, shared xray, port allocation |
| `test_telegram_proxy_scraper.py` | 21 | Extracting MTProto and SOCKS5 from content |
| `test_proxy_monitor.py` | 19 | Chain monitoring, stop event |
| `test_pipeline_e2e.py` | 19 | Full offline pipeline run with every seam stubbed |
| `test_config_tagger.py` | 18 | ConfigTagger: source+protocol tagging; `utils/__init__.py` declares no imports |
| `test_fetcher.py` | 16 | Fetching, response parsing, error handling |
| `test_executor_cache.py` | 17 | Thread pool, shutdown, WSL detection |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_ip_verifier.py` | 35 | env vars, TCP port polling, response validators, chain reads |
| `test_telegram_proxy_verifier.py` | 14 | MTProto/SOCKS5 proxy verification |
| `test_ip_checker.py` | 14 | IP check, `_make_request` |
| `test_url_stats.py` | 13 | `record_fetch`, `get_dead_urls`, persistence |
| `test_scripts_import.py` | 12 | Import smoke tests for the `scripts/` entry points, benchmark loader |
| `test_progress.py` | 6 | tqdm consolidation |
| `test_docs_figures.py` | 5 | Docs figures match the collected suite |
| `test_main.py` | 6 | Upload-path guards and the deferred SDK import in the entry point |
| `test_telegram_proxy_processor.py` | 3 | Writing MTProto/SOCKS5 proxies to files |
| `test_purge_stale_urls.py` | 3 | Cache loading in `scripts/purge_stale_urls.py` |

The coverage number depends on what is measured and in which mode, and the
figures are not comparable: the mode is branches (`branch = true` in
`[tool.coverage]` in `pyproject.toml`), not statements alone. A statement
executed once still hides the arm of an `if` that never ran, and that is where
this pipeline's crashes have lived.

| Command | Scope | Coverage |
|---------|-------|----------|
| `pytest --cov=fetchers --cov=utils` | two packages | **58 %** (5596 statements, 2181 missed, 1884 branches) |
| `pytest --cov=.` — the full run, as in CI | all of `source/` | **71 %** (12959 statements, 3187 missed, 2808 branches) |
| `pytest -m "not integration" --cov=.` — the offline floor | all of `source/` | **69 %** (12959 statements, 3446 missed, 2808 branches) |

`fail_under = 65` is stated for the CI scope — the whole `source/` tree. It is not
a per-scope number: `pytest --cov=fetchers --cov=utils` reports 58 % and does not
pass the floor, because two packages and the tree have different denominators.
That run illustrates that coverage depends on scope; it is not the gate.

Below the floor, CI fails. The number comes from the offline floor (69 % — a run
without the 30 network tests and without the coverage those tests alone provide)
minus a 4-point headroom, about 520 statements. The offline figure is
a measurement from the development machine (Windows): the runner is Linux and
executes the other side of the `sys.platform` branches in `utils/download_xray.py`,
`utils/xray_batch.py` and `utils/xray_tester.py`, so the runner's own number has
never been observed. It will be recorded here the first time CI runs green; until
then the floor rests on a Windows measurement and does not move — changing it now
would be calibrating against something unmeasured.

Every coverage command carries `--cov-config=../pyproject.toml`, the CI step
included. pytest-cov looks for a `.coveragerc` in the invocation directory
(`source/`) rather than the repository root, so without the flag
`[tool.coverage]` is read by nothing: branch mode and the floor disappear
silently and the report stays a report.

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

CI runs `mypy` as a blocking gate over the **whole tree** (`Type check` in
`.github/workflows/ci.yml`): an error in any module fails the step. The path list
that used to sit here is the weaker gate by construction — a list covers the
files on it and cannot see a module that is not on it.

The list existed to migrate a residual that is gone (0 errors across the tree),
which is why the check now runs over the tree. The proof is reproducible: at the
revision the burn-down started from (`60a69368`), the 27-module list exited 0
(`Success: no issues found in 27 source files`) while `mypy .` reported **87
errors in 22 files**.

`strict`, `disallow_untyped_defs` and `check_untyped_defs` are deliberately not
enabled: each multiplies the error count rather than surfacing new defects, so
strictness is staged. The `name-defined` findings that used to sit in the
residual were defects and are resolved. The error and file counts move from card
to card — measure them with the command above instead of carrying a number over
from a document.

## Warnings

The pytest config carries no global `ignore`: the first `DeprecationWarning`
from our own code is the early signal for the next dependency bump, and
silencing it by category would hide that signal. If a third-party library turns
noisy, the filter is scoped to its module
(`ignore::DeprecationWarning:<module>.*`), never to the category.

`default::ResourceWarning` is on deliberately: it shows unclosed files and
sockets. At the last measurement there are 8 such warnings, and every one of
them is triggered by a test: `test_config_processor.py` — 6,
`test_file_utils.py` — 1, `test_pipeline_e2e.py` — 1. None is allocated in
production code — there used to be 10, and two of them were allocated in
`check_internet_connectivity` (`utils/health_check.py`), which opened a socket
and never closed it. The socket is now closed with `contextlib.closing`, which
is why the count fell to 8. The run stays green — the warnings are only printed.
