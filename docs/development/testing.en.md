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
`-m integration` actually select something: 1076 and 15 tests out of 1091
(measured with `pytest --collect-only -q` under each marker). Only the two
modules that reach the network and skip themselves when it is unavailable
(`test_fetcher.py`, `test_ip_checker.py`) carry `integration`. Pure logic needs
no network and lives in the unit modules, including `test_fetcher_unit.py`,
which took the 15 pure-logic tests out of `test_fetcher.py`.

## Test structure

**1091 tests** in 38 files. A full run takes around 70–80 seconds on the
development machine (Windows, Python 3.12); the time depends on disk and machine
load, so measure with `pytest -q` on your own machine.

| File | Tests | Scope |
|------|--------|---------|
| `test_config_processor.py` | 86 | Processing pipeline, `prepare_config_content`, `_add_unique`, `write_configs_file` |
| `test_file_utils.py` | 70 | `extract_host_port`, `deduplicate_configs`, `is_valid_vpn_config_url`, `filter_secure_configs` |
| `test_xray_tester.py` | 50 | Parsers, signals, startup-timeout, security edge cases, TLS fragment stage, SSR ciphers |
| `test_vpn_config.py` | 42 | VPNConfig typed dataclasses |
| `test_security_filter.py` | 71 | `has_insecure_setting`, all protocols and edge cases, 2022 key length validation, the xray cipher allowlist, `extract_ss_credentials` |
| `test_logger.py` | 30 | Logging, levels, format |
| `test_yaml_converter.py` | 32 | Clash/Surge YAML to VPN URL conversion |
| `test_smart_eta.py` | 27 | SmartETA: 3-way estimate (window, global, EMA) + timeout floor |
| `test_git_updater.py` | 26 | GitUpdater: init, pull, stage, commit, push, retry |
| `test_simple_tester.py` | 25 | `extract_host_port` + `SimpleTester` (TCP ping) |
| `test_process_registry.py` | 25 | ProcessRegistry, cleanup, callbacks |
| `test_git_auto_cleaner.py` | 24 | Auto-cleaning of auto-commits |
| `test_health_check.py` | 22 | Health check: DNS fallback, disk, memory, token |
| `test_github_handler.py` | 22 | GitHub API, rate limits, 409 conflicts, batch |
| `test_xray_batch.py` | 21 | BatchRunner, shared xray, port allocation |
| `test_xray_compat_filter.py` | 64 | `filter_xray_compatible`: which configs reach verification at all, the Shadowsocks cipher allowlist |
| `test_telegram_proxy_scraper.py` | 21 | Extracting MTProto and SOCKS5 from content |
| `test_proxy_monitor.py` | 19 | Chain monitoring, stop event |
| `test_pipeline_e2e.py` | 19 | Full offline pipeline run with every seam stubbed |
| `test_config_tagger.py` | 18 | ConfigTagger: source+protocol tagging; `utils/__init__.py` declares no imports |
| `test_fetcher.py` | 1 | `fetch_data` against a real URL; self-skips without network |
| `test_fetcher_unit.py` | 84 | Env proxy, session shape, verified retries and the opt-in TLS downgrades, error mapping, private-range guard (no network) |
| `test_fetch_posture.py` | 55 | Destination refusals (counter, report, the strictness of the marker, a URL's life in `URLS.txt`, and the limit the classifier accepts), the GitHub token's hosts held against a literal and against `SECURITY.md`, and the addresses translation prefixes carry (no network) |
| `test_fetch_run_conditions.py` | 6 | An outcome of the run rather than the source: the marker, the counter and the report, and that a verified failure still ages a URL (no network) |
| `test_fetch_guard_scope.py` | 70 | The fetch guard's written scope: the allowlist entry that switches the guard off, refused at load; the entry forms `config/settings.py` promises, held against the matcher; which port a qualified entry pins; the warning-filter walk, and what it still cannot see (no network) |
| `test_executor_cache.py` | 17 | Thread pool, shutdown, WSL detection |
| `test_managed_process.py` | 15 | ManagedProcess lifecycle |
| `test_ip_verifier.py` | 35 | env vars, TCP port polling, response validators, chain reads |
| `test_telegram_proxy_verifier.py` | 14 | MTProto/SOCKS5 proxy verification |
| `test_ip_checker.py` | 14 | IP check, `_make_request` |
| `test_url_stats.py` | 25 | `record_fetch`, `get_dead_urls`, persistence; neither a refusal nor a run condition ages a URL, and one channel per fact — the error text, not a derived flag |
| `test_scripts_import.py` | 12 | Import smoke tests for the `scripts/` entry points, benchmark loader |
| `test_progress.py` | 6 | tqdm consolidation |
| `test_docs_figures.py` | 7 | Docs figures match the collected suite: its totals, the per-file table, the README trees, and the coverage rows with their anchor |
| `test_module_size.py` | 4 | Module ceiling and the debt budget: the ceiling covers the whole tree, a budget only shrinks |
| `test_main.py` | 6 | Upload-path guards and the deferred SDK import in the entry point |
| `test_telegram_proxy_processor.py` | 3 | Writing MTProto/SOCKS5 proxies to files |
| `test_purge_stale_urls.py` | 3 | Cache loading in `scripts/purge_stale_urls.py` |

The coverage number depends on what is measured and in which mode, and the
figures are not comparable: the mode is branches (`branch = true` in
`[tool.coverage]` in `pyproject.toml`), not statements alone. A statement
executed once still hides the arm of an `if` that never ran, and that is where
this pipeline's crashes have lived.

The `--cov=.` rows measure the code, not the test suite: it is excluded from the
measurement (`omit = ["tests/*"]` in `[tool.coverage.run]`). It used to be included —
6556 of the tree's 14234 statements were the tests, covered at 98 % against the code's
57 % — so the percentage was mostly a statement about the suite rather than about the
code it exists for, and every change to the suite moved the figures. That is
why these rows went stale three times. The two-package row measured code only from the
start; it has a denominator of its own.

| Command | Scope | Coverage |
|---------|-------|----------|
| `pytest --cov=fetchers --cov=utils` | two packages | **60.59 %** (5879 statements, 2128 missed, 1974 branches; the spread this scope carries is stated below) |
| `pytest --cov=.` — the full run, as in CI | the code under `source/` | **57.08 %** (7653 statements, 3065 missed, 2530 branches; ±0.1 pt between runs) |
| `pytest -m "not integration" --cov=.` — the offline floor | the code under `source/` | **56.89 %** (7653 statements, 3081 missed, 2530 branches) |

The figures above are a measurement on branch `main` at commit `5dad902f`, taken with
the commands in the table's first column and `--cov-config=../pyproject.toml`. They are a
historical fact rather than a claim about HEAD, and the commit names the revision of the
code that was measured: it is the last one the measured tree changed at — the one that made
every fetch attempt a verified one and retired the TLS downgrades (the measured tree: 7653
statements, down from 7659 at the previous anchor). The test suite is out of the
denominator, so a change that moves the suite no longer moves the figures — a change that
moves the code still does. The figures guard
(`source/tests/test_docs_figures.py`) holds the anchor, the arithmetic behind each row and
the agreement between the two languages; it does not re-derive the numbers, which would
take a second instrumented run inside the suite.

The percentage in the rows taken with the full suite carries a ±0.1 point tolerance,
which is the precision the measurement has. The 15 `integration`-marked tests touch the
network and skip themselves when it is unavailable, so different runs execute a different
amount of code and the missed counters part company: the record has two runs on one tree
printing 3073 and 3079 missed statements, about 0.08 of a point apart. The offline floor
deselects those same 15 tests and so does not carry the spread. The digits after the point
are what the command printed; the tolerance says how far the claim holds.

The two-package row carries a wider spread than ±0.1 point, and the record for this tree
says so: four runs printed 2128 missed statements and 60.59 %, and a fifth printed 2214
and 58.64 % — nearly two points lower, on the same tree, with the counters of the other
two scopes unchanged. It is not the network tests moving. The scope is executed by tests
that hand work to child processes and thread pools, and a run started while the machine is
already busy sees less of that code execute. The table states one of the five; when a
figure from this scope is going to be written down, repeat the command and quote the runs
that agree.

`fail_under = 53` is stated for the CI scope — the code under `source/`, without the
suite. It is not a per-scope number: the two-package row now sits above the floor, but
two packages and the tree's code have different denominators, and the coincidence says
nothing about coverage. That run illustrates that coverage depends on scope; it is not
the gate.

Below the floor, CI fails. The 53 is the offline floor — the last row of the table
above, a run without the 15 network tests and without the coverage those tests alone
provide — less the four points this floor has always been set under that measurement;
rounding to a whole number leaves 3.89 points of headroom. It is not comparable with the
65 it replaces, and the difference is the point: that floor stood over a tree in which
the tests were measured as code and covered themselves at 98 %, so the same run read
73.58 % for the tree while the code the tests exist for read 57 %. The offline floor is
a measurement from the development machine (Windows), while the runner is Linux, where
that number has never been observed — the headroom is partly held for that unmeasured
side. Not for the `sys.platform` branches: their sides swap one for one (what Linux
would cover is what Windows covers instead), and the only block that exists on the
non-Windows side alone (`utils/download_xray.py:334-338`, the `os.chmod`) is reached by
the suite on neither platform — at most ~2 statements of the measured 7635, ~0.03 of a
point. The runner's number will be recorded here the first time CI runs green.

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
residual were defects and are resolved. The error and file counts move from commit
to commit — measure them with the command above instead of carrying a number over
from a document.

## Module size

Every file under `source/` has a ceiling — **800 lines** — and the files that were already
over it when the gate landed have a budget: the size each was measured at that day.
`source/tests/test_module_size.py` checks both, as a test rather than a separate CI step:
it runs inside the suite, sees the same tree, and bypasses neither `--strict-markers` nor
the figures guard.

What the gate protects is not "small files". A file that has grown is hard to review: what
depends on what stops being visible in it, and every further change makes it worse. The
line counts are a proxy for that and are worth reading as a proxy: 800 lines are not
harmful by themselves, a file whose change cannot be read in one pass is.

- the ceiling covers **every** `.py` file in the tree, tests included, found by walking
  directories rather than a list, so a module added tomorrow in a new subdirectory is
  covered without an edit to the gate;
- a file on the debt list may not grow by a single line: a budget is a measurement, not
  permission;
- a budget may only be lowered. A file more than 10 % below its budget fails the gate,
  which asks for the budget to be lowered in the same commit — otherwise nobody lowers it,
  and in two years the file is twice the size it should be and still "within budget". Ten
  percent is the compromise: more than an ordinary edit moves, less than any real split, so
  a genuine reduction costs one extra edit. That cost is the mechanism;
- a file that drops below the ceiling comes off the list: while the entry stands, the
  file's limit is its budget, which sits above the ceiling;
- the list is closed: it holds the files that were over the ceiling on the day the gate
  landed, four of them named before the gate existed. A file over the ceiling is a file to split;
  adding it to the list silences the gate instead of satisfying it.

The debt is still debt. Four modules started this list — `xray_tester`, `xray_batch`,
`config_processor` and `protocol_parsers` — and the whole-tree measurement added three test
files to them, among them the largest file in the repository (`test_config_processor.py`).
None of them has been split: the gate makes the debt visible and forbids it growing, and
splitting them is separate work. The list with its sizes is in
`source/tests/test_module_size.py`, in `BUDGETS`.

A failure says what to do: it names the file, its current size, its limit and the response
— split it, and for a listed file also that the budget may not be raised. Changing the gate
itself is a change of policy: its own commit, with the reason in the message, not a way to
find room for more lines.

## Warnings

The pytest config carries no global `ignore`: the first `DeprecationWarning`
from our own code is the early signal for the next dependency bump, and
silencing it by category would hide that signal. If a third-party library turns
noisy, the filter is scoped to its module
(`ignore::DeprecationWarning:<module>.*`), never to the category.

`default::ResourceWarning` is on deliberately: it shows unclosed files and
sockets. The run now reports none. There used to be 10, and two of them were
allocated in `check_internet_connectivity` (`utils/health_check.py`), which
opened a socket and never closed it; closing it with `contextlib.closing` took
the count down to 8. The remaining eight were all in the tests: six temporary
output files read without a context manager in `test_config_processor.py`
(`open(out).read()` → `out.read_text()`), one module file read the same way in
`test_file_utils.py`, and one socket in `test_pipeline_e2e.py`, now owned by
`contextlib.closing`. The filter is what made them visible — a category-wide
`ignore` would have hidden all eight. The run stays green: warnings are printed,
so a new one is a signal rather than a failure.
