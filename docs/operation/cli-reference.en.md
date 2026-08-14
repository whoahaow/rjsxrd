> **Language:** [Русский](cli-reference.md) · [English](cli-reference.en.md)

# CLI reference

## Syntax

```bash
python main.py [OPTIONS]
```

## Flags

### Execution modes

| Flag | Description |
|------|----------|
| `--dry-run` | Download and process configs locally, without uploading to GitHub |
| `--use-git` | Use git commands instead of the GitHub API (for GitHub Actions) |

### Output file management (feature flags)

These flags override the values from `config/settings.py` for one run (without changing the file):

| Flag | Description |
|------|----------|
| `--enable-default-files` | Generate default/ (1.txt, all.txt, all-secure.txt) |
| `--disable-default-files` | Skip default/ generation |
| `--enable-bypass-unsecure` | Generate bypass-unsecure/ |
| `--disable-bypass-unsecure` | Skip bypass-unsecure/ |
| `--enable-protocol-split` | Generate split-by-protocols/ |
| `--disable-protocol-split` | Skip split-by-protocols/ |
| `--enable-tg-proxy` | Generate tg-proxy/ |
| `--disable-tg-proxy` | Skip tg-proxy/ |
| `--publish-raw-files` | Upload /raw/ subfolders |
| `--no-publish-raw-files` | Don't upload /raw/ subfolders |

### Verification modes

| Flag | Description |
|------|----------|
| _(no flag)_ | Xray-core: launching a separate Xray process per config, HTTP test via SOCKS5. Maximum accuracy. |
| `--tcp-ping` | TCP ping: fast testing via a TCP connection to host:port. 10-20x faster than Xray. Implicitly enables `--skip-xray`. |
| `--skip-xray` | Skip verification — only raw files without testing |
| `--batch-mode` | Batch mode: one Xray per N configs (shared Xray, less RAM). Overrides XRAY_BATCH_MODE. |
| `--single-mode` | Single mode: one Xray per config (more isolation). Overrides XRAY_BATCH_MODE. |

**Comparison of verification modes:**

| Mode | Accuracy | Time (for ~700 configs) | Dependencies |
|-------|----------|--------------------------|-------------|
| Xray-core (default) | High | 60-120 s | Xray-core binary |
| `--tcp-ping` | Medium | ~5 s | None |
| `--skip-xray` | None | 0 s | None |

### Proxy

| Flag | Description |
|------|----------|
| `--proxy=<URL>` | A single proxy for the whole generator. Format: `vless://`, `socks5://`, etc. |
| `--proxy-chain=<URL1,URL2,URL3>` | Proxy chain (minimum 2). Comma-separated, without spaces. |
| `--no-proxy-check` | Disable proxy detection and verification. |

### Debugging

| Flag | Description |
|------|----------|
| `--verbose` | Verbose log: shows skipped configs, filtering details |

## Examples

```bash
# Local testing
python main.py --dry-run

# Quick check without Xray
python main.py --tcp-ping --dry-run

# Full run with upload
python main.py --use-git

# Through your own proxy
python main.py --proxy="vless://uuid@host:443?security=tls&..."

# Chain of two proxies
python main.py --proxy-chain="vless://hop1@a.com:443,vless://hop2@b.com:443"

# Without proxy, verbose log
python main.py --dry-run --no-proxy-check --verbose
```

## Environment variables

All variables can be set via the `.env` file in the project root (see `.env.example`).

| Variable | Default | Description |
|------------|-----------|----------|
| `GITHUB_TOKEN` | — | GitHub token with repo access (from `.env`) |
| `REPO_NAME` | whoahaow/rjsxrd | Repository for upload (from `.env`) |
| `TELEGRAM_BOT_TOKEN` | — | Bot token for notifications (from `.env`) |
| `MAX_WORKERS` | 50 | Number of threads for downloads |
| `FETCH_TIMEOUT` | 5 | HTTP request timeout (s) |
| `FETCH_MAX_ATTEMPTS` | 3 | Number of URL fetch attempts |
| `VALIDATION_TCP_CONCURRENCY` | 300 | TCP ping concurrency |
| `VALIDATION_HTTP_CONCURRENCY` | 20 | HTTP check concurrency |
| `VALIDATION_MAX_WORKERS` | 200 | Maximum verification threads |
| `ASYNC_CONCURRENCY_WIN32` | 50 | Xray concurrency on Windows |
| `ASYNC_CONCURRENCY_LINUX` | 300 | Xray concurrency on Linux |
| `VALIDATION_TCP_TIMEOUT` | 3 | TCP connection timeout (s) |
| `VALIDATION_HTTP_TIMEOUT` | 5 | HTTP request timeout (s) |
| `XRAY_BATCH_MODE` | single | Testing mode: single or batch |
| `XRAY_BATCH_SIZE` | 1000 | Configs per one Xray in batch mode (50-2000) |
| `XRAY_BATCH_PROCESSES` | 1 | Parallel Xray processes in batch mode |
| `XRAY_BATCH_STARTUP_DELAY_MS` | 1000 | Delay before ping after Xray starts (ms) |
| `XRAY_BATCH_PORT_RANGE_SIZE` | 2000 | Port range per chunk in batch mode |
