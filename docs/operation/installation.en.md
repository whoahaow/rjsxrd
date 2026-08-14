> **Language:** [Русский](installation.md) · [English](installation.en.md)

# Installing and running the generator

## Requirements

- Python 3.8+
- Git (for `--use-git`)
- (Optional) Xray-core — downloaded automatically

## Installation

```bash
git clone https://github.com/whoahaow/rjsxrd
cd rjsxrd/source
python -m pip install -r requirements.txt
```

## Configuration

Settings are set via the `.env` file in the project root (optional — all parameters have sensible default values). Copy the template and fill it in:

```bash
cp .env.example ../.env   # .env in the project root
nano ../.env              # specify GITHUB_TOKEN and REPO_NAME
```

The full list of variables and their default values — in `source/config/settings.py`.

### Main variables

| Variable | Required | Description |
|------------|-------------|----------|
| `GITHUB_TOKEN` | yes | GitHub Personal Access Token (repo access) |
| `REPO_NAME` | yes | Repository in `owner/repo` format |
| `TELEGRAM_BOT_TOKEN` | no | Bot token for notifications |
| `TELEGRAM_CHAT_ID` | no | Chat ID for notifications |

### Xray verification

| Variable | Default | Description |
|------------|-------------|----------|
| `TEST_PING_URLS` | gstatic/generate_204 | URL(s) for the ping test (comma-separated) |
| `TLS_FINGERPRINT` | chrome | TLS fingerprint (chrome/firefox/safari/edge/randomized) |
| `ENABLE_FRAGMENT` | true | TLS fragment (stealth) — protection from DPI |
| `FRAGMENT_PACKETS` | tlshello | Packet type for fragmentation |
| `FRAGMENT_LENGTH` | 100-200 | Fragment length range |
| `FRAGMENT_INTERVAL` | 10-20 | Fragment interval range |
| `XRAY_STARTUP_TIMEOUT` | 3 | Xray-core startup timeout (sec) |
| `XRAY_BATCH_MODE` | single | Testing mode: single or batch |
| `XRAY_BATCH_SIZE` | 1000 | Configs per one Xray in batch mode (50-2000) |
| `XRAY_BATCH_PROCESSES` | 1 | Parallel Xray processes in batch mode |
| `XRAY_BATCH_STARTUP_DELAY_MS` | 1000 | Delay before ping (ms) |
| `XRAY_BATCH_PORT_RANGE_SIZE` | 2000 | Port range per chunk |

## Run

```bash
python main.py
```

The configs will appear in `../githubmirror/`.

> **Note:** by default, the generator only creates the `bypass/` folder (verified configs). The other sets (`default/`, `bypass-unsecure/`, `split-by-protocols/`, `tg-proxy/`, raw files) are enabled with `--enable-*` feature flags — see the [CLI reference](cli-reference.en.md).

**Local testing without uploading:**

```bash
python main.py --dry-run
```

**For VPS (cron, primary):**

```bash
python main.py --use-git --no-proxy-check
```

**For GitHub Actions (fallback):**

```bash
python main.py --use-git --no-proxy-check
```

## Deployment on a VPS

For hourly config updates, a VPS with the `source/scripts/setup-vps.sh` script is used:

1. Run the setup-vps.sh script on a clean Ubuntu/Debian VPS
2. The script will install Python, dependencies, Xray-core, and set up cron
3. Cron run: `python main.py --use-git --no-proxy-check` every hour

**Note:** GitHub Actions is used as a fallback channel (every 2 days). The main pipeline runs on the VPS.

**Related links:**
- [GitHub Actions limits](https://docs.github.com/en/actions/reference/limits) — free limit of 2000 minutes/month
- [GitHub Acceptable Use Policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies) — Actions is intended for CI/CD, not for permanent task hosting
- [Scheduled workflows disablement](https://stackoverflow.com/questions/67184368/prevent-scheduled-github-actions-from-becoming-disabled) — GitHub disables scheduled workflows after 60 days without activity in the repository

## Health check

Before running, the generator performs 5 checks via `health_check.py`:

| Check | What it checks | Severity |
|----------|---------------|-------------|
| internet | TCP connection to DNS servers (1.1.1.1, 8.8.8.8, 77.88.8.8, etc., 2 s timeout each) | 🟡 warning |
| disk space | `shutil.disk_usage` — at least 100 MB free | 🟡 warning |
| memory | `psutil.virtual_memory` — at least 256 MB | 🟡 warning |
| Xray-core | whether the binary exists, whether it is executable | 🟡 warning |
| GitHub token | not empty, longer than 10 characters | 🟡 warning |

The internet check does not block the run — on its failure, the generator continues to work with a warning.

With `--tcp-ping` or `--skip-xray`, the generator does not require Xray-core.

## Config sources

The main URL list is in `source/config/URLS.txt`. The file is parsed by the `parse_urls_file()` function — sections are determined by `#` markers:

| Section | Marker | Purpose |
|--------|--------|------------|
| `# default` | `# yaml` / `# telegram` / `# extra_bypass` not found | Main sources |
| `# extra_bypass` | `extra` or `bypass` in the line | Additional for bypass sets |
| `# yaml` | `yaml` in the line | Clash/Surge — converted via `yaml_converter.py` |
| `# telegram` | `telegram` or `tg` in the line | Telegram proxy sources |

**Base64 autodetect:** each URL is checked for base64 encoding. Heuristics: newline ratio (<10%), absence of `://`, space ratio (<5%), character composition (only A-Za-z0-9+/=).

To add a source, simply place the URL under the appropriate heading. Dead URLs are removed automatically after 3 consecutive fetch errors (via `URLStats`).

## Dependencies

**Main:**

| Package | Purpose |
|-------|------------|
| `curl_cffi` | HTTP client with TLS fingerprint (2-3x faster than requests) |
| `PyGithub` | GitHub API |
| `PyYAML` | Clash/Surge YAML parsing |
| `requests[socks]` | HTTP through a proxy (fallback) |
| `tqdm` | Progress bars |
| `psutil` | Xray process management |

**Optional:**

| Package | Purpose |
|-------|------------|
| `aiodns` | Async DNS (verification speedup) |
| `dnspython` | DNS utilities |

**For development:**

```
pytest pytest-cov pytest-asyncio pytest-xdist pytest-mock
```
