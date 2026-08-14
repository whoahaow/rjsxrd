> **Language:** [Русский](performance.md) · [English](performance.en.md)

# Optimizations and performance

## Concurrency

| Operation | Mechanism | Threads |
|----------|----------|---------|
| URL download | ThreadPoolExecutor | **50** (configurable) |
| File writing | ThreadPoolExecutor | 8 |
| Config filtering | ProcessPoolExecutor | 8* |
| Xray testing (Linux) | Async + curl_cffi | **300** (formerly 150, increased after the ETA fix, ~50MB RAM per process) |
| Xray testing (Windows) | ThreadPoolExecutor | **50** |
| TCP ping | asyncio | up to 300 (`VALIDATION_TCP_CONCURRENCY`) |

\* Number of CPUs.

**Platform optimization:** Windows has higher process overhead, so concurrency is lower. Linux/WSL can handle more parallel operations.

### ExecutorCache — thread pool caching

All ThreadPoolExecutors go through `ExecutorCache` (`utils/executor_cache.py`):

- **lazy initialization** — pools are created on first use and reused in all subsequent calls
- **WSL detection** — automatic reduction of workers on WSL (to `default/2`) to prevent the vmmem memory leak
- **Memory adaptation:**
  - `< 2 GB`: 2 workers
  - `2-4 GB`: 4 workers
  - `> 4 GB`: full amount
- **atexit termination** — all pools are correctly closed on exit

Executor types:

| Name | Workers | Purpose |
|-----|---------|------------|
| `file_io` | 8 | Parallel chunk writing |
| `network_io` | 50 | URL download |
| `cpu_bound` | CPU count | Filtering via ProcessPoolExecutor |
| `regex` | 8 | `filter_secure_configs()`, SNI/CIDR |

**Processes vs Threads:**
- `filter_secure_configs()` uses ProcessPoolExecutor (CPU-bound — hash, base64, JSON checks)
- Other operations — ThreadPoolExecutor (I/O-bound — network, disks, regex under the GIL)

Environment variables for tuning:

```bash
ASYNC_CONCURRENCY_WIN32=100   # Windows (default 50)
ASYNC_CONCURRENCY_LINUX=300   # Linux (default 300)
VALIDATION_TCP_CONCURRENCY=200
FETCH_TIMEOUT=4               # HTTP request timeout (default 5)
FETCH_MAX_ATTEMPTS=1          # URL fetch attempts (default 3)
MAX_WORKERS=80                # Parallel URL downloads (default 50)
```

## Caching

- **DNS:** 60-second TTL, lock-free, aiodns resolver
- **Dedup key:** `lru_cache` on `_get_dedup_key()` — avoids re-parsing URLs
- **HTTP:** Connection pooling in curl_cffi sessions (keep-alive)

## Network optimizations

- **curl_cffi** instead of `requests` — 2-3x faster, TLS impersonation (Chrome 124), bypasses anti-bot systems
- **SOCKS5** format `socks5://` for curl_cffi
- **Remote DNS** via `socks5h://` — prevents DNS leaks
- **Chrome User-Agent** for compatibility with sources

## Resource management

- **Ports:** dynamic allocation, availability check, ranges 20000-24999
- **Processes:** signal handlers + atexit + psutil (guaranteed cleanup)
- **Logs:** aggressive spam filtering of Xray logs
- **Temporary files:** `tempfile.mkstemp()` + `chmod 0600` (owner only)
- **Timeouts:** `VALIDATION_TCP_TIMEOUT=3s`, `VALIDATION_HTTP_TIMEOUT=5s`, `XRAY_STARTUP_TIMEOUT=3s`
- **Circuit breaker:** 5 errors in a row → 60 s recovery (`CIRCUIT_BREAKER_FAILURE_THRESHOLD=5`, `CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60`)
- **Retry:** 2 attempts per config (Xray), 5 attempts per GitHub upload (exponential delay from 0.5 s)

### DNS cache

`DNS_CACHE_TTL_SECONDS=60` — lock-free implementation via `aiodns`. No locks, 60-second TTL for dynamic IPs.

### Xray ports

| Range | Purpose |
|----------|------------|
| 20000-21999 | Batch testing (2000 ports) |
| 22000-23999 | Proxy chains (dialerProxy) |
| 24000-24999 | Persistent proxies |

Ports are allocated dynamically from the ranges above. For batch testing, the 20000-21999 range (2000 ports) was increased from 1000 to avoid TIME_WAIT conflicts. `XRAY_PORT_MAX_ATTEMPTS=10` attempts for a free port.

### Batch mode (Shared Xray)

**Problem:** when testing 1000+ configs in single mode, each config launches a separate Xray process (~50MB RAM). At concurrency 300 this is 15 GB of peak consumption.

**Solution:** v2rayN-style — one Xray process per N configs through N SOCKS inbounds. **Not enabled by default** — by default `XRAY_BATCH_MODE=single` (one Xray per config). Enabled via `XRAY_BATCH_MODE=batch` or `--batch-mode`.

```bash
# Enabling batch mode
XRAY_BATCH_MODE=batch python main.py --dry-run --tcp-ping
# Or via the CLI flag
python main.py --dry-run --tcp-ping --batch-mode
```

**How concurrency works:**
- 1000 configs → 1 chunk of 1000 configs (`XRAY_BATCH_SIZE=1000`)
- Chunks run via ThreadPoolExecutor (`XRAY_BATCH_PROCESSES=1` by default)
- Each chunk: one Xray with 1000 inbounds → 1000ms wait → ping all 1000 in parallel
- **Result:** ~2.5 s for all 1000 configs, ~50MB RAM

**Mode comparison:**

| Characteristic | Single (1 Xray per config) | Batch (shared Xray) |
|----------------|---------------------------|---------------------|
| Xray processes for 1000 configs | 1000 (up to the concurrency limit) | 1 (1 chunk × 1000, with `XRAY_BATCH_PROCESSES=1`) |
| Peak RAM | ~50MB × concurrency limit (15GB at 300) | ~50MB × processes (50MB at 1) |
| Time for 1000 configs | ~10s (at 300 concurrency, OOM risk) | ~2.5s (1 chunk × 1000 configs) |
| Isolation | Full | Partial (Xray crash = the whole chunk) |
| Startup delay | 500ms × number of rounds | 1000ms × 1 (port polling) |

**Configuration (environment variables):**

```bash
XRAY_BATCH_MODE=batch               # "single" (default) or "batch"
XRAY_BATCH_SIZE=1000                # Configs per one Xray (50-2000)
XRAY_BATCH_PROCESSES=1              # Parallel Xray processes (usually 1)
XRAY_BATCH_STARTUP_DELAY_MS=1000    # Delay before ping (50-5000ms, default 1000)
XRAY_BATCH_PORT_RANGE_SIZE=2000     # Port range per chunk (100-5000)
```

## SmartETA

A smart time estimator for batch testing.

**Problem:** fast configs finish first, the global average speed is overestimated, and the standard ETA constantly shows less than the real time.

**Solution:**
1. **Three-component estimate** — max of three: sliding window (fast reaction), global speed (stable), EMA of config durations (independent of the order)
2. **Duration EMA** — exponential moving average, updated on each config (not only per batch). Adapts to the current distribution of fast/slow
3. **Timeout floor** — a physical limit: `ceil(remaining / concurrency) * timeout` (without discount)
4. **Dynamic window** — size `max(500, min(total // 10, 5000))`, scales to 30k-100k configs

## Benchmarks

Typical times for ~10000 configs (Ubuntu):

| Phase | Time |
|------|-------|
| URL download (50 workers) | 10-30 s |
| Creating all.txt (deduplication) | 5-10 s |
| SNI/CIDR filtering (32 chunks) | 5-15 s |
| Xray verification (300 concurrent) | 60-120 s |
| Split by protocols | 5-10 s |
| Upload to GitHub | 20-40 s |
| **Total** | **2-5 min** |
