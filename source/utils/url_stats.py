"""URL fetch and config yield statistics tracking.

Persistent JSON storage for per-URL:
- Fetch success/failure history (across pipeline runs)
- Config yield (raw, secure, verified counts)
- Per-config verification tracking for MANUAL_SERVERS

Thread-safe (threading.Lock). Uses atomic file writes.
"""

import hashlib
import json
import os
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime

from utils.logger import log

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
STATS_PATH = os.path.join(DATA_DIR, "url_stats.json")
URLS_TXT_PATH = os.path.join(os.path.dirname(DATA_DIR), "config", "URLS.txt")
SERVERS_TXT_PATH = os.path.join(os.path.dirname(DATA_DIR), "config", "servers.txt")
MAX_HISTORY = 3


@dataclass
class FetchHistoryItem:
    """A single fetch attempt result."""

    success: bool
    status: int = 0
    error: str = ""
    time: str = ""


@dataclass
class FetchStats:
    """Fetch tracking for a single URL."""

    consecutive_failures: int = 0
    history: list[FetchHistoryItem] = field(default_factory=list)


@dataclass
class YieldStats:
    """Config yield tracking for a single URL."""

    raw: int = 0
    secure: int = 0
    total_raw: int = 0
    total_secure: int = 0
    verified: int = 0
    verified_total: int = 0
    last_updated: str = ""


@dataclass
class ConfigVerification:
    """Per-config verification tracking (for servers.txt)."""

    verifications: list[bool] = field(default_factory=list)
    consecutive_failures: int = 0
    preview: str = ""


@dataclass
class URLEntry:
    """Top-level entry for one URL in the stats database."""

    fetch: FetchStats | None = None
    yield_: YieldStats | None = None
    configs: dict[str, ConfigVerification] = field(default_factory=dict)


# Dict-key helpers: mapping from dataclass field names to JSON dict keys
_FETCH_KEY = "fetch"
_YIELD_KEY = "yield"
_CONFIGS_KEY = "configs"


def _fetch_from_dict(data: dict) -> FetchStats:
    """Convert a raw dict to a typed FetchStats."""
    f = data.get(_FETCH_KEY, {}) or {}
    history = [FetchHistoryItem(**h) for h in f.get("history", [])]
    return FetchStats(
        consecutive_failures=f.get("consecutive_failures", 0),
        history=history,
    )


def _yield_from_dict(data: dict) -> YieldStats:
    """Convert a raw dict to a typed YieldStats."""
    y = data.get(_YIELD_KEY, {}) or {}
    return YieldStats(
        raw=y.get("raw", 0),
        secure=y.get("secure", 0),
        total_raw=y.get("total_raw", 0),
        total_secure=y.get("total_secure", 0),
        verified=y.get("verified", 0),
        verified_total=y.get("verified_total", 0),
        last_updated=y.get("last_updated", ""),
    )


def _configs_from_dict(data: dict) -> dict[str, ConfigVerification]:
    """Convert raw config tracking dict to typed dict."""
    cfgs = data.get(_CONFIGS_KEY, {}) or {}
    return {
        k: ConfigVerification(
            verifications=v.get("verifications", []),
            consecutive_failures=v.get("consecutive_failures", 0),
            preview=v.get("preview", ""),
        )
        for k, v in cfgs.items()
    }


class URLStats:
    def __init__(self, path: str = STATS_PATH) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.data = self._load()
        self._dirty = False
        # Per-run accumulators for total_raw/total_secure. Reset on every
        # URLStats() construction (= every process start, since URLStats is
        # instantiated once per main.py run). The persisted JSON has the
        # LAST run's totals, which is fine — the persistent layer just
        # remembers the most recent totals, the in-memory accumulator
        # tracks the current run.
        self._run_totals: dict[str, tuple[int, int]] = {}

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(suffix=".json", dir=os.path.dirname(self.path))
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def flush(self) -> None:
        """Explicit flush to disk. Call at pipeline breakpoints."""
        with self.lock:
            if self._dirty:
                self._save()
                self._dirty = False

    # --- Fetch tracking ---

    def record_fetch(self, url: str, success: bool, status_code: int = 0, error: str = "") -> None:
        """Thread-safe fetch result recording. Save happens on flush()."""
        with self.lock:
            entry = self.data.setdefault(url, {})
            f = entry.setdefault("fetch", {"consecutive_failures": 0, "history": []})
            if success:
                f["consecutive_failures"] = 0
            else:
                f["consecutive_failures"] = f.get("consecutive_failures", 0) + 1
            f["history"].append(
                {
                    "success": success,
                    "status": status_code,
                    "error": error[:200],
                    "time": datetime.now().isoformat(),
                }
            )
            if len(f["history"]) > MAX_HISTORY:
                f["history"] = f["history"][-MAX_HISTORY:]
            self._dirty = True

    # --- Config yield tracking ---

    def record_config_yield(self, url: str, raw: int = 0, secure: int = 0) -> None:
        """Record a single URL's config yield for this run.

        Two callers in config_processor.py invoke this per-URL per-run:
        - During fetch: with raw=count, secure=0 (secure filter not run yet)
        - In the per-source yield loop: with raw=count, secure=count_secure

        Storing the LATEST values for `raw` and `secure` is intentional — the
        second call has more accurate data (secure filter has been run) and
        overwrites the placeholder.

        `total_raw` and `total_secure` accumulate across calls within this
        process (== this run, since URLStats is constructed once per run).
        If the same URL is fetched twice in one run (e.g. once from URLS and
        once from URLS_EXTRA_BYPASS), the totals reflect the sum. This fixes
        the v1 audit bug where repeated fetches in one run silently lost
        prior counts.
        """
        with self.lock:
            entry = self.data.setdefault(url, {})
            y = entry.setdefault("yield", {})
            y["raw"] = raw
            y["secure"] = secure
            prev_raw, prev_secure = self._run_totals.get(url, (0, 0))
            self._run_totals[url] = (prev_raw + raw, prev_secure + secure)
            y["total_raw"] = prev_raw + raw
            y["total_secure"] = prev_secure + secure
            y["last_updated"] = datetime.now().isoformat()
            self._dirty = True

    def record_verified_yield(self, source_counts: dict[str, tuple[int, int]]) -> None:
        """source_counts: {url: (tested_count, working_count)}"""
        with self.lock:
            for url, (tested, working) in source_counts.items():
                entry = self.data.setdefault(url, {})
                y = entry.setdefault("yield", {})
                y["verified"] = working
                y["verified_total"] = tested
                y["last_updated"] = datetime.now().isoformat()
            self._dirty = True

    # --- Per-config tracking (only for MANUAL_SERVERS) ---

    def record_config_verification(self, source: str, config: str, is_working: bool) -> None:
        """Track individual config verification (for servers.txt cleanup)."""
        if source != "MANUAL_SERVERS":
            return
        with self.lock:
            entry = self.data.setdefault(source, {})
            cfgs = entry.setdefault("configs", {})
            cfg_key = hashlib.sha256(config.encode()).hexdigest()[:16]
            c = cfgs.setdefault(cfg_key, {"verifications": [], "consecutive_failures": 0})
            c["verifications"].append(is_working)
            if len(c["verifications"]) > MAX_HISTORY:
                c["verifications"] = c["verifications"][-MAX_HISTORY:]
            if is_working:
                c["consecutive_failures"] = 0
            else:
                c["consecutive_failures"] = c.get("consecutive_failures", 0) + 1
            c["preview"] = config[:80]
            self._dirty = True

    # --- Queries ---

    def get_dead_urls(self, threshold: int = 3) -> list[tuple[str, int]]:
        with self.lock:
            result = []
            for url, entry in self.data.items():
                if url.startswith("MANUAL_") or url in (
                    "DAILY_REPO",
                    "SSTAP_ORG",
                    "UPSTREAM_AGGREGATOR",
                ):
                    continue
                cf = entry.get("fetch", {}).get("consecutive_failures", 0)
                if cf >= threshold:
                    result.append((url, cf))
            return sorted(result, key=lambda x: -x[1])

    def get_dead_configs(self, threshold: int = 3) -> list[tuple[str, str]]:
        """Returns [(config_preview, sha256_hash)] for dead configs."""
        with self.lock:
            entry = self.data.get("MANUAL_SERVERS", {})
            cfgs = entry.get("configs", {})
            result = []
            for cfg_key, info in cfgs.items():
                if info.get("consecutive_failures", 0) >= threshold:
                    result.append((info.get("preview", ""), cfg_key))
            return result

    def get_low_yield_urls(self, max_verified: int = 0) -> list[tuple[str, int]]:
        with self.lock:
            result = []
            for url, entry in self.data.items():
                if url.startswith("MANUAL_") or url in (
                    "DAILY_REPO",
                    "SSTAP_ORG",
                    "UPSTREAM_AGGREGATOR",
                ):
                    continue
                v = entry.get("yield", {}).get("verified", -1)
                if v <= max_verified and v >= 0:
                    result.append((url, v))
            return sorted(result, key=lambda x: x[1])

    def get_top_yield_urls(self, n: int = 10) -> list[tuple[str, int]]:
        with self.lock:
            items = []
            for url, entry in self.data.items():
                if url.startswith("MANUAL_") or url in (
                    "DAILY_REPO",
                    "SSTAP_ORG",
                    "UPSTREAM_AGGREGATOR",
                ):
                    continue
                v = entry.get("yield", {}).get("verified", 0)
                items.append((url, v))
            return sorted(items, key=lambda x: -x[1])[:n]

    # --- Auto-cleanup ---

    def remove_dead_from_urls_txt(self, path: str = URLS_TXT_PATH, threshold: int = 3) -> None:
        if not os.path.exists(path):
            return
        dead_urls = {url for url, _ in self.get_dead_urls(threshold)}
        if not dead_urls:
            return

        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError) as e:
            log(f"URL Stats: cannot read {path}: {e}")
            return

        result = []
        removed = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and stripped in dead_urls:
                removed.append(stripped)
                continue
            result.append(line)

        if removed:
            try:
                shutil.copy2(path, path + ".backup")
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(result)
            except OSError as e:
                log(f"URL Stats: cannot write {path}: {e}")
                return
            # Prune dead entries from in-memory stats to prevent bloat
            with self.lock:
                for url in removed:
                    self.data.pop(url, None)
                self._dirty = True
            log(f"URL Stats: removed {len(removed)} dead URLs from {path}")
            for r in removed:
                log(f"  Removed: {r[:100]}")

    def remove_dead_from_servers_txt(
        self, path: str = SERVERS_TXT_PATH, threshold: int = 3
    ) -> None:
        if not os.path.exists(path):
            return
        dead_info = self.get_dead_configs(threshold)
        if not dead_info:
            return
        dead_hashes = {h for _, h in dead_info}

        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError) as e:
            log(f"URL Stats: cannot read {path}: {e}")
            return

        result = []
        removed = []
        for line in lines:
            stripped = line.rstrip("\n")
            if stripped and not stripped.startswith("#"):
                line_hash = hashlib.sha256(stripped.encode()).hexdigest()[:16]
                if line_hash in dead_hashes:
                    removed.append(stripped)
                    continue
            result.append(line)

        if removed:
            try:
                shutil.copy2(path, path + ".backup")
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(result)
            except OSError as e:
                log(f"URL Stats: cannot write {path}: {e}")
                return
            # Prune dead config entries from in-memory stats to prevent bloat
            with self.lock:
                entry = self.data.get("MANUAL_SERVERS", {}).get("configs", {})
                for _, cfg_key in dead_info:
                    entry.pop(cfg_key, None)
                self._dirty = True
            log(f"URL Stats: removed {len(removed)} dead configs from {path}")

    # --- Report ---

    def print_report(self, threshold: int = 3) -> None:
        log("")
        log("=" * 60)
        log("URL HEALTH REPORT")
        log("=" * 60)

        dead = self.get_dead_urls(threshold)
        if dead:
            log(f"DEAD URLs ({threshold}+ consecutive fails): {len(dead)}")
            for url, fails in dead[:20]:
                log(f"  [{fails}x] {url[:100]}")
            if len(dead) > 20:
                log(f"  ... and {len(dead) - 20} more")
        else:
            log("DEAD URLs: none")

        dead_cfgs = self.get_dead_configs(threshold)
        if dead_cfgs:
            log(f"DEAD servers.txt configs ({threshold}+ fails): {len(dead_cfgs)}")
            for preview, _ in dead_cfgs[:10]:
                log(f"  {preview}")
            if len(dead_cfgs) > 10:
                log(f"  ... and {len(dead_cfgs) - 10} more")

        low = self.get_low_yield_urls(0)
        if low:
            log(f"ZERO verified configs: {len(low)} URLs")
            for url, _ in low[:10]:
                log(f"  {url[:100]}")
            if len(low) > 10:
                log(f"  ... and {len(low) - 10} more")

        top = self.get_top_yield_urls(10)
        if top:
            log("TOP 10 sources by verified configs:")
            for i, (url, count) in enumerate(top, 1):
                log(f"  #{i}: {count} verified — {url[:100]}")

        log("=" * 60)
