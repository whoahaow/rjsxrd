"""Auto-detect system resources at startup. Single source of truth for concurrency limits.

Detects total RAM, CPU cores, WSL, container cgroup limits. Provides safe
concurrency values for different types of work (URL fetch, xray, tcp ping).
All values are computed once at module load and cached.

Usage:
    specs = SystemSpecs.detect()
    xray_workers = specs.safe_xray_workers()
    url_workers = specs.safe_url_workers()
    tcp_workers = specs.safe_tcp_workers()
"""

import os
import sys
import multiprocessing
from dataclasses import dataclass
from typing import Optional

from utils.psutil_available import psutil, HAS_PSUTIL


@dataclass(frozen=True)
class SystemSpecs:
    """Immutable snapshot of system resources at startup.

    All values are detected once and frozen. Use the classmethod ``detect()``
    to create an instance.
    """

    total_ram_mb: float
    cpu_count: int
    is_wsl: bool
    is_container: bool

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @classmethod
    def detect(cls) -> "SystemSpecs":
        """Detect system resources and return a frozen snapshot."""
        total_ram = 1024.0  # safe pessimistic default
        if psutil is not None:
            total_ram = psutil.virtual_memory().total / (1024 * 1024)

        cpu_count = max(1, multiprocessing.cpu_count())

        is_wsl = _detect_wsl()
        is_container = False
        container_limit = _detect_container_memory_mb()

        if container_limit is not None and 0 < container_limit < total_ram * 0.95:
            total_ram = container_limit
            is_container = True

        return cls(
            total_ram_mb=total_ram,
            cpu_count=cpu_count,
            is_wsl=is_wsl,
            is_container=is_container,
        )

    # ------------------------------------------------------------------
    # Safe concurrency helpers
    # ------------------------------------------------------------------

    def safe_xray_workers(self, mem_per_process_mb: float = 24) -> int:
        """Maximum concurrent Xray processes that fit in RAM."""
        headroom = 200 if not self.is_wsl else 350
        available = self.total_ram_mb - headroom
        ram_based = max(1, int(available / mem_per_process_mb))
        cpu_based = max(1, self.cpu_count * 40)
        return min(ram_based, cpu_based)

    def safe_url_workers(self) -> int:
        """URL fetching is I/O bound, so generous. Cap at sane limits."""
        if self.total_ram_mb < 2048:
            return min(6, self.cpu_count * 6)
        return min(20, self.cpu_count * 10)

    def safe_fetch_workers(self) -> int:
        """Parallel fetch workers — CPU-bound TLS handshakes limit concurrency.
        
        Returns workers count based on CPU cores, clamped to [20, 50].
        1 core → 20, 2 cores → 30, 4+ cores → 50.
        """
        cpu_based = self.cpu_count * 10 + 10
        return max(20, min(50, cpu_based))

    def safe_tcp_workers(self) -> int:
        """TCP ping is very light (~5 MB per worker). Can be generous."""
        if self.total_ram_mb < 1024:
            return min(30, self.cpu_count * 30)
        return min(150, self.cpu_count * 50)

    def safe_http_workers(self) -> int:
        """HTTP validation (curl_cffi) is moderate. Between TCP and Xray."""
        if self.total_ram_mb < 1024:
            return min(8, self.cpu_count * 8)
        return min(20, self.cpu_count * 15)

    def safe_validation_max_workers(self) -> int:
        """Batch processing cap — bounded by RAM."""
        if self.total_ram_mb < 1024:
            return 50
        if self.total_ram_mb < 2048:
            return 100
        return 200

    def safe_max_file_mb(self) -> float:
        """Max per-file size before splitting. GitHub limit is ~50 MB,
        but on low-RAM VPS we split earlier to avoid memory pressure."""
        if self.total_ram_mb < 2048:
            return 10.0
        return 49.0

    def summary(self) -> str:
        """Human-readable one-line summary."""
        return (
            f"{self.total_ram_mb:.0f} MB RAM, {self.cpu_count} CPU cores"
            f"{' (WSL)' if self.is_wsl else ''}{' (container)' if self.is_container else ''}"
        )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _detect_wsl() -> bool:
    """Detect if running under WSL."""
    try:
        with open("/proc/version") as f:
            v = f.read().lower()
        return "microsoft" in v or "wsl" in v
    except FileNotFoundError:
        return False


def _detect_container_memory_mb() -> Optional[float]:
    """Detect cgroup v2/v1 memory limit. Returns None if no limit found.

    psutil.virtual_memory() inside a container reports *host* memory, not
    the container's ``--memory`` limit. We check cgroup files directly.
    """
    # cgroups v2
    try:
        with open("/sys/fs/cgroup/memory.max") as f:
            val = f.read().strip()
            if val and val != "max":
                return int(val) / (1024 * 1024)
    except (FileNotFoundError, ValueError, OSError):
        pass

    # cgroups v1
    try:
        with open("/sys/fs/cgroup/memory/memory.limit_in_bytes") as f:
            val = f.read().strip()
            if val:
                limit = int(val)
                if 0 < limit < 2**40:  # sanity: less than 1 TB
                    return limit / (1024 * 1024)
    except (FileNotFoundError, ValueError, OSError):
        pass

    return None


# ------------------------------------------------------------------
# Module-level cached instance (lazy, import-safe)
# ------------------------------------------------------------------

_SPECS: Optional[SystemSpecs] = None


def get_specs() -> SystemSpecs:
    """Get cached SystemSpecs, detecting on first call."""
    global _SPECS
    if _SPECS is None:
        _SPECS = SystemSpecs.detect()
    return _SPECS
