"""Cached thread pool executors to avoid recreation overhead.

Provides module-level cached executors that are reused across the application
instead of creating new ThreadPoolExecutor instances for each operation.

Worker counts are auto-sized using SystemSpecs (RAM-aware, CPU-aware).
"""

import atexit
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional

from utils.system_specs import get_specs


def _get_optimal_workers(default: int = 8, label: str = "generic") -> int:
    """Get optimal worker count based on platform, RAM, and CPU.

    Uses SystemSpecs to auto-detect resources. Falls back to the ``default``
    value when the detected safe count is higher (env vars take precedence
    for downward overrides only).

    Args:
        default: User-configured or caller-chosen default.
        label: Description for logging ("url_fetch", "file_io", etc.).

    Returns:
        A worker count that won't exhaust system memory.
    """
    specs = get_specs()

    # WSL has higher memory overhead per thread
    if specs.is_wsl:
        return max(2, default // 2)

    # Low RAM: cap workers aggressively
    if specs.total_ram_mb < 1024:
        return max(2, min(default, 8))
    elif specs.total_ram_mb < 2048:
        return max(4, min(default, 16))

    # Enough RAM: use default (it's already reasonable, floor at 2)
    return max(2, default)


class ExecutorCache:
    """Cache for reusable ThreadPoolExecutor instances.
    
    Executors are created lazily and reused across calls. All executors
    are properly shut down on program exit.
    """
    
    _executors: Dict[str, ThreadPoolExecutor] = {}
    _lock = None  # Initialized lazily to avoid import-order issues
    _registered: bool = False  # Idempotency guard for atexit.register
    
    @classmethod
    def _get_lock(cls) -> "threading.Lock":
        """Get or create lock lazily."""
        if cls._lock is None:
            import threading
            cls._lock = threading.Lock()
        return cls._lock
    
    @classmethod
    def get(cls, name: str, max_workers: int = None) -> ThreadPoolExecutor:
        """Get cached executor by name.
        
        Args:
            name: Unique identifier for this executor type
            max_workers: Number of workers (only used on first creation,
                        auto-optimized for WSL/low-memory if not specified)
            
        Returns:
            Cached ThreadPoolExecutor instance
            
        Example:
            executor = ExecutorCache.get('file_io', max_workers=8)
            results = list(executor.map(process_func, items))
        """
        lock = cls._get_lock()
        
        with lock:
            if name not in cls._executors:
                # Auto-optimize worker count if not specified
                if max_workers is None:
                    max_workers = _get_optimal_workers(default=8)
                
                cls._executors[name] = ThreadPoolExecutor(
                    max_workers=max_workers,
                    thread_name_prefix=name
                )
            return cls._executors[name]
    
    @classmethod
    def shutdown_all(cls) -> None:
        """Shutdown all cached executors.
        
        Called automatically on program exit via atexit handler.
        """
        lock = cls._get_lock()
        
        with lock:
            for name, executor in cls._executors.items():
                try:
                    executor.shutdown(wait=True)
                except (OSError, RuntimeError):
                    pass
            cls._executors.clear()


# Register shutdown handler (idempotent — only on first import)
if not getattr(ExecutorCache, '_registered', False):
    atexit.register(ExecutorCache.shutdown_all)
    ExecutorCache._registered = True


# Convenience functions for common executor types
def get_file_io_executor() -> ThreadPoolExecutor:
    """Get cached executor for file I/O operations."""
    return ExecutorCache.get('file_io', max_workers=8)


def get_network_io_executor() -> ThreadPoolExecutor:
    """Get cached executor for network I/O operations."""
    return ExecutorCache.get('network_io', max_workers=16)


def get_cpu_bound_executor() -> ThreadPoolExecutor:
    """Get cached executor for CPU-bound operations."""
    import multiprocessing
    cpu_count = multiprocessing.cpu_count()
    return ExecutorCache.get('cpu_bound', max_workers=cpu_count)


def get_regex_executor() -> ThreadPoolExecutor:
    """Get cached executor for regex operations (IO-bound due to GIL)."""
    return ExecutorCache.get('regex', max_workers=8)
