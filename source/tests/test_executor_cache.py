"""Tests for executor_cache.py — cached thread pool executors."""

from utils.executor_cache import (
    ExecutorCache,
    _get_optimal_workers,
    get_cpu_bound_executor,
    get_file_io_executor,
    get_network_io_executor,
    get_regex_executor,
)


class TestGetOptimalWorkers:
    """Test the worker count optimizer."""

    def test_default_on_native_non_wsl(self):
        """On non-WSL with enough memory, returns default (8)."""
        workers = _get_optimal_workers(default=8)
        assert isinstance(workers, int)
        assert workers >= 2  # Always at least 2

    def test_never_below_two(self):
        """Even with very low default, floor is 2."""
        workers = _get_optimal_workers(default=1)
        assert workers >= 2


class TestExecutorCache:
    """Test executor creation, caching, and shutdown."""

    def setup_method(self):
        """Clean up executors before each test."""
        ExecutorCache._executors.clear()

    def test_get_creates_new_executor(self):
        """First get() creates and caches an executor."""
        exec1 = ExecutorCache.get("test_create")
        assert exec1 is not None
        assert "test_create" in ExecutorCache._executors

    def test_get_returns_cached_executor(self):
        """Second get() returns the same instance."""
        exec1 = ExecutorCache.get("test_cache")
        exec2 = ExecutorCache.get("test_cache")
        assert exec1 is exec2

    def test_different_names_different_executors(self):
        """Different names produce different executors."""
        exec1 = ExecutorCache.get("test_name_a")
        exec2 = ExecutorCache.get("test_name_b")
        assert exec1 is not exec2

    def test_get_with_custom_max_workers(self):
        """Passing max_workers explicitly should be respected."""
        exec1 = ExecutorCache.get("test_custom", max_workers=4)
        assert exec1._max_workers == 4

    def test_get_without_max_workers_auto_optimizes(self):
        """Omitting max_workers triggers auto-optimization via _get_optimal_workers."""
        exec1 = ExecutorCache.get("test_auto")
        assert exec1._max_workers >= 2

    def test_shutdown_all_clears_executors(self):
        """shutdown_all stops all executors and clears the cache."""
        ExecutorCache.get("test_shutdown")
        assert len(ExecutorCache._executors) == 1
        ExecutorCache.shutdown_all()
        assert len(ExecutorCache._executors) == 0

    def test_shutdown_all_twice_is_safe(self):
        """Calling shutdown_all on empty cache must not raise."""
        ExecutorCache.shutdown_all()  # First call — no-op
        ExecutorCache.shutdown_all()  # Second call — still no-op

    def test_shutdown_all_handles_exceptions(self):
        """If an executor.shutdown() raises, the exception must not propagate
        and other executors must still be cleaned up."""
        ExecutorCache._executors.clear()
        # Register two executors, one that raises on shutdown
        from unittest.mock import MagicMock

        bad_executor = MagicMock()
        bad_executor.shutdown.side_effect = RuntimeError("shutdown failed")
        good_executor = MagicMock()
        ExecutorCache._executors["bad"] = bad_executor
        ExecutorCache._executors["good"] = good_executor
        ExecutorCache.shutdown_all()
        # Both should have been attempted; cache is cleared
        assert len(ExecutorCache._executors) == 0

    def test_concurrent_callers_receive_one_lock(self):
        """Every thread reaching for the lock must get the same object.

        The lock was built lazily behind `if cls._lock is None` — a
        check-then-act: two threads could each see None, each build a lock, and
        the loser's lock was discarded, leaving both callers holding different
        locks and the mutual exclusion void during its own initialisation.
        """
        import threading

        barrier = threading.Barrier(8)
        seen = []

        def grab_lock():
            barrier.wait()
            seen.append(id(ExecutorCache._get_lock()))

        threads = [threading.Thread(target=grab_lock) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(seen) == 8
        assert len(set(seen)) == 1, "threads received different lock objects"
        assert seen[0] == id(ExecutorCache._lock)

    def test_lock_exists_as_soon_as_the_module_loads(self):
        """The lock must be created with the class, not on first use."""
        import importlib
        import threading

        import utils.executor_cache as executor_cache

        module = importlib.reload(executor_cache)
        lock = module.ExecutorCache._lock

        assert lock is not None, "the lock is still created lazily"
        assert isinstance(lock, type(threading.Lock()))
        # Reloading keeps the module in the state its source describes, so a
        # second load must expose the same eager property.
        assert module.ExecutorCache._get_lock() is lock


class TestConvenienceFunctions:
    """Test the module-level get_*_executor helpers."""

    def setup_method(self):
        ExecutorCache._executors.clear()

    def test_get_file_io_executor(self):
        """get_file_io_executor returns a cached executor named 'file_io'."""
        exec1 = get_file_io_executor()
        exec2 = get_file_io_executor()
        assert exec1 is exec2
        assert exec1._max_workers == 8

    def test_get_network_io_executor(self):
        """get_network_io_executor returns a cached executor."""
        exec1 = get_network_io_executor()
        assert exec1 is not None

    def test_get_cpu_bound_executor(self):
        """get_cpu_bound_executor returns a cached executor."""
        exec1 = get_cpu_bound_executor()
        assert exec1 is not None

    def test_get_regex_executor(self):
        """get_regex_executor returns a cached executor."""
        exec1 = get_regex_executor()
        exec2 = get_regex_executor()
        assert exec1 is exec2
        assert exec1._max_workers == 8
