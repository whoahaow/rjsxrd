"""Simple TCP ping-based config tester. No external dependencies, no root required.

Tests VPN configs by TCP-connecting to the extracted host:port and measuring RTT.
Returns results in the same format as XrayTester.test_batch() for drop-in replacement.
"""

import asyncio
import socket
import sys
import time

from config.settings import VALIDATION_TCP_CONCURRENCY
from utils.file_utils import extract_host_port
from utils.logger import log
from utils.progress import get_async_pbar
from utils.smart_eta import SmartETA


def get_concurrency_limit() -> int:
    """Platform-aware concurrency limit for TCP ping testing."""
    return VALIDATION_TCP_CONCURRENCY


class SimpleTester:
    """TCP ping-based config tester.

    Tests configs by establishing TCP connections to extracted host:port pairs.
    Returns (url, is_working, latency_ms) tuples sorted by latency — same
    interface as XrayTester.test_batch().
    """

    def __init__(self, concurrency: int = None, timeout: float = 3.0) -> None:
        self.concurrency = concurrency or get_concurrency_limit()
        self.timeout = timeout

    @staticmethod
    def _in_async_context() -> bool:
        """Check if we're inside a running event loop.

        asyncio.run() crashes with RuntimeError when called from within
        a running event loop. Checking via get_running_loop() lets us
        handle both sync and async callers."""
        try:
            asyncio.get_running_loop()
            return True
        except RuntimeError:
            return False

    async def _tcp_ping_one(
        self, host: str, port: int, sem: asyncio.Semaphore, timeout: float = None
    ) -> tuple[bool, float]:
        """TCP connect to a single host:port, return (reachable, rtt_ms)."""
        _timeout = timeout or self.timeout
        async with sem:
            try:
                start = asyncio.get_event_loop().time()
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=_timeout,
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                writer.close()
                await writer.wait_closed()
                return True, round(elapsed, 1)
            except (
                TimeoutError,
                ConnectionRefusedError,
                ConnectionAbortedError,
                OSError,
                socket.gaierror,
            ):
                return False, 0.0

    async def run_batch_async(
        self, targets: list[tuple[str, int, str]], timeout: float = None
    ) -> list[tuple[str, bool, float]]:
        """Run TCP ping on all targets concurrently with semaphore and progress bar.

        This is the async core of test_batch(). Use it directly when calling
        from an async context. From a sync context, use test_batch() instead.
        """
        _timeout = timeout or self.timeout
        eta_tracker = SmartETA(len(targets), self.concurrency, _timeout)

        sem = asyncio.Semaphore(self.concurrency)
        results_lock = asyncio.Lock()
        completed = [0]
        failed_count = [0]

        pbar = get_async_pbar(
            total=len(targets),
            desc="TCP ping | Working: 0 (0%) ETA: ?s",
            unit="config",
            unit_scale=True,
            unit_divisor=1000,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}, {rate_fmt}]",
            mininterval=0.1,
            maxinterval=1.0,
            file=sys.stderr,
            delay=0,
            leave=True,
        )

        async def test_one(host: str, port: int, url: str) -> tuple[str, bool, float]:
            t0 = time.time()
            ok, rtt = await self._tcp_ping_one(host, port, sem, timeout=_timeout)
            duration = time.time() - t0
            async with results_lock:
                completed[0] += 1
                if not ok:
                    failed_count[0] += 1
                working_count = completed[0] - failed_count[0]
                success_rate = (working_count / completed[0] * 100) if completed[0] > 0 else 0
            eta_tracker.record_completion(duration)
            if pbar:
                pbar.update(1)
                pbar.set_description(
                    f"TCP ping | ETA {eta_tracker.description} | Working: {working_count} ({success_rate:.1f}%)"
                )
            elif completed[0] % 200 == 0 or completed[0] == len(targets):
                log(
                    f"TCP ping progress: {completed[0]}/{len(targets)} ({completed[0] / (time.time() - t0 + 0.01):.1f}/s, ETA: {eta_tracker.description}) - Working: {working_count} ({success_rate:.1f}%)"
                )
            return url, ok, rtt

        tasks = [test_one(h, p, u) for h, p, u in targets]
        all_results = await asyncio.gather(*tasks)

        if pbar:
            try:
                await asyncio.get_event_loop().run_in_executor(None, pbar.close)
            except (RuntimeError, OSError):
                pass  # best-effort cleanup

        working = [(url, ok, rtt) for url, ok, rtt in all_results if ok]
        working.sort(key=lambda x: x[2])
        failed = [(url, ok, rtt) for url, ok, rtt in all_results if not ok]

        return working + failed

    def test_batch(
        self,
        configs: list[str],
        timeout: float = None,
        verbose: bool = False,
        progress_callback=None,
    ) -> list[tuple[str, bool, float]]:
        """Test configs via TCP ping.

        Args:
            configs: List of config URL strings
            timeout: Per-connection timeout in seconds
            verbose: Log skipped config details when True
            progress_callback: Ignored in TCP mode (verification is fast)

        Returns:
            List of (url, is_reachable, rtt_ms) sorted by latency.
            Unreachable configs are appended at the end with rtt=0.
        """
        effective_timeout = timeout if timeout is not None else self.timeout

        targets = []
        skipped_urls = []
        for cfg in configs:
            hp = extract_host_port(cfg)
            if hp:
                targets.append((hp[0], hp[1], cfg))
            else:
                skipped_urls.append(cfg)

        if skipped_urls:
            if verbose:
                for url in skipped_urls:
                    log(f"TCP ping: skipped {url[:80]} (could not extract host:port)")
            log(f"TCP ping: skipped {len(skipped_urls)} configs (could not extract host:port)")

        if not targets:
            log("TCP ping: no valid targets to test")
            return [(cfg, False, 0.0) for cfg in configs]

        log(
            f"TCP ping: testing {len(targets)} configs "
            f"(concurrency={self.concurrency}, timeout={effective_timeout}s)"
        )

        # Detect if we're already inside a running event loop.
        # asyncio.run() crashes with RuntimeError if called from within one.
        # The async core is available as self.run_batch_async() for async callers.
        if self._in_async_context():
            log(
                "TCP ping: called from async context — use run_batch_async() directly. "
                "Falling back: creating temp loop in thread."
            )
            # Last resort: run in a new thread with its own event loop
            from utils.executor_cache import ExecutorCache

            ex = ExecutorCache.get("simple_tester_fallback", max_workers=1)
            future = ex.submit(
                lambda: asyncio.run(self.run_batch_async(targets, timeout=effective_timeout))
            )
            results = future.result()
        else:
            results = asyncio.run(self.run_batch_async(targets, timeout=effective_timeout))

        working_count = sum(1 for _, ok, _ in results if ok)
        log(f"TCP ping: {working_count}/{len(targets)} reachable")

        return results
