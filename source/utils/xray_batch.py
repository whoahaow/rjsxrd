"""Batch runner for Xray config testing.

Extracted from xray_tester.py. Handles concurrent batch testing of VPN
configs via Xray-core. Delegates process lifecycle and config building
to the parent XrayTester instance.
"""

import os
import sys
import time
import asyncio
import threading
import concurrent.futures
from typing import List, Tuple, Dict, Optional, Callable

import requests

from utils.logger import log
from utils.executor_cache import ExecutorCache
from utils.smart_eta import SmartETA
from config.settings import XRAY_STARTUP_TIMEOUT, MAX_CONFIGS_PER_FILE, XRAY_BASE_PORT, XRAY_BATCH_PORT_RANGE_SIZE
from utils.progress import get_async_pbar, get_sync_pbar as _tqdm_sync

from utils.curl_import import CurlSession, AsyncSession, CURL_CFFI_AVAILABLE



class BatchRunner:
    """Orchestrates batch testing of VPN configs via an XrayTester instance.

    Takes an XrayTester and runs concurrent/single-config tests through it.
    Owns the batch loop logic, progress tracking, ETA estimation, and
    result aggregation. Process lifecycle (start/stop xray, config building)
    stays on the tester.
    """

    def __init__(self, tester: "XrayTester") -> None:
        self.tester = tester

    # ── Public API ──────────────────────────────────────────────────

    def test_through_socks(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """Test connection through SOCKS proxy - HTTP only (port already verified)."""
        return self._http_ping_through_proxy(socks_port, timeout, verbose)

    def test_single_config(self, url: str, timeout: float, verbose: bool = False,
                           max_retries: int = 1, skip_tcp_ping: bool = False) -> Tuple[str, bool, float, str]:
        """Test config through Xray HTTP test only."""
        last_error = "Unknown error"

        for attempt in range(max_retries):
            valid, error = self.tester._quick_validate_url(url)
            if not valid:
                self.tester._track_error(error)
                return (url, False, 0.0, error)

            socks_port = self.tester._get_next_port()
            config = self.tester.create_single_outbound_config(url, socks_port)
            if not config:
                last_error = "Failed to parse config"
                self.tester._track_error(last_error)
                return (url, False, 0.0, last_error)

            success, process, error_msg = self.tester.start_xray_instance(config, socks_port, verbose=verbose)
            if not success:
                self.tester._track_error(error_msg or "Xray failed to start")
                if attempt < max_retries - 1:
                    time.sleep(0.1)
                    continue
                return (url, False, 0.0, error_msg or "Xray failed to start")

            try:
                tested, latency = self.test_through_socks(socks_port, timeout)
                if tested:
                    return (url, tested, latency, "")

                last_error = "HTTP test failed (no response)"
                self.tester._track_error(last_error)

                if attempt < max_retries - 1:
                    time.sleep(0.1)
                    continue
                return (url, False, 0.0, last_error)
            finally:
                self.tester.stop_xray_process(process)

        return (url, False, 0.0, last_error)

    def _process_single_chunk(
        self, chunk_urls: List[str], chunk_idx: int,
        timeout: float, concurrency: int, verbose: bool,
        startup_delay: float,
    ) -> List[Tuple[str, bool, float]]:
        """Process one chunk: build shared config, start xray, test, cleanup.

        Runs a single chunk end-to-end: creates one xray config with N
        SOCKS inbounds, starts xray, waits for port binding, tests all
        profiles concurrently, kills xray. Returns results for this chunk.

        Designed to run in a worker thread (parallel chunks).
        """
        from config.settings import XRAY_BASE_PORT, XRAY_BATCH_PORT_RANGE_SIZE

        chunk_port_base = XRAY_BASE_PORT + chunk_idx * XRAY_BATCH_PORT_RANGE_SIZE

        # Build one config with N inbounds
        config, port_map = self.tester.create_multi_config(chunk_urls, chunk_port_base)
        if not config or not port_map:
            # All configs in this chunk failed to parse
            return [(url, False, 0.0) for url in chunk_urls]

        # Track parse failures — URLs that create_multi_config couldn't handle
        tested_urls = set(port_map.values())
        failed_results = [(url, False, 0.0) for url in chunk_urls if url not in tested_urls]

        # Start xray — poll the first allocated port
        first_port = min(port_map.keys())
        success, process, error = self.tester.start_xray_instance(config, first_port)
        if not success:
            log(f"Chunk {chunk_idx + 1}: xray failed to start on port {first_port}: {error or 'unknown'}")
            return failed_results + [(url, False, 0.0) for _port, url in port_map.items()]

        # Wait for port binding (port poll in start_xray_instance already waited,
        # this extra delay ensures all inbounds are registered in xray's event loop)
        if startup_delay > 0:
            time.sleep(startup_delay)

        try:
            chunk_workers = min(concurrency, max(len(port_map), 1))
            chunk_results = self._test_batch_concurrent(
                port_map, timeout, chunk_workers, verbose,
                executor_name=f'batch_chunk_{chunk_idx}',
            )
            return failed_results + chunk_results
        finally:
            self.tester.stop_xray_process(process)

    def _test_batch_shared_xray(
        self, urls: List[str], concurrency: int = None, timeout: float = None,
        verbose: bool = False,
        progress_callback: Optional[callable] = None,
    ) -> List[Tuple[str, bool, float]]:
        """Batch mode: parallel chunks with shared xray per chunk (v2rayN-style).

        Chunks profiles by XRAY_BATCH_SIZE. Runs up to XRAY_BATCH_PROCESSES
        chunks IN PARALLEL via ThreadPoolExecutor. Each chunk:
          - Builds ONE xray config with N SOCKS inbounds
          - Starts ONE xray, waits for port binding
          - Tests all profiles concurrently through their assigned SOCKS ports
          - Kills the xray

        Parallel chunks drastically reduce total time vs sequential:
        - 1000 configs, batch_size=100, processes=10 → 10 chunks in parallel
        - Each chunk takes ~2.5s (200ms startup + 2s ping)
        - Total time: ~2.5s (not 25s sequential!)
        - RAM: 10 xrays × 50MB = 500MB peak

        Returns:
            List of (url, success, latency) sorted by latency (working first).
        """
        from config.settings import (
            XRAY_BATCH_SIZE, XRAY_BATCH_PROCESSES,
            XRAY_BATCH_STARTUP_DELAY_MS,
            VALIDATION_HTTP_TIMEOUT, ASYNC_CONCURRENCY_WIN32, ASYNC_CONCURRENCY_LINUX,
        )
        if not urls:
            return []

        default_timeout = timeout or VALIDATION_HTTP_TIMEOUT
        if concurrency is None:
            from utils.system_specs import get_specs
            specs = get_specs()
            concurrency = specs.safe_xray_workers()

        if sys.platform == "win32":
            concurrency = min(concurrency, ASYNC_CONCURRENCY_WIN32)
        else:
            concurrency = min(concurrency, ASYNC_CONCURRENCY_LINUX)

        batch_size = XRAY_BATCH_SIZE
        max_processes = XRAY_BATCH_PROCESSES
        startup_delay = XRAY_BATCH_STARTUP_DELAY_MS / 1000.0
        # Divide global concurrency fairly among parallel chunks
        per_chunk_concurrency = max(10, concurrency // max_processes)

        log(
            f"Batch mode (parallel): {len(urls)} configs, "
            f"batch_size={batch_size}, processes={max_processes}, "
            f"per_chunk_concurrency={per_chunk_concurrency}, "
            f"startup_delay={startup_delay}s, timeout={default_timeout}s"
        )

        # Chunk urls — each chunk gets its own xray with N inbounds
        chunks = [urls[i:i + batch_size] for i in range(0, len(urls), batch_size)]
        num_chunks = len(chunks)

        log(
            f"Split into {num_chunks} chunk(s), processing up to "
            f"{max_processes} in parallel"
        )

        all_results: List[Tuple[str, bool, float]] = []
        results_lock = threading.Lock()
        working_count = [0]
        last_callback_file = [0]

        def _run_chunk(chunk_urls: List[str], chunk_idx: int) -> List[Tuple[str, bool, float]]:
            """Wrapper that processes a chunk and updates shared progress state."""
            chunk_results = self._process_single_chunk(
                chunk_urls, chunk_idx, default_timeout,
                per_chunk_concurrency, verbose, startup_delay,
            )

            with results_lock:
                all_results.extend(chunk_results)
                for _url, success, _latency in chunk_results:
                    if success:
                        working_count[0] += 1
                        if progress_callback:
                            wc = working_count[0]
                            if wc // MAX_CONFIGS_PER_FILE > last_callback_file[0]:
                                last_callback_file[0] = wc // MAX_CONFIGS_PER_FILE
                                sorted_working = [
                                    u for u, _s, _l in sorted(
                                        [(u, s, l) for u, s, l in all_results if s],
                                        key=lambda x: x[1],
                                    )
                                ]
                                progress_callback(sorted_working, len(all_results))

            log(
                f"Chunk {chunk_idx + 1}/{num_chunks} done: "
                f"{sum(1 for _, s, _ in chunk_results if s)}/"
                f"{len(chunk_results)} working"
            )
            return chunk_results

        # Process chunks in parallel using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_processes) as executor:
            future_to_idx = {
                executor.submit(_run_chunk, chunks[i], i): i
                for i in range(num_chunks)
            }
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    future.result(timeout=default_timeout + 30)
                except concurrent.futures.TimeoutError:
                    log(f"Chunk {idx + 1}: timed out after {default_timeout + 30}s")
                except Exception as e:
                    log(f"Chunk {idx + 1}: failed with {type(e).__name__}: {e}")

        # Sort final results: working first (by latency), failed last
        working = [(url, s, l) for url, s, l in all_results if s]
        working.sort(key=lambda x: x[2])
        failed = [(url, s, l) for url, s, l in all_results if not s]
        sorted_results = working + failed

        success_rate = len(working) / len(urls) * 100 if urls else 0
        log(
            f"Batch mode complete: {len(working)}/{len(urls)} working "
            f"({success_rate:.1f}%) across {num_chunks} parallel chunk(s)"
        )
        self.tester._print_error_summary()

        return sorted_results

    def test_batch(self, urls: List[str], concurrency: int = None, timeout: float = None,
                   verbose: bool = False,
                   progress_callback: Optional[callable] = None) -> List[Tuple[str, bool, float]]:
        """Test configs through Xray with TCP+TLS fallback. Uses async on all platforms.

        Args:
            progress_callback: Called on each working config: fn(working_urls_sorted, total_tested)

        Returns:
            List of (url, success, latency) sorted by latency (working first).
        """
        if not urls:
            return []

        # Check batch mode — short-circuit to shared xray if enabled
        from config.settings import XRAY_BATCH_MODE, BATCH_MODE_OVERRIDE
        batch_mode = BATCH_MODE_OVERRIDE if BATCH_MODE_OVERRIDE is not None else XRAY_BATCH_MODE
        if batch_mode == "batch":
            return self._test_batch_shared_xray(urls, concurrency, timeout, verbose, progress_callback)

        try:
            from config.settings import VALIDATION_HTTP_TIMEOUT, ASYNC_CONCURRENCY_WIN32, ASYNC_CONCURRENCY_LINUX
            default_timeout = VALIDATION_HTTP_TIMEOUT
        except ImportError:
            default_timeout = 10.0
            ASYNC_CONCURRENCY_WIN32 = 50
            ASYNC_CONCURRENCY_LINUX = 300

        timeout = timeout or default_timeout
        if concurrency is None:
            from utils.system_specs import get_specs
            specs = get_specs()
            concurrency = specs.safe_xray_workers()
            log(f"Auto-detected xray concurrency: {concurrency} "
                f"(system: {specs.summary()})")

        if sys.platform == "win32":
            concurrency = min(concurrency, ASYNC_CONCURRENCY_WIN32)
            log(f"Testing {len(urls)} configs (Windows, concurrency={concurrency}, timeout={timeout}s) - Progress bar enabled")
        else:
            concurrency = min(concurrency, ASYNC_CONCURRENCY_LINUX)
            log(f"Testing {len(urls)} configs (Linux/WSL, concurrency={concurrency}, timeout={timeout}s) - Progress bar enabled")

        # Try async first, fall back to sync if it fails.
        # We catch Exception broadly here because this is a fallback
        # pattern — any failure of the async wrapper should trigger
        # the sync fallback rather than crashing the test pipeline.
        try:
            return self._test_batch_async_wrapper(urls, concurrency, timeout, verbose, progress_callback)
        except Exception as e:
            log(f"Async testing failed ({type(e).__name__}: {str(e)[:100]}), falling back to sync mode")
            return self._test_batch_single(urls, concurrency, timeout, verbose, progress_callback)

    # ── Async batch internals ───────────────────────────────────────

    def _test_batch_async_wrapper(self, urls: List[str], concurrency: int, timeout: float,
                                  verbose: bool,
                                  progress_callback: Optional[callable] = None) -> List[Tuple[str, bool, float]]:
        """Simple async wrapper: Xray in threads, HTTP via requests (hybrid approach)."""
        executor = ExecutorCache.get('xray_worker', max_workers=min(concurrency, 300))

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.set_default_executor(executor)

            results = loop.run_until_complete(self._test_batch_async(urls, concurrency, timeout, verbose, progress_callback))

            time.sleep(0.5)

            working = [(url, s, l) for url, s, l in results if s]
            working.sort(key=lambda x: x[2])

            success_rate = len(working) / len(urls) * 100 if urls else 0
            log(f"Async testing complete: {len(working)}/{len(urls)} working ({success_rate:.1f}%)")

            self.tester._print_error_summary()

            return working
        finally:
            loop.close()

    async def _test_batch_async(self, urls: List[str], concurrency: int, timeout: float,
                                verbose: bool,
                                progress_callback: Optional[callable] = None) -> List[Tuple[str, bool, float]]:
        """Test configs with PIPELINED ASYNC (Xray startup overlaps with HTTP testing)."""
        eta_tracker = SmartETA(len(urls), concurrency, timeout)

        semaphore = asyncio.Semaphore(concurrency)
        results = []
        results_lock = asyncio.Lock()
        completed = [0]
        failed_count = [0]
        cleanup_futures: list = []

        pbar = get_async_pbar(
            total=len(urls),
            desc="Testing | Working: 0 (0%) ETA: ?s",
            unit="config",
            unit_scale=True,
            unit_divisor=1000,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}, {rate_fmt}]',
            mininterval=0.1,
            maxinterval=1.0,
            file=sys.stderr,
            delay=0,
            leave=True,
        )
        if pbar is not None:
            pbar.set_description("Testing | Working: 0 (0%) ETA: ?s")

        # Progressive upload tracking
        working_results: list = []
        last_callback_file = [0]

        async def test_with_semaphore(url: str) -> Tuple[str, bool, float]:
            try:
                async with semaphore:
                    t0 = time.time()
                    try:
                        result = await self._test_single_config_pipelined_async(
                            url, timeout, verbose=False, cleanup_futures=cleanup_futures
                        )
                        duration = time.time() - t0
                        async with results_lock:
                            completed[0] += 1
                            count = completed[0]
                            if not result[1]:
                                failed_count[0] += 1
                            working_count = count - failed_count[0]
                            success_rate = (working_count / count * 100) if count > 0 else 0
                            if result[1]:
                                working_results.append((result[2], url))
                            # Atomic check+update prevents multiple coroutines
                            # from firing the same callback simultaneously
                            should_fire = False
                            if result[1] and progress_callback:
                                current_file = working_count // MAX_CONFIGS_PER_FILE
                                if current_file > last_callback_file[0]:
                                    should_fire = True
                                    last_callback_file[0] = current_file
                                    snapshot = [u for _, u in sorted(working_results, key=lambda x: x[0])]

                        if should_fire:
                            loop = asyncio.get_running_loop()
                            await loop.run_in_executor(None, progress_callback, snapshot, count)
                        eta_tracker.record_completion(duration)
                        if pbar:
                            pbar.update(1)
                            pbar.set_description(f"Testing | ETA {eta_tracker.description} | Working: {working_count} ({success_rate:.1f}%)")
                        elif count % 50 == 0 or count == len(urls):
                            log(f"Progress: {count}/{len(urls)} ({count/(time.time()-t0+0.01):.1f}/s, ETA: {eta_tracker.description}) - Working: {working_count} ({success_rate:.1f}%)")
                        return result
                    except (OSError, RuntimeError, asyncio.TimeoutError) as e:
                        duration = time.time() - t0
                        if verbose:
                            log(f"Async test failed for {url[:60]}: {type(e).__name__}: {str(e)[:100]}")
                        async with results_lock:
                            completed[0] += 1
                            failed_count[0] += 1
                            working_count = completed[0] - failed_count[0]
                            success_rate = (working_count / completed[0] * 100) if completed[0] > 0 else 0
                        eta_tracker.record_completion(duration)
                        if pbar:
                            pbar.update(1)
                            pbar.set_description(f"Testing | ETA {eta_tracker.description} | Working: {working_count} ({success_rate:.1f}%)")
                        return (url, False, 0.0)
            finally:
                pass

        tasks = [test_with_semaphore(url) for url in urls]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        if cleanup_futures:
            await asyncio.wait_for(
                asyncio.gather(*cleanup_futures, return_exceptions=True),
                timeout=120,
            )

        if pbar:
            try:
                await asyncio.get_event_loop().run_in_executor(None, pbar.close)
            except (RuntimeError, OSError):
                pass

        for i, result in enumerate(task_results):
            if isinstance(result, Exception):
                results.append((urls[i], False, 0.0))
            else:
                results.append(result)

        return results

    async def _test_single_config_pipelined_async(self, url: str, timeout: float, verbose: bool = False,
                                                   cleanup_futures: "list | None" = None) -> Tuple[str, bool, float]:
        """Pipelined test: Xray in thread, curl_cffi async HTTP with socks5h://."""
        loop = asyncio.get_running_loop()

        socks_port = self.tester._get_next_port()
        config = self.tester.create_single_outbound_config(url, socks_port)

        if not config:
            self.tester._track_error("parse_error")
            return (url, False, 0.0)

        def start_xray_sync():
            success, process, error = self.tester.start_xray_instance(config, socks_port, verbose=False)
            return (process, success, error)

        try:
            process, success, error = await asyncio.wait_for(
                loop.run_in_executor(None, start_xray_sync),
                timeout=XRAY_STARTUP_TIMEOUT,
            )
        except asyncio.TimeoutError:
            self.tester._track_error("xray_startup_timeout")
            if verbose:
                log(f"Xray startup timed out after {XRAY_STARTUP_TIMEOUT}s for {url[:60]}")
            return (url, False, 0.0)

        if not success:
            self.tester._track_error(error or "Xray_failed")
            return (url, False, 0.0)

        try:
            tested, latency = await self._http_ping_through_proxy_async(socks_port, timeout, verbose=verbose)
            if tested:
                return (url, True, latency)
            self.tester._track_error("HTTP_test_failed")
            return (url, False, 0.0)
        finally:
            cleanup_future = loop.run_in_executor(None, self.tester.stop_xray_process, process)
            if cleanup_futures is not None:
                cleanup_futures.append(cleanup_future)

    # ── HTTP ping methods ───────────────────────────────────────────

    def _http_ping_through_proxy(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """HTTP request through proxy using curl_cffi."""
        if CURL_CFFI_AVAILABLE:
            return self._http_ping_through_proxy_curl(socks_port, timeout, verbose)
        return self._http_ping_through_proxy_requests(socks_port, timeout, verbose)

    def _http_ping_through_proxy_curl(self, socks_port: int, timeout: float,
                                       verbose: bool = False) -> Tuple[bool, float]:
        """HTTP request through proxy using curl_cffi (sync Session)."""
        proxy_url = f"socks://127.0.0.1:{socks_port}"

        for test_url in self.tester.TEST_URLS:
            try:
                start = time.perf_counter()
                with CurlSession() as session:
                    response = session.get(
                        test_url,
                        proxy=proxy_url,
                        timeout=timeout,
                        allow_redirects=True,
                    )
                    latency = (time.perf_counter() - start) * 1000
                    if self.tester._validate_response(test_url, response.text):
                        if verbose:
                            log(f"Port {socks_port}: OK via {test_url[:40]} in {latency:.0f}ms")
                        return True, latency
                    break
            except (requests.RequestException, OSError, ValueError) as e:
                if verbose:
                    log(f"HTTP attempt failed: {type(e).__name__}: {str(e)[:80]}")

        if verbose:
            log(f"Port {socks_port}: All test URLs failed")
        return False, 0.0

    def _http_ping_through_proxy_requests(self, socks_port: int, timeout: float,
                                           verbose: bool = False) -> Tuple[bool, float]:
        """HTTP request through proxy using requests with socks5h:// (remote DNS)."""
        session = self.tester._get_session()
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }

        for test_url in self.tester.TEST_URLS:
            try:
                start = time.perf_counter()
                response = session.get(
                    test_url,
                    proxies=proxies,
                    timeout=(min(10.0, timeout), timeout),
                    allow_redirects=True,
                )
                latency = (time.perf_counter() - start) * 1000
                if self.tester._validate_response(test_url, response.text):
                    if verbose:
                        log(f"Port {socks_port}: OK via {test_url[:40]} in {latency:.0f}ms")
                    return True, latency
                break
            except (requests.RequestException, OSError, ValueError) as e:
                if verbose:
                    log(f"Port {socks_port}: {test_url[:40]} failed - {type(e).__name__}: {str(e)[:80]}")

        if verbose:
            log(f"Port {socks_port}: All test URLs failed")
        return False, 0.0

    async def _http_ping_through_proxy_async(self, socks_port: int, timeout: float,
                                              verbose: bool = False) -> Tuple[bool, float]:
        """Native curl_cffi async HTTP test through SOCKS5 proxy."""
        if not CURL_CFFI_AVAILABLE:
            return self._http_ping_through_proxy(socks_port, timeout, verbose)

        proxy_url = f"socks://127.0.0.1:{socks_port}"

        for test_url in self.tester.TEST_URLS:
            try:
                async with AsyncSession(
                    impersonate="chrome124",
                    trust_env=False,
                ) as session:
                    start = time.perf_counter()
                    response = await session.get(
                        test_url,
                        proxy=proxy_url,
                        timeout=timeout,
                        allow_redirects=True,
                    )
                    latency = (time.perf_counter() - start) * 1000
                    if self.tester._validate_response(test_url, response.text):
                        if verbose:
                            log(f"Port {socks_port}: OK via {test_url[:40]} in {latency:.0f}ms")
                        return True, latency
                    break
            except (asyncio.TimeoutError, Exception):
                pass

        if verbose:
            log(f"Port {socks_port}: All test URLs failed")
        return False, 0.0

    # ── Sync batch internals ────────────────────────────────────────

    def _run_single_config_test(
        self, url: str, timeout: float, eta_tracker: SmartETA,
        completed: list, failed_count: list, pbar, total_urls: int,
    ) -> Tuple[str, bool, float]:
        """Test a single config and update progress tracking.

        Extracted from _test_batch_single's inner closure so it can be tested
        in isolation. Returns (url, success, latency) tuple.
        """
        t0 = time.time()
        try:
            result = self.test_single_config(url, timeout, verbose=False, max_retries=1, skip_tcp_ping=False)
            duration = time.time() - t0

            completed[0] += 1
            count = completed[0]
            if not result[1]:
                failed_count[0] += 1
            working_count = count - failed_count[0]
            success_rate = (working_count / count * 100) if count > 0 else 0
            eta_tracker.record_completion(duration)
            if pbar:
                pbar.update(1)
                pbar.set_description(f"Testing | ETA {eta_tracker.description} | Working: {working_count} ({success_rate:.1f}%)")
            elif count % 50 == 0 or count == total_urls:
                log(f"Progress: {count}/{total_urls} ({count/(time.time()-t0+0.01):.1f}/s, ETA: {eta_tracker.description}) - Working: {working_count} ({success_rate:.1f}%)")
            return (result[0], result[1], result[2])
        except (OSError, RuntimeError, ValueError) as e_test:
            duration = time.time() - t0
            log(f"_run_single_config_test: unexpected error testing {url}: {e_test}")
            completed[0] += 1
            working_count = completed[0] - failed_count[0]
            success_rate = (working_count / completed[0] * 100) if completed[0] > 0 else 0
            eta_tracker.record_completion(duration)
            if pbar:
                pbar.update(1)
                pbar.set_description(f"Testing | ETA {eta_tracker.description} | Working: {working_count} ({success_rate:.1f}%)")
            return (url, False, 0.0)

    def _test_batch_single(self, urls: List[str], concurrency: int, timeout: float,
                           verbose: bool,
                           progress_callback: Optional[callable] = None) -> List[Tuple[str, bool, float]]:
        """Single-config mode: Test each config individually with fallback."""
        eta_tracker = SmartETA(len(urls), concurrency, timeout)
        start_time = time.time()
        results = []
        results_lock = threading.Lock()
        completed = [0]
        failed_count = [0]
        max_future_timeout = timeout * 3 + 10

        log(f"Starting single-config test with {concurrency} workers...")
        t = self.tester

        pbar = _tqdm_sync(
            total=len(urls),
            desc="Testing | Working: 0 (0%) ETA: ?s",
            unit="config",
            unit_scale=True,
            unit_divisor=1000,
            ncols=100,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}, {rate_fmt}]',
            mininterval=0.1,
            maxinterval=1.0,
            file=sys.stderr,
            delay=0,
            leave=True,
        )

        executor = ExecutorCache.get('xray_chain_test', max_workers=concurrency)
        # Progressive upload tracking (sync mode)
        working_results_sync = []
        last_callback_file = [0]
        futures = {
            executor.submit(
                self._run_single_config_test, url, timeout, eta_tracker, completed, failed_count, pbar, len(urls)
            ): url for url in urls
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=max_future_timeout)
                with results_lock:
                    results.append(result)
                    if result[1]:
                        working_results_sync.append((result[2], url))
                    wc = len(working_results_sync)
                    if result[1] and progress_callback:
                        cf = wc // MAX_CONFIGS_PER_FILE
                        if cf > last_callback_file[0]:
                            sorted_w = [u for _, u in sorted(working_results_sync, key=lambda x: x[0])]
                            last_callback_file[0] = cf
                        else:
                            sorted_w = None
                    else:
                        sorted_w = None
                if sorted_w is not None and progress_callback:
                    progress_callback(sorted_w, wc)
            except concurrent.futures.TimeoutError:
                url = futures[future]
                with results_lock:
                    results.append((url, False, 0.0))
                    completed[0] += 1
                    failed_count[0] += 1
            except (OSError, RuntimeError, ValueError) as e_result:
                url = futures[future]
                log(f"as_completed: unexpected error for {url}: {e_result}")
                with results_lock:
                    results.append((url, False, 0.0))

        if pbar:
            pbar.close()

        t.cleanup()

        working = [(url, s, l) for url, s, l in results if s]
        working.sort(key=lambda x: x[2])

        elapsed = time.time() - start_time
        success_rate = len(working) / len(urls) * 100 if urls else 0
        log(f"Single-config complete: {len(working)}/{len(urls)} working ({success_rate:.1f}%) in {elapsed:.1f}s")

        t._print_error_summary()

        return working

    def _test_batch_concurrent(self, port_map: Dict[int, str], timeout: float, concurrency: int,
                                verbose: bool = False,
                                executor_name: Optional[str] = None) -> List[Tuple[str, bool, float]]:
        """Test all configs in batch concurrently through different ports.

        Args:
            executor_name: Unique name for ExecutorCache to avoid cross-caller
                contention on the same thread pool. Each parallel chunk should
                use its own name (e.g. 'batch_chunk_0', 'batch_chunk_1').
        """
        results = []
        failed_ports = []

        def test_port(port: int) -> Tuple[str, bool, float]:
            url = port_map[port]
            try:
                tested, latency = self.test_through_socks(port, timeout, verbose=False)
                if not tested:
                    failed_ports.append(port)
                return (url, tested, latency)
            except (OSError, RuntimeError, ValueError) as e:
                if verbose:
                    log(f"Port {port} ({url[:60]}...) exception: {type(e).__name__}: {str(e)[:100]}")
                failed_ports.append(port)
                return (url, False, 0.0)

        exec_name = executor_name or 'xray_test'
        executor = ExecutorCache.get(exec_name, max_workers=concurrency)
        futures = {executor.submit(test_port, port): port for port in port_map.keys()}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=timeout + 5)
                results.append(result)
            except concurrent.futures.TimeoutError:
                port = futures[future]
                if verbose:
                    log(f"Port {port} test timed out after {timeout + 5}s")
                results.append((port_map[port], False, 0.0))
            except (RuntimeError, OSError, ValueError) as e:
                port = futures[future]
                if verbose:
                    log(f"Port {port} future exception: {type(e).__name__}: {str(e)[:100]}")
                results.append((port_map[port], False, 0.0))

        if verbose and failed_ports:
            log(f"Batch testing complete: {len(results) - len(failed_ports)}/{len(results)} passed, {len(failed_ports)} failed")

        return results
