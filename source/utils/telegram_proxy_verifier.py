"""Telegram proxy verifier - OPTIMIZED for speed with curl_cffi and async pipelining."""

import asyncio
import base64
import logging
import os
import socket
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

# Suppress asyncio and socket cleanup warnings/errors
warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")
warnings.filterwarnings("ignore", category=ResourceWarning, module="socket")
logging.getLogger("asyncio").setLevel(logging.ERROR)

from utils.curl_import import CURL_CFFI_AVAILABLE, AsyncSession

# Test URL for SOCKS5 HTTP verification (same as config verification)
TEST_URL = "https://www.gstatic.com/generate_204"


class TelegramProxyVerifier:
    """Optimized Telegram proxy verifier with curl_ciffe and parallel endpoint testing."""

    TELEGRAM_ENDPOINTS = [
        ("149.154.175.50", 443),
        ("149.154.167.50", 443),
        ("149.154.175.100", 443),
    ]

    # Class-level executor for MTProto socket operations
    _socket_executor: ThreadPoolExecutor | None = None

    @classmethod
    def _get_socket_executor(cls) -> ThreadPoolExecutor:
        """Get or create dedicated thread pool for socket operations (250 threads)."""
        if cls._socket_executor is None:
            cls._socket_executor = ThreadPoolExecutor(
                max_workers=250, thread_name_prefix="mtproto_socket"
            )
        return cls._socket_executor

    @classmethod
    def shutdown(cls) -> None:
        """Cleanup all resources."""
        if cls._socket_executor:
            cls._socket_executor.shutdown(wait=False)
            cls._socket_executor = None

    @staticmethod
    def parse_proxy_url(url: str) -> dict:
        """Parse proxy URL and return dict with server, port, secret, username, password."""
        # Convert tg:// to https://t.me format
        if url.startswith("tg://"):
            url = "https://t.me" + url[4:]
        # Convert socks5:// to t.me/socks format for proper parsing
        elif url.startswith("socks5://"):
            parsed_raw = urlparse(url)
            host = parsed_raw.hostname or ""
            port = parsed_raw.port or 1080
            user = parsed_raw.username or ""
            passwd = parsed_raw.password or ""
            if user and passwd:
                url = f"https://t.me/socks?server={host}&port={port}&user={user}&pass={passwd}"
            else:
                url = f"https://t.me/socks?server={host}&port={port}"

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        return {
            "server": params.get("server", [None])[0],
            "port": int(params.get("port", [0])[0]),
            "secret": params.get("secret", [""])[0],
            "username": params.get("user", [None])[0],
            "password": params.get("pass", [None])[0],
            "type": "socks5" if "socks" in parsed.path.lower() else "mtproto",
        }

    def _create_handshake_packet(self, secret: str) -> bytes:
        """Create MTProto handshake packet."""
        random_data = os.urandom(56)

        try:
            if len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret):
                secret_bytes = bytes.fromhex(secret)
            else:
                secret_bytes = base64.b64decode(secret)
        except (ValueError, TypeError):
            secret_bytes = secret.encode()[:16]

        return random_data[:8] + secret_bytes[:16] + random_data[24:]

    def mtproto_connectivity_test(
        self, host: str, port: int, secret: str, timeout: int = 5
    ) -> tuple[bool, float]:
        """Test MTProto proxy connectivity - FIXED: Require actual handshake response."""
        sock = None
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # DIRECT connection
            sock.connect((host, port))

            try:
                handshake = self._create_handshake_packet(secret)
                sock.settimeout(2.0)
                sock.sendall(handshake)

                sock.settimeout(3.0)
                response = sock.recv(64)

                # FIX #1: Require actual response (not empty)
                if not response or len(response) == 0:
                    return False, 0.0

                # FIX #2: Validate response has meaningful length
                if len(response) < 8:
                    return False, 0.0

                latency = time.time() - start_time
                return True, latency

            except TimeoutError:
                # FIX #3: Timeout is FAILURE, not success!
                return False, 0.0
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False, 0.0
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass  # best-effort socket cleanup
        except (TimeoutError, OSError):
            return False, 0.0

    async def async_verify_mtproto(
        self, host: str, port: int, secret: str, timeout: float = 5.0
    ) -> tuple[bool, float]:
        """Async MTProto verification - runs sync test in DEDICATED executor (250 threads)."""
        try:
            loop = asyncio.get_event_loop()

            def test_sync():
                return self.mtproto_connectivity_test(host, port, secret, timeout=int(timeout))

            executor = self._get_socket_executor()
            is_connected, latency = await loop.run_in_executor(executor, test_sync)
            return is_connected, latency

        except (RuntimeError, OSError):
            return False, 0.0

    async def async_verify_socks5_http(
        self,
        host: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 3.0,
    ) -> tuple[bool, float]:
        """SOCKS5 verification using curl_cffi HTTP test - same as config verification."""
        if not CURL_CFFI_AVAILABLE:
            # Fallback to basic TCP connect test
            return await self._async_verify_socks5_tcp(host, port, username, password, timeout)

        try:
            start_time = time.perf_counter()

            # Build proxy URL with auth if provided
            if username and password:
                proxy_url = f"socks5h://{username}:{password}@{host}:{port}"
            else:
                proxy_url = f"socks5h://{host}:{port}"

            proxies = {"http": proxy_url, "https": proxy_url}

            # Single HTTP request through SOCKS5 proxy
            async with AsyncSession(impersonate="chrome124", trust_env=False) as session:
                response = await session.get(
                    TEST_URL, proxies=proxies, timeout=timeout, allow_redirects=True
                )

                latency = (time.perf_counter() - start_time) * 1000
                return True, latency

        except (TimeoutError, OSError, ValueError):
            return False, 0.0

    async def _async_verify_socks5_tcp(
        self,
        host: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 3.0,
    ) -> tuple[bool, float]:
        """Fallback: Basic SOCKS5 TCP connect test (no HTTP)."""
        has_auth = username is not None and password is not None

        try:
            start_time = time.perf_counter()

            # Connect to SOCKS5 proxy
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            connect_time = (time.perf_counter() - start_time) * 1000

            # SOCKS5 handshake
            request = b"\x05\x02\x00\x02" if has_auth else b"\x05\x01\x00"
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=timeout / 2)
            response = await asyncio.wait_for(reader.read(2), timeout=timeout / 2)

            # Check handshake response
            if len(response) < 2 or response[1] == 0xFF:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, RuntimeError):
                    pass
                return False, 0.0

            # Auth if needed
            if has_auth:
                auth_data = (
                    b"\x01"
                    + bytes([len(username)])
                    + username.encode()
                    + bytes([len(password)])
                    + password.encode()
                )
                writer.write(auth_data)
                await asyncio.wait_for(writer.drain(), timeout=timeout / 2)
                response = await asyncio.wait_for(reader.read(2), timeout=timeout / 2)
                if len(response) < 2 or response[1] != 0:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, RuntimeError):
                        pass
                    return False, 0.0

            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass

            return True, connect_time

        except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            return False, 0.0
        except (ConnectionError, RuntimeError):
            return False, 0.0

    async def verify_proxy_async(
        self,
        server: str,
        port: int,
        hex_secret: str = None,
        timeout: float = 3.0,
        proxy_type: str = "mtproto",
        username: str | None = None,
        password: str | None = None,
    ) -> tuple[bool, str]:
        """Verify single proxy asynchronously."""
        try:
            if proxy_type == "mtproto":
                is_connected, latency = await self.async_verify_mtproto(
                    server, port, hex_secret, timeout
                )
            else:
                # Use curl_cffi HTTP test (same as config verification)
                is_connected, latency = await self.async_verify_socks5_http(
                    server, port, username, password, timeout
                )

            if is_connected:
                return True, f"OK - {latency:.0f}ms"
            return False, "FAILED"

        except TimeoutError:
            return False, "TIMEOUT"
        except asyncio.CancelledError:
            return False, "CANCELLED"
        except (OSError, ConnectionError, RuntimeError) as e:
            return False, f"ERROR: {str(e)}"

    def verify_proxy(
        self,
        server: str,
        port: int,
        hex_secret: str = None,
        timeout: float = 3.0,
        proxy_type: str = "mtproto",
        username: str | None = None,
        password: str | None = None,
    ) -> tuple[bool, str]:
        """Verify single proxy synchronously."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.verify_proxy_async(
                    server, port, hex_secret, timeout, proxy_type, username, password
                )
            )
        finally:
            loop.close()

    async def verify_proxy_list_async(
        self, proxy_urls: list[str], timeout: float = 3.0, max_concurrent: int = 400
    ) -> list[tuple[str, bool, str]]:
        """Verify list of proxies asynchronously with pipelined execution."""
        from utils.logger import log

        if not proxy_urls:
            return []

        # Custom exception handler to suppress cleanup noise
        loop = asyncio.get_event_loop()

        def exception_handler(loop, context) -> None:
            msg = str(context.get("message", ""))
            if (
                "transport" in msg.lower()
                or "connection_lost" in msg.lower()
                or "proactor" in str(context.get("source", "")).lower()
            ):
                return
            log(f"Error: {context.get('message', 'Unknown error')}")

        loop.set_exception_handler(exception_handler)

        semaphore = asyncio.Semaphore(max_concurrent)
        completed = [0]
        last_reported = [0]
        report_lock = asyncio.Lock()

        async def verify_with_semaphore(proxy_url: str):
            async with semaphore:
                try:
                    parsed = self.parse_proxy_url(proxy_url)

                    result = await self.verify_proxy_async(
                        server=parsed["server"],
                        port=parsed["port"],
                        hex_secret=parsed["secret"],
                        timeout=timeout,
                        proxy_type=parsed["type"],
                        username=parsed["username"],
                        password=parsed["password"],
                    )

                    completed[0] += 1

                    # Progress logging every 10%
                    current_percent = (completed[0] * 100) // len(proxy_urls)
                    if current_percent >= last_reported[0] + 10:
                        async with report_lock:
                            if current_percent >= last_reported[0] + 10:
                                last_reported[0] = current_percent
                                log(
                                    f"Progress: {current_percent}% ({completed[0]}/{len(proxy_urls)})"
                                )

                    return (proxy_url, result[0], result[1])

                except (OSError, RuntimeError, ValueError) as e:
                    completed[0] += 1
                    return (proxy_url, False, f"ERROR: {str(e)[:100]}")

        # Run all tasks concurrently (pipelined - new starts while others running)
        tasks = [verify_with_semaphore(url) for url in proxy_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append((proxy_urls[i], False, f"EXCEPTION: {str(result)[:100]}"))
            else:
                processed.append(result)

        log(f"Verification complete: {len(processed)} proxies processed")
        return processed

    def verify_proxy_list(
        self, proxy_urls: list[str], timeout: float = 3.0, max_concurrent: int = 400
    ) -> list[tuple[str, bool, str]]:
        """Verify list of proxies synchronously with concurrent processing."""
        import concurrent.futures

        def run_in_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    self.verify_proxy_list_async(proxy_urls, timeout, max_concurrent)
                )
            finally:
                pending = (
                    asyncio.all_tasks(loop)
                    if hasattr(asyncio, "all_tasks")
                    else asyncio.Task.all_tasks(loop)
                )
                for task in pending:
                    task.cancel()
                try:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except (OSError, RuntimeError):
                    pass
                loop.close()

        # Run in thread to avoid event loop conflicts
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run_in_thread)
            try:
                # Dynamic timeout: 10s minimum + 0.1s per proxy
                dynamic_timeout = max(10, len(proxy_urls) * 0.1)
                results = future.result(timeout=dynamic_timeout)
                return results if results else []
            except concurrent.futures.TimeoutError:
                return [(url, False, "OVERALL_TIMEOUT") for url in proxy_urls]
            finally:
                # ALWAYS shutdown executor to prevent thread leak
                self.shutdown()
