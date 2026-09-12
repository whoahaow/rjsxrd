"""Proxy health monitoring with automatic failover prompt."""

import contextlib
import json
import threading

import requests

from utils.ip_verifier import _make_request
from utils.logger import log
from utils.process_registry import default_registry

# IP check endpoint used to verify the proxy is actually hiding the real IP
IP_CHECK_URL = "https://ipwho.is/"

# Defaults for ProxyMonitor instances
DEFAULT_CHECK_INTERVAL = 30  # seconds between proxy health checks
DEFAULT_TIMEOUT = 5.0  # seconds for each IP check request

# Shutdown behavior
STOP_JOIN_TIMEOUT = 2  # seconds to wait for monitor thread to join on stop()

# Logging
ERROR_TRUNCATE_LEN = 100  # chars of error message to include in logs


class ProxyMonitor:
    """Monitor proxy health and prompt for replacement if failed."""

    def __init__(
        self,
        socks_port: int,
        real_ip: str,
        check_interval: int = DEFAULT_CHECK_INTERVAL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.socks_port = socks_port
        self.real_ip = real_ip
        self.check_interval = check_interval
        self.timeout = timeout
        self.running = False
        self.thread = None
        self.proxy_failed = False
        self.last_check_ok = True
        # threading.Event for interruptible shutdown. stop() sets this so
        # the monitor loop wakes from sleep immediately instead of waiting
        # the full check_interval. Also checked by prompt_for_new_proxy_chain
        # so a shutdown request between prompts is respected.
        self._stop_event = threading.Event()
        default_registry.register_monitor(self)

    def check_proxy(self) -> bool:
        """Check if proxy is still working AND hiding real IP."""
        try:
            socks_url = f"socks5h://127.0.0.1:{self.socks_port}"
            proxies = {"http": socks_url, "https": socks_url}

            response = _make_request(IP_CHECK_URL, proxies=proxies, timeout=self.timeout)
            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                log(f"Monitor: Non-JSON response from IP check ({response.status_code})")
                return False
            proxy_ip = data.get("ip")

            if not proxy_ip:
                log("Monitor: Failed to get IP through proxy")
                return False
            if proxy_ip == self.real_ip:
                log("Monitor: WARNING - Real IP is exposed!")
                return False

            if not self.last_check_ok:
                log(f"Monitor: Proxy recovered - IP: {proxy_ip}")
            self.last_check_ok = True
            return True

        except (requests.Timeout, requests.ConnectionError) as e:
            if self.last_check_ok:
                log(f"Monitor: Network error - {type(e).__name__}")
            self.last_check_ok = False
            return False
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            if self.last_check_ok:
                log(f"Monitor: Response parse error - {type(e).__name__}")
            self.last_check_ok = False
            return False

    def prompt_for_new_proxy_chain(self) -> tuple:
        """Prompt user to enter new proxy chain."""
        log("\n" + "=" * 70)
        log("ENTER NEW PROXY CHAIN")
        log("=" * 70)
        log("\nEnter TWO proxy URLs for chaining:")
        log("  Hop 1 (entry): Your IP → Proxy 1")
        log("  Hop 2 (exit):  Proxy 1 → Proxy 2 → Internet")
        log("=" * 70)

        while True:
            log("\n--- Hop 1 (Entry Proxy) ---")
            proxy1 = input("Enter first proxy URL (or 'quit' to exit): ").strip()

            if proxy1.lower() == "quit":
                return ("quit", None)
            if not proxy1 or "://" not in proxy1:
                log("Invalid format. Use: vless://uuid@host:port")
                continue

            log("\n--- Hop 2 (Exit Proxy) ---")
            proxy2 = input("Enter second proxy URL (or 'quit' to exit): ").strip()

            if proxy2.lower() == "quit":
                return ("quit", None)
            if not proxy2 or "://" not in proxy2:
                log("Invalid format. Use: vless://uuid@host:port")
                continue

            log("\nTesting proxy chain...")
            from utils.ip_verifier import setup_proxy_chain

            result = setup_proxy_chain([proxy1, proxy2], timeout=8.0)

            if result["active"]:
                log(f"[OK] Proxy chain working ({result.get('country', 'Unknown')})")
                return ("ok", [proxy1, proxy2])
            log(f"[FAIL] Proxy chain failed: {result.get('error', 'Unknown error')}")
            log("\nTry different proxies. Common issues:")
            log("  • One or both proxies are offline")
            log("  • Proxies don't support chaining")
            log("  • Network connectivity issues")

    def monitor_loop(self) -> None:
        """Main monitoring loop. Runs in a daemon thread.

        Uses self._stop_event.wait(timeout=...) instead of time.sleep(...)
        so stop() can wake the loop immediately via _stop_event.set().
        When the user types 'quit' in the proxy prompt, the loop returns
        cleanly — no process-kill, just a normal thread exit that stop()
        can join.
        """
        while self.running and not self.proxy_failed:
            # Interruptible sleep — stop() sets _stop_event to wake us
            if self._stop_event.wait(timeout=self.check_interval):
                # Shutdown was signaled during the wait
                break
            if not self.check_proxy():
                log("\n" + "=" * 70)
                log("!!! PROXY CHAIN FAILED !!!")
                log("=" * 70)
                log("\nFetching stopped to prevent IP leaks.")
                log("\nNext steps:")
                log("  1. Enter new proxy chain (2 proxies) to continue")
                log("  2. Or type 'quit' to exit")
                log("=" * 70)

                self.proxy_failed = True
                status, new_chain = self.prompt_for_new_proxy_chain()

                if status == "quit":
                    log("\nShutdown requested — monitor exiting...")
                    self.running = False
                    # Clean thread exit. The daemon thread
                    # returns naturally so stop() can join it cleanly. There
                    # is no process from a non-main thread in Python 3 —
                    # SystemExit in a daemon thread just kills the thread.
                    # But returning is still cleaner because stop() knows
                    # the thread has exited rather than dying silently.
                    return
                if status == "ok" and new_chain:
                    log("\n✓ Proxy chain restored - resuming fetch...")
                    self.proxy_failed = False
                    self.last_check_ok = True

    def _safe_monitor_loop(self) -> None:
        try:
            self.monitor_loop()
        except KeyboardInterrupt:
            log("\nMonitor interrupted")
        except (ConnectionError, OSError, RuntimeError) as e:
            log(f"Monitor thread crashed: {type(e).__name__}: {str(e)[:ERROR_TRUNCATE_LEN]}")
            self.proxy_failed = True

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._safe_monitor_loop, daemon=True)
        self.thread.start()
        log(f"Proxy monitor started (checking every {self.check_interval}s)")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        # Signal the monitor loop to wake from sleep immediately
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=STOP_JOIN_TIMEOUT)
        # Remove from registry
        with contextlib.suppress(OSError, RuntimeError):
            default_registry.unregister_monitor(self)
