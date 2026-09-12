"""Single shared registry for spawned Xray processes and proxy monitors.

Before this module existed, there were three competing registries:
- _active_testers (xray_tester.py) — list of XrayTester instances
- _xray_process_registry (ip_verifier.py) — list of (tester, process) tuples
- _active_proxy_monitors (proxy_monitor.py) — module-level list of ProxyMonitor

Each had its own atexit handler and its own signal handler. Result:
- a tester created by ip_verifier was in BOTH _active_testers and _xray_process_registry
- SIGINT cleanup could fire one handler and miss the other

The fix: a single ProcessRegistry class. xray_tester, ip_verifier, and
proxy_monitor all use it. Cleanup is centralized. atexit and signal handling
live here too (so they don't fight each other).
"""

import atexit
import signal
import subprocess
import threading
from collections.abc import Callable

from utils.logger import log
from utils.managed_process import ManagedProcess


class ProcessRegistry:
    """Thread-safe registry of (tester, process) pairs with central cleanup.

    Also tracks ProxyMonitor instances (for proxy chain health monitoring) so
    the signal handler can stop monitors before terminating xray processes.
    Monitor cleanup runs BEFORE process cleanup in the signal handler order
    (monitors depend on SOCKS ports that dying xray processes provide).

    Each entry represents a spawned Xray subprocess plus the tester that
    spawned it (so cleanup can call the tester's per-process stop method
    which handles things like psutil-based port tracking).

    Thread-safety: every mutator is protected by a lock. The cleanup methods
    iterate over a snapshot (entries[:]) so concurrent additions don't
    affect the cleanup pass.
    """

    def __init__(self, name: str = "default") -> None:
        self._entries: list[tuple[object, subprocess.Popen]] = []
        self._lock = threading.Lock()
        self._name = name
        # Proxy monitor instances (for proxy chain health monitoring).
        # Tracked separately from xray processes because monitors are thread
        # objects, not subprocesses. Cleaned up BEFORE process termination.
        self._proxy_monitors: list[object] = []
        # Per-registry cleanup callbacks (e.g. main.py's proxy monitor cleanup).
        # Run in registration order during cleanup, before process termination.
        self._cleanup_callbacks: list[Callable[[], None]] = []

    def register(self, tester: object, process: subprocess.Popen) -> None:
        """Track a (tester, process) pair. Idempotent — duplicate registration
        of the same process is silently ignored (avoids double-cleanup)."""
        with self._lock:
            entry = (tester, process)
            if entry in self._entries:
                return
            self._entries.append(entry)

    def unregister(self, tester: object, process: subprocess.Popen) -> None:
        """Remove a (tester, process) pair. Idempotent — missing entries are
        silently ignored."""
        with self._lock:
            entry = (tester, process)
            if entry in self._entries:
                self._entries.remove(entry)

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register a cleanup callback. Run BEFORE process termination during
        cleanup. Useful for things like env-var restoration that must happen
        before processes die."""
        with self._lock:
            self._cleanup_callbacks.append(callback)

    def register_monitor(self, monitor: object) -> None:
        """Register a ProxyMonitor instance for cleanup tracking."""
        with self._lock:
            if monitor not in self._proxy_monitors:
                self._proxy_monitors.append(monitor)

    def unregister_monitor(self, monitor: object) -> None:
        """Remove a ProxyMonitor instance from cleanup tracking."""
        with self._lock:
            if monitor in self._proxy_monitors:
                self._proxy_monitors.remove(monitor)

    def cleanup(self, force: bool = False) -> None:
        """Stop all registered processes. Order:

        0. Stop all tracked proxy monitors (before killing xray — monitors
           depend on SOCKS ports)
        1. Run all registered cleanup callbacks (env restore, etc.)
        2. For each entry: call tester.stop_xray_process(process)
           — graceful TERM + KILL fallback
           OR if force=True, terminate() directly with kill fallback
        3. Clear the registry

        Idempotent. Safe to call multiple times.
        """
        with self._lock:
            entries = self._entries[:]
            monitors = self._proxy_monitors[:]
            callbacks = self._cleanup_callbacks[:]
            self._entries.clear()
            self._proxy_monitors.clear()
            self._cleanup_callbacks.clear()

        # Stop proxy monitors first (they depend on SOCKS ports from xray)
        for monitor in monitors:
            try:
                if hasattr(monitor, "stop"):
                    monitor.stop()
            except (AttributeError, RuntimeError) as e:
                log(f"Warning: failed to stop proxy monitor: {e}")

        for cb in callbacks:
            try:
                cb()
            except (TypeError, RuntimeError) as e:
                log(f"Warning: cleanup callback {getattr(cb, '__name__', repr(cb))} failed: {e}")

        for tester, process in entries:
            try:
                mp = ManagedProcess(process)
                if process.poll() is not None:
                    # Already exited
                    continue
                if force:
                    mp.stop(force=True, kill_timeout=2, force_kill_timeout=1)
                else:
                    # Graceful: ask the tester to stop the process
                    if hasattr(tester, "stop_xray_process"):
                        tester.stop_xray_process(process)
                    elif hasattr(tester, "cleanup"):
                        # Fallback: tester has a cleanup() that takes no args
                        tester.cleanup()
            except (OSError, subprocess.TimeoutExpired, AttributeError, RuntimeError) as e:
                log(f"Warning: failed to clean up process {getattr(process, 'pid', '?')}: {e}")

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# Module-level singleton. Importing this gives every caller the same
# registry, so a tester in xray_tester and a process in ip_verifier are
# tracked in the same place.
default_registry = ProcessRegistry(name="default")


# Centralized cleanup wiring. atexit runs on normal interpreter shutdown.
# signal handler runs on SIGINT/SIGTERM — only registered if no other
# handler is already installed (preserves main.py's handler if it ran first).
def _default_cleanup() -> None:
    default_registry.cleanup(force=True)


_signal_handler_installed = False


def install_signal_handler() -> None:
    """Install SIGINT/SIGTERM handlers that trigger the default registry's
    force-cleanup. Only installs if no handler is already present.

    Idempotent. Safe to call multiple times.
    """
    global _signal_handler_installed
    if _signal_handler_installed:
        return

    def _handler(signum, frame) -> None:
        default_registry.cleanup(force=True)
        # Don't sys.exit — let the next-registered handler decide policy.
        # Re-raise the signal as a KeyboardInterrupt so the interpreter
        # still terminates, but at the priority of the LAST handler.
        raise KeyboardInterrupt

    try:
        if signal.getsignal(signal.SIGINT) == signal.default_int_handler:
            signal.signal(signal.SIGINT, _handler)
        if signal.getsignal(signal.SIGTERM) == signal.default_int_handler:
            signal.signal(signal.SIGTERM, _handler)
    except (OSError, AttributeError):
        pass
    atexit.register(_default_cleanup)
    _signal_handler_installed = True
