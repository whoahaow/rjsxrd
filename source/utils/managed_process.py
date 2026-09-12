"""Managed subprocess wrapper with guaranteed cleanup.

Encapsulates the terminate→wait→kill→wait pattern used across
xray_tester.py, ip_verifier.py, and process_registry.py into a
single class. Every caller gets consistent lifecycle behavior.
"""

import os
import subprocess


class ManagedProcess:
    """Wraps a subprocess.Popen with unified lifecycle management.

    Guarantees: after stop() returns, the process has been sent TERM,
    waited, and KILLed if it didn't respond. Temporary files associated
    with the process (config JSON, etc.) are also cleaned up.

    Thread-safe only if the wrapped subprocess.Popen is thread-safe
    (it is — Popen uses its own lock for poll/wait/terminate/kill).
    """

    def __init__(self, process: subprocess.Popen, config_file: str | None = None) -> None:
        self._process = process
        self._config_file = config_file

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def process(self) -> subprocess.Popen:
        """Expose the underlying Popen for callers that need it (e.g. stdout)."""
        return self._process

    def poll(self) -> int | None:
        """Check if process has exited. Returns exit code or None."""
        return self._process.poll()

    def is_running(self) -> bool:
        """True if process is still running."""
        return self._process.poll() is None

    def stop(self, force: bool = False, kill_timeout: int = 3, force_kill_timeout: int = 2) -> None:
        """Stop the process with guaranteed cleanup.

        Order:
        1. Clean up config file (always, even if already exited)
        2. If already exited → done
        3. TERM + wait(kill_timeout)
        4. If timeout → KILL + wait(force_kill_timeout)

        Idempotent. Safe to call multiple times on the same process.
        Config file is cleaned up even if the process already exited
        (prevents credential leaks from temp files).
        """
        # Always clean up config file, regardless of process state.
        # The caller may have already popped the config_file reference
        # from its internal bookkeeping — the ManagedProcess still
        # holds it via self._config_file.
        self._cleanup_config()

        if self._process.poll() is not None:
            return

        try:
            self._process.terminate()
            try:
                self._process.wait(timeout=kill_timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=force_kill_timeout)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def wait(self, timeout: float | None = None) -> int | None:
        """Wait for process to exit, returning exit code."""
        return self._process.wait(timeout=timeout)

    def _cleanup_config(self) -> None:
        """Remove the associated config file if it exists."""
        if self._config_file and os.path.exists(self._config_file):
            try:
                os.unlink(self._config_file)
            except OSError:
                pass
