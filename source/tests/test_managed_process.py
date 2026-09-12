"""Tests for ManagedProcess — subprocess lifecycle + config file safety.

ManagedProcess wraps subprocess.Popen with guaranteed cleanup of
temporary config files (which contain credentials). The 18th-pass bug
was: stop() returned early for already-exited processes, skipping the
config file cleanup. These tests prevent that regression.
"""
import os
import subprocess
import sys
import tempfile

from utils.managed_process import ManagedProcess


class TestManagedProcessConfigCleanup:
    """Config file cleanup is the PRIMARY safety property of ManagedProcess.

    Config files contain VPN credentials (UUIDs, passwords, public keys).
    If they leak to disk, anyone with filesystem access can use them.
    """

    def test_config_file_cleaned_up_when_process_already_exited(self):
        """THE REGRESSION from 18th pass: stop() must clean up config
        even if the process already exited before stop() was called.

        This is the most common real-world case — xray finishes testing
        a config (or fails to start), the process exits, and then stop()
        is called. Without this fix, credentials leak indefinitely.
        """
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            config_path = f.name
            f.write(b'{"creds": "secret"}')

        # Simulate an already-exited process
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()  # Let it exit before ManagedProcess wraps it
        assert proc.poll() == 0, "process should have exited"

        mp = ManagedProcess(proc, config_file=config_path)
        assert os.path.exists(config_path), "config should exist before stop"

        mp.stop()  # The 18th-pass fix: cleanup runs before early-return

        assert not os.path.exists(config_path), (
            "config file must be cleaned up after stop(), even when "
            "the process already exited"
        )

    def test_config_file_cleaned_up_on_running_process(self):
        """For running processes, stop() must clean config file after
        terminating/killing the process."""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            config_path = f.name
            f.write(b'{"creds": "secret"}')

        # A process that runs until killed
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(30)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            mp = ManagedProcess(proc, config_file=config_path)
            assert os.path.exists(config_path)
            mp.stop(kill_timeout=1, force_kill_timeout=1)
            assert not os.path.exists(config_path), (
                "config file must be cleaned up after stop()"
            )
        finally:
            # Safety: ensure process is dead even if test fails
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)

    def test_cleanup_does_not_raise_on_missing_config_file(self):
        """stop() should not crash if config_file was already removed
        (e.g. by another cleanup pass or manual deletion)."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()
        # config_file points to a non-existent path
        mp = ManagedProcess(proc, config_file='/tmp/nonexistent_config.json')
        # Should not raise
        mp.stop()

    def test_stop_without_config_file_does_not_raise(self):
        """ManagedProcess can be created without a config_file (config_file=None).
        stop() must handle this gracefully."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()
        mp = ManagedProcess(proc, config_file=None)
        mp.stop()  # Should not raise

class TestManagedProcessLifecycle:
    """Process lifecycle management."""

    def test_is_running_returns_true_for_active_process(self):
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(5)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            mp = ManagedProcess(proc)
            assert mp.is_running(), "process should be running"
            assert mp.poll() is None, "poll should return None for running"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)

    def test_is_running_returns_false_for_exited_process(self):
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(42)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()
        mp = ManagedProcess(proc)
        assert not mp.is_running(), "process should have exited"
        assert mp.poll() == 42, "poll should return exit code"

    def test_stop_terminates_running_process(self):
        """stop() must actually kill the process, not just return."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(30)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            mp = ManagedProcess(proc)
            mp.stop(kill_timeout=1, force_kill_timeout=1)
            # After stop, process should be dead
            proc.wait(timeout=3)
            assert proc.poll() is not None, "process should be dead after stop"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)

    def test_stop_idempotent(self):
        """Calling stop() multiple times is safe."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            config_path = f.name
            f.write(b'{}')
        proc.wait()
        mp = ManagedProcess(proc, config_file=config_path)
        # First call
        mp.stop()
        # Second call — should be no-op, no crash
        mp.stop()
        assert not os.path.exists(config_path), (
            "config should still be cleaned up after double stop"
        )

    def test_stop_with_force_kill_on_unresponsive_process(self):
        """If process ignores TERM, stop() sends KILL."""
        # A process that ignores SIGTERM
        proc = subprocess.Popen(
            [sys.executable, '-c',
             'import signal, time; '
             'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
             'time.sleep(30)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            mp = ManagedProcess(proc)
            assert mp.is_running()
            mp.stop(kill_timeout=1, force_kill_timeout=1)
            proc.wait(timeout=3)
            assert proc.poll() is not None, "process should be dead after force kill"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)

    def test_wait_blocks_until_exit(self):
        """wait() must block until the process exits and return the exit code."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(99)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        mp = ManagedProcess(proc)
        # Process is already running, wait for it
        exit_code = mp.wait(timeout=5)
        assert exit_code == 99, f"expected exit code 99, got {exit_code}"

    def test_pid_property(self):
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(1)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            mp = ManagedProcess(proc)
            assert mp.pid == proc.pid, "pid should match wrapped process"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)

    def test_process_property_exposes_popen(self):
        """The .process property gives access to the underlying Popen."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()
        mp = ManagedProcess(proc)
        assert mp.process is proc, "should expose the wrapped Popen"

class TestManagedProcessErrorHandling:
    """Edge cases and error paths."""

    def test_stop_no_exception_on_already_killed_process(self):
        """If the process was killed externally between poll() and
        terminate(), stop() should not raise."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(30)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        mp = ManagedProcess(proc)
        # Kill the process externally
        proc.kill()
        proc.wait(timeout=3)
        # Now stop() should handle it gracefully — already handled by
        # the early-return-after-cleanup logic
        mp.stop()

    def test_cleanup_config_safe_on_non_existent_path(self):
        """_cleanup_config() should not raise on non-existent files."""
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()
        mp = ManagedProcess(proc, config_file='/definitely/not/a/real/path.json')
        # Should not raise OSError
        mp._cleanup_config()

    def test_cleanup_config_removes_file_with_secret_data(self):
        """Verify the config file is actually emptyable/removable
        even when it contains sensitive data."""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            config_path = f.name
            f.write(b'{"uuid": "test-uuid-123", "password": "supersecret"}')
        assert os.path.getsize(config_path) > 0
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.exit(0)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait()
        mp = ManagedProcess(proc, config_file=config_path)
        mp._cleanup_config()
        assert not os.path.exists(config_path), "file must be removed"
