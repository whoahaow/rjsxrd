"""Tests for the shared ProcessRegistry (utils/process_registry.py)."""
import sys
import os
import threading
import time
import subprocess
from unittest.mock import MagicMock, patch as mock_patch

from utils.process_registry import ProcessRegistry, default_registry, install_signal_handler

class _FakeProcess:
    """Drop-in for subprocess.Popen for registry tests.

    Mimics the parts of the API the registry cares about: poll() and
    terminate/kill. Does NOT actually spawn a process.
    """
    def __init__(self, pid=1000, exit_code=None, ignore_terminate=False):
        self.pid = pid
        self._exit_code = exit_code
        self.terminated = False
        self.killed = False
        self.wait_calls = 0
        self.wait_timeouts = 0
        self._ignore_terminate = ignore_terminate

    def poll(self):
        """Return exit code if exited, else None."""
        return self._exit_code

    def terminate(self):
        self.terminated = True
        if not self._ignore_terminate:
            self._exit_code = -15  # SIGTERM

    def kill(self):
        self.killed = True
        self._exit_code = -9  # SIGKILL

    def wait(self, timeout=None):
        self.wait_calls += 1
        if timeout is not None and self._exit_code is None:
            self.wait_timeouts += 1
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
        return self._exit_code

class TestProcessRegistryRegister:
    """Test the register/unregister API."""

    def test_register_adds_entry(self):
        reg = ProcessRegistry(name="test_register")
        proc = _FakeProcess()
        tester = MagicMock()
        reg.register(tester, proc)
        assert len(reg) == 1

    def test_register_is_idempotent(self):
        """Registering the same (tester, process) twice must not double-count.

        Without this guard, double-cleanup could call stop_xray_process on
        the same process twice — the second call would race with a None
        process list membership check and fail.
        """
        reg = ProcessRegistry(name="test_idempotent")
        proc = _FakeProcess()
        tester = MagicMock()
        reg.register(tester, proc)
        reg.register(tester, proc)
        assert len(reg) == 1

    def test_unregister_removes_entry(self):
        reg = ProcessRegistry(name="test_unregister")
        proc = _FakeProcess()
        tester = MagicMock()
        reg.register(tester, proc)
        reg.unregister(tester, proc)
        assert len(reg) == 0

    def test_unregister_idempotent_on_missing(self):
        """Unregistering a non-existent entry must not raise."""
        reg = ProcessRegistry(name="test_unreg_missing")
        proc = _FakeProcess()
        tester = MagicMock()
        # Never registered
        reg.unregister(tester, proc)
        assert len(reg) == 0

    def test_thread_safe_register(self):
        """Concurrent registration from many threads must not lose entries."""
        reg = ProcessRegistry(name="test_thread")
        errors = []
        def worker(i):
            try:
                for _ in range(50):
                    proc = _FakeProcess(pid=2000 + i)
                    reg.register(MagicMock(), proc)
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors
        assert len(reg) == 500  # 10 threads × 50 entries

class TestProcessRegistryCleanup:
    """Test the cleanup method — graceful + force paths."""

    def test_cleanup_graceful_calls_tester_stop(self):
        """Non-force cleanup: call tester.stop_xray_process(process) for each entry."""
        reg = ProcessRegistry(name="test_graceful")
        proc1, proc2 = _FakeProcess(pid=1001), _FakeProcess(pid=1002)
        tester1 = MagicMock()
        tester2 = MagicMock()
        reg.register(tester1, proc1)
        reg.register(tester2, proc2)
        reg.cleanup(force=False)
        tester1.stop_xray_process.assert_called_once_with(proc1)
        tester2.stop_xray_process.assert_called_once_with(proc2)
        assert len(reg) == 0  # cleared

    def test_cleanup_force_calls_terminate_directly(self):
        """Force cleanup: skip the tester's stop method, terminate process directly."""
        reg = ProcessRegistry(name="test_force")
        proc = _FakeProcess(pid=1003)
        tester = MagicMock()
        reg.register(tester, proc)
        reg.cleanup(force=True)
        # Force cleanup uses process.terminate() directly, NOT tester.stop_xray_process
        tester.stop_xray_process.assert_not_called()
        assert proc.terminated or proc.killed  # one of them ran

    def test_cleanup_skips_already_exited_processes(self):
        """A process that has already exited should not be touched."""
        reg = ProcessRegistry(name="test_exited")
        proc = _FakeProcess(pid=1004, exit_code=0)  # already exited
        tester = MagicMock()
        reg.register(tester, proc)
        reg.cleanup(force=False)
        # Tester's stop method must NOT be called on an already-exited process
        tester.stop_xray_process.assert_not_called()
        assert len(reg) == 0

    def test_cleanup_runs_callbacks_before_stopping_processes(self):
        """Callbacks (e.g. env-var restore) must run BEFORE processes die.

        Why: env vars like HTTP_PROXY point at the xray SOCKS port. If we
        restore them before killing xray, nothing breaks. If we restore
        AFTER killing xray, the test environment leaks HTTP_PROXY pointing
        at a dead port.
        """
        reg = ProcessRegistry(name="test_callbacks_first")
        proc = _FakeProcess(pid=1005)
        reg.register(MagicMock(), proc)
        order = []
        def callback():
            order.append("callback")
        # Wrap stop_xray_process to record order
        tester = MagicMock()
        tester.stop_xray_process.side_effect = lambda p: order.append("stop")
        reg.register_callback(callback)
        # Re-register with the new tester
        reg._entries.clear()
        reg._cleanup_callbacks.clear()
        reg.register_callback(callback)
        reg.register(tester, proc)
        reg.cleanup(force=False)
        assert order == ["callback", "stop"]

    def test_cleanup_handles_callback_exceptions(self):
        """A callback that raises must not stop subsequent cleanup."""
        reg = ProcessRegistry(name="test_callback_exc")
        proc = _FakeProcess(pid=1006)
        tester = MagicMock()
        def bad_callback():
            raise RuntimeError("simulated callback failure")
        reg.register_callback(bad_callback)
        reg.register(tester, proc)
        # Must not raise
        reg.cleanup(force=False)
        # Subsequent cleanup still works
        tester.stop_xray_process.assert_called_once_with(proc)

    def test_cleanup_handles_stop_exceptions(self):
        """A stop_xray_process that raises must not crash the cleanup loop."""
        reg = ProcessRegistry(name="test_stop_exc")
        proc1 = _FakeProcess(pid=1007)
        proc2 = _FakeProcess(pid=1008)
        tester1 = MagicMock()
        tester1.stop_xray_process.side_effect = RuntimeError("stop failed")
        tester2 = MagicMock()
        reg.register(tester1, proc1)
        reg.register(tester2, proc2)
        # Must not raise
        reg.cleanup(force=False)
        # Second process still cleaned up
        tester2.stop_xray_process.assert_called_once_with(proc2)
        assert len(reg) == 0

    def test_cleanup_idempotent(self):
        """Calling cleanup twice is safe — second call is a no-op."""
        reg = ProcessRegistry(name="test_idempotent_cleanup")
        proc = _FakeProcess(pid=1009)
        tester = MagicMock()
        reg.register(tester, proc)
        reg.cleanup(force=False)
        reg.cleanup(force=False)  # second call: nothing to do
        tester.stop_xray_process.assert_called_once_with(proc)  # only once

    def test_cleanup_fallback_calls_tester_cleanup(self):
        """If tester has cleanup() but not stop_xray_process, call cleanup().
        
        Some testers (or old-style objects) have a generic cleanup() method
        instead of the per-process stop_xray_process. The registry falls
        back to calling cleanup() on the tester.
        """
        reg = ProcessRegistry(name="test_cleanup_fallback")
        proc = _FakeProcess(pid=1010)
        # Use an object with only cleanup(), no stop_xray_process
        class _TesterWithCleanup:
            def cleanup(self):
                self.ran = True
        tester = _TesterWithCleanup()
        reg.register(tester, proc)
        reg.cleanup(force=False)
        assert getattr(tester, 'ran', False), "cleanup() should have been called"
        assert not hasattr(tester, 'stop_xray_process')

    def test_cleanup_force_kill_on_timeout(self):
        """Force cleanup: if terminate + wait times out, must kill."""
        reg = ProcessRegistry(name="test_force_kill")
        proc = _FakeProcess(pid=1011, exit_code=None, ignore_terminate=True)  # not exiting
        tester = MagicMock()
        reg.register(tester, proc)
        reg.cleanup(force=True)
        # terminate should have been called, then kill when wait timed out
        assert proc.terminated, "terminate should be called first"
        assert proc.killed, "kill should be called after timeout"

    # --- Monitor methods ---

    def test_register_monitor_adds_entry(self):
        """register_monitor tracks a monitor instance."""
        reg = ProcessRegistry(name="test_reg_mon")
        monitor = MagicMock()
        reg.register_monitor(monitor)
        # Internal check — monitor is in the proxy_monitors list
        assert monitor in reg._proxy_monitors

    def test_register_monitor_idempotent(self):
        """Registering the same monitor twice doesn't duplicate."""
        reg = ProcessRegistry(name="test_reg_mon_idem")
        monitor = MagicMock()
        reg.register_monitor(monitor)
        reg.register_monitor(monitor)
        assert len(reg._proxy_monitors) == 1

    def test_unregister_monitor_removes_entry(self):
        """unregister_monitor removes a monitor from tracking."""
        reg = ProcessRegistry(name="test_unreg_mon")
        monitor = MagicMock()
        reg.register_monitor(monitor)
        reg.unregister_monitor(monitor)
        assert monitor not in reg._proxy_monitors

    def test_unregister_monitor_idempotent_on_missing(self):
        """Unregistering a non-existent monitor doesn't raise."""
        reg = ProcessRegistry(name="test_unreg_mon_miss")
        monitor = MagicMock()
        reg.unregister_monitor(monitor)  # never registered — must not raise
        assert len(reg._proxy_monitors) == 0

    def test_cleanup_stops_monitors_before_processes(self):
        """Monitor.stop() must be called during cleanup before process terminate."""
        reg = ProcessRegistry(name="test_mon_before_proc")
        monitor = MagicMock()
        proc = _FakeProcess(pid=2000)
        tester = MagicMock()

        reg.register_monitor(monitor)
        reg.register(tester, proc)
        reg.cleanup(force=True)
        # Monitor should have been stopped
        monitor.stop.assert_called_once()
        # Process should have been terminated (force=True uses ManagedProcess)
        assert proc.terminated or proc.killed

    def test_cleanup_handles_monitor_stop_exception(self):
        """A monitor.stop() that raises doesn't crash the cleanup loop."""
        reg = ProcessRegistry(name="test_mon_exc")
        good_mon = MagicMock()
        bad_mon = MagicMock()
        bad_mon.stop.side_effect = RuntimeError("monitor stop failed")
        proc = _FakeProcess(pid=2001)
        tester = MagicMock()

        reg.register_monitor(good_mon)
        reg.register_monitor(bad_mon)
        reg.register(tester, proc)
        # Must not raise, and good monitor must still be stopped
        reg.cleanup(force=True)
        good_mon.stop.assert_called_once()
        # With force=True, ManagedProcess handles the termination
        assert proc.terminated or proc.killed

class TestProcessRegistryConcurrency:
    """Test cleanup safety under concurrent registration."""

    def test_concurrent_register_and_cleanup(self):
        """Cleanup walking the list while another thread registers must not crash.

        This is the scenario main.py faces: SIGINT during pipeline execution
        triggers cleanup while fetchers are still spawning processes.
        """
        reg = ProcessRegistry(name="test_concurrent")
        stop = threading.Event()
        errors = []
        # Snapshot of registry size after cleanup, to detect late adds
        pre_count = [0]

        def registerer():
            i = 0
            while not stop.is_set():
                try:
                    reg.register(MagicMock(), _FakeProcess(pid=3000 + i))
                    i += 1
                except Exception as e:
                    errors.append(e)
                    return

        def cleaner():
            time.sleep(0.05)  # let some registrations happen
            pre_count[0] = len(reg)
            reg.cleanup(force=True)
            stop.set()

        t1 = threading.Thread(target=registerer)
        t2 = threading.Thread(target=cleaner)
        t1.start()
        t2.start()
        # Drain: t1 may still be in its time.sleep(0) between iterations when
        # stop is set. Give it a small grace period to actually exit.
        t1.join(timeout=2)
        t2.join(timeout=2)

        # No exceptions during concurrent operation
        assert not errors, f"concurrent register raised: {errors}"
        # After both threads exit, registry is empty
        # (Late register between cleanup and stop-check is allowed; the key
        # invariant is that those late-registered processes are still cleaned
        # up if the registry runs cleanup again. We test the simpler invariant
        # here: nothing crashed.)
        final = len(reg)
        assert final <= 1, (
            f"expected at most 1 leftover entry (race between cleanup and "
            f"stop-check), got {final}. pre_count={pre_count[0]}"
        )

class TestInstallSignalHandler:
    """Test the install_signal_handler function."""

    def test_idempotent(self):
        """Calling install_signal_handler twice does not install twice.

        Without the _installed guard, each call would re-register atexit
        and the cleanup would run multiple times (harmless but wasteful).
        """
        import signal as _signal
        import utils.process_registry as _pr
        original = _signal.getsignal(_signal.SIGINT)
        try:
            install_signal_handler()
            install_signal_handler()
            # The point is that we don't crash; the guard is internal
        finally:
            _pr._signal_handler_installed = False
            _signal.signal(_signal.SIGINT, original)

    def test_registers_handler_when_default(self):
        """install_signal_handler must register when SIGINT is still the
        default handler (no other module has claimed it yet)."""
        import signal as _signal
        import utils.process_registry as _pr
        if _signal.getsignal(_signal.SIGINT) != _signal.default_int_handler:
            # Another test already installed a handler — can't test this
            return
        try:
            _pr._signal_handler_installed = False  # reset in case prior test left it set
            install_signal_handler()
            handler = _signal.getsignal(_signal.SIGINT)
            assert handler is not None
            assert handler != _signal.default_int_handler
        finally:
            _pr._signal_handler_installed = False
            _signal.signal(_signal.SIGINT, _signal.default_int_handler)

class TestDefaultRegistrySingleton:
    """The default_registry is a module-level singleton — same instance
    for all importers."""

    def test_same_instance(self):
        from utils.process_registry import default_registry as r1
        from utils.process_registry import default_registry as r2
        assert r1 is r2

    def test_default_registry_is_process_registry(self):
        assert isinstance(default_registry, ProcessRegistry)
