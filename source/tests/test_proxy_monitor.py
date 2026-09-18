"""Tests for proxy_monitor.py — focus on the constants and check_proxy error paths."""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from utils.proxy_monitor import (
    DEFAULT_CHECK_INTERVAL,
    DEFAULT_TIMEOUT,
    ERROR_TRUNCATE_LEN,
    IP_CHECK_URL,
    STOP_JOIN_TIMEOUT,
    ProxyMonitor,
)

pytestmark = pytest.mark.unit


class TestProxyMonitorConstants:
    """Module-level constants are exposed and have sane values."""

    def test_ip_check_url_is_https(self):
        """IP_CHECK_URL is an HTTPS endpoint for ipwho.is."""
        assert IP_CHECK_URL.startswith("https://")
        assert "ipwho" in IP_CHECK_URL

    def test_default_check_interval_positive(self):
        """DEFAULT_CHECK_INTERVAL is a positive integer."""
        assert DEFAULT_CHECK_INTERVAL > 0
        assert isinstance(DEFAULT_CHECK_INTERVAL, int)

    def test_default_timeout_positive(self):
        """DEFAULT_TIMEOUT is a positive number."""
        assert DEFAULT_TIMEOUT > 0
        assert isinstance(DEFAULT_TIMEOUT, (int, float))

    def test_stop_join_timeout_positive(self):
        """STOP_JOIN_TIMEOUT is a positive number."""
        assert STOP_JOIN_TIMEOUT > 0

    def test_error_truncate_len_positive(self):
        """ERROR_TRUNCATE_LEN is a positive number."""
        assert ERROR_TRUNCATE_LEN > 0


class TestCheckProxyErrorPaths:
    """check_proxy() handles network and parse errors gracefully."""

    def _make_monitor(self, **kwargs):
        """Helper: create a ProxyMonitor without starting the monitor thread."""
        defaults = {"socks_port": 12345, "real_ip": "5.5.5.5"}
        defaults.update(kwargs)
        return ProxyMonitor(**defaults)

    def test_returns_false_on_network_timeout(self):
        """A network timeout returns False, not a swallowed exception."""
        monitor = self._make_monitor()
        with patch("utils.proxy_monitor._make_request", side_effect=requests.Timeout("timed out")):
            assert monitor.check_proxy() is False

    def test_returns_false_on_non_json_response(self):
        """A 502 error page (HTML, not JSON) returns False, not a swallowed exception."""
        monitor = self._make_monitor()
        mock_response = MagicMock()
        mock_response.status_code = 502
        mock_response.json.side_effect = json.JSONDecodeError("no json", "", 0)
        with patch("utils.proxy_monitor._make_request", return_value=mock_response):
            assert monitor.check_proxy() is False

    def test_returns_false_on_missing_ip_field(self):
        """A valid JSON response without 'ip' field returns False."""
        monitor = self._make_monitor()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"country": "XX", "asn": {}}  # no 'ip'
        with patch("utils.proxy_monitor._make_request", return_value=mock_response):
            assert monitor.check_proxy() is False

    def test_returns_true_when_ip_matches_proxy(self):
        """Valid response with a different IP than real_ip returns True."""
        monitor = self._make_monitor(real_ip="5.5.5.5")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip": "6.6.6.6", "country": "XX", "asn": {}}
        with patch("utils.proxy_monitor._make_request", return_value=mock_response):
            assert monitor.check_proxy() is True

    def test_returns_false_when_real_ip_exposed(self):
        """Valid response returning the real_ip (proxy leaked) returns False."""
        monitor = self._make_monitor(real_ip="5.5.5.5")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip": "5.5.5.5", "country": "XX", "asn": {}}
        with patch("utils.proxy_monitor._make_request", return_value=mock_response):
            assert monitor.check_proxy() is False


class TestProxyMonitorShutdown:
    """The monitor thread shuts down cleanly — no sys.exit(), just a clean
    thread return that stop() can join."""

    def _make_monitor(self, **kwargs):
        """Helper: create a ProxyMonitor with a short check_interval so
        monitor_loop doesn't block for 30 seconds in tests. Also patches
        check_proxy and prompt_for_new_proxy_chain so we don't hit real
        network or stdin."""
        defaults = {
            "socks_port": 12345,
            "real_ip": "5.5.5.5",
            "check_interval": 0.01,  # near-instant for tests
        }
        defaults.update(kwargs)
        return ProxyMonitor(**defaults)

    def test_init_creates_stop_event(self):
        """Every ProxyMonitor starts with a threading.Event for shutdown signals."""
        monitor = self._make_monitor()
        assert hasattr(monitor, "_stop_event")
        assert isinstance(monitor._stop_event, __import__("threading").Event)

    def test_quit_returns_cleanly_not_sys_exit(self):
        """When prompt_for_new_proxy_chain returns ('quit', None),
        monitor_loop sets self.running = False and returns — NO sys.exit() call."""

        monitor = self._make_monitor()
        monitor.running = True

        # Mock check_proxy to indicate failure (triggers the prompt)
        monitor.check_proxy = MagicMock(return_value=False)
        # Mock prompt_for_new_proxy_chain to return 'quit' immediately
        # (instead of blocking on real input())
        monitor.prompt_for_new_proxy_chain = MagicMock(return_value=("quit", None))

        # Call monitor_loop directly (NOT in a thread) — it should
        # detect proxy failure, call the prompt, get 'quit', log, and
        # return cleanly without raising.
        try:
            monitor.monitor_loop()
        except SystemExit:
            raise AssertionError(
                "monitor_loop called sys.exit() on 'quit' — should return, not exit process"
            )

        # After quit, the thread marked itself as not running
        assert monitor.running is False
        # proxy_failed was set during the failure detection, then the loop
        # returns; since we mocked prompt to return 'quit', it should still
        # be True (the loop never resets it for the 'quit' path)
        assert monitor.proxy_failed is True

    def test_message_logged_on_quit(self):
        """When the user types 'quit', the log should mention 'Shutdown requested'."""
        from unittest.mock import patch

        monitor = self._make_monitor()
        monitor.running = True
        monitor.check_proxy = MagicMock(return_value=False)
        monitor.prompt_for_new_proxy_chain = MagicMock(return_value=("quit", None))

        with patch("utils.proxy_monitor.log") as mock_log:
            monitor.monitor_loop()

        shutdown_calls = [c for c in mock_log.call_args_list if "Shutdown requested" in str(c)]
        assert shutdown_calls, (
            f"Expected 'Shutdown requested' in log after quit, got: {mock_log.call_args_list}"
        )

    def test_no_sys_exit_in_source(self):
        """sys.exit() should not appear anywhere in the proxy_monitor source.
        Regression test for the audit bug (8th pass)."""
        import inspect

        source = inspect.getsource(ProxyMonitor)
        assert "sys.exit" not in source, (
            "sys.exit() found in ProxyMonitor source — should use clean "
            "return + stop_event.set() instead"
        )


class TestProxyMonitorLifecycle:
    """Test start/stop lifecycle of ProxyMonitor."""

    def _make_monitor(self, **kwargs):
        defaults = {
            "socks_port": 12345,
            "real_ip": "5.5.5.5",
            "check_interval": 0.01,
            "timeout": 5.0,
        }
        defaults.update(kwargs)
        return ProxyMonitor(**defaults)

    def test_start_sets_running(self):
        """start() should set self.running = True and start the daemon thread."""
        monitor = self._make_monitor()
        # Patch check_proxy so the thread doesn't actually make network calls
        monitor.check_proxy = MagicMock(return_value=True)
        monitor.start()
        assert monitor.running is True
        assert monitor.thread is not None
        assert monitor.thread.daemon is True
        # Clean shutdown
        monitor.stop()
        monitor.thread.join(timeout=2)

    def test_stop_cleans_up(self):
        """stop() should set running=False and join the thread."""
        monitor = self._make_monitor()
        monitor.check_proxy = MagicMock(return_value=True)
        monitor.start()
        assert monitor.running is True
        monitor.stop()
        assert monitor.running is False
        assert not monitor.thread.is_alive(), "thread should have stopped"

    def test_start_twice_no_error(self):
        """Calling start() on an already-running monitor should not crash."""
        monitor = self._make_monitor()
        monitor.check_proxy = MagicMock(return_value=True)
        monitor.start()
        monitor.start()  # second call — should be no-op or safe
        assert monitor.running is True
        monitor.stop()

    def test_stop_without_start_is_safe(self):
        """Calling stop() on a monitor that was never started should not crash."""
        monitor = self._make_monitor()
        monitor.stop()  # must not raise

    def test_recovery_logs_message(self):
        """When check_proxy returns True after a previous failure, log recovery."""
        monitor = self._make_monitor()
        monitor.last_check_ok = False  # Previous check failed

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip": "6.6.6.6", "country": "XX"}

        log_calls = []

        def capture_log(msg, *a, **kw):
            log_calls.append(str(msg))

        with (
            patch("utils.proxy_monitor._make_request", return_value=mock_response),
            patch("utils.proxy_monitor.log", side_effect=capture_log),
        ):
            result = monitor.check_proxy()

        assert result is True
        recovery_msgs = [m for m in log_calls if "recovered" in m.lower()]
        assert len(recovery_msgs) > 0, f"expected recovery log, got: {log_calls}"
