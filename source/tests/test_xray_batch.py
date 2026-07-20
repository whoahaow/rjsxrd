"""Tests for BatchRunner — shared-xray batch mode dispatch and orchestration."""

import os
import sys
import threading
import time
from unittest.mock import patch as mock_patch, MagicMock, PropertyMock

import pytest


class TestBatchModeSwitch:
    """Test that test_batch() dispatches correctly based on XRAY_BATCH_MODE."""

    def _make_mock_tester(self):
        """Create a mock XrayTester with all methods BatchRunner calls."""
        from unittest.mock import MagicMock
        tester = MagicMock()
        tester.xray_path = "/fake/xray"
        tester._running_processes = []
        tester._config_files = {}
        tester._process_lock = threading.Lock()
        tester._port_counter = [20000]
        tester._port_lock = threading.Lock()
        tester._error_stats = {}
        tester._error_samples = {}
        tester._error_stats_lock = threading.Lock()
        tester._thread_local = threading.local()
        return tester

    def test_batch_mode_dispatches_to_shared_xray(self):
        """When XRAY_BATCH_MODE='batch', test_batch calls _test_batch_shared_xray."""
        from utils.xray_batch import BatchRunner
        from config.settings import BATCH_MODE_OVERRIDE

        # Save original override
        orig_override = BATCH_MODE_OVERRIDE

        try:
            # Force batch mode via override
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = "batch"

            tester = self._make_mock_tester()
            runner = BatchRunner(tester)

            # Mock _test_batch_shared_xray to return known results
            expected = [("vless://a", True, 50.0), ("vless://b", False, 0.0)]
            with mock_patch.object(runner, '_test_batch_shared_xray', return_value=expected) as mock_method:
                result = runner.test_batch(["vless://a", "vless://b"])

                assert mock_method.called, "_test_batch_shared_xray was not called"
                assert result == expected

        finally:
            # Restore override
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = orig_override

    def test_single_mode_dispatches_to_async(self):
        """When XRAY_BATCH_MODE='single', test_batch uses existing async path."""
        from utils.xray_batch import BatchRunner
        from config.settings import BATCH_MODE_OVERRIDE

        orig_override = BATCH_MODE_OVERRIDE

        try:
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = "single"

            tester = self._make_mock_tester()
            runner = BatchRunner(tester)

            # Mock _test_batch_async_wrapper to return known results
            expected = [("vless://a", True, 50.0)]
            with mock_patch.object(runner, '_test_batch_async_wrapper', return_value=expected) as mock_method:
                result = runner.test_batch(["vless://a"])

                assert mock_method.called, "_test_batch_async_wrapper was not called"
                assert result == expected

        finally:
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = orig_override

    def test_override_takes_precedence_over_env(self):
        """BATCH_MODE_OVERRIDE takes precedence over XRAY_BATCH_MODE env var."""
        from utils.xray_batch import BatchRunner
        from config.settings import BATCH_MODE_OVERRIDE

        orig_override = BATCH_MODE_OVERRIDE

        try:
            import config.settings as _settings
            # Set env to "single" but override to "batch"
            os.environ["XRAY_BATCH_MODE"] = "single"
            # Force-reload the module-level constant by patching
            _settings.BATCH_MODE_OVERRIDE = "batch"

            tester = self._make_mock_tester()
            runner = BatchRunner(tester)

            with mock_patch.object(runner, '_test_batch_shared_xray', return_value=[]) as mock_batch:
                with mock_patch.object(runner, '_test_batch_async_wrapper', return_value=[]) as mock_single:
                    runner.test_batch(["vless://a"])

                    assert mock_batch.called, "_test_batch_shared_xray should be called when override=batch"
                    assert not mock_single.called, "_test_batch_async_wrapper should NOT be called"

        finally:
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = orig_override
            os.environ.pop("XRAY_BATCH_MODE", None)

    def test_empty_urls_returns_empty(self):
        """Empty URL list returns [] regardless of mode."""
        from utils.xray_batch import BatchRunner

        tester = self._make_mock_tester()
        runner = BatchRunner(tester)

        result = runner.test_batch([])
        assert result == []

    def test_shared_xray_empty_urls(self):
        """_test_batch_shared_xray with empty urls returns []."""
        from utils.xray_batch import BatchRunner

        tester = self._make_mock_tester()
        runner = BatchRunner(tester)

        result = runner._test_batch_shared_xray([])
        assert result == []


class TestBatchSharedXray:
    """Test the _test_batch_shared_xray orchestration with mocks."""

    def _make_tester_with_mocks(self):
        """Create BatchRunner with all xray methods mocked."""
        from unittest.mock import MagicMock
        from utils.xray_batch import BatchRunner

        tester = MagicMock()
        tester.xray_path = "/fake/xray"
        tester._running_processes = []
        tester._config_files = {}
        tester._process_lock = threading.Lock()
        tester._port_counter = [20000]
        tester._port_lock = threading.Lock()
        tester._error_stats = {}
        tester._error_samples = {}
        tester._error_stats_lock = threading.Lock()
        tester._thread_local = threading.local()
        tester._print_error_summary = MagicMock()

        runner = BatchRunner(tester)
        return runner, tester

    def test_single_chunk_all_working(self):
        """Single chunk where all configs work."""
        runner, tester = self._make_tester_with_mocks()

        urls = [f"vless://{i}@host.com" for i in range(3)]
        port_map = {20000: urls[0], 20001: urls[1], 20002: urls[2]}

        tester.create_multi_config.return_value = (
            {"log": {}, "inbounds": [], "outbounds": [], "routing": {}},
            port_map,
        )
        tester.start_xray_instance.return_value = (True, MagicMock(), "")
        runner._test_batch_concurrent = MagicMock(
            return_value=[(urls[0], True, 30.0), (urls[1], True, 50.0), (urls[2], True, 100.0)]
        )

        result = runner._test_batch_shared_xray(urls)

        assert len(result) == 3
        # Sorted by latency: 30, 50, 100
        assert result[0][2] <= result[1][2] <= result[2][2]
        assert all(s for _, s, _ in result)

        # Verify create_multi_config was called with the chunk
        tester.create_multi_config.assert_called_once()

        # Verify start_xray was called with first port
        tester.start_xray_instance.assert_called_once()
        args, _ = tester.start_xray_instance.call_args
        assert args[1] == 20000  # first port in port_map

        # Verify cleanup
        tester.stop_xray_process.assert_called_once()

    def test_multiple_chunks(self):
        """Multiple chunks each get their own xray process."""
        runner, tester = self._make_tester_with_mocks()

        # Create enough urls for 2 chunks (with small batch size via settings override)
        urls = [f"vless://{i}@host.com" for i in range(5)]

        # First chunk returns port_map with 3 ports, second with 2
        def make_multi_config_side_effect(chunk_urls, base_port):
            port_map = {base_port + i: url for i, url in enumerate(chunk_urls)}
            return ({"inbounds": list(port_map.keys()), "outbounds": [], "routing": {}}, port_map)

        tester.create_multi_config.side_effect = make_multi_config_side_effect
        tester.start_xray_instance.return_value = (True, MagicMock(), "")

        # Track concurrent calls
        chunk_results_map = {}

        def concurrent_side_effect(port_map, timeout, concurrency, verbose, **kwargs):
            chunk_results_map[len(chunk_results_map)] = list(port_map.values())
            return [(url, True, 50.0 + i * 10) for i, (url, _) in enumerate(port_map.items())]

        runner._test_batch_concurrent = MagicMock(side_effect=concurrent_side_effect)

        # Override batch size for test
        with mock_patch("config.settings.XRAY_BATCH_SIZE", 3):
            result = runner._test_batch_shared_xray(urls)

        assert len(result) == 5  # all urls have results
        assert tester.create_multi_config.call_count == 2  # 2 chunks
        assert tester.start_xray_instance.call_count == 2  # 2 xrays
        assert tester.stop_xray_process.call_count == 2  # 2 cleanups

    def test_chunk_with_parse_failures(self):
        """URLs that fail to parse are reported as failed, not dropped."""
        runner, tester = self._make_tester_with_mocks()

        urls = ["vless://good1@host.com", "invalid-url", "vless://good2@host.com"]
        port_map = {20000: urls[0], 20002: urls[2]}  # url[1] failed to parse

        tester.create_multi_config.return_value = (
            {"inbounds": [{}], "outbounds": [], "routing": {}},
            port_map,
        )
        tester.start_xray_instance.return_value = (True, MagicMock(), "")
        runner._test_batch_concurrent = MagicMock(
            return_value=[(urls[0], True, 40.0), (urls[2], True, 60.0)]
        )

        result = runner._test_batch_shared_xray(urls)

        assert len(result) == 3
        # The invalid URL should be failed
        failed = [(u, s, l) for u, s, l in result if not s]
        assert len(failed) == 1
        assert failed[0][0] == "invalid-url"

    def test_xray_startup_failure(self):
        """When xray fails to start, all URLs in that chunk are marked failed."""
        runner, tester = self._make_tester_with_mocks()

        urls = ["vless://a@host.com", "vless://b@host.com"]
        port_map = {20000: urls[0], 20001: urls[1]}

        tester.create_multi_config.return_value = ({"inbounds": [{}]}, port_map)
        tester.start_xray_instance.return_value = (False, None, "Port in use")

        result = runner._test_batch_shared_xray(urls)

        assert len(result) == 2
        assert all(not s for _, s, _ in result)

        # stop_xray should NOT be called (startup failed, nothing to stop)
        tester.stop_xray_process.assert_not_called()

    def test_create_multi_config_returns_none(self):
        """When create_multi_config returns None, chunk is skipped."""
        runner, tester = self._make_tester_with_mocks()

        urls = ["vless://a@host.com"]
        tester.create_multi_config.return_value = (None, {})

        result = runner._test_batch_shared_xray(urls)

        assert len(result) == 1
        assert result[0][1] is False  # failed

        # xray should NOT be started
        tester.start_xray_instance.assert_not_called()


class TestBatchSettings:
    """Test that batch mode settings validate correctly."""

    def test_xray_batch_mode_valid_values(self):
        """XRAY_BATCH_MODE accepts 'single' or 'batch'."""
        from config.settings import XRAY_BATCH_MODE
        assert XRAY_BATCH_MODE in ("single", "batch")

    def test_xray_batch_size_within_bounds(self):
        """XRAY_BATCH_SIZE is validated within [50, 2000]."""
        from config.settings import XRAY_BATCH_SIZE
        assert 50 <= XRAY_BATCH_SIZE <= 2000

    def test_xray_batch_processes_within_bounds(self):
        """XRAY_BATCH_PROCESSES is validated within [1, 16]."""
        from config.settings import XRAY_BATCH_PROCESSES
        assert 1 <= XRAY_BATCH_PROCESSES <= 16

    def test_xray_batch_startup_delay_within_bounds(self):
        """XRAY_BATCH_STARTUP_DELAY_MS is validated within [200, 5000]."""
        from config.settings import XRAY_BATCH_STARTUP_DELAY_MS
        assert 200 <= XRAY_BATCH_STARTUP_DELAY_MS <= 5000

    def test_xray_batch_port_range_size_within_bounds(self):
        """XRAY_BATCH_PORT_RANGE_SIZE is validated within [100, 5000]."""
        from config.settings import XRAY_BATCH_PORT_RANGE_SIZE
        assert 100 <= XRAY_BATCH_PORT_RANGE_SIZE <= 5000

    def test_batch_mode_override_default_none(self):
        """BATCH_MODE_OVERRIDE defaults to None."""
        from config.settings import BATCH_MODE_OVERRIDE
        assert BATCH_MODE_OVERRIDE is None

    def test_batch_mode_override_takes_string(self):
        """BATCH_MODE_OVERRIDE accepts string values."""
        from config.settings import BATCH_MODE_OVERRIDE

        saved = BATCH_MODE_OVERRIDE
        try:
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = "batch"
            from config.settings import BATCH_MODE_OVERRIDE as override
            assert override == "batch"
        finally:
            import config.settings as _settings
            _settings.BATCH_MODE_OVERRIDE = saved

    def test_invalid_mode_env_falls_back_to_single(self, monkeypatch):
        """Setting an invalid env var causes fallback to 'single'."""
        # Simulate what happens at import: env var with invalid value
        monkeypatch.setenv("XRAY_BATCH_MODE", "invalid_mode_value")

        # Re-import the module to trigger the import-time validation
        # We need to reload the module
        import importlib
        import config.settings
        importlib.reload(config.settings)

        from config.settings import XRAY_BATCH_MODE
        assert XRAY_BATCH_MODE == "single"
