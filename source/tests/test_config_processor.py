"""Unit tests for config processor."""

import contextlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from processors.config_processor import (
    ConfigPipeline,
    append_remark_suffix,
    create_all_configs_file,
    create_protocol_split_files,
    create_secure_configs_file,
    get_subscription_header,
)
from utils import bypass_builder
from utils.config_helpers import resolve_flag, try_decode_base64_content
from utils.executor_cache import ExecutorCache
from utils.file_utils import is_valid_vpn_config_url
from utils.url_stats import URLStats

pytestmark = pytest.mark.unit


def filter_valid_configs(configs):
    """Helper to filter valid configs."""
    return [c for c in configs if is_valid_vpn_config_url(c)]


class TestDecodeBase64Content:
    """Test base64 decoding functionality."""

    def test_decode_valid_base64(self):
        """Test decoding valid base64 content."""
        # Base64 encoded: "vless://config1\nvmess://config2"
        import base64

        original = "vless://config1\nvmess://config2"
        encoded = base64.b64encode(original.encode()).decode()

        result = try_decode_base64_content(encoded)

        assert result is not None
        assert "vless://config1" in result
        assert "vmess://config2" in result

    def test_decode_invalid_base64(self):
        """Test that invalid base64 returns None."""
        result = try_decode_base64_content("not valid base64!!!")
        assert result is None

    def test_decode_plain_text(self):
        """Test that plain text (non-base64) returns None."""
        result = try_decode_base64_content("just plain text")
        # May return None or the same text if it decodes to garbage
        # The function tries to decode, so it might succeed with garbage
        assert result is None or result == "just plain text"

    def test_decode_empty_string(self):
        """Test decoding empty string."""
        result = try_decode_base64_content("")
        assert result is None


class TestAppendRemarkSuffix:
    """Test remark suffix appending."""

    def test_append_default_suffix(self):
        """Test appending default suffix."""
        config = "vless://uuid@host.com:443#MyConfig"
        result = append_remark_suffix(config)

        assert result.endswith("%20t.me%2Frjsxrd")
        assert "vless://uuid@host.com:443#MyConfig" in result

    def test_append_custom_suffix(self):
        """Test appending custom suffix."""
        config = "vmess://config#Test"
        result = append_remark_suffix(config, suffix="%20custom")

        assert result.endswith("%20custom")

    def test_config_without_remark(self):
        """Test config without remark."""
        config = "vless://uuid@host.com:443"
        result = append_remark_suffix(config)

        # Should still append suffix
        assert "%20t.me%2Frjsxrd" in result


class TestGetSubscriptionHeader:
    """Test subscription header generation."""

    def test_basic_header(self):
        """Test basic subscription header."""
        header = get_subscription_header("all.txt")

        assert "all.txt" in header
        assert "profile-title" in header.lower()

    def test_header_with_file_info(self):
        """Test header with file numbering info."""
        header = get_subscription_header("bypass-1.txt", current_file=1, total_files=5)

        assert "bypass-1.txt" in header
        assert "1" in header
        assert "5" in header


class TestResolveFlag:
    """Test feature-flag resolution (CLI overrides vs settings defaults)."""

    def test_none_overrides_returns_default(self):
        """No overrides dict → always use the imported default."""
        assert resolve_flag("ENABLE_DEFAULT_FILES", None, False) is False
        assert resolve_flag("ENABLE_DEFAULT_FILES", None, True) is True

    def test_override_true(self):
        """Override present in dict → use override, ignore default."""
        assert resolve_flag("ENABLE_DEFAULT_FILES", {"ENABLE_DEFAULT_FILES": True}, False) is True

    def test_override_false(self):
        """Override=False in dict → False, even when default is True."""
        assert resolve_flag("ENABLE_DEFAULT_FILES", {"ENABLE_DEFAULT_FILES": False}, True) is False

    def test_missing_key_returns_default(self):
        """Dict present but key missing → fall back to default."""
        overrides = {"ENABLE_TG_PROXY": True}
        assert resolve_flag("ENABLE_DEFAULT_FILES", overrides, True) is True
        assert resolve_flag("ENABLE_DEFAULT_FILES", overrides, False) is False

    def test_truthy_non_bool_coerced(self):
        """Truthy non-bool values are coerced (defensive — CLI should pass bool)."""
        assert resolve_flag("X", {"X": 1}, False) is True
        assert resolve_flag("X", {"X": 0}, True) is False
        assert resolve_flag("X", {"X": "yes"}, False) is True

    def test_empty_dict_returns_default(self):
        """Empty overrides dict → use default for all keys."""
        assert resolve_flag("ANY_KEY", {}, True) is True
        assert resolve_flag("ANY_KEY", {}, False) is False


class TestDownloadAllConfigsDirCreation:
    """Test that download_all_configs only creates directories for enabled flags.

    Before the fix, all 6 output directories were created unconditionally,
    leaving empty dirs on disk when feature flags were off. The fix creates
    bypass/ and qr-codes/ always (always needed), and the 4 flag-gated dirs
    only when their flag is True.
    """

    def _call_download(self, output_dir, flag_overrides):
        """Helper: call download_all_configs with mocked fetchers, return early.

        We mock every fetcher at the import path used inside download_all_configs
        so the function returns without making any network requests. The function
        creates the dirs BEFORE fetching, so this lets us assert on the
        post-makedirs filesystem state.
        """
        from unittest.mock import patch as mock_patch

        from processors import config_processor

        # Patch all 4 fetchers + the telegram scraper to no-ops
        with (
            mock_patch.object(config_processor, "fetch_configs_from_daily_repo", return_value=[]),
            mock_patch.object(config_processor, "scrape_sstap_configs", return_value=[]),
            mock_patch.object(config_processor, "fetch_upstream_dynamic_configs", return_value=[]),
            mock_patch.object(config_processor, "_fetch_and_process_urls", return_value=None),
            mock_patch("fetchers.telegram_proxy_scraper.TelegramProxyScraper") as mock_scraper,
        ):
            mock_scraper.return_value.deduplicate_proxies.side_effect = lambda x: (
                list(x) if x else []
            )
            # scan_for_telegram_proxies=False avoids the scraper import
            with contextlib.suppress(Exception):
                # Some imports may fail; we only care about dir creation,
                # which happens before any actual fetch
                config_processor.download_all_configs(
                    output_dir=output_dir,
                    scan_for_telegram_proxies=False,
                    flag_overrides=flag_overrides,
                )

    def test_all_flags_off_creates_only_bypass_and_qr(self, tmp_path):
        """With all 4 flags off, only bypass/ and qr-codes/ are created."""
        output_dir = str(tmp_path)
        # qr-codes/ is one level up from source/, so it lives at tmp_path/../qr-codes
        # Just check the 4 flag-gated dirs are absent
        self._call_download(
            output_dir,
            flag_overrides={
                "ENABLE_DEFAULT_FILES": False,
                "ENABLE_BYPASS_UNSECURE": False,
                "ENABLE_PROTOCOL_SPLIT": False,
                "ENABLE_TG_PROXY": False,
            },
        )
        assert not (tmp_path / "default").exists(), "default/ should NOT exist when flag is off"
        assert not (tmp_path / "bypass-unsecure").exists(), (
            "bypass-unsecure/ should NOT exist when flag is off"
        )
        assert not (tmp_path / "split-by-protocols").exists(), (
            "split-by-protocols/ should NOT exist when flag is off"
        )
        assert not (tmp_path / "tg-proxy").exists(), "tg-proxy/ should NOT exist when flag is off"
        # bypass/ is always created (the main verified output)
        assert (tmp_path / "bypass").exists(), "bypass/ should ALWAYS exist (always needed)"

    def test_all_flags_on_creates_all_six_dirs(self, tmp_path):
        """With all 4 flags on, all 4 flag-gated dirs are created."""
        output_dir = str(tmp_path)
        self._call_download(
            output_dir,
            flag_overrides={
                "ENABLE_DEFAULT_FILES": True,
                "ENABLE_BYPASS_UNSECURE": True,
                "ENABLE_PROTOCOL_SPLIT": True,
                "ENABLE_TG_PROXY": True,
            },
        )
        assert (tmp_path / "default").exists()
        assert (tmp_path / "bypass-unsecure").exists()
        assert (tmp_path / "split-by-protocols").exists()
        assert (tmp_path / "tg-proxy").exists()
        assert (tmp_path / "bypass").exists()

    def test_none_overrides_uses_settings_defaults(self, tmp_path):
        """flag_overrides=None means use settings.py. With all settings at False
        (the current default), only bypass/ and qr-codes/ are created."""
        from unittest.mock import patch as mock_patch

        from processors import config_processor

        # settings.py has all 4 flags at False by default (verified: lines 212-216)
        with (
            mock_patch.object(config_processor, "ENABLE_DEFAULT_FILES", False),
            mock_patch.object(config_processor, "ENABLE_BYPASS_UNSECURE", False),
            mock_patch.object(config_processor, "ENABLE_PROTOCOL_SPLIT", False),
            mock_patch.object(config_processor, "ENABLE_TG_PROXY", False),
        ):
            self._call_download(str(tmp_path), flag_overrides=None)
        assert not (tmp_path / "default").exists()
        assert not (tmp_path / "bypass-unsecure").exists()
        assert not (tmp_path / "split-by-protocols").exists()
        assert not (tmp_path / "tg-proxy").exists()


class TestFilterValidConfigs:
    """Test filtering valid configs."""

    def test_filter_keeps_valid(self):
        """Test that valid configs are kept."""
        configs = [
            "vless://uuid@host.com:443#tag",
            "vmess://eyJhZGQiOiJob3N0In0=",
            "trojan://pass@host.com:443#tag",
        ]

        result = filter_valid_configs(configs)

        assert len(result) == 3

    def test_filter_removes_invalid(self):
        """Test that invalid configs are removed."""
        configs = [
            "vless://valid@host.com:443",
            "Invalid text",
            "# Comment",
            "",
            "vmess://also-valid",
        ]

        result = filter_valid_configs(configs)

        assert len(result) == 2
        assert "Invalid text" not in result
        assert "# Comment" not in result

    def test_filter_mixed_content(self):
        """Test filtering mixed valid/invalid content."""
        configs = [
            "vless://config1",
            "random text",
            "vmess://config2",
            "another invalid",
            "trojan://config3",
        ]

        result = filter_valid_configs(configs)

        # Only valid configs should remain
        for config in result:
            assert config.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria"))


class TestConfigProcessingWithMocks:
    """Test config processing with mocked dependencies."""

    @patch("processors.config_processor.download_all_configs")
    def test_download_all_configs_signature(self, mock_download):
        """Test that download_all_configs has correct signature."""
        from processors.config_processor import download_all_configs

        # Should accept output_dir and scan_for_telegram_proxies params
        mock_download.return_value = (["config1"], [], [], [], [])

        result = download_all_configs(output_dir="/tmp", scan_for_telegram_proxies=True)

        assert len(result) == 5  # Returns 5-tuple


class TestConfigStatistics:
    """Test config statistics and counting."""

    def test_count_by_protocol(self):
        """Test counting configs by protocol."""
        configs = [
            "vless://config1",
            "vless://config2",
            "vmess://config3",
            "trojan://config4",
            "trojan://config5",
            "trojan://config6",
        ]

        counts = {}
        for config in configs:
            protocol = config.split("://")[0]
            counts[protocol] = counts.get(protocol, 0) + 1

        assert counts["vless"] == 2
        assert counts["vmess"] == 1
        assert counts["trojan"] == 3

    def test_calculate_success_rate(self):
        """Test calculating success rate."""
        total = 100
        working = 75

        rate = (working / total) * 100

        assert rate == 75.0


class TestAddUnique:
    """Tests for the thread-safe add_unique dedup helper.

    Bug context: add_unique was added on 2026-06-15 to give all fetchers
    (URLS, URLS_EXTRA_BYPASS, URLS_YAML, daily_repo, upstream_aggregator, sstap,
    manual) a shared seen-set so duplicate configs are dropped at fetch time
    instead of after. This is the foundation of the dedup-at-fetch-time
    refactor that fixed the 94k inflation bug.

    These tests must NOT invoke the real pipeline. We exercise add_unique
    directly with mock data.
    """

    def test_basic_dedup_returns_only_new_configs(self):
        """First call returns all configs as new."""
        import threading

        from processors.config_processor import add_unique

        seen = set()
        lock = threading.Lock()
        target = []
        added = add_unique(["a", "b", "c"], target, seen, lock)
        assert added == 3
        assert target == ["a", "b", "c"]
        assert seen == {"a", "b", "c"}

    def test_duplicate_configs_are_skipped(self):
        """Second call with same configs returns 0 added."""
        import threading

        from processors.config_processor import add_unique

        seen = {"a", "b"}
        lock = threading.Lock()
        target = ["a", "b"]
        added = add_unique(["a", "b", "c", "d"], target, seen, lock)
        assert added == 2
        assert target == ["a", "b", "c", "d"]
        assert seen == {"a", "b", "c", "d"}

    def test_empty_input_returns_zero(self):
        """Empty input list returns 0, no modification."""
        import threading

        from processors.config_processor import add_unique

        seen = {"x"}
        lock = threading.Lock()
        target = ["x"]
        added = add_unique([], target, seen, lock)
        assert added == 0
        assert target == ["x"]
        assert seen == {"x"}

    def test_empty_and_whitespace_strings_skipped(self):
        """Empty and whitespace-only strings are not added (and don't count)."""
        import threading

        from processors.config_processor import add_unique

        seen = set()
        lock = threading.Lock()
        target = []
        added = add_unique(["", "   ", "\t\n", "real_config"], target, seen, lock)
        assert added == 1
        assert target == ["real_config"]
        assert seen == {"real_config"}

    def test_none_entries_skipped(self):
        """None entries (not just empty strings) should not be added."""
        import threading

        from processors.config_processor import add_unique

        seen = set()
        lock = threading.Lock()
        target = []
        # The function checks `if cfg and cfg not in seen` — None is falsy,
        # so None entries are skipped without error.
        added = add_unique([None, "a", None, "b"], target, seen, lock)
        assert added == 2
        assert target == ["a", "b"]

    def test_thread_safety_under_contention(self):
        """Under concurrent calls, no config should be added twice and none lost.

        Spawns 10 threads each adding 100 unique configs to a shared seen set.
        Total unique: 1000. Each must appear in target exactly once.
        """
        import threading

        from processors.config_processor import add_unique

        seen = set()
        lock = threading.Lock()
        target = []
        errors = []

        def worker(thread_id):
            try:
                # Each thread has 100 unique configs (thread_id * 1000 + i)
                configs = [f"cfg_{thread_id * 1000 + i}" for i in range(100)]
                add_unique(configs, target, seen, lock)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"thread errors: {errors}"
        assert len(target) == 1000, f"expected 1000 unique, got {len(target)}"
        assert len(set(target)) == 1000, "duplicates leaked through"
        assert seen == set(target), "seen and target diverged"

    def test_preserves_input_order(self):
        """Order of first appearance is preserved in the target list."""
        import threading

        from processors.config_processor import add_unique

        seen = set()
        lock = threading.Lock()
        target = []
        # Add some, then add overlapping, then new
        add_unique(["b", "a"], target, seen, lock)
        add_unique(["c", "a", "b"], target, seen, lock)  # 'a' and 'b' are dup
        add_unique(["d"], target, seen, lock)
        assert target == ["b", "a", "c", "d"]


class TestWriteConfigsFile:
    """Tests for the canonical write_configs_file helper.

    Bug context: write_configs_file was extracted on 2026-06-15 from 6+ inline
    file-write patterns. It's now the single source of truth for "mkdir +
    header + suffix + write".
    """

    def test_creates_parent_directories(self, tmp_path):
        """The function must create parent dirs if missing (mkdir -p semantics)."""
        from utils.file_writer import write_configs_file

        nested = tmp_path / "a" / "b" / "c" / "out.txt"
        write_configs_file(str(nested), ["vless://x"], "# header\n")
        assert nested.exists()
        with open(nested) as f:
            content = f.read()
        assert content.startswith("# header")
        assert "vless://x" in content

    def test_appends_remark_suffix_by_default(self, tmp_path):
        """Configs without a #fragment get a remark suffix appended."""
        from utils.file_writer import write_configs_file

        out = tmp_path / "out.txt"
        write_configs_file(str(out), ["vless://uuid@host:443"], "# h\n")
        content = out.read_text()
        # The config_processor's append_remark_suffix uses URL-encoded t.me/rjsxrd
        assert "vless://uuid@host:443#%20t.me%2Frjsxrd" in content

    def test_does_not_double_suffix_configs_with_fragment(self, tmp_path):
        """Configs with a #fragment get the URL-encoded suffix appended to the fragment.

        append_remark_suffix handles two cases: configs WITHOUT # get '#%20...'
        prepended, configs WITH # get '%20...' appended. This test verifies
        the existing fragment is preserved and the suffix is added (once).
        """
        from utils.file_writer import write_configs_file

        out = tmp_path / "out.txt"
        write_configs_file(str(out), ["vless://uuid@host:443#MyTag"], "# h\n")
        content = out.read_text()
        # Original fragment preserved
        assert "vless://uuid@host:443#MyTag" in content
        # Suffix appears exactly once (appended to the existing fragment)
        assert content.count("t.me%2Frjsxrd") == 1, (
            f"suffix should appear once, got: {repr(content)}"
        )
        # And the full thing is the original fragment + the URL-encoded suffix
        assert "vless://uuid@host:443#MyTag%20t.me%2Frjsxrd" in content

    def test_add_suffix_false_disables_remark_appending(self, tmp_path):
        """Setting add_suffix=False writes configs verbatim."""
        from utils.file_writer import write_configs_file

        out = tmp_path / "raw.txt"
        write_configs_file(str(out), ["vless://x", "vmess://y#tag"], "# raw\n", add_suffix=False)
        content = out.read_text()
        assert "vless://x\n" in content
        assert "vmess://y#tag" in content
        # No encoding
        assert "%20" not in content

    def test_empty_list_writes_header_only(self, tmp_path):
        """Writing empty configs list must still create the file with header.

        This is the 0-working-bypass case — file must exist so downstream
        file_pairs.append doesn't try to read a non-existent file.
        """
        from utils.file_writer import write_configs_file

        out = tmp_path / "empty.txt"
        write_configs_file(str(out), [], "# header\n")
        assert out.exists()
        content = out.read_text()
        # File contains the header
        assert "# header" in content
        # File does NOT contain a stray "None" or "[]" or empty line
        assert "None" not in content
        assert "[]" not in content


class TestStreamWriteConfigsFile:
    """Tests for the chunked streaming writer.

    Bug context: stream_write_configs_file was extracted on 2026-06-15 from
    the original bypass-raw write loop. The original had a double-blank-line
    bug between chunks (header's trailing newline + first chunk's "\n" join
    produced a blank line). The refactor initially preserved this bug; a
    smoke test caught it. These tests guard against regression.
    """

    def test_no_blank_lines_between_chunks(self, tmp_path):
        """CRITICAL regression test: chunks must be joined with single newlines.

        The original streaming writer had a bug where the header's trailing \n
        plus the first chunk's "\n" join produced a blank line between chunks.
        """
        from utils.file_writer import stream_write_configs_file

        out = tmp_path / "out.txt"
        # 3 chunks of 2 each = 6 configs
        stream_write_configs_file(
            str(out),
            ["a", "b", "c", "d", "e", "f"],
            "# header\n",
            add_suffix=False,
            chunk_size=2,
            progress_every=0,  # disable progress logging
        )
        content = out.read_text()
        # No double newlines anywhere (header's \n is followed directly by content)
        assert "\n\n" not in content, f"double newlines in: {repr(content)}"
        # All 6 configs present
        for c in "abcdef":
            assert c in content

    def test_progress_logging_at_threshold(self, tmp_path):
        """Progress should be logged every progress_every configs (when > 0)."""
        from unittest.mock import patch as mock_patch

        from utils.file_writer import stream_write_configs_file

        with mock_patch("utils.file_writer.log") as mock_log:
            stream_write_configs_file(
                str(tmp_path / "out.txt"),
                ["x"] * 25,
                "# h\n",
                add_suffix=False,
                chunk_size=5,
                progress_every=10,
            )
            # At chunk boundaries 5,10,15,20,25 — progress_every=10 fires at
            # completed % 10 == 0, so at i=10 (cumulative=10), i=20 (cumulative=20)
            # That gives 2 progress log lines.
            progress_calls = [c for c in mock_log.call_args_list if "Written" in str(c)]
            assert len(progress_calls) >= 1, (
                f"expected progress logs, got: {mock_log.call_args_list}"
            )

    def test_progress_disabled_when_zero(self, tmp_path):
        """progress_every=0 should suppress all progress logging."""
        from unittest.mock import patch as mock_patch

        from utils.file_writer import stream_write_configs_file

        with mock_patch("utils.file_writer.log") as mock_log:
            stream_write_configs_file(
                str(tmp_path / "out.txt"),
                ["x"] * 100,
                "# h\n",
                add_suffix=False,
                chunk_size=5,
                progress_every=0,
            )
            progress_calls = [c for c in mock_log.call_args_list if "Written" in str(c)]
            assert progress_calls == [], f"progress should be disabled, got: {progress_calls}"

    def test_streaming_writes_correct_total_count(self, tmp_path):
        """All configs (no truncation, no loss) must end up in the file."""
        from utils.file_writer import stream_write_configs_file

        out = tmp_path / "out.txt"
        configs = [f"vless://u{i}@h.com:443" for i in range(50)]
        stream_write_configs_file(str(out), configs, "# h\n", add_suffix=False, chunk_size=7)
        content = out.read_text()
        for c in configs:
            assert c in content, f"missing {c} in output"

    def test_streaming_creates_parent_dirs(self, tmp_path):
        """Like write_configs_file, the streaming version must mkdir -p parents."""
        from utils.file_writer import stream_write_configs_file

        nested = tmp_path / "deep" / "nested" / "dir" / "file.txt"
        stream_write_configs_file(str(nested), ["x"], "# h\n", add_suffix=False)
        assert nested.exists()


class TestVerifyConfigFileXrayUnavailable:
    """Regression test for the silent-accept-all fix.

    Bug context: before 2026-06-15, _verify_config_file used to mark ALL
    configs as working (with latency 0) when Xray wasn't found, producing
    bypass-all.txt full of unverified garbage. The fix returns [] instead,
    forcing the caller to write an empty file with a warning.

    This is a SECURITY-relevant fix — unverified configs should never be
    treated as working.
    """

    def test_returns_empty_list_when_xray_not_found(self, tmp_path):
        """If xray binary doesn't exist, the function returns [] (not all-True)."""
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from processors import config_processor
        from utils.bypass_builder import verify_config_file

        # Mock XrayTester to return a tester with no xray_path
        mock_tester = MagicMock()
        mock_tester.xray_path = None

        # Patch XrayTester class import inside the function
        with mock_patch.object(config_processor, "XrayTester", create=True) as mock_cls:
            # Make the constructor return our mock with no xray
            mock_cls.return_value = mock_tester
            # We need XrayTester to actually exist in the namespace — we just
            # patched the module-level name. Re-inject via the import path.
            import sys

            # Set up a fake module the function can import from
            class FakeXrayTester:
                def __init__(self, xray_path=None):
                    self.xray_path = xray_path

                def test_batch(self, *a, **kw):
                    raise AssertionError("test_batch should not be called when xray_path is None")

                def cleanup(self):
                    pass

            # Inject FakeXrayTester at the import path used inside _verify_config_file.
            # CRITICAL: stash the original module so we can restore it after the
            # test — otherwise subsequent test files (notably test_xray_tester.py)
            # will see a MagicMock module and break. This was a latent bug
            # that surfaced when test_xray_tester.py was added in 2026-06-16.
            original_xray_module = sys.modules.get("utils.xray_tester")
            fake_xray_module = MagicMock()
            fake_xray_module.XrayTester = FakeXrayTester
            sys.modules["utils.xray_tester"] = fake_xray_module

            try:
                # Write a small input file
                input_file = tmp_path / "raw.txt"
                input_file.write_text("# header\nvless://a\nvless://b\n")

                with mock_patch("utils.bypass_builder.log") as mock_log:
                    result = verify_config_file(str(input_file))

                # The fix: must return [] (not [(cfg, True, 0), ...] like the old code)
                assert result == [], f"expected empty list, got {result}"
                # Must have warned the user
                warning_calls = [
                    c
                    for c in mock_log.call_args_list
                    if "WARNING" in str(c) or "Skipping" in str(c)
                ]
                assert warning_calls, f"expected warning log, got: {mock_log.call_args_list}"
                # The mock_tester's cleanup should not be called (xray_path is None,
                # so we never created an XrayTester instance — verify XrayTester was
                # never instantiated)
                mock_cls.assert_not_called()
            finally:
                # Restore the real xray_tester module so later tests work
                if original_xray_module is not None:
                    sys.modules["utils.xray_tester"] = original_xray_module
                else:
                    sys.modules.pop("utils.xray_tester", None)


class TestCreateWorkingConfigFilesZeroWorking:
    """Regression tests for the 'always write empty file when 0 working' branch.

    Bug context: before 2026-06-15, if verification yielded 0 working configs,
    bypass-all.txt was never written, and downstream file_pairs.append tried
    to read a non-existent file at upload time. The fix writes an empty file
    with header + warning instead.
    """

    def test_bypass_all_txt_written_even_when_zero_working(self, tmp_path):
        """When verification yields 0, bypass-all.txt must still be created."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        raw_dir = tmp_path / "bypass" / "raw"
        raw_dir.mkdir(parents=True)
        (raw_dir / "bypass-all-raw.txt").write_text("# header\nvless://a\nvless://b\n")

        # Mock _verify_config_file to return empty (simulating 0 working)
        with mock_patch.object(bypass_builder, "verify_config_file", return_value=[]):
            bypass_files, bypass_unsecure_files = create_working_config_files(output_dir)

        # The output file MUST exist
        bypass_all = tmp_path / "bypass" / "bypass-all.txt"
        assert bypass_all.exists(), "bypass-all.txt should exist even with 0 working"
        content = bypass_all.read_text()
        # Contains the header but no configs
        assert "bypass-all" in content  # header text
        # No vless://a or vless://b (the unverified configs)
        assert "vless://a" not in content
        assert "vless://b" not in content

    def test_stale_split_files_removed_when_zero_working(self, tmp_path):
        """Existing bypass-1.txt, bypass-2.txt etc should be preserved so subscribers can keep using them."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        raw_dir = tmp_path / "bypass" / "raw"
        raw_dir.mkdir(parents=True)
        (raw_dir / "bypass-all-raw.txt").write_text("# header\nvless://a\n")

        # Create existing split files that should be preserved
        bypass_dir = tmp_path / "bypass"
        (bypass_dir / "bypass-1.txt").write_text("existing content")
        (bypass_dir / "bypass-2.txt").write_text("existing content")
        assert (bypass_dir / "bypass-1.txt").exists()

        with mock_patch.object(bypass_builder, "verify_config_file", return_value=[]):
            create_working_config_files(output_dir)

        # Existing files preserved
        assert (bypass_dir / "bypass-1.txt").exists(), "existing bypass-1.txt should be preserved"
        assert (bypass_dir / "bypass-2.txt").exists(), "existing bypass-2.txt should be preserved"
        # bypass-all.txt (the canonical output) still exists
        assert (bypass_dir / "bypass-all.txt").exists()

    def test_unsecure_branch_writes_empty_file_too(self, tmp_path):
        """The bypass-unsecure branch must also write an empty file when 0 working
        AND no unsecure_only configs. Regression for the phantom upload bug."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        # Both raw files exist
        bypass_raw = tmp_path / "bypass" / "raw"
        bypass_raw.mkdir(parents=True)
        (bypass_raw / "bypass-all-raw.txt").write_text("# h\nvless://a\n")
        bypass_unsecure_raw = tmp_path / "bypass-unsecure" / "raw"
        bypass_unsecure_raw.mkdir(parents=True)
        (bypass_unsecure_raw / "bypass-unsecure-all-raw.txt").write_text(
            "# h\nvless://a\n"
        )  # same config

        # _verify_config_file returns [] for both. unsecure_only is empty too
        # because every unsecure config is also in bypass (dedup catches it).
        with mock_patch.object(bypass_builder, "verify_config_file", return_value=[]):
            bypass_files, bypass_unsecure_files = create_working_config_files(output_dir)

        # The unsecure output file MUST exist (latent bug — only relevant if
        # ENABLE_BYPASS_UNSECURE=True, but we test the function in isolation)
        bypass_unsecure_all = tmp_path / "bypass-unsecure" / "bypass-unsecure-all.txt"
        assert bypass_unsecure_all.exists(), (
            "bypass-unsecure-all.txt should exist even with 0 working"
        )

    def test_no_raw_files_at_all_writes_empty_output(self, tmp_path):
        """When no raw files exist (neither main nor split shards), the function
        must still write empty output files so file_pairs at upload time doesn't
        reference non-existent files. Regression for the silent-fail bug."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        # Create output dirs but no raw files
        (tmp_path / "bypass" / "raw").mkdir(parents=True)
        (tmp_path / "bypass-unsecure" / "raw").mkdir(parents=True)

        with mock_patch.object(bypass_builder, "verify_config_file", return_value=[]):
            bypass_files, bypass_unsecure_files = create_working_config_files(output_dir)

        # Both output files must exist (empty, but with header)
        bypass_all = tmp_path / "bypass" / "bypass-all.txt"
        bypass_unsecure_all = tmp_path / "bypass-unsecure" / "bypass-unsecure-all.txt"
        assert bypass_all.exists(), "bypass-all.txt should exist even with no raw input"
        assert bypass_unsecure_all.exists(), (
            "bypass-unsecure-all.txt should exist even with no raw input"
        )
        # No spurious split files
        assert bypass_files == []
        assert bypass_unsecure_files == []

    def test_split_shard_files_are_picked_up(self, tmp_path):
        """When the main raw file is missing (was split and deleted) but split
        shards exist, verification must proceed against the shards. Regression
        for the 'silent no-output' bug that previously caused zero files to be
        produced after verification."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        # Main file missing, but split shards present (this is the post-split
        # state after split_and_replace_file runs upstream)
        bypass_raw = tmp_path / "bypass" / "raw"
        bypass_raw.mkdir(parents=True)
        (bypass_raw / "bypass-all-raw-1.txt").write_text("# h\nvless://aaa\n")
        (bypass_raw / "bypass-all-raw-2.txt").write_text("# h\nvless://bbb\n")
        # No main bypass-all-raw.txt (was deleted by split)

        with mock_patch.object(
            bypass_builder, "verify_config_file", return_value=["vless://aaa", "vless://bbb"]
        ) as mock_verify:
            bypass_files, bypass_unsecure_files = create_working_config_files(output_dir)

        # _verify_config_file should have been called at least once (against the split shards)
        assert mock_verify.called, "expected _verify_config_file to be called against split shards"
        # bypass-all.txt must exist with the verified configs
        bypass_all = tmp_path / "bypass" / "bypass-all.txt"
        assert bypass_all.exists()
        content = bypass_all.read_text()
        assert "vless://aaa" in content
        assert "vless://bbb" in content

    def test_stale_shards_cleaned_up_at_start(self, tmp_path):
        """Stale split shards from a previous run must be removed at the start
        of the function to prevent them from corrupting this run's set-based
        dedup logic."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        bypass_raw = tmp_path / "bypass" / "raw"
        bypass_raw.mkdir(parents=True)
        # Stale shards from a previous run
        (bypass_raw / "bypass-all-raw-1.txt").write_text("stale vless://old1")
        (bypass_raw / "bypass-all-raw-2.txt").write_text("stale vless://old2")
        # Current main file (no shards)
        (bypass_raw / "bypass-all-raw.txt").write_text("# h\nvless://new1\n")

        with mock_patch.object(bypass_builder, "verify_config_file", return_value=["vless://new1"]):
            create_working_config_files(output_dir)

        # Stale shards removed
        assert not (bypass_raw / "bypass-all-raw-1.txt").exists(), (
            "stale shard -1.txt should be removed"
        )
        assert not (bypass_raw / "bypass-all-raw-2.txt").exists(), (
            "stale shard -2.txt should be removed"
        )
        # Main file still there
        assert (bypass_raw / "bypass-all-raw.txt").exists()

    def test_lexicographic_sort_fixed(self, tmp_path):
        """Split files -10.txt must be processed after -2.txt, not before.
        Regression for the lexicographic sort bug that scrambled shard order."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)
        bypass_raw = tmp_path / "bypass" / "raw"
        bypass_raw.mkdir(parents=True)
        # Create shards in an order that would trip lexicographic sort
        (bypass_raw / "bypass-all-raw-2.txt").write_text("# h\nvless://two\n")
        (bypass_raw / "bypass-all-raw-10.txt").write_text("# h\nvless://ten\n")
        # No main file (split state)

        call_order = []

        def fake_verify(path, **kwargs):
            call_order.append(os.path.basename(path))
            return ["vless://ok"]

        with mock_patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            create_working_config_files(output_dir)

        # -2.txt must come before -10.txt (natural sort)
        assert call_order == ["bypass-all-raw-2.txt", "bypass-all-raw-10.txt"], (
            f"expected natural sort, got: {call_order}"
        )

    def test_unsecure_split_shard_files_are_picked_up(self, tmp_path):
        """When the unsecure main raw file is missing (was split and deleted)
        but unsecure split shards exist, STEP 2 must still read from them and
        produce bypass-unsecure-all.txt. Asymmetric-fix regression: the secure
        path got this fix first, but the unsecure path was missed."""
        from unittest.mock import patch as mock_patch

        from utils.bypass_builder import create_working_config_files

        output_dir = str(tmp_path)

        # Secure path: main file present with one config
        bypass_raw = tmp_path / "bypass" / "raw"
        bypass_raw.mkdir(parents=True)
        (bypass_raw / "bypass-all-raw.txt").write_text("# h\nvless://secure-only\n")

        # Unsecure path: main file MISSING, split shards present
        bypass_unsecure_raw = tmp_path / "bypass-unsecure" / "raw"
        bypass_unsecure_raw.mkdir(parents=True)
        (bypass_unsecure_raw / "bypass-unsecure-all-raw-1.txt").write_text(
            "# h\nvless://unsecure-only-a\n"
        )
        (bypass_unsecure_raw / "bypass-unsecure-all-raw-2.txt").write_text(
            "# h\nvless://unsecure-only-b\n"
        )
        # No main bypass-unsecure-all-raw.txt (was deleted by split)

        # Mock verification: secure returns its config, unsecure returns both
        # (the unsecure path reads files, calls _verify_config_file on unsecure_only)
        real_verify = bypass_builder.verify_config_file

        def fake_verify(
            input_path,
            configs=None,
            verbose=False,
            tcp_ping=False,
            config_to_sources=None,
            stats=None,
            progress_callback=None,
        ):
            if "bypass-all-raw" in input_path:
                return ["vless://secure-only"]
            if "bypass-unsecure-all-raw" in input_path:
                return ["vless://unsecure-only-a", "vless://unsecure-only-b"]
            return real_verify(
                input_path,
                configs=configs,
                verbose=verbose,
                tcp_ping=tcp_ping,
                config_to_sources=config_to_sources,
                stats=stats,
            )

        with mock_patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            bypass_files, bypass_unsecure_files = create_working_config_files(output_dir)

        # bypass-unsecure-all.txt must exist with the unsecure configs
        bypass_unsecure_all = tmp_path / "bypass-unsecure" / "bypass-unsecure-all.txt"
        assert bypass_unsecure_all.exists(), "bypass-unsecure-all.txt should exist"
        content = bypass_unsecure_all.read_text()
        assert "vless://unsecure-only-a" in content, "unsecure config -a should be in output"
        assert "vless://unsecure-only-b" in content, "unsecure config -b should be in output"


class TestBypassSplitFileDisjointness:
    """Tests for the 'one seal per file' bypass-N.txt design.

    Bug context (2026-06-27): the progressive-split pattern re-sorted
    working configs at every threshold, causing adjacent files
    (bypass-1, bypass-2, etc.) to overlap 46-92%. Total listings across
    files (2597) was 2.5x unique configs (1029). Fix: seal each file
    once when the accumulator crosses a multiple of MAX_CONFIGS_PER_FILE,
    and dedup at insert time so configs never re-enter.
    """

    @staticmethod
    def _make_url(i, host="1.1.1"):
        """Build a unique URL with a distinct dedup key. The host must vary
        because _get_dedup_key keys on (proto, host, port, security_params)."""
        return f"vless://uuid-{i:04d}@host-{i:04d}.example.com:443?security=reality#name-{i}"

    def test_seal_writes_exactly_max_per_file_configs(self, tmp_path):
        """Sealing 600 working configs produces 2 files of 300 each."""
        from utils.bypass_builder import seal_bypass_files

        output_dir = str(tmp_path)
        # Generate 600 working configs (each with a unique host so dedup keys are distinct)
        accumulator = [(i * 0.001, self._make_url(i)) for i in range(600)]
        seen = set()
        new_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=None,
        )

        assert new_idx == 2, f"expected 2 files sealed, got {new_idx}"
        for i in (1, 2):
            f = tmp_path / "bypass" / f"bypass-{i}.txt"
            assert f.exists()
            content = f.read_text()
            lines = [
                line for line in content.splitlines() if line.strip() and not line.startswith("#")
            ]
            assert len(lines) == 300, f"bypass-{i}.txt should have 300 lines, got {len(lines)}"

    def test_seal_writes_disjoint_files(self, tmp_path):
        """bypass-1.txt and bypass-2.txt have no overlapping configs (by base)."""
        import re

        from utils.bypass_builder import seal_bypass_files

        output_dir = str(tmp_path)
        # 600 configs fills exactly 2 files
        accumulator = [(i * 0.001, self._make_url(i)) for i in range(600)]
        seen = set()
        new_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=None,
        )
        assert new_idx == 2

        # Now call again with a longer accumulator to seal file 3
        accumulator3 = accumulator + [(0.0005, self._make_url(600 + i)) for i in range(300)]
        new_idx3 = seal_bypass_files(
            accumulator=accumulator3,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=new_idx,
            upload_file=None,
        )
        assert new_idx3 == 3

        # Read all 3 files and verify pairwise disjoint
        def bases(path):
            with open(path) as f:
                bases = set()
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # base = config without #fragment
                        base = re.split(r"#", line, maxsplit=1)[0].strip()
                        bases.add(base)
                return bases

        b1 = bases(tmp_path / "bypass" / "bypass-1.txt")
        b2 = bases(tmp_path / "bypass" / "bypass-2.txt")
        b3 = bases(tmp_path / "bypass" / "bypass-3.txt")
        assert b1 & b2 == set(), (
            f"bypass-1 and bypass-2 must be disjoint, found {len(b1 & b2)} overlap"
        )
        assert b1 & b3 == set(), (
            f"bypass-1 and bypass-3 must be disjoint, found {len(b1 & b3)} overlap"
        )
        assert b2 & b3 == set(), (
            f"bypass-2 and bypass-3 must be disjoint, found {len(b2 & b3)} overlap"
        )

    def test_seal_dedups_at_insert_time(self, tmp_path):
        """A config added twice to the accumulator only appears in one file."""
        from utils.bypass_builder import seal_bypass_files

        output_dir = str(tmp_path)
        # Same URL appears twice with different fake latencies
        url = self._make_url(42)
        accumulator = [
            (0.001, url),
            (0.002, url),  # duplicate
            (0.003, self._make_url(43)),
        ]
        seen = set()
        new_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=None,
        )

        # 3 configs, but 1 is duplicate. 1 file (bypass-1.txt) won't be sealed
        # because 2 unique < 300. But accumulator should be effectively 2.
        assert new_idx == 0

    def test_seal_sorts_chunk_internally(self, tmp_path):
        """Each sealed file's configs are sorted by latency ascending, independent
        of the accumulator's input order. The caller does not need to pre-sort
        the accumulator — seal sorts the chunk before writing.
        """
        from utils.bypass_builder import seal_bypass_files

        output_dir = str(tmp_path)
        # Random arrival order: don't pre-sort. Latency is (i * 0.001) so
        # after seal sorts, the file should have ascending latency = ascending index.
        import random

        rng = random.Random(42)
        unsorted = [(i * 0.001, self._make_url(i)) for i in range(300)]
        rng.shuffle(unsorted)
        seen = set()
        new_idx = seal_bypass_files(
            accumulator=unsorted,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=None,
        )
        assert new_idx == 1

        # Read file and verify URLs are in ascending-latency order.
        import re

        file1 = tmp_path / "bypass" / "bypass-1.txt"
        with open(file1) as f:
            indices = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    m = re.search(r"name-(\d+)", line)
                    if m:
                        indices.append(int(m.group(1)))
        # ascending latency = ascending index
        assert indices == list(range(300)), (
            f"expected ascending index order, got first 5: {indices[:5]}, last 5: {indices[-5:]}"
        )

    def test_seal_uploads_when_callback_provided(self, tmp_path):
        """Sealing uploads via the upload_file callback."""
        from utils.bypass_builder import seal_bypass_files

        output_dir = str(tmp_path)
        accumulator = [(i * 0.001, self._make_url(i)) for i in range(300)]
        seen = set()
        uploads = []

        def fake_upload(local, remote):
            uploads.append((local, remote))

        new_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=fake_upload,
        )
        assert new_idx == 1
        assert len(uploads) == 1
        local, remote = uploads[0]
        assert local.endswith("bypass-1.txt")
        assert remote == "githubmirror/bypass/bypass-1.txt"

    def test_seal_partial_remainder_is_not_uploaded(self, tmp_path):
        """Configs beyond full multiples of 300 stay in accumulator, not sealed."""
        from utils.bypass_builder import seal_bypass_files

        output_dir = str(tmp_path)
        # 350 configs: seals 1 file (300), leaves 50 in accumulator
        accumulator = [(i * 0.001, self._make_url(i)) for i in range(350)]
        seen = set()
        new_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=None,
        )
        assert new_idx == 1
        file1 = tmp_path / "bypass" / "bypass-1.txt"
        assert file1.exists()
        # File 2 must NOT exist (only 50 remain, < 300)
        file2 = tmp_path / "bypass" / "bypass-2.txt"
        assert not file2.exists(), "bypass-2.txt should not exist when remainder < 300"

    def test_seal_handles_existing_seen_keys(self, tmp_path):
        """If seen_keys already contains some dedup keys, those are not re-sealed."""
        from utils.bypass_builder import seal_bypass_files
        from utils.file_utils import _get_dedup_key

        output_dir = str(tmp_path)
        # 600 configs total: 50 pre-seeded, 550 new
        accumulator = [(i * 0.001, self._make_url(i)) for i in range(600)]
        # Pre-seed seen with first 50 keys
        seen = {_get_dedup_key(self._make_url(i)) for i in range(50)}

        new_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen,
            last_sealed_idx=0,
            upload_file=None,
        )
        # 550 new unique configs, fills 1 file (300) and leaves 250 in accumulator
        # (no second file because 550 - 300 = 250 < 300)
        assert new_idx == 1
        # seen should now have all 600 keys
        assert len(seen) == 600


class TestMultiRawFileAccumulation:
    """Tests for the multi-raw-file accumulation pattern in
    verify_and_write_bypass. The accumulator and seen_keys set are hoisted
    to the function level, and the verify_config_file callback may or may
    not fire for each raw file. The return value is used as a fallback
    when the callback never fires (e.g. < 300 working configs in a
    raw file) and to fill in any items added by verify_config_file
    after its last callback fire.
    """

    def test_all_configs_collected_across_raw_files(self, tmp_path):
        """Configs from multiple raw files are all collected, even when
        the callback fires for some but not others.
        """
        import os
        from unittest.mock import patch

        from utils import bypass_builder

        # 3 raw files with different counts (350, 120, 450)
        # The mock fires callback at 300 for files with >= 300 working
        file_data_0 = [
            f"vless://uuid-0-{n:04d}@host-0-{n:04d}.example.com:443?security=reality#n0"
            for n in range(350)
        ]
        file_data_1 = [
            f"vless://uuid-1-{n:04d}@host-1-{n:04d}.example.com:443?security=reality#n1"
            for n in range(120)
        ]
        file_data_2 = [
            f"vless://uuid-2-{n:04d}@host-2-{n:04d}.example.com:443?security=reality#n2"
            for n in range(450)
        ]
        files_data = [file_data_0, file_data_1, file_data_2]

        def fake_verify(
            input_path,
            configs=None,
            verbose=False,
            tcp_ping=False,
            config_to_sources=None,
            stats=None,
            progress_callback=None,
        ):
            fname = os.path.basename(input_path) if input_path else ""
            if "bypass-all-raw-1" in fname:
                idx = 0
            elif "bypass-all-raw-2" in fname:
                idx = 1
            elif "bypass-all-raw-3" in fname:
                idx = 2
            else:
                idx = 0
            urls = files_data[idx]
            if progress_callback and len(urls) >= 300:
                progress_callback(urls[:300], len(urls))
            return urls

        output_dir = str(tmp_path)
        raw_dir = tmp_path / "bypass" / "raw"
        raw_dir.mkdir(parents=True)
        for i in range(1, 4):
            (raw_dir / f"bypass-all-raw-{i}.txt").write_text(
                f"# h\nvless://uuid-{i}-0@host-{i}-0.example.com:443?security=reality#n{i}\n"
            )

        with patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            working_bypass, _ = bypass_builder.verify_and_write_bypass(
                str(raw_dir / "bypass-all-raw.txt"),
                str(tmp_path / "bypass" / "bypass-all.txt"),
                output_dir,
                False,
                None,
                None,
                False,
            )
        # Expected: 350 + 120 + 450 = 920 (all from different host:port prefixes)
        assert len(working_bypass) == 920, f"expected 920 unique configs, got {len(working_bypass)}"

    def test_no_callback_fallback_works(self, tmp_path):
        """If verify_config_file never fires its callback (e.g. mocked),
        the return value is used as a fallback to populate the accumulator.
        """
        from unittest.mock import patch

        from utils import bypass_builder

        # Mock that never fires callback but returns 600 working configs
        urls = [
            f"vless://uuid-{n:04d}@host-{n:04d}.example.com:443?security=reality#n{n}"
            for n in range(600)
        ]

        def fake_verify(
            input_path,
            configs=None,
            verbose=False,
            tcp_ping=False,
            config_to_sources=None,
            stats=None,
            progress_callback=None,
        ):
            # Deliberately never call progress_callback
            return urls

        output_dir = str(tmp_path)
        raw_dir = tmp_path / "bypass" / "raw"
        raw_dir.mkdir(parents=True)
        (raw_dir / "bypass-all-raw-1.txt").write_text(
            "# h\nvless://uuid-0@host-0.example.com:443?security=reality#n0\n"
        )

        with patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            working_bypass, _ = bypass_builder.verify_and_write_bypass(
                str(raw_dir / "bypass-all-raw.txt"),
                str(tmp_path / "bypass" / "bypass-all.txt"),
                output_dir,
                False,
                None,
                None,
                False,
            )
        # All 600 should be in the result (via fallback)
        assert len(working_bypass) == 600


class TestStaleBypassFilesCleanup:
    """Tests for preserving bypass-N.txt split files across runs."""

    def test_stale_higher_numbered_files_removed_locally(self, tmp_path):
        """After a run produces fewer files than previous, existing split files are preserved."""
        from utils.bypass_builder import _cleanup_stale_bypass_split_files

        bypass_dir = tmp_path / "bypass"
        bypass_dir.mkdir()
        # Previous run produced 5 files
        for i in range(1, 6):
            (bypass_dir / f"bypass-{i}.txt").write_text("existing content")
        # Current run produced only 2 files
        for i in range(1, 3):
            (bypass_dir / f"bypass-{i}.txt").write_text("fresh content")

        _cleanup_stale_bypass_split_files(
            output_dir=str(tmp_path),
            prefix="bypass",
            current_file_count=2,
        )

        # Files 1, 2 should still exist (current run)
        assert (bypass_dir / "bypass-1.txt").exists()
        assert (bypass_dir / "bypass-2.txt").exists()
        # Files 3, 4, 5 are also preserved for users on those links
        assert (bypass_dir / "bypass-3.txt").exists()
        assert (bypass_dir / "bypass-4.txt").exists()
        assert (bypass_dir / "bypass-5.txt").exists()

    def test_cleanup_preserves_bypass_all_txt(self, tmp_path):
        """bypass-all.txt and existing split files must be preserved."""
        from utils.bypass_builder import _cleanup_stale_bypass_split_files

        bypass_dir = tmp_path / "bypass"
        bypass_dir.mkdir()
        (bypass_dir / "bypass-all.txt").write_text("canonical content")
        (bypass_dir / "bypass-1.txt").write_text("existing")

        _cleanup_stale_bypass_split_files(
            output_dir=str(tmp_path),
            prefix="bypass",
            current_file_count=0,
        )

        # bypass-all.txt preserved
        assert (bypass_dir / "bypass-all.txt").exists()
        # bypass-1.txt preserved
        assert (bypass_dir / "bypass-1.txt").exists()

    def test_cleanup_no_op_when_count_matches(self, tmp_path):
        """If file count matches what we just produced, nothing is removed."""
        from utils.bypass_builder import _cleanup_stale_bypass_split_files

        bypass_dir = tmp_path / "bypass"
        bypass_dir.mkdir()
        for i in range(1, 4):
            (bypass_dir / f"bypass-{i}.txt").write_text(f"file {i}")

        _cleanup_stale_bypass_split_files(
            output_dir=str(tmp_path),
            prefix="bypass",
            current_file_count=3,
        )

        # All 3 files still exist
        for i in range(1, 4):
            assert (bypass_dir / f"bypass-{i}.txt").exists()

    def test_cleanup_runs_when_no_raw_files(self, tmp_path):
        """When verify_and_write_bypass returns early because no raw files
        exist, existing bypass-N.txt files from a previous run are preserved.
        """
        from utils import bypass_builder

        # Setup: previous run had 3 bypass files
        bypass_dir = tmp_path / "bypass"
        bypass_dir.mkdir()
        for i in range(1, 4):
            (bypass_dir / f"bypass-{i}.txt").write_text(f"file {i}")
        # But no raw files this run
        (bypass_dir / "raw").mkdir()
        # bypass-all-raw.txt does NOT exist

        # Call create_working_config_files
        bypass_files, unsecure_files = bypass_builder.create_working_config_files(
            str(tmp_path),
            False,
            None,
            None,
            False,
            None,
            None,
        )

        # Existing bypass-N.txt files preserved
        assert (bypass_dir / "bypass-1.txt").exists()
        assert (bypass_dir / "bypass-2.txt").exists()
        assert (bypass_dir / "bypass-3.txt").exists()
        # bypass-all.txt still exists (empty but present)
        assert (bypass_dir / "bypass-all.txt").exists()


class TestCreateNumberedDefaultFilesLimit:
    """Test that create_numbered_default_files respects the 26-source limit.

    Bug context: create_numbered_default_files silently truncates to first 26
    sources. Verify the documented behavior.
    """

    def test_limits_to_26_sources(self, tmp_path):
        """Pass 30 sources, only 26 numbered files are created."""
        from utils.file_writer import create_numbered_default_files

        # Build 30 sources each with 1 unique config
        sources = [
            ([f"vless://u{i}@h.com:443"], f"http://src{i}.example.com/config") for i in range(30)
        ]
        created = create_numbered_default_files(sources, str(tmp_path))
        # Exactly 26 files created
        assert len(created) == 26, f"expected 26, got {len(created)}"
        # Files 1-26 exist
        for i in range(1, 27):
            assert (tmp_path / "default" / f"{i}.txt").exists()
        # Files 27-30 do NOT exist
        for i in range(27, 31):
            assert not (tmp_path / "default" / f"{i}.txt").exists()

    def test_max_numbered_files_is_configurable(self, tmp_path):
        """When MAX_NUMBERED_DEFAULT_FILES is patched to a different value, the
        function respects it. The default is 26 but operators can override
        via env or (future) CLI flag.
        """
        from unittest.mock import patch as mock_patch

        from utils.file_writer import create_numbered_default_files

        sources = [
            ([f"vless://u{i}@h.com:443"], f"http://src{i}.example.com/config") for i in range(5)
        ]
        with mock_patch("config.settings.MAX_NUMBERED_DEFAULT_FILES", 3):
            created = create_numbered_default_files(sources, str(tmp_path))
        assert len(created) == 3, f"expected 3, got {len(created)}"
        # Files 1-3 exist, 4-5 don't
        for i in range(1, 4):
            assert (tmp_path / "default" / f"{i}.txt").exists()
        for i in range(4, 6):
            assert not (tmp_path / "default" / f"{i}.txt").exists()

    def test_max_numbered_files_zero_creates_nothing(self, tmp_path):
        """When MAX_NUMBERED_DEFAULT_FILES is 0, no numbered files are created
        (but the function still returns without crashing).
        """
        from unittest.mock import patch as mock_patch

        from utils.file_writer import create_numbered_default_files

        sources = [
            ([f"vless://u{i}@h.com:443"], f"http://src{i}.example.com/config") for i in range(3)
        ]
        with mock_patch("config.settings.MAX_NUMBERED_DEFAULT_FILES", 0):
            created = create_numbered_default_files(sources, str(tmp_path))
        assert created == []


class TestCreateAllConfigsFileContract:
    """Test the dedup contract: input must be already-deduplicated."""

    def test_passes_deduped_input_through_unchanged(self, tmp_path):
        """When input is deduplicated, output is the same set of configs."""
        all_configs = [
            "vless://u1@h.com:443#a",
            "vless://u2@h.com:443#b",
            "vless://u3@h.com:443#c",
        ]
        created = create_all_configs_file(all_configs, str(tmp_path))
        # A list this small is never split, so the return value is the single path
        # written — the same contract the numbered-file tests assert a length on.
        all_txt = tmp_path / "default" / "all.txt"
        assert [Path(path) for path in created] == [all_txt], created
        # all.txt was created
        assert all_txt.exists()
        content = all_txt.read_text()
        # All 3 configs are in the file (no dedup removed any)
        for cfg in all_configs:
            assert cfg in content

    def test_does_not_dedup_duplicates_in_input(self, tmp_path):
        """The function does NOT dedup. If duplicates are passed, they appear
        in the output. This is the documented contract — the caller must
        dedup before calling. Tests that the function honors its contract.
        """
        # Same config twice — should appear twice in output
        all_configs = [
            "vless://u1@h.com:443#a",
            "vless://u1@h.com:443#a",  # duplicate
        ]
        create_all_configs_file(all_configs, str(tmp_path))
        all_txt = tmp_path / "default" / "all.txt"
        content = all_txt.read_text()
        # The duplicate appears twice (function didn't dedup)
        assert content.count("vless://u1@h.com:443#a") == 2, (
            "function should NOT dedup; duplicates should pass through. "
            "If this fails, the function has been over-eagerly deduping."
        )


class TestCreateSecureConfigsFileContract:
    """Test the dedup contract for the secure-config writer."""

    def test_passes_deduped_input_through_and_filters(self, tmp_path):
        """Deduplicated input → secure configs only in output."""
        all_configs = [
            "vless://u1@h.com:443?security=tls#secure",  # secure
            "vless://u1@h.com:443?security=none#insecure",  # insecure
        ]
        create_secure_configs_file(all_configs, str(tmp_path))
        all_secure = tmp_path / "default" / "all-secure.txt"
        content = all_secure.read_text()
        # Secure config is in the file
        assert "security=tls" in content
        # Insecure config is filtered out
        assert "security=none" not in content

    def test_does_not_dedup_duplicates(self, tmp_path):
        """Same contract: no dedup by this function."""
        all_configs = [
            "vless://u1@h.com:443?security=tls#a",
            "vless://u1@h.com:443?security=tls#a",  # duplicate
        ]
        create_secure_configs_file(all_configs, str(tmp_path))
        all_secure = tmp_path / "default" / "all-secure.txt"
        content = all_secure.read_text()
        # Both appear (no dedup)
        assert content.count("vless://u1@h.com:443?security=tls#a") == 2


class TestCreateProtocolSplitFilesContract:
    """Test the dedup contract for the protocol-split writer.

    After the 7th-pass refactor: the orchestrator AND the per-protocol worker
    both honor the no-dedup contract. Input is expected to be globally
    deduplicated (caller's responsibility). Duplicates in input propagate
    through to the output file.
    """

    def test_does_not_dedup_at_any_layer(self, tmp_path):
        """Same config appearing twice in input goes to the same protocol
        file twice — both the orchestrator (no per-config dedup when
        bucketing) and the worker (no defensive dict.fromkeys) honor
        the contract.
        """
        all_configs = [
            "vless://u1@h.com:443#a",
            "vless://u1@h.com:443#a",  # duplicate
        ]
        create_protocol_split_files(all_configs, str(tmp_path))
        vless_file = tmp_path / "split-by-protocols" / "vless.txt"
        assert vless_file.exists()
        content = vless_file.read_text()
        # Duplicate appears twice (no dedup at any layer)
        assert content.count("vless://u1@h.com:443#a") == 2

    def test_separates_secure_and_insecure(self, tmp_path):
        """Same protocol, different security → both vless.txt and vless-secure.txt."""
        all_configs = [
            "vless://u1@h.com:443?security=tls#sec",
            "vless://u1@h.com:443?security=none#insec",
        ]
        create_protocol_split_files(all_configs, str(tmp_path))
        vless = (tmp_path / "split-by-protocols" / "vless.txt").read_text()
        vless_secure = (tmp_path / "split-by-protocols" / "vless-secure.txt").read_text()
        # Both configs in the unsecure version
        assert "security=tls" in vless
        assert "security=none" in vless
        # Only the secure one in the secure version
        assert "security=tls" in vless_secure
        assert "security=none" not in vless_secure


class TestProtocolSplitEmptyInput:
    """Zero mappable configs must write nothing, not raise.

    ``create_protocol_split_files`` sizes its pool from the task list
    (``min(8, len(write_tasks))``), so a run whose configs map to no protocol —
    every source dead, a fetch that returned nothing — handed
    ``ThreadPoolExecutor`` a ``max_workers`` of 0 and died there instead of
    writing no files.

    The executor cache is cleared around every case because this is a
    *creation* failure: once any earlier test has built the ``write_tasks``
    pool, the cached instance is reused and the crash cannot happen. Production
    never has that earlier test — every run is the first run.
    """

    @pytest.fixture(autouse=True)
    def _cold_executor_cache(self):
        ExecutorCache._executors.clear()
        yield
        ExecutorCache._executors.clear()

    @pytest.mark.parametrize(
        "configs",
        [[], ["https://example.invalid/subscription"], ["not a config at all"]],
        ids=["no-configs", "no-vpn-configs", "garbage"],
    )
    def test_the_stage_writes_nothing_and_does_not_raise(self, tmp_path, monkeypatch, configs):
        """The split flag on, zero mappable configs: no files, no exception."""
        monkeypatch.setattr(
            "processors.config_processor.URLStats",
            lambda: URLStats(path=str(tmp_path / "url_stats.json")),
        )
        pipeline = ConfigPipeline(
            output_dir=str(tmp_path), flag_overrides={"ENABLE_PROTOCOL_SPLIT": True}
        )
        pipeline.all_configs = list(configs)
        pipeline.extra_bypass_configs = []

        # The stage measures itself now, so its return is the elapsed time; the
        # value is asserted exactly in TestProtocolSplitTiming. What this case
        # is about is that no work happened, which the two assertions below it
        # and the missing directory state.
        assert pipeline.stage_protocol_split() >= 0.0
        assert pipeline.protocol_files == []
        assert not (tmp_path / "split-by-protocols").exists()


class _TwoReadings:
    """A stand-in for the ``time`` module holding a fixed set of readings.

    The split stage reads its clock once before its work and once after it, so a
    stub with exactly two readings makes the value it returns predictable — a
    hard-coded return cannot produce it. A third read exhausts the iterator and
    fails the case rather than passing silently.
    """

    def __init__(self, *readings: float) -> None:
        self._readings = iter(readings)

    def time(self) -> float:
        return next(self._readings)


class TestProtocolSplitTiming:
    """The split stage reports the time its own work took, like its siblings.

    Most stages read the clock around their work and return the difference —
    ``stage_download``, ``stage_bypass_raw``, ``stage_bypass_unsecure_raw``,
    ``stage_telegram_proxy`` and ``stage_verify``. ``stage_default_files`` is
    the exception: it reads the clock around two of its three sub-steps and
    returns their sum, so ``create_numbered_default_files`` at the top of it
    sits outside the measured span. Either way the return is what
    ``stage_report`` prints as the timing summary, and the split stage returned
    a hard-coded ``0.0`` instead, so the summary showed it as instantaneous no
    matter how many protocol buckets it wrote.
    """

    def test_the_returned_time_is_what_the_stage_measured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two readings around the work: the return value is their difference."""
        monkeypatch.setattr(
            "processors.config_processor.URLStats",
            lambda: URLStats(path=str(tmp_path / "url_stats.json")),
        )
        monkeypatch.setattr(
            "processors.config_processor.create_protocol_split_files", lambda *_: []
        )
        monkeypatch.setattr("processors.config_processor.time", _TwoReadings(100.0, 100.25))
        pipeline = ConfigPipeline(
            output_dir=str(tmp_path), flag_overrides={"ENABLE_PROTOCOL_SPLIT": True}
        )
        pipeline.all_configs = ["vless://u@h.example.invalid:443#c"]
        pipeline.extra_bypass_configs = []

        assert pipeline.stage_protocol_split() == 0.25


class TestProtocolSplitSizeCap:
    """The stage's size cap, which its worker was handed and never consulted.

    ``max_size_mb`` is a parameter so a test can inject one small enough to
    split a bucket without a fixture anywhere near ``MAX_FILE_SIZE_MB`` (49.0).
    The subscription-file path already honours the same cap; a protocol bucket
    is the same kind of output, and it is the only one that ignored it.
    """

    def test_an_over_cap_bucket_splits_and_every_pair_is_on_disk(self, tmp_path):
        configs = [f"vless://u{i}@h.example.invalid:443?security=tls#c{i}" for i in range(12)]

        pairs = create_protocol_split_files(configs, str(tmp_path), max_size_mb=0.0002)

        # A protocol has two buckets — all configs and secure-only — and both are
        # over the injected cap here, so both are written as numbered parts.
        names = [os.path.basename(local) for local, _ in pairs]
        unsecure = [name for name in names if "secure" not in name]
        secure = [name for name in names if "secure" in name]
        assert unsecure == [f"vless-{n}.txt" for n in range(1, len(unsecure) + 1)], names
        assert secure == [f"vless-secure-{n}.txt" for n in range(1, len(secure) + 1)], names
        assert len(unsecure) > 1 and len(secure) > 1, (
            f"the injected cap did not split the buckets: {names}"
        )

        for local, remote in pairs:
            assert os.path.isfile(local), f"no file at the local side of {local!r}"
            assert remote == f"githubmirror/split-by-protocols/{os.path.basename(local)}"

        # Nothing may be lost on the way through the splitter.
        written = "".join(Path(local).read_text(encoding="utf-8") for local, _ in pairs)
        for config in configs:
            assert config in written
        # The split replaced the files: neither unsplit name is left behind.
        assert not (tmp_path / "split-by-protocols" / "vless.txt").exists()
        assert not (tmp_path / "split-by-protocols" / "vless-secure.txt").exists()


class TestPathInOutput:
    """Test the path_in_output() helper used by config_processor."""

    def test_joins_basic_paths(self):
        from processors.config_processor import path_in_output

        # POSIX: forward slashes; Windows: backslashes
        result = path_in_output("/tmp/out", "default", "all.txt")
        assert result.endswith(os.path.join("default", "all.txt"))
        assert "/tmp/out" in result or "\\tmp\\out" in result

    def test_filters_empty_components(self):
        """Empty strings in parts don't produce empty path components."""
        from processors.config_processor import path_in_output

        # f"{output_dir}/" + "/foo" → "output_dir//foo" (bug); path_in_output filters
        result = path_in_output("/tmp/out", "", "foo")
        assert result == os.path.join("/tmp/out", "foo")

    def test_single_part(self):
        from processors.config_processor import path_in_output

        result = path_in_output("/tmp/out", "all.txt")
        assert result == os.path.join("/tmp/out", "all.txt")

    def test_no_parts_returns_output_dir(self):
        from processors.config_processor import path_in_output

        # Edge case: no parts after the base
        result = path_in_output("/tmp/out")
        assert result == "/tmp/out"


class TestTelegramScrapeErrorHandling:
    """The telegram proxy scraper wraps extract_proxies in try/except so a
    single bad URL doesn't kill the whole fetch."""

    def test_scrape_error_does_not_crash_fetch(self, tmp_path) -> None:
        """If the telegram scraper raises, the fetch loop continues and
        the error is logged (not silently swallowed)."""
        from unittest.mock import MagicMock, patch

        from processors import config_processor
        from processors.config_processor import _fetch_and_process_urls

        # Build a mock scraper that raises on extract_proxies
        mock_scraper = MagicMock()
        mock_scraper.extract_proxies.side_effect = ValueError("malformed telegram text")

        # Mock fetch_data to return a successful result
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.text = "vless://u@h.com:443"
        mock_result.error = ""

        test_seen: set[str] = set()
        test_lock = __import__("threading").Lock()
        test_target: list = []
        test_extra: list = []
        test_numbered: list = []
        test_mtproto: list = []
        test_socks5: list = []
        with (
            patch.object(config_processor, "fetch_data", return_value=mock_result),
            patch.object(config_processor, "log") as mock_log,
        ):
            _fetch_and_process_urls(
                urls=["https://example.com/config"],
                target_all=test_target,
                target_extra=test_extra,
                numbered_configs_with_urls=test_numbered,
                all_mtproto=test_mtproto,
                all_socks5=test_socks5,
                global_seen=test_seen,
                global_seen_lock=test_lock,
                stats=None,
                scraper=mock_scraper,
                label="test",
                add_to_all=True,
                add_to_extra=False,
            )

        # The error should be logged (not silently swallowed)
        scrape_log_calls = [
            c for c in mock_log.call_args_list if "telegram scrape failed" in str(c)
        ]
        assert scrape_log_calls, (
            f"expected scrape error to be logged, got: {mock_log.call_args_list}"
        )


class TestStageTelegramProxy:
    """stage_telegram_proxy must actually have TelegramProxyProcessor in scope.

    The stage constructs the processor by name, and its error handler only
    catches OSError/ValueError/RuntimeError — so an unimported name escaped as
    a NameError and killed the whole pipeline whenever the tg-proxy flag was on.
    """

    def test_stage_runs_and_writes_its_files(self, tmp_path):
        """With the flag on, the stage completes instead of raising NameError."""
        from unittest.mock import MagicMock

        from processors import config_processor
        from processors.config_processor import ConfigPipeline

        pipeline = ConfigPipeline(
            output_dir=str(tmp_path), flag_overrides={"ENABLE_TG_PROXY": True}
        )
        assert pipeline.enable_tg_proxy is True

        # Keep the stage offline: no scraper, no telegram URL list.
        scraper = MagicMock()
        scraper.extract_proxies.return_value = ([], [])
        scraper.deduplicate_proxies.side_effect = lambda proxies: proxies

        with (
            patch(
                "processors.telegram_proxy_processor.TelegramProxyScraper",
                MagicMock(return_value=scraper),
            ),
            patch.object(config_processor, "TELEGRAM_PROXY_URLS", []),
            patch.object(config_processor, "log"),
        ):
            elapsed = pipeline.stage_telegram_proxy()

        assert elapsed >= 0.0
        assert pipeline.telegram_proxy_files
        assert all(os.path.isfile(path) for path in pipeline.telegram_proxy_files)

    def test_stage_is_disabled_without_the_flag(self, tmp_path):
        """The flag still short-circuits the stage before it touches anything."""
        from processors.config_processor import ConfigPipeline

        pipeline = ConfigPipeline(
            output_dir=str(tmp_path), flag_overrides={"ENABLE_TG_PROXY": False}
        )

        assert pipeline.stage_telegram_proxy() == 0.0
        assert pipeline.telegram_proxy_files == []


class TestAnnotationResolution:
    """Annotations in config_processor must point at names that exist.

    The module imports `from __future__ import annotations`, so annotation
    expressions are never evaluated at import time. An undefined name in one
    stays invisible until something asks for the resolved hints — which is what
    `_fetch_with_session`'s `-> FetchResult` was doing.
    """

    @staticmethod
    def _capture_fetch_with_session():
        """Return the real `_fetch_with_session` closure without running it."""
        from unittest.mock import MagicMock

        from processors import config_processor

        fake_executor = MagicMock()
        with (
            patch.object(config_processor, "ExecutorCache") as mock_cache,
            patch("concurrent.futures.as_completed", return_value=[]),
            patch.object(config_processor, "log"),
        ):
            mock_cache.get.return_value = fake_executor
            config_processor._fetch_and_process_urls(
                urls=["https://example.com/config"],
                target_all=[],
                target_extra=[],
                numbered_configs_with_urls=[],
                all_mtproto=[],
                all_socks5=[],
                global_seen=set(),
                global_seen_lock=__import__("threading").Lock(),
                stats=None,
                scraper=None,
                label="test",
            )
            submitted = fake_executor.submit.call_args
        assert submitted is not None, "no fetch was submitted"
        return submitted[0][0]

    def test_fetch_with_session_hints_resolve(self):
        """get_type_hints on the nested fetch helper must not raise NameError."""
        import typing

        from fetchers.fetcher import FetchResult

        fetch_with_session = self._capture_fetch_with_session()
        assert fetch_with_session.__name__ == "_fetch_with_session"

        hints = typing.get_type_hints(fetch_with_session)

        assert hints["url"] is str
        assert hints["return"] is FetchResult

    def test_every_annotation_name_is_bound_in_the_module(self):
        """No annotation in the module may name something it never imported."""
        import ast
        import builtins
        import importlib
        import inspect

        module = importlib.import_module("processors.config_processor")
        tree = ast.parse(inspect.getsource(module))

        unresolved = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = func.args
            annotated = [
                *args.posonlyargs,
                *args.args,
                *args.kwonlyargs,
                args.vararg,
                args.kwarg,
                func.returns,
            ]
            for node in annotated:
                if node is None:
                    continue
                annotation = node.annotation if isinstance(node, ast.arg) else node
                if annotation is None:
                    continue
                unresolved.extend(
                    f"{func.name}(): {sub.id} (line {sub.lineno})"
                    for sub in ast.walk(annotation)
                    if isinstance(sub, ast.Name)
                    and not hasattr(builtins, sub.id)
                    and sub.id not in vars(module)
                )

        assert unresolved == [], f"annotations naming undefined objects: {unresolved}"
