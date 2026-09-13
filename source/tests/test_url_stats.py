"""Unit tests for URL statistics tracking."""

import os
import tempfile

import pytest

from utils.url_stats import URLStats

pytestmark = pytest.mark.unit


class TestURLStats:
    def test_record_fetch_success_resets_counter(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        stats.record_fetch("https://example.com", False, 404, "Not Found")
        stats.record_fetch("https://example.com", False, 500, "Error")
        stats.record_fetch("https://example.com", True, 200, "")
        assert stats.get_dead_urls(3) == []

    def test_record_fetch_three_fails_detects_dead(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        stats.record_fetch("https://example.com", False, 404, "")
        stats.record_fetch("https://example.com", False, 404, "")
        stats.record_fetch("https://example.com", False, 404, "")
        dead = stats.get_dead_urls(3)
        assert len(dead) == 1
        assert dead[0][0] == "https://example.com"
        assert dead[0][1] == 3

    def test_get_dead_urls_excludes_special_sources(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        stats.record_fetch("https://example.com", False, 404, "")
        stats.record_fetch("https://example.com", False, 404, "")
        stats.record_fetch("https://example.com", False, 404, "")
        stats.record_fetch("MANUAL_SERVERS", False, 0, "err")
        stats.record_fetch("DAILY_REPO", False, 0, "err")
        stats.record_fetch("SSTAP_ORG", False, 0, "err")
        stats.record_fetch("UPSTREAM_AGGREGATOR", False, 0, "err")
        dead = stats.get_dead_urls(3)
        urls = [u for u, _ in dead]
        assert "MANUAL_SERVERS" not in urls
        assert "DAILY_REPO" not in urls
        assert "SSTAP_ORG" not in urls
        assert "UPSTREAM_AGGREGATOR" not in urls
        assert "https://example.com" in urls

    def test_record_config_verification_by_hash(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        cfg = "vless://uuid@host:443?security=tls#Test"
        stats.record_config_verification("MANUAL_SERVERS", cfg, False)
        stats.record_config_verification("MANUAL_SERVERS", cfg, False)
        stats.record_config_verification("MANUAL_SERVERS", cfg, False)
        dead = stats.get_dead_configs(3)
        assert len(dead) == 1

    def test_record_config_verification_resets_on_success(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        cfg = "vless://uuid@host:443?security=tls#Test"
        stats.record_config_verification("MANUAL_SERVERS", cfg, False)
        stats.record_config_verification("MANUAL_SERVERS", cfg, True)
        stats.record_config_verification("MANUAL_SERVERS", cfg, False)
        dead = stats.get_dead_configs(3)
        assert len(dead) == 0  # success reset counter

    def test_history_trimmed_to_max(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        for i in range(5):
            stats.record_fetch("https://example.com", True, 200, "")
        data = stats.data["https://example.com"]["fetch"]["history"]
        assert len(data) == 3  # MAX_HISTORY = 3

    def test_flush_and_reload(self):
        path = tempfile.mktemp(suffix=".json")
        stats = URLStats(path=path)
        stats.record_fetch("https://example.com", True, 200, "")
        stats.flush()
        stats2 = URLStats(path=path)
        assert stats2.data["https://example.com"]["fetch"]["consecutive_failures"] == 0
        os.unlink(path)

    def test_existing_empty_file_loads_as_empty_state(self, temp_file):
        """An existing but empty file loads as empty state, not a crash.

        `tempfile.mktemp()` (used by the tests above) never creates the file,
        so they only exercise the "no file yet" branch; a truncated or
        zero-byte stats file is the other real-world state.
        """
        stats = URLStats(path=str(temp_file))
        assert stats.data == {}

    def test_get_low_yield_urls(self):
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        stats.record_config_yield("https://good.com", raw=10, secure=8)
        stats.record_config_yield("https://bad.com", raw=3, secure=0)
        stats.record_verified_yield({"https://good.com": (8, 7), "https://bad.com": (3, 0)})
        low = stats.get_low_yield_urls(0)
        assert len(low) == 1
        assert low[0][0] == "https://bad.com"

    def test_record_config_yield_accumulates_totals(self):
        """Regression: the old code OVERWROTE raw/secure on every call, losing
        data when the same URL was recorded twice in one run (which happens:
        once during fetch, once in the per-source yield loop). The new code
        keeps raw/secure as the latest snapshot AND adds total_raw/total_secure
        as lifetime accumulators.
        """
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        # First call: fetch-time placeholder (raw=N, secure=0)
        stats.record_config_yield("https://a.com", raw=100, secure=0)
        # Second call: post-secure-filter update (raw=100, secure=85)
        stats.record_config_yield("https://a.com", raw=100, secure=85)
        # raw/secure are the latest values
        yield_data = stats.data["https://a.com"]["yield"]
        assert yield_data["raw"] == 100
        assert yield_data["secure"] == 85
        # total_raw/total_secure accumulate across both calls
        assert yield_data["total_raw"] == 200
        assert yield_data["total_secure"] == 85

    def test_record_config_yield_totals_start_at_zero(self):
        """Fresh URL with no prior data: totals should be 0 on first call's
        init, then equal to the call's value (not double-counted)."""
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        stats.record_config_yield("https://new.com", raw=5, secure=3)
        yield_data = stats.data["https://new.com"]["yield"]
        assert yield_data["total_raw"] == 5
        assert yield_data["total_secure"] == 3

    def test_record_config_yield_totals_persist_across_flushes(self):
        """flush() saves the latest totals to disk. A reloaded URLStats has a
        fresh _run_totals dict (per-run accumulator), so disk-persisted totals
        don't carry over to the in-memory accumulator in a new run.

        The persisted JSON shows the most recent run's totals; the in-memory
        accumulator tracks only the current run. This is the correct semantic:
        across runs, only the latest totals are reported (matching the old
        overwrite behavior, which was per-run by accident). Within a run,
        totals accumulate across multiple calls.
        """
        path = tempfile.mktemp(suffix=".json")
        stats = URLStats(path=path)
        stats.record_config_yield("https://a.com", raw=10, secure=5)
        stats.record_config_yield("https://a.com", raw=10, secure=5)
        stats.flush()
        # Reload from disk — _run_totals is fresh
        stats2 = URLStats(path=path)
        # New call in reloaded instance: starts at 0, gets 10 added
        stats2.record_config_yield("https://a.com", raw=10, secure=5)
        yield_data = stats2.data["https://a.com"]["yield"]
        assert yield_data["total_raw"] == 10  # not 30 — fresh accumulator
        assert yield_data["total_secure"] == 5
        os.unlink(path)
