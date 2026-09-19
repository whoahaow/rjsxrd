"""Unit tests for URL statistics tracking."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from utils.fetch_outcomes import (
    DESTINATION_REFUSAL_PREFIX,
    RUN_CONDITION_PREFIX,
    is_destination_refusal,
    is_source_evidence,
)
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
        for _ in range(5):
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

    def test_non_object_payload_loads_as_empty_state(self, tmp_path):
        """A stats file holding a JSON array must not become `self.data`.

        `_load` is declared to return a dict and every write goes through
        `self.data[...]`, so a list payload raises TypeError on the first
        record instead of starting from empty state.
        """
        path = tmp_path / "url_stats.json"
        path.write_text('["not", "an", "object"]', encoding="utf-8")

        stats = URLStats(path=str(path))

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

    def test_a_destination_refusal_does_not_age_the_url(self):
        """A refusal is an outcome, not a failure: three of them are not three failures.

        The marker is the one the guard builds its own message from
        (`utils/fetch_outcomes.py`), so this also holds the two ends of that contract
        together — a refusal recorded here is what keeps a curated source in `URLS.txt`.
        The class is read back out of the recorded text, which is the only copy of it: the
        store keeps no derived flag to disagree with.
        """
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))
        refusal = (
            f"{DESTINATION_REFUSAL_PREFIX}example.com: it resolves to the "
            "non-public address 127.0.0.1"
        )

        for _ in range(3):
            stats.record_fetch("https://example.com", False, 0, refusal)

        assert stats.get_dead_urls(3) == []
        history = stats.data["https://example.com"]["fetch"]["history"]
        assert [is_destination_refusal(item["error"]) for item in history] == [True, True, True]

    def test_a_fetch_failure_that_is_not_a_refusal_still_ages_the_url(self):
        """The converse: an error that is not a refusal is a failure, and it counts."""
        stats = URLStats(path=tempfile.mktemp(suffix=".json"))

        for _ in range(3):
            stats.record_fetch("https://example.com", False, 0, "connection reset")

        assert stats.get_dead_urls(3) == [("https://example.com", 3)]
        history = stats.data["https://example.com"]["fetch"]["history"]
        assert [is_destination_refusal(item["error"]) for item in history] == [False, False, False]


class TestWhatCountsAsEvidenceAboutASource:
    """The predicate a URL's lifetime hangs on, and the class it asks about.

    `record_fetch` raises a URL's failure count from one question: does this outcome say
    something about the source, or only about the run? A refusal answers no, and so does every
    other outcome this run's own rules produced — a curtailed fetch, a call that asked for no
    attempt at all — which is why the question is asked about the class
    (`utils.fetch_outcomes.is_source_evidence`) rather than one marker at a time.
    """

    def test_a_refusal_is_not_evidence_about_the_source(self) -> None:
        refusal = (
            f"{DESTINATION_REFUSAL_PREFIX}example.com: it resolves to the "
            "non-public address 127.0.0.1"
        )

        assert is_source_evidence(refusal) is False
        assert is_destination_refusal(refusal) is True

    def test_a_run_condition_is_not_evidence_about_the_source(self) -> None:
        curtailed = f"{RUN_CONDITION_PREFIX}2 insecure attempt(s) skipped by REFUSE_INSECURE_FETCH"

        assert is_source_evidence(curtailed) is False
        assert is_destination_refusal(curtailed) is False

    def test_a_marker_that_is_not_at_position_zero_is_evidence(self) -> None:
        """The class predicate is as strict as the refusal's, and for the same reason.

        A transport error that quotes one of these markers is a failure of the fetch: reading a
        marker anywhere in the text would let a source be kept alive by an error that merely
        mentions the policy, and it would do it for every member of the class at once.
        """
        assert is_source_evidence(f"boom: {DESTINATION_REFUSAL_PREFIX}x") is True
        assert is_source_evidence(f"boom: {RUN_CONDITION_PREFIX}x") is True

    def test_an_absent_reason_is_evidence(self) -> None:
        """An empty error is a bare failure, and a bare failure ages the URL.

        The other direction would make one permanent: `record_fetch` is called with an empty
        error for a failure the transport reported without a message.
        """
        assert is_source_evidence("") is True


class TestARunConditionAndTheURL:
    """What a run condition means for a URL's life, at the seam the pipeline calls."""

    def test_three_curtailed_fetches_leave_the_url_alone(self, tmp_path) -> None:
        """A run condition ages nothing, which is the whole point of the class.

        `REFUSE_INSECURE_FETCH` skipping the ladder's downgrades is a fact about the run, and a
        source the operator's own setting left untested must not be deleted from `URLS.txt` for
        for it — the same reason a refusal is not allowed to. The history keeps the reason the
        fetch returned and the class is read from it, so what it was is in one place.
        """
        stats = URLStats(path=str(tmp_path / "url_stats.json"))
        curtailed = f"{RUN_CONDITION_PREFIX}2 insecure attempt(s) skipped by REFUSE_INSECURE_FETCH"

        for _ in range(3):
            stats.record_fetch("https://example.com", False, 0, curtailed)

        assert stats.get_dead_urls(3) == []
        history = stats.data["https://example.com"]["fetch"]["history"]
        assert [is_destination_refusal(item["error"]) for item in history] == [False, False, False]

    def test_a_run_condition_neither_ages_nor_clears_the_count(self, tmp_path) -> None:
        """Evidence neither way, like a refusal: two real failures stay two.

        Clearing the count would let a run in which the safety setting was engaged mask a
        source that is genuinely dead; raising it is the defect this class fixes.
        """
        stats = URLStats(path=str(tmp_path / "url_stats.json"))
        curtailed = f"{RUN_CONDITION_PREFIX}the fetch was called with max_attempts below 1"

        stats.record_fetch("https://example.com", False, 0, "connection reset")
        stats.record_fetch("https://example.com", False, 0, "connection reset")
        assert stats.data["https://example.com"]["fetch"]["consecutive_failures"] == 2

        stats.record_fetch("https://example.com", False, 0, curtailed)

        assert stats.data["https://example.com"]["fetch"]["consecutive_failures"] == 2
        assert stats.get_dead_urls(3) == []

        stats.record_fetch("https://example.com", False, 0, "connection reset")

        assert stats.get_dead_urls(3) == [("https://example.com", 3)]


class TestAStoreWrittenBeforeTheDerivedFlagWasDropped:
    """What an entry written by an earlier version means to this one.

    `record_fetch` used to persist `refused` — a second, derived copy of one fact, written
    beside the error text it was derived from. It is gone: the text is the single source, and
    a reader that wants the class asks the text (`utils.fetch_outcomes.is_destination_refusal`).
    Entries written before that keep the key on disk, and a schema-less JSON store read as
    plain dicts is exactly where an old key is silently ignored — or crashes a loader that
    unpacks it into a dataclass. These walk the read paths over a file in the old shape rather
    than assuming which happened.
    """

    REFUSAL = f"{DESTINATION_REFUSAL_PREFIX}example.com: it resolves to the non-public address"

    def _store_in_the_old_shape(self, path: Path) -> str:
        """A stats file holding two entries whose history items carry the dropped key."""
        path.write_text(
            json.dumps(
                {
                    "https://kept.example/list.txt": {
                        "fetch": {
                            "consecutive_failures": 0,
                            "history": [
                                {
                                    "success": False,
                                    "refused": True,
                                    "status": 0,
                                    "error": self.REFUSAL,
                                    "time": "2026-01-01T00:00:00",
                                }
                            ],
                        }
                    },
                    "https://dead.example/list.txt": {
                        "fetch": {
                            "consecutive_failures": 3,
                            "history": [
                                {
                                    "success": False,
                                    "refused": False,
                                    "status": 0,
                                    "error": "connection reset",
                                    "time": "2026-01-01T00:00:00",
                                }
                            ],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return str(path)

    DISAGREEING_REFUSAL = (
        f"{DESTINATION_REFUSAL_PREFIX}disagreeing.example: it resolves to the "
        "non-public address 127.0.0.1"
    )

    def _store_where_the_key_disagrees(self, path: Path) -> str:
        """A stats file whose stale `refused` keys contradict the texts beside them.

        The two directions the agreeing file cannot show: `refused` set to True beside a
        transport error, and to False beside a refusal. A writer that persisted the key
        could set it from anything; what the class of an entry is has to come from the one
        channel that is still written, and these entries are where the two disagree.
        """
        path.write_text(
            json.dumps(
                {
                    "https://key-says-refused.example/list.txt": {
                        "fetch": {
                            "consecutive_failures": 3,
                            "history": [
                                {
                                    "success": False,
                                    "refused": True,
                                    "status": 0,
                                    "error": "connection reset",
                                    "time": "2026-01-01T00:00:00",
                                }
                            ],
                        }
                    },
                    "https://key-says-failed.example/list.txt": {
                        "fetch": {
                            "consecutive_failures": 0,
                            "history": [
                                {
                                    "success": False,
                                    "refused": False,
                                    "status": 0,
                                    "error": self.DISAGREEING_REFUSAL,
                                    "time": "2026-01-01T00:00:00",
                                }
                            ],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return str(path)

    def test_the_old_key_is_ignored_and_the_text_still_decides(self, tmp_path: Path) -> None:
        """The file loads, the counts stand, and the class comes from the recorded text."""
        stats = URLStats(path=self._store_in_the_old_shape(tmp_path / "url_stats.json"))

        assert stats.get_dead_urls(3) == [("https://dead.example/list.txt", 3)]
        kept = stats.data["https://kept.example/list.txt"]["fetch"]["history"][0]
        assert "refused" in kept
        assert is_destination_refusal(kept["error"]) is True

    def test_a_new_record_writes_the_text_and_nothing_derived(self, tmp_path: Path) -> None:
        """The write side keeps one channel too: the reason, and no copy of its class."""
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        stats.record_fetch("https://example.com", False, 0, self.REFUSAL)

        recorded = stats.data["https://example.com"]["fetch"]["history"][0]
        assert recorded["error"] == self.REFUSAL
        assert "refused" not in recorded
        assert is_destination_refusal(recorded["error"]) is True

    def test_a_stale_key_cannot_shelter_a_failed_fetch(self, tmp_path: Path) -> None:
        """refused=True beside a transport error: the text decides, so the URL still ages.

        The direction that costs a source its line in `URLS.txt` if a reader believes the
        key: three real failures are three real failures however the dropped flag was set.
        """
        stats = URLStats(path=self._store_where_the_key_disagrees(tmp_path / "url_stats.json"))
        url = "https://key-says-refused.example/list.txt"
        item = stats.data[url]["fetch"]["history"][0]

        assert item["refused"] is True
        assert is_destination_refusal(item["error"]) is False
        assert is_source_evidence(item["error"]) is True
        assert (url, 3) in stats.get_dead_urls(3)

    def test_a_stale_key_cannot_hide_a_refusal(self, tmp_path: Path) -> None:
        """refused=False beside a refusal text: the text decides, so the URL does not age.

        The other direction, and the one the class exists for: a refusal was never a failure,
        and a reader that asks the text sees that even where the dropped key says otherwise.
        """
        stats = URLStats(path=self._store_where_the_key_disagrees(tmp_path / "url_stats.json"))
        url = "https://key-says-failed.example/list.txt"
        item = stats.data[url]["fetch"]["history"][0]

        assert item["refused"] is False
        assert is_destination_refusal(item["error"]) is True
        assert is_source_evidence(item["error"]) is False
        assert url not in [dead_url for dead_url, _ in stats.get_dead_urls(3)]

        stats.record_fetch(url, False, 0, item["error"])

        assert stats.data[url]["fetch"]["consecutive_failures"] == 0
        assert url not in [dead_url for dead_url, _ in stats.get_dead_urls(3)]
