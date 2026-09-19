"""What a fetch this run was not allowed to make means for its source.

`REFUSE_INSECURE_FETCH` exists so an operator can decline the ladder's TLS downgrades.
Turning it on used to make a source look dead: the attempts that would have tested it were
skipped by the operator's own setting, the fetch failed, and the URL aged toward removal from
`URLS.txt` — the safety setting produced a worse outcome than leaving it off, and one nobody
asked for.

The class rather than the instance, because that is the shape of the defect: several outcomes a
fetch stage can produce say nothing about a source — a destination that resolved somewhere this
pipeline must not connect to (decided before the request and again after a redirect), a fetch
this run's own rules curtailed, and a call that asked for no attempt at all — and they share one
marker vocabulary, one counter and one question (`utils.fetch_outcomes.is_source_evidence`)
rather than a special case each in the stats.

It lives in a module of its own because `test_fetch_posture.py` grew past the 800-line ceiling
(`tests/test_module_size.py`) with this class in it; moving the class out is the split that gate
asks for, and one class is one coherent part.

Same rules as the posture module: the resolver is stubbed for the whole file and the client is a
mock, so nothing here reaches the network.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import fetchers.fetcher as fetcher_module
from fetchers.fetcher import fetch_data
from utils.fetch_outcomes import (
    RUN_CONDITION_PREFIX,
    RUN_CONDITIONS,
    is_destination_refusal,
    is_source_evidence,
    report_run_conditions,
)
from utils.logger import LOGS_BY_FILE
from utils.url_stats import URLStats

pytestmark = pytest.mark.unit

# Addresses the tests below use as resolver answers. They are never dialled — what is under
# test is what an outcome means for a URL's lifetime, not the answer.
PUBLIC_ADDRESS = "93.184.216.34"
LOOPBACK_ADDRESS = "127.0.0.1"

SOURCE_URL = "https://subscriptions.example/list.txt"
SOURCE_HOST = "subscriptions.example"


@pytest.fixture(autouse=True)
def offline_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep this module off the network, and its run-condition counter clean.

    The guard resolves the name before connecting, so without this stub every fetch here would
    reach a real resolver; `RUN_CONDITIONS` is one object for the whole process, so one test's
    numbers would otherwise be the next test's starting point. `time.sleep` is stubbed with
    them: the failing-transport cases below would otherwise pay the ladder's one-second wait
    per attempt for something none of these tests are about.
    """
    monkeypatch.setattr(fetcher_module, "_resolved_addresses", lambda host, port: [PUBLIC_ADDRESS])
    monkeypatch.setattr(fetcher_module.time, "sleep", lambda _seconds: None)
    RUN_CONDITIONS.reset()


def _answer_with(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    """Make the resolver answer `address`, whatever name it is asked for."""
    monkeypatch.setattr(fetcher_module, "_resolved_addresses", lambda host, port: [address])


def _failing_session() -> MagicMock:
    """A client whose every call fails, as an unreachable host does."""
    session = MagicMock()
    session.get.side_effect = ConnectionError("blocked")
    return session


def _refusing_session() -> MagicMock:
    """A client that must never be called: a refusal is decided before any request."""
    session = MagicMock()
    session.get.side_effect = AssertionError("a refused destination was dialled")
    return session


def _record(stats: URLStats, url: str, result) -> None:
    """Record a result the way the pipeline's fetch stage does.

    Spelled out rather than imported because the pipeline calls this seam inline
    (`processors/config_processor.py`); what is under test is what the stats make of the
    outcome, not how the call is reached.
    """
    stats.record_fetch(url, result.success, result.status_code, result.error)


def _source_file(tmp_path: Path) -> Path:
    """A `URLS.txt` holding one live source line, and the path to it."""
    path = tmp_path / "URLS.txt"
    path.write_text(f"# sources\n{SOURCE_URL}\n", encoding="utf-8")
    return path


class TestARunConditionIsAnOutcomeOfItsOwn:
    """A fetch this run was not allowed to make is not evidence about its source.

    `REFUSE_INSECURE_FETCH` exists so an operator can decline the ladder's TLS downgrades.
    Turning it on used to make a source look dead: the attempts that would have tested it were
    skipped by the operator's own setting, the fetch failed, and the URL aged toward removal
    from `URLS.txt` — the safety setting produced a worse outcome than leaving it off, and one
    nobody asked for.

    The class rather than the instance, because that is the shape of the defect: three outcomes
    a run can produce say nothing about a source — a destination that resolved somewhere this
    pipeline must not connect to (decided before the request and again after a redirect), a
    fetch this run's own rules curtailed, and a call that asked for no attempt at all — and they
    share one marker vocabulary, one counter and one question (`is_source_evidence`) rather than
    a special case each in the stats.
    """

    def test_a_curtailed_fetch_carries_the_run_condition_marker(self) -> None:
        """The outcome starts with the marker, and it is not a refusal.

        The message keeps both halves of the story — nothing further was tried, and the
        verified attempt failed — with the half that decides the URL's fate at the front.
        """
        with patch.object(fetcher_module, "REFUSE_INSECURE_FETCH", True):
            result = fetch_data(SOURCE_URL, session=_failing_session())

        assert result.success is False
        assert result.text == ""
        assert result.error.startswith(RUN_CONDITION_PREFIX)
        assert is_source_evidence(result.error) is False
        assert is_destination_refusal(result.error) is False
        assert "REFUSE_INSECURE_FETCH" in result.error
        assert "blocked" in result.error

    def test_the_run_counts_and_names_them(self) -> None:
        """Three curtailed fetches: three outcomes, one host, and the reason is kept."""
        with patch.object(fetcher_module, "REFUSE_INSECURE_FETCH", True):
            for _ in range(3):
                fetch_data(SOURCE_URL, session=_failing_session())

        stats = RUN_CONDITIONS.snapshot()

        assert stats.outcomes == 3
        assert stats.hosts_affected == 1
        assert [host for host, _ in stats.conditions] == [SOURCE_HOST]
        assert "REFUSE_INSECURE_FETCH" in stats.conditions[0][1]

        LOGS_BY_FILE.clear()
        reported = report_run_conditions()

        report = "\n".join(LOGS_BY_FILE[0])
        assert reported.outcomes == 3
        assert "[fetch-security] 3 outcome(s) on 1 host(s)" in report
        assert f"{SOURCE_HOST}: 2 insecure attempt(s) skipped by REFUSE_INSECURE_FETCH" in report

    def test_the_report_says_so_when_nothing_was_curtailed(self) -> None:
        """Silence is not a clean run unless the report says it is one."""
        LOGS_BY_FILE.clear()

        stats = report_run_conditions()

        assert stats.outcomes == 0
        assert any(
            "no fetch was curtailed by this run's own rules" in line for line in LOGS_BY_FILE[0]
        ), LOGS_BY_FILE[0]

    def test_a_call_that_asked_for_no_attempt_is_a_run_condition_too(self) -> None:
        """The fourth outcome of the class: `max_attempts=0` never reached the source.

        Enumerated rather than discovered one incident at a time. Four things `fetch_data` can
        return are not evidence about a source — the refusal before the request, the refusal
        after a redirect, a curtailed fetch, and a call for zero attempts — and the last of them
        used to age the URL for a caller's mistake. A source aged by its own fetch stage's
        arguments is the same defect as one aged by the operator's safety setting.

        The session is the refusing one, so an attempt that somehow ran would raise instead of
        passing quietly.
        """
        result = fetch_data(SOURCE_URL, session=_refusing_session(), max_attempts=0)

        assert result.success is False
        assert is_source_evidence(result.error) is False
        assert RUN_CONDITIONS.snapshot().outcomes == 1

    def test_a_refusal_is_not_source_evidence_either(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One question answers for both members of the class: the class, not one case."""
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)

        result = fetch_data(SOURCE_URL, session=_refusing_session())

        assert is_source_evidence(result.error) is False

    def test_three_curtailed_fetches_do_not_age_the_source_out_of_urls_txt(
        self, tmp_path: Path
    ) -> None:
        """The defect this class exists for: the safety setting deleting a curated source.

        With `REFUSE_INSECURE_FETCH` engaged, three fetch rounds of a source whose network
        breaks TLS leave the line in `URLS.txt` and the URL out of the dead list. The fetch
        stage never got to test it, and the operator's own policy is not the source's failure.
        """
        urls_txt = _source_file(tmp_path)
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        with patch.object(fetcher_module, "REFUSE_INSECURE_FETCH", True):
            for _ in range(3):
                _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_failing_session()))

        assert RUN_CONDITIONS.snapshot().outcomes == 3
        assert stats.get_dead_urls(3) == []

        stats.remove_dead_from_urls_txt(path=str(urls_txt))

        assert SOURCE_URL in urls_txt.read_text(encoding="utf-8")

    def test_the_default_path_still_ages_a_source_it_cannot_reach(self, tmp_path: Path) -> None:
        """With the setting off, nothing about reachability changed — the regression guard.

        The ladder's downgrades are how this pipeline reaches a source on a network that
        interferes with TLS, and a source none of the three attempts could reach is the failure
        the purge exists for. No marker appears on that outcome: it was tested, and it failed.
        """
        urls_txt = _source_file(tmp_path)
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        for _ in range(3):
            result = fetch_data(SOURCE_URL, session=_failing_session())
            assert is_source_evidence(result.error) is True
            assert RUN_CONDITION_PREFIX not in result.error
            _record(stats, SOURCE_URL, result)

        assert stats.get_dead_urls(3) == [(SOURCE_URL, 3)]

        stats.remove_dead_from_urls_txt(path=str(urls_txt))

        assert SOURCE_URL not in urls_txt.read_text(encoding="utf-8")
