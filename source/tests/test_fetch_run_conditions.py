"""What a fetch this run was not allowed to make means for its source.

Only a failure that says something about the *source* may age a URL toward removal from
`URLS.txt`. A fetch the transport failed says that: every attempt was made, over a verified
connection, and none got through. What does not say it is a fetch the run itself declined to
make — a destination whose name resolved somewhere this pipeline must not connect to, decided
before the request and again after a redirect, and a call that asked for no attempt at all.
Those share one marker vocabulary, one counter and one question
(`utils.fetch_outcomes.is_source_evidence`) rather than a special case each in the stats, and a
source aged by the operator's own rules is the defect that class exists to prevent.

The TLS downgrades are no longer a member of the class, because refusing them is the default
and the retries they used to replace are real requests: a source whose only reachable mode was
an unverified or plaintext one now fails like any unreachable source and ages. `ALLOW_TLS_DOWNGRADE=1`
brings the ladder back, and a fetch that fails on it is a tested failure too — nothing about the
outcome carries the run's rules into the URL's history.

It lives in a module of its own because `test_fetch_posture.py` grew past the 800-line ceiling
(`tests/test_module_size.py`) with this class in it; moving the class out is the split that gate
asks for, and one class is one coherent part.

Same rules as the posture module: the resolver is stubbed for the whole file and the client is a
mock, so nothing here reaches the network.
"""

from pathlib import Path
from unittest.mock import MagicMock

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
    """A fetch this run declined to make is not evidence about its source.

    The class is enumerated rather than discovered one incident at a time: a destination that
    resolved somewhere this pipeline must not connect to (decided before the request, and again
    after a redirect), and a call that asked for no attempt at all. Each of those used to age a
    curated line toward removal from `URLS.txt` exactly as a dead source did — the operator's own
    rules, or a caller's bad argument, recorded as a fact about somebody else's server.

    They share one marker, one counter and one question so a new member is a prefix plus a mark
    at the site that produces it, not a second special case in the stats.
    """

    def test_a_call_that_asked_for_no_attempt_carries_the_run_condition_marker(self):
        """`max_attempts=0` never reached the source, so its error is not about the source.

        The session is the refusing one: an attempt that somehow ran would raise rather than
        pass quietly.
        """
        result = fetch_data(SOURCE_URL, session=_refusing_session(), max_attempts=0)

        assert result.success is False
        assert result.text == ""
        assert result.error.startswith(RUN_CONDITION_PREFIX)
        assert is_source_evidence(result.error) is False
        assert is_destination_refusal(result.error) is False
        assert "max_attempts" in result.error

    def test_the_run_counts_and_names_them(self) -> None:
        """Three curtailed fetches: three outcomes, one host, and the reason is kept."""
        for _ in range(3):
            fetch_data(SOURCE_URL, session=_failing_session(), max_attempts=0)

        stats = RUN_CONDITIONS.snapshot()

        assert stats.outcomes == 3
        assert stats.hosts_affected == 1
        assert [host for host, _ in stats.conditions] == [SOURCE_HOST]
        assert "max_attempts" in stats.conditions[0][1]

        LOGS_BY_FILE.clear()
        reported = report_run_conditions()

        report = "\n".join(LOGS_BY_FILE[0])
        assert reported.outcomes == 3
        assert "[fetch-security] 3 outcome(s) on 1 host(s)" in report
        assert f"{SOURCE_HOST}: the fetch was called with max_attempts below 1" in report

    def test_the_report_says_so_when_nothing_was_curtailed(self) -> None:
        """Silence is not a clean run unless the report says it is one."""
        LOGS_BY_FILE.clear()

        stats = report_run_conditions()

        assert stats.outcomes == 0
        assert any(
            "no fetch was curtailed by this run's own rules" in line for line in LOGS_BY_FILE[0]
        ), LOGS_BY_FILE[0]

    def test_a_refusal_is_not_source_evidence_either(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One question answers for both members of the class: the class, not one case."""
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)

        result = fetch_data(SOURCE_URL, session=_refusing_session())

        assert is_source_evidence(result.error) is False

    def test_three_verified_failures_age_the_source_out_of_urls_txt(self, tmp_path: Path) -> None:
        """The consequence of refusing the downgrades, stated as a test.

        Every attempt is now a real verified request, so a source none of them reached is the
        failure the purge exists for — including a source that would have answered an unverified
        or plaintext attempt. That is what the flip costs, and it is the honest direction: the
        line goes because the source cannot be fetched under the rules this pipeline runs by, not
        because a rule was in the way. `ALLOW_TLS_DOWNGRADE=1` buys the reach back.
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

    def test_a_curtailed_fetch_does_not_age_the_source_out_of_urls_txt(
        self, tmp_path: Path
    ) -> None:
        """The defect this class exists for: the run's own rules deleting a curated source.

        Three rounds in which no request left the process leave the line in `URLS.txt` and the
        URL out of the dead list. The fetch stage never got to test the source, and a caller's
        argument is not the source's failure.
        """
        urls_txt = _source_file(tmp_path)
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        for _ in range(3):
            _record(
                stats,
                SOURCE_URL,
                fetch_data(SOURCE_URL, session=_refusing_session(), max_attempts=0),
            )

        assert RUN_CONDITIONS.snapshot().outcomes == 3
        assert stats.get_dead_urls(3) == []

        stats.remove_dead_from_urls_txt(path=str(urls_txt))

        assert SOURCE_URL in urls_txt.read_text(encoding="utf-8")
