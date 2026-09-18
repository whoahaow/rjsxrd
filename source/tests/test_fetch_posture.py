"""What a refused destination means for a source, outside the budgeted test modules.

`test_fetcher_unit.py` covers the same security posture and is at its line budget
(`tests/test_module_size.py`), so behaviour added after that budget landed is pinned here.
Same rules as that module: the resolver is stubbed for the whole file and the client is a
mock, so nothing here reaches the network.

What this file pins is the difference between three outcomes a run's output has to keep
apart: a source that is dead (a fetch that failed), a source whose name resolved somewhere
this pipeline must not connect to (a refusal), and a source that was fetched without TLS
verification (a downgrade). A refusal is the second kind, and it must not be aged toward
removal from `URLS.txt` as if it were the first.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import fetchers.fetcher as fetcher_module
from fetchers.destination_guard import DESTINATION_REFUSALS, report_destination_refusals
from fetchers.fetcher import INSECURE_FETCHES, fetch_data, report_fetch_security
from utils.fetch_outcomes import DESTINATION_REFUSAL_PREFIX, is_destination_refusal
from utils.logger import LOGS_BY_FILE
from utils.url_stats import URLStats

pytestmark = pytest.mark.unit

# Addresses the tests below use as resolver answers. They are never dialled — what is
# under test is what the guard does with an answer, not the answer.
PUBLIC_ADDRESS = "93.184.216.34"
LOOPBACK_ADDRESS = "127.0.0.1"

SOURCE_URL = "https://subscriptions.example/list.txt"
SOURCE_HOST = "subscriptions.example"
REDIRECT_HOST = "elsewhere.example"


@pytest.fixture(autouse=True)
def offline_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep this module off the network, and its run counters clean.

    The guard resolves the name before connecting, so without this stub every fetch here
    would reach a real resolver; both counters are one object for the whole process, so one
    test's numbers would otherwise be the next test's starting point. `time.sleep` is
    stubbed with them: the failing-transport cases below would otherwise pay the ladder's
    one-second wait per attempt for something none of these tests are about.
    """
    monkeypatch.setattr(fetcher_module, "_resolved_addresses", lambda host, port: [PUBLIC_ADDRESS])
    monkeypatch.setattr(fetcher_module.time, "sleep", lambda _seconds: None)
    DESTINATION_REFUSALS.reset()
    INSECURE_FETCHES.reset()


def _answer_with(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    """Make the resolver answer `address`, whatever name it is asked for."""
    monkeypatch.setattr(fetcher_module, "_resolved_addresses", lambda host, port: [address])


def _answer_per_host(monkeypatch: pytest.MonkeyPatch, answers: dict[str, str]) -> None:
    """Answer per name, with `PUBLIC_ADDRESS` for every name not in `answers`."""
    monkeypatch.setattr(
        fetcher_module,
        "_resolved_addresses",
        lambda host, port: [answers.get(host, PUBLIC_ADDRESS)],
    )


def _response(text: str = "content", url: str = SOURCE_URL) -> MagicMock:
    """A successful response, as the client hands one back.

    `.url` is where the request ended, which is what the redirect check reads; it defaults
    to the requested URL, so the common case is "no redirect".
    """
    response = MagicMock()
    response.text = text
    response.status_code = 200
    response.url = url
    response.raise_for_status = MagicMock()
    return response


def _refusing_session() -> MagicMock:
    """A client that must never be called: a refusal is decided before any request."""
    session = MagicMock()
    session.get.side_effect = AssertionError("a refused destination was dialled")
    return session


def _failing_session() -> MagicMock:
    """A client whose every call fails, as an unreachable host does."""
    session = MagicMock()
    session.get.side_effect = ConnectionError("blocked")
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


class TestARefusalIsAnOutcomeOfItsOwn:
    """A refusal is named, counted and reported — never an empty success, never a death."""

    def test_a_refused_destination_is_reported_as_a_failure_with_both_names(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The message carries the host and the address, so the caller can report it.

        The transport is never reached: the refusal is decided from the resolver's answer,
        before a connection exists.
        """
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)

        result = fetch_data(SOURCE_URL, session=_refusing_session())

        assert result.success is False
        assert result.text == ""
        assert SOURCE_HOST in result.error
        assert LOOPBACK_ADDRESS in result.error

    def test_the_marker_the_stats_recognize_is_the_guards_own_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One side produces the marker and the other reads it; this pins the agreement.

        `utils/url_stats.py` decides what a recorded outcome means for a URL's lifetime
        from a string, so a test has to hold the two ends together: the guard's message has
        to be what `utils.fetch_outcomes` describes, or a refusal would age the very source
        it must not.
        """
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)

        result = fetch_data(SOURCE_URL, session=_refusing_session())

        assert result.error.startswith(DESTINATION_REFUSAL_PREFIX)
        assert is_destination_refusal(result.error) is True

    def test_a_transport_failure_is_not_a_refusal(self) -> None:
        """The other direction of the same pin: a failed fetch is not a refusal."""
        result = fetch_data(SOURCE_URL, session=_failing_session())

        assert result.success is False
        assert is_destination_refusal(result.error) is False

    def test_the_run_counts_refusals_by_host_and_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Three refusals of one destination: three refusals, one host, one address."""
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)

        for _ in range(3):
            fetch_data(SOURCE_URL, session=_refusing_session())

        stats = DESTINATION_REFUSALS.snapshot()

        assert stats.refusals == 3
        assert stats.hosts_affected == 1
        assert stats.destinations == ((SOURCE_HOST, LOOPBACK_ADDRESS),)

    def test_a_redirect_into_a_refused_destination_is_counted_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second place a refusal is produced, counted by the same counter.

        The client follows redirects itself, so a body that arrived from an address this
        pipeline must not connect to is discarded after the fact — and that refusal is as
        real as the one decided before the request. The requested host resolves publicly
        here, so the refusal can only come from where the request ended.
        """
        _answer_per_host(monkeypatch, {REDIRECT_HOST: LOOPBACK_ADDRESS})
        session = MagicMock()
        session.get.side_effect = lambda *args, **kwargs: _response(
            text="payload", url=f"https://{REDIRECT_HOST}/list.txt"
        )

        result = fetch_data(SOURCE_URL, session=session)

        assert result.success is False
        assert result.text == ""
        assert DESTINATION_REFUSALS.snapshot().destinations == ((REDIRECT_HOST, LOOPBACK_ADDRESS),)


class TestTheRefusalReport:
    """What one run's output says about the destinations it refused."""

    def test_the_report_names_the_count_the_host_and_the_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator reading the end of a run sees who was refused, and how often."""
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)
        for _ in range(3):
            fetch_data(SOURCE_URL, session=_refusing_session())
        LOGS_BY_FILE.clear()

        stats = report_destination_refusals()

        report = "\n".join(LOGS_BY_FILE[0])
        assert stats.refusals == 3
        assert "[fetch-security] 3 destination refusal(s) on 1 host(s)" in report
        assert f"refused {SOURCE_HOST}: non-public address {LOOPBACK_ADDRESS}" in report

    def test_the_report_says_a_refusal_is_not_a_dead_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The distinction this change exists for, stated where it will be read.

        A run's output already says "dead URLs"; a refusal has to be readable as something
        else, or the operator's next move is the wrong one.
        """
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)
        fetch_data(SOURCE_URL, session=_refusing_session())
        LOGS_BY_FILE.clear()

        report_destination_refusals()

        assert "not dead sources" in "\n".join(LOGS_BY_FILE[0])

    def test_the_report_says_so_when_nothing_was_refused(self) -> None:
        """Silence is not a clean run unless the report says it is one."""
        LOGS_BY_FILE.clear()

        stats = report_destination_refusals()

        assert stats.refusals == 0
        assert any("no destination was refused" in line for line in LOGS_BY_FILE[0]), LOGS_BY_FILE[
            0
        ]

    def test_the_runs_security_report_prints_both_of_its_figures(self) -> None:
        """One call at the end of a run, two sections: refusals, then TLS downgrades.

        They answer different questions and call for different responses, so they stay
        separate paragraphs rather than being folded into one number.
        """
        LOGS_BY_FILE.clear()

        report_fetch_security()

        report = "\n".join(LOGS_BY_FILE[0])
        assert "no destination was refused" in report
        assert "no fetch skipped TLS verification" in report


class TestThePurgeAndARefusal:
    """`URLS.txt`'s lifecycle, which a refusal must not change by accident."""

    def test_three_refusals_do_not_age_the_source_out_of_urls_txt(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """The defect this change exists for: a curated source deleted by a DNS blip.

        Three consecutive refusals used to be indistinguishable from three dead fetches, and
        `remove_dead_from_urls_txt()` deleted the line. The source stays in the file and the
        run reports it — a decision for a human, not a silent deletion.
        """
        _answer_with(monkeypatch, LOOPBACK_ADDRESS)
        urls_txt = _source_file(tmp_path)
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        for _ in range(3):
            _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_refusing_session()))

        assert DESTINATION_REFUSALS.snapshot().refusals == 3
        assert stats.get_dead_urls(3) == []

        stats.remove_dead_from_urls_txt(path=str(urls_txt))

        assert SOURCE_URL in urls_txt.read_text(encoding="utf-8")

    def test_three_genuine_failures_still_remove_the_source_from_urls_txt(self, tmp_path) -> None:
        """The converse, which matters as much: the purge has to keep working.

        A source that a real fetch cannot reach three times running is what the purge is
        for, and excluding refusals from it must not have made a dead source permanent.
        """
        urls_txt = _source_file(tmp_path)
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        for _ in range(3):
            _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_failing_session()))

        assert stats.get_dead_urls(3) == [(SOURCE_URL, 3)]

        stats.remove_dead_from_urls_txt(path=str(urls_txt))

        assert SOURCE_URL not in urls_txt.read_text(encoding="utf-8")

    def test_a_refusal_neither_ages_nor_clears_the_count(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A refusal is evidence neither way, so it leaves the count where it was.

        Clearing it would let a poisoned or flapping resolver mask a source that is
        genuinely dead; raising it is the defect being fixed. Two real failures stay two, and
        one more real failure is then enough for the purge.
        """
        stats = URLStats(path=str(tmp_path / "url_stats.json"))

        _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_failing_session()))
        _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_failing_session()))
        assert stats.data[SOURCE_URL]["fetch"]["consecutive_failures"] == 2

        _answer_with(monkeypatch, LOOPBACK_ADDRESS)
        _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_refusing_session()))

        assert stats.data[SOURCE_URL]["fetch"]["consecutive_failures"] == 2
        assert stats.get_dead_urls(3) == []

        _answer_with(monkeypatch, PUBLIC_ADDRESS)
        _record(stats, SOURCE_URL, fetch_data(SOURCE_URL, session=_failing_session()))

        assert stats.get_dead_urls(3) == [(SOURCE_URL, 3)]
