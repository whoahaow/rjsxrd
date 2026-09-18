"""The pure-logic half of `test_fetcher.py`, marked `unit`.

Every test here stubs the client and then asserts on what the module did with
it: environment proxy resolution, the shape of the built session, the retry loop
and the error mapping. None of them builds a real HTTP client or reaches the
network, so `-m unit` selects them and an offline runner exercises them.

Two of them pin behaviour nothing else pins: the unknown-status sentinel
`_extract_status` returns when a client reports a status that is not an `int`,
and the `None` `_fetch_via_api` returns when the body it received is not a `str`.

The regression test for `max_attempts=0` belongs here for the same reason it
exists at all: it is pure logic, and a regression test that only runs on a
machine with network is a regression test that silently stops guarding.

What stayed behind in `test_fetcher.py` is the class that actually attempts
traffic — `fetch_data` against a real URL — which self-skips when the network is
unavailable and carries the `integration` marker for that reason.

The security posture the fetch path carries is covered here too: the retry
ladder's three attempts, the log line and the count each downgrade produces, the
setting that refuses the downgrades, and the scope of the one warning filter this
module still installs. None of those reach the network — the client is a mock.
"""

import os
import warnings
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import fetchers.fetcher as fetcher_module
from fetchers.fetcher import (
    INSECURE_FETCHES,
    _attempt_mode,
    _extract_status,
    _fetch_via_api,
    _get_env_proxy,
    build_session,
    fetch_data,
    report_insecure_fetches,
)
from utils.logger import LOGS_BY_FILE

pytestmark = pytest.mark.unit

CONFIG_URL = "https://example.com/config.txt"
PLAINTEXT_CONFIG_URL = "http://example.com/config.txt"


@pytest.fixture(autouse=True)
def clean_run_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the run's downgrade counter clean, and the ladder's waits short.

    The counter is one object for the whole process, so without this one test's
    numbers would be the next test's starting point. `time.sleep` is stubbed
    with it because the ladder's one-second wait is not what these tests are
    about and it would otherwise be paid per retry.
    """
    monkeypatch.setattr(fetcher_module.time, "sleep", lambda _seconds: None)
    INSECURE_FETCHES.reset()


def _response(text: str = "content", url: str = CONFIG_URL) -> MagicMock:
    """A successful response, as the client hands one back.

    `.url` is where the request ended, which is what the redirect check reads;
    it defaults to the requested URL, so the common case is "no redirect".
    """
    response = MagicMock()
    response.text = text
    response.status_code = 200
    response.url = url
    response.raise_for_status = MagicMock()
    return response


def _session(*outcomes: object) -> MagicMock:
    """A session that answers `outcomes` in order, raising the exceptions.

    With no outcomes it is a session that succeeds on every call — the tests
    that pass it that way are asserting about a destination, not a response.
    The success case is a callable rather than a return value because a mock's
    `side_effect` is iterated when it is set to an object, and a `MagicMock` is
    iterable.
    """
    session = MagicMock()
    session.get.side_effect = list(outcomes) if outcomes else lambda *args, **kwargs: _response()
    return session


def _failing_session(error: Exception | None = None) -> MagicMock:
    """A session whose every call fails."""
    session = MagicMock()
    session.get.side_effect = error or ConnectionError("blocked")
    return session


class TestGetEnvProxy:
    """Test _get_env_proxy function."""

    def test_no_proxy_env(self):
        """Test when no proxy env vars are set."""
        with patch.dict(os.environ, {}, clear=True):
            result = _get_env_proxy()
            assert result is None

    def test_https_proxy(self):
        """Test HTTPS_PROXY env var."""
        with patch.dict(os.environ, {"HTTPS_PROXY": "socks5h://localhost:1080"}):
            result = _get_env_proxy()
            assert result == "socks5h://localhost:1080"

    def test_http_proxy(self):
        """Test HTTP_PROXY env var."""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:8080"}):
            result = _get_env_proxy()
            assert result == "http://proxy.example.com:8080"

    def test_all_proxy(self):
        """Test ALL_PROXY env var."""
        with patch.dict(os.environ, {"ALL_PROXY": "socks5://proxy:1080"}):
            result = _get_env_proxy()
            assert result == "socks5://proxy:1080"

    def test_priority_order(self):
        """Test priority order: HTTPS_PROXY > HTTP_PROXY > ALL_PROXY."""
        with patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": "https://first:443",
                "HTTP_PROXY": "http://second:80",
                "ALL_PROXY": "socks://third:1080",
            },
        ):
            result = _get_env_proxy()
            assert result == "https://first:443"


class TestBuildSession:
    """Test build_session function."""

    def test_session_without_proxy(self):
        """Test session creation without proxy."""
        session = build_session()
        assert session is not None
        assert hasattr(session, "get")
        assert hasattr(session, "post")
        # Check curl_cffi session type
        assert "curl_cffi" in str(type(session))

    def test_session_with_proxy(self):
        """Test session creation with proxy."""
        proxy = "socks5h://localhost:1080"
        session = build_session(proxy_url=proxy)
        assert session is not None
        assert session.proxies == {"http": proxy, "https": proxy}

    def test_session_user_agent(self):
        """Test session has user agent set."""
        session = build_session()
        assert "User-Agent" in session.headers
        assert session.headers["User-Agent"]  # Should not be empty

    def test_session_max_pool_size_param(self):
        """Test max_pool_size parameter is accepted (for compatibility)."""
        # Should not raise even though curl_cffi handles pooling internally
        session = build_session(max_pool_size=10)
        assert session is not None


class TestFetchData:
    """Test fetch_data function."""

    @patch("fetchers.fetcher.build_session")
    def test_fetch_success(self, mock_build_session):
        """Test successful fetch."""
        mock_session = MagicMock()
        mock_session.get.return_value.text = "test content"
        mock_session.get.return_value.raise_for_status = MagicMock()
        mock_build_session.return_value = mock_session

        result = fetch_data("https://example.com/config.txt")

        assert result.text == "test content"
        assert result.success is True
        mock_session.get.assert_called_once()

    @patch("fetchers.fetcher.build_session")
    def test_fetch_with_custom_timeout(self, mock_build_session):
        """Test fetch with custom timeout."""
        mock_session = MagicMock()
        mock_session.get.return_value.text = "content"
        mock_session.get.return_value.raise_for_status = MagicMock()
        mock_build_session.return_value = mock_session

        fetch_data("https://example.com", timeout=15)

        call_kwargs = mock_session.get.call_args[1]
        assert call_kwargs["timeout"] == 15

    @patch("fetchers.fetcher.build_session")
    def test_fetch_retry_logic(self, mock_build_session):
        """Test retry on failure."""
        mock_session = MagicMock()
        # First two calls fail, third succeeds
        mock_session.get.side_effect = [
            ConnectionError("timeout"),
            ConnectionError("connection error"),
            MagicMock(text="success", raise_for_status=MagicMock()),
        ]
        mock_build_session.return_value = mock_session

        result = fetch_data("https://example.com", max_attempts=3)

        assert result.text == "success"
        assert result.success is True
        assert mock_session.get.call_count == 3

    @patch("fetchers.fetcher.build_session")
    def test_fetch_all_retries_fail(self, mock_build_session):
        """Test when all retries fail."""
        mock_session = MagicMock()
        mock_session.get.side_effect = ConnectionError("permanent error")
        mock_build_session.return_value = mock_session

        result = fetch_data("https://example.com", max_attempts=3, timeout=1)
        assert result.success is False
        assert result.text == ""

    @patch("fetchers.fetcher.build_session")
    def test_zero_attempts_returns_a_failed_result_not_none(self, mock_build_session):
        """`max_attempts=0` skips the retry loop entirely.

        The function is declared to return a FetchResult, and every caller reads
        `.success` off it — returning None from here turns a bad argument into an
        AttributeError inside the caller instead of a reported fetch failure.
        """
        mock_build_session.return_value = MagicMock()

        result = fetch_data("https://example.com", max_attempts=0)

        assert result is not None
        assert result.success is False
        assert result.text == ""

    @patch("fetchers.fetcher._get_env_proxy")
    @patch("fetchers.fetcher.build_session")
    def test_fetch_uses_proxy_from_env(self, mock_build_session, mock_get_env):
        """Test fetch uses proxy from environment."""
        mock_get_env.return_value = "socks5://env-proxy:1080"
        mock_session = MagicMock()
        mock_session.get.return_value.text = "content"
        mock_session.get.return_value.raise_for_status = MagicMock()
        mock_build_session.return_value = mock_session

        fetch_data("https://example.com", proxy_url=None)

        # Should call build_session with proxy from env
        mock_build_session.assert_called()
        call_args = mock_build_session.call_args[1]
        assert call_args["proxy_url"] == "socks5://env-proxy:1080"


class _ClientError(Exception):
    """The shape both HTTP clients raise when a request fails.

    The status is read off the exception or off the response it carries, and it
    is not guaranteed to be an `int` — that is what the guard under test is for.
    """

    def __init__(self, status: object = None, *, on_response: bool = False) -> None:
        super().__init__("request failed")
        if on_response:
            self.response = SimpleNamespace(status_code=status)
        else:
            self.status_code = status


class TestExtractStatus:
    """`_extract_status` maps what a client reports onto the module's own status."""

    def test_a_status_that_is_not_an_int_on_the_exception_is_the_unknown_sentinel(self):
        """A status the client reports as a string is not a status this module knows.

        `0` is the sentinel the field defaults to on `FetchResult`, and the value
        is declared `int`: a caller comparing the number must not receive `"500"`
        and turn a reported failure into a type error.
        """
        assert _extract_status(_ClientError("500")) == 0

    def test_a_status_that_is_not_an_int_on_the_response_is_the_unknown_sentinel(self):
        """The response it carries goes through the same validation."""
        assert _extract_status(_ClientError("500", on_response=True)) == 0

    def test_an_int_status_still_passes_through(self):
        """The sentinel is for the unusable value, not for the whole path."""
        assert _extract_status(_ClientError(503)) == 503
        assert _extract_status(_ClientError(503, on_response=True)) == 503


class TestFetchViaApiBody:
    """What `_fetch_via_api` hands back for the body it received."""

    RAW_URL = "https://raw.githubusercontent.com/example/example/main/config.txt"

    @staticmethod
    def _session_returning(body: object) -> MagicMock:
        """A session that answers the metadata call, then the raw re-fetch.

        A file over 1 MB makes `_fetch_via_api` ask for the body with the raw
        media type, which is the call whose `.text` is under test.
        """
        metadata = MagicMock(status_code=200)
        metadata.json.return_value = {"size": 2_000_000}
        raw = MagicMock(status_code=200)
        raw.text = body
        session = MagicMock()
        session.get.side_effect = [metadata, raw]
        return session

    def test_a_body_that_is_not_a_str_yields_none(self):
        """The large-file path returns `.text` verbatim, so it has to be text.

        A client answering with bytes would otherwise hand the caller an object
        the rest of the pipeline treats as a subscription body.
        """
        session = self._session_returning(b"vless://example")

        assert _fetch_via_api(self.RAW_URL, session=session) is None

    def test_a_body_that_is_a_str_is_returned(self):
        """The guard rejects the unusable body, not the whole path."""
        session = self._session_returning("vless://example")

        assert _fetch_via_api(self.RAW_URL, session=session) == "vless://example"


class TestRetryLadder:
    """The three attempts, as the security posture left them.

    The ladder is load-bearing: it exists because the network this pipeline runs
    on interferes with TLS, and tightening it by accident is the one change that
    would break the product. These pin the order, the URL each attempt uses and
    which of them skips verification, so a future edit that looks like a
    simplification fails here instead of in production.
    """

    def test_the_second_attempt_skips_certificate_verification(self):
        """Attempt 2 keeps the URL and drops `verify` — as it always did."""
        session = _session(ConnectionError("blocked"), _response())

        result = fetch_data(CONFIG_URL, session=session)

        assert result.success is True
        first, second = session.get.call_args_list
        assert first.kwargs["verify"] is True
        assert second.kwargs["verify"] is False
        assert second.args[0] == CONFIG_URL

    def test_the_third_attempt_goes_plaintext_when_the_url_is_https(self):
        """Attempt 3 rewrites https to http — the DPI workaround, unchanged."""
        session = _session(
            ConnectionError("blocked"),
            ConnectionError("blocked"),
            _response(url=PLAINTEXT_CONFIG_URL),
        )

        result = fetch_data(CONFIG_URL, session=session)

        assert result.success is True
        third = session.get.call_args_list[2]
        assert third.args[0] == PLAINTEXT_CONFIG_URL
        assert third.kwargs["verify"] is False

    def test_the_third_attempt_keeps_a_plaintext_url_as_it_is(self):
        """An http URL has no scheme to downgrade; the attempt is just attempt 2."""
        session = _session(
            ConnectionError("blocked"),
            ConnectionError("blocked"),
            _response(url=PLAINTEXT_CONFIG_URL),
        )

        result = fetch_data(PLAINTEXT_CONFIG_URL, session=session)

        assert result.success is True
        assert session.get.call_args_list[2].args[0] == PLAINTEXT_CONFIG_URL

    def test_an_attempt_past_the_third_is_verified_again(self):
        """The loop resets `verify` per attempt; a fourth try is not insecure."""
        session = _session(
            ConnectionError("blocked"),
            ConnectionError("blocked"),
            ConnectionError("blocked"),
            _response(),
        )

        result = fetch_data(CONFIG_URL, session=session, max_attempts=4)

        assert result.success is True
        fourth = session.get.call_args_list[3]
        assert fourth.args[0] == CONFIG_URL
        assert fourth.kwargs["verify"] is True


class TestAttemptModes:
    """The two rules of the ladder that are not obvious from the call site."""

    def test_the_third_attempt_is_only_a_downgrade_for_an_https_url(self):
        """An http URL is not "downgraded" by attempt 3 — it was never encrypted."""
        assert _attempt_mode(2, CONFIG_URL) == "unverified"
        assert _attempt_mode(2, PLAINTEXT_CONFIG_URL) == "unverified"
        assert _attempt_mode(3, CONFIG_URL) == "plaintext"
        assert _attempt_mode(3, PLAINTEXT_CONFIG_URL) == "unverified"

    def test_later_attempts_are_verified_again(self):
        """`max_attempts` can go to 5; only 2 and 3 are insecure."""
        assert _attempt_mode(1, CONFIG_URL) == "verified"
        assert _attempt_mode(4, CONFIG_URL) == "verified"
        assert _attempt_mode(5, CONFIG_URL) == "verified"


class TestDowngradeObservability:
    """What a run's log says about a downgrade, and what the run counts.

    A downgrade that nothing reports is the defect these replaced: the ladder
    was documented in a docstring and invisible in the output, so a run in which
    every source was fetched without certificate validation read exactly like a
    clean one.
    """

    def test_the_unverified_attempt_is_logged_with_its_host_and_attempt(self):
        """The line names the host and the attempt, not just the condition."""
        session = _session(ConnectionError("blocked"), _response())

        with patch.object(fetcher_module, "warning") as logged:
            result = fetch_data(CONFIG_URL, session=session)

        assert result.success is True
        messages = [call.args[0] for call in logged.call_args_list]
        assert any(
            "attempt 2" in message
            and "example.com" in message
            and "without TLS certificate verification" in message
            for message in messages
        ), messages

    def test_the_plaintext_attempt_is_logged_as_plaintext(self):
        """Attempt 3 says what it is: the same request, in the clear."""
        session = _session(
            ConnectionError("blocked"),
            ConnectionError("blocked"),
            _response(url=PLAINTEXT_CONFIG_URL),
        )

        with patch.object(fetcher_module, "warning") as logged:
            fetch_data(CONFIG_URL, session=session)

        messages = [call.args[0] for call in logged.call_args_list]
        assert any(
            "attempt 3" in message and "plaintext HTTP" in message and "example.com" in message
            for message in messages
        ), messages

    def test_a_verified_fetch_logs_nothing_and_counts_nothing(self):
        """The loud path has to stay quiet when there is nothing to say."""
        session = _session(_response())

        with patch.object(fetcher_module, "warning") as logged:
            result = fetch_data(CONFIG_URL, session=session)

        assert result.success is True
        assert logged.call_args_list == []
        assert INSECURE_FETCHES.snapshot().attempts == 0

    def test_the_counter_tracks_attempts_and_hosts_separately(self):
        """Two hosts, three downgraded attempts: the report needs both numbers."""
        fetch_data("https://a.example/config.txt", session=_failing_session(), max_attempts=3)
        fetch_data("https://b.example/config.txt", session=_failing_session(), max_attempts=2)

        stats = INSECURE_FETCHES.snapshot()

        assert stats.attempts == 3
        assert stats.unverified_attempts == 2
        assert stats.plaintext_attempts == 1
        assert stats.hosts_affected == 2
        assert stats.unverified_hosts == ("a.example", "b.example")
        assert stats.plaintext_hosts == ("a.example",)

    def test_the_end_of_run_report_states_the_totals_and_names_the_hosts(self):
        """The count reaches the log through the same channel as the other stats."""
        fetch_data("https://a.example/config.txt", session=_failing_session(), max_attempts=3)
        fetch_data("https://b.example/config.txt", session=_failing_session(), max_attempts=3)
        LOGS_BY_FILE.clear()

        stats = report_insecure_fetches()

        report = "\n".join(LOGS_BY_FILE[0])
        assert stats.hosts_affected == 2
        assert "[WARN] [fetch-security] 4 attempts on 2 host(s)" in report
        assert "a.example" in report
        assert "b.example" in report
        assert "plaintext HTTP: a.example" in report
        assert "unverified TLS: b.example" in report

    def test_the_end_of_run_report_says_so_when_nothing_was_downgraded(self):
        """Silence is not the same as a clean run unless the report says it."""
        LOGS_BY_FILE.clear()

        stats = report_insecure_fetches()

        assert stats.attempts == 0
        assert any("no fetch skipped TLS verification" in line for line in LOGS_BY_FILE[0]), (
            LOGS_BY_FILE[0]
        )


class TestRefuseInsecureFetch:
    """The setting an operator turns on to refuse the downgrades outright."""

    def test_the_setting_is_off_by_default(self):
        """Today's behaviour is the default; the refusal is opt-in."""
        assert fetcher_module.REFUSE_INSECURE_FETCH is False

    def test_refusing_skips_both_downgrades_and_reports_why(self):
        """Only the verified attempt is made, and the refusal is the reason."""
        session = _failing_session()

        with (
            patch.object(fetcher_module, "REFUSE_INSECURE_FETCH", True),
            patch.object(fetcher_module, "warning") as logged,
        ):
            result = fetch_data(CONFIG_URL, session=session)

        assert session.get.call_count == 1
        assert result.success is False
        assert result.text == ""
        assert "blocked" in result.error  # the transport error is kept
        assert "REFUSE_INSECURE_FETCH" in result.error
        assert INSECURE_FETCHES.snapshot().attempts == 0
        assert any("REFUSE_INSECURE_FETCH" in call.args[0] for call in logged.call_args_list), [
            call.args[0] for call in logged.call_args_list
        ]

    def test_refusing_does_not_touch_a_verified_attempt_that_works(self):
        """The setting removes the fallbacks, not the fetch."""
        session = _session(_response(text="payload"))

        with patch.object(fetcher_module, "REFUSE_INSECURE_FETCH", True):
            result = fetch_data(CONFIG_URL, session=session)

        assert result.success is True
        assert result.text == "payload"
        assert session.get.call_count == 1
        assert session.get.call_args.kwargs["verify"] is True


class TestTlsWarningScope:
    """The one warning filter this module installs, and how far it reaches."""

    def test_no_process_wide_ignore_for_the_client_warning_is_installed(self):
        """The regression guard for the defect this replaced.

        The filter used to be installed at import time, so it was present in the
        process's filter list whenever any code warned — not only around the
        call that needed it. Nothing else in the process suppresses this
        message, so an entry matching it while no fetch is running is the leak.
        """
        leaked = [
            entry
            for entry in warnings.filters
            if entry[0] == "ignore" and entry[1] and "Unverified HTTPS" in entry[1].pattern
        ]

        assert leaked == []

    def test_the_client_warning_is_silenced_inside_the_call_and_seen_outside_it(self):
        """The same message is suppressed in the call and reported after it."""
        calls = {"n": 0}

        def get(url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("blocked")
            warnings.warn(
                "Unverified HTTPS request is being made to host 'example.com'.",
                UserWarning,
                stacklevel=2,
            )
            return _response()

        session = MagicMock()
        session.get.side_effect = get

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = fetch_data(CONFIG_URL, session=session)
            warnings.warn(
                "Unverified HTTPS request is being made to host 'outside'.",
                UserWarning,
                stacklevel=2,
            )

        assert result.success is True
        messages = [str(entry.message) for entry in caught]
        assert not any("'example.com'" in message for message in messages), messages
        assert any("'outside'" in message for message in messages), messages

    def test_a_verified_call_silences_nothing(self):
        """A verified request never enters the suppressing branch."""

        def get(url, **kwargs):
            warnings.warn(
                "Unverified HTTPS request is being made to host 'example.com'.",
                UserWarning,
                stacklevel=2,
            )
            return _response()

        session = MagicMock()
        session.get.side_effect = get

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            fetch_data(CONFIG_URL, session=session)

        assert len(caught) == 1
