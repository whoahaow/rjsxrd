"""The pure-logic half of `test_fetcher.py`, marked `unit`.

Every test here stubs the session and then asserts on what `fetch_data` did with
it: environment proxy resolution, the shape of the built session, the retry loop
and the error mapping. None of them builds a real HTTP client or reaches the
network, so `-m unit` selects them and an offline runner exercises them.

The regression test for `max_attempts=0` belongs here for the same reason it
exists at all: it is pure logic, and a regression test that only runs on a
machine with network is a regression test that silently stops guarding.

What stayed behind in `test_fetcher.py` is the class that actually attempts
traffic — `fetch_data` against a real URL — which self-skips when the network is
unavailable and carries the `integration` marker for that reason.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from fetchers.fetcher import _get_env_proxy, build_session, fetch_data

pytestmark = pytest.mark.unit


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
