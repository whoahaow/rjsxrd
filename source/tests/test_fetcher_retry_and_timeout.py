"""Unit tests for fetch timeout wiring, raw-first GitHub fallback, and dead-URL non-retry."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
import requests
from curl_cffi.curl import CurlOpt

import config.settings as settings
import fetchers.fetcher as fetcher_module
import processors.config_processor as config_processor
from fetchers.fetcher import FetchResult, build_session, fetch_data

pytestmark = pytest.mark.unit

PUBLIC_ADDRESS = "93.184.216.34"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/example/repo/main/list.txt"


class _HttpStatusError(requests.HTTPError):
    """HTTPError carrying a response status_code for offline status tests."""

    def __init__(self, status: int) -> None:
        resp = requests.Response()
        resp.status_code = status
        super().__init__(f"HTTP Error {status}", response=resp)


@pytest.fixture(autouse=True)
def offline_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep all tests in this module offline and skip retry sleeps."""
    monkeypatch.setattr(fetcher_module, "_resolved_addresses", lambda host, port: [PUBLIC_ADDRESS])
    monkeypatch.setattr(fetcher_module.time, "sleep", lambda _seconds: None)


def _ok_response(text: str = "vless://ok", url: str = GITHUB_RAW_URL) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.status_code = 200
    resp.url = url
    resp.raise_for_status = MagicMock()
    return resp


class TestFetchTimeoutAndSessionOptions:
    """Default 90s timeout and libcurl connect/stall guardrails."""

    def test_default_fetch_timeout_is_90_and_used_by_fetch_data(self) -> None:
        assert settings.FETCH_TIMEOUT == 90
        session = MagicMock()
        session.get.return_value = _ok_response(url="https://example.com/list.txt")

        result = fetch_data("https://example.com/list.txt", session=session)

        assert result.success is True
        assert session.get.call_args.kwargs["timeout"] == 90

    def test_build_session_configures_connect_and_low_speed_options(self) -> None:
        session = build_session()
        opts = session.curl_options
        assert opts[CurlOpt.CONNECTTIMEOUT_MS] == settings.FETCH_CONNECT_TIMEOUT * 1000
        assert opts[CurlOpt.LOW_SPEED_LIMIT] == settings.FETCH_LOW_SPEED_LIMIT
        assert opts[CurlOpt.LOW_SPEED_TIME] == settings.FETCH_LOW_SPEED_TIME


class TestNonRetryableAndFallbackOrder:
    """Dead HTTP statuses fail once; GitHub API runs only after raw fails."""

    @pytest.mark.parametrize("status", [400, 401, 404, 410, 429])
    def test_dead_http_status_does_not_retry_or_hit_api_fallback(
        self, monkeypatch: pytest.MonkeyPatch, status: int
    ) -> None:
        monkeypatch.setattr(fetcher_module, "GITHUB_API_FALLBACK", True)
        session = MagicMock()
        session.get.side_effect = _HttpStatusError(status)

        result = fetch_data(GITHUB_RAW_URL, session=session, max_attempts=3)

        assert result.success is False
        assert result.status_code == status
        assert session.get.call_count == 1
        assert session.get.call_args.args[0] == GITHUB_RAW_URL

    def test_403_skips_raw_retries_but_tries_github_api_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(fetcher_module, "GITHUB_API_FALLBACK", True)
        api_resp = MagicMock(status_code=200)
        api_resp.json.return_value = {
            "content": base64.b64encode(b"vless://via-api").decode(),
            "encoding": "base64",
        }
        session = MagicMock()
        session.get.side_effect = [_HttpStatusError(403), api_resp]

        result = fetch_data(GITHUB_RAW_URL, session=session, max_attempts=3)

        assert result.success is True
        assert result.text == "vless://via-api"
        assert session.get.call_count == 2
        assert session.get.call_args_list[0].args[0] == GITHUB_RAW_URL
        assert session.get.call_args_list[1].args[0].startswith("https://api.github.com/repos/")

    def test_github_raw_runs_before_api_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fetcher_module, "GITHUB_API_FALLBACK", True)
        session = MagicMock()
        session.get.return_value = _ok_response(text="vless://from-raw")

        result = fetch_data(GITHUB_RAW_URL, session=session)

        assert result.success is True
        assert result.text == "vless://from-raw"
        assert session.get.call_count == 1
        assert session.get.call_args.args[0] == GITHUB_RAW_URL


class TestConfigProcessorFetchWiring:
    """config_processor passes FETCH_TIMEOUT and honors explicit MAX_WORKERS."""

    def test_fetch_and_process_urls_passes_fetch_timeout_and_max_workers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        monkeypatch.setenv("MAX_WORKERS", "7")
        monkeypatch.setattr(config_processor, "DEFAULT_MAX_WORKERS", 7)
        monkeypatch.setattr(config_processor, "FETCH_TIMEOUT", 90)
        seen_timeouts: list[int] = []

        def fake_fetch(url: str, **kwargs):
            seen_timeouts.append(kwargs["timeout"])
            return FetchResult(text="", status_code=200)

        with (
            patch.object(config_processor, "fetch_data", side_effect=fake_fetch),
            patch.object(
                config_processor.ExecutorCache,
                "get",
                wraps=config_processor.ExecutorCache.get,
            ) as mock_exec,
        ):
            urls = [f"https://example.com/{i}.txt" for i in range(10)]
            config_processor._fetch_and_process_urls(
                urls,
                target_all=[],
                target_extra=[],
                numbered_configs_with_urls=[],
                all_mtproto=[],
                all_socks5=[],
                global_seen=set(),
                global_seen_lock=threading.Lock(),
                stats=None,
                scraper=None,
            )

        assert seen_timeouts == [90] * 10
        assert mock_exec.call_args.kwargs["max_workers"] == 7
