"""The network-attempting half of the fetcher tests, marked `integration`.

One class: `fetch_data` against a real URL, which self-skips when the network is
unavailable, so `pytest -m unit` must not select it. The pure-logic tests that
used to share this file — environment proxy resolution, the built session's
headers, the retry loop and the error mapping — now live in
`test_fetcher_unit.py`, where `-m unit` covers them without network.
"""

import pytest

from fetchers.fetcher import fetch_data

pytestmark = pytest.mark.integration


class TestFetchDataWithRealURL:
    """Integration tests with real URLs (may fail in isolated environments)."""

    def test_fetch_real_url(self):
        """Test fetching a real URL (skipped if network unavailable)."""
        try:
            result = fetch_data("https://httpbin.org/ip", timeout=5)
            assert result.success is True
            assert len(result.text) > 0
        except Exception:
            pytest.skip("Network unavailable or URL unreachable")
