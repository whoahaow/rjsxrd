"""Deciding whether fetched bytes are configs at all.

Two modules sniff base64 subscription content: `config_helpers.try_decode_base64_content()`
for the pipeline and `daily_repo_fetcher._decode_if_base64()` for the daily-scraper repos.
Both hold their own list of scheme markers, and a scheme missing from one of them makes a
whole feed yield nothing -- no error, just an empty source -- so the lists are pinned
against `SUPPORTED_PROTOCOLS`, the tuple the rest of the pipeline matches on.

Offline by construction: the input is a string this test encodes itself.
"""

import base64

import pytest

from utils.config_helpers import try_decode_base64_content
from utils.file_utils import SUPPORTED_PROTOCOLS

pytestmark = pytest.mark.unit


class TestSubscriptionContentIsRecognised:
    """Every published scheme has to survive the base64 sniff."""

    @pytest.mark.parametrize("scheme", SUPPORTED_PROTOCOLS)
    def test_every_published_scheme_is_recognised_after_base64(self, scheme):
        """The sniffer has to know every scheme the rest of the pipeline publishes.

        A subscription arrives base64-encoded, and this heuristic is what decides
        whether the bytes are configs at all. It listed `hysteria://` and `hy2://` but
        not `hysteria2://` -- a spelling `SUPPORTED_PROTOCOLS`, the tagger, both
        builders and `create_protocol_split_files` all accept -- so a source carrying
        only Hysteria2 nodes was never recognised and yielded nothing, with no error
        anywhere to say a whole feed had been skipped. The list is checked against
        `SUPPORTED_PROTOCOLS`, so it cannot drift again.
        """

        from fetchers.daily_repo_fetcher import _decode_if_base64

        line = f"{scheme}://token@h.example.com:443?sni=h.example.com"

        assert try_decode_base64_content(base64.b64encode(line.encode()).decode()) == line
        assert _decode_if_base64(base64.b64encode(line.encode()).decode()) == line
