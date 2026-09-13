"""Tests for TelegramProxyProcessor.create_proxy_files — offline, tmp_path.

Proxy entries reach the processor in two shapes: plain URL strings (unverified
input, and the shape the scraping helpers return) and ``(url, latency_ms)``
tuples (verification output). Both must produce files that contain whole URLs.
"""

from processors.telegram_proxy_processor import TelegramProxyProcessor

MTPROTO_URLS = [
    "https://t.me/proxy?server=mtproto-one.example&port=443&secret=ee1111",
    "https://t.me/proxy?server=mtproto-two.example&port=443&secret=ee2222",
]
SOCKS5_URLS = [
    "https://t.me/socks?server=socks-one.example&port=1080",
    "https://t.me/socks?server=socks-two.example&port=1080",
]


def _create_files(tmp_path, mtproto_proxies, socks5_proxies):
    """Run create_proxy_files with verification off — no network, no subprocess."""
    processor = TelegramProxyProcessor(output_dir=str(tmp_path))
    return processor.create_proxy_files(
        mtproto_proxies,
        socks5_proxies,
        verify_mtproto=False,
        verify_socks5=False,
    )


def _read(tmp_path, name):
    return (tmp_path / "tg-proxy" / name).read_text(encoding="utf-8")


class TestCreateProxyFilesPlainUrls:
    """Plain URL strings are an accepted input shape.

    Every per-type branch guards for them, so the combined all.txt must too.
    """

    def test_all_txt_contains_whole_urls(self, tmp_path):
        _create_files(tmp_path, list(MTPROTO_URLS), list(SOCKS5_URLS))

        # No latency on unverified input, so the incoming order is kept.
        assert _read(tmp_path, "all.txt").split("\n\n") == MTPROTO_URLS + SOCKS5_URLS

    def test_per_type_files_contain_whole_urls(self, tmp_path):
        _create_files(tmp_path, list(MTPROTO_URLS), list(SOCKS5_URLS))

        assert _read(tmp_path, "MTProto.txt").split("\n\n") == MTPROTO_URLS
        assert _read(tmp_path, "socks.txt").split("\n\n") == SOCKS5_URLS


class TestCreateProxyFilesLatencyTuples:
    """Verification output — (url, latency_ms) pairs — still sorts fastest first."""

    def test_entries_are_sorted_by_latency(self, tmp_path):
        slow = ("https://t.me/proxy?server=slow.example&port=443&secret=ee3333", 900.0)
        fast = ("https://t.me/proxy?server=fast.example&port=443&secret=ee4444", 10.0)

        _create_files(tmp_path, [slow, fast], [])

        assert _read(tmp_path, "MTProto.txt").split("\n\n") == [fast[0], slow[0]]
        assert _read(tmp_path, "all.txt").split("\n\n") == [fast[0], slow[0]]
