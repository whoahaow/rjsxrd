"""Tests for SimpleTester and extract_host_port."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from utils.file_utils import extract_host_port


class TestExtractHostPort:
    """Test extract_host_port for all protocol types."""

    def test_vless(self):
        hp = extract_host_port("vless://uuid@server.com:443?security=tls")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443

    def test_vmess_base64_json(self):
        hp = extract_host_port(
            "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkIn0="
        )
        assert hp is not None
        assert hp[0] == "example.com"
        assert hp[1] == 443

    def test_vmess_without_host(self):
        hp = extract_host_port("vmess://eyJwb3J0Ijo0NDMsImlkIjoidXVpZCJ9")
        assert hp is None

    def test_trojan(self):
        hp = extract_host_port("trojan://pass@server.com:443?security=tls")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443

    def test_shadowsocks(self):
        hp = extract_host_port("ss://YWVzLTI1Ni1nY206cGFzcw==@server.com:8388")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 8388

    def test_ssr(self):
        hp = extract_host_port(
            "ssr://c2VydmVyLmNvbTo4Mzg4Om9yaWdpbjphZXMtMjU2LWNmYjp0bXMxMjM6cGFzcw=="
        )
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 8388

    def test_hysteria2(self):
        hp = extract_host_port("hysteria2://pass@server.com:443?insecure=0")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443

    def test_hy2(self):
        hp = extract_host_port("hy2://pass@server.com:443")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443

    def test_hysteria(self):
        hp = extract_host_port("hysteria://pass@server.com:443")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443

    def test_tuic(self):
        hp = extract_host_port("tuic://uuid:pass@server.com:443?congestion_control=bbr")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443

    def test_invalid_no_protocol(self):
        assert extract_host_port("just some text") is None

    def test_invalid_empty(self):
        assert extract_host_port("") is None

    def test_invalid_none(self):
        assert extract_host_port(None) is None

    def test_vless_ipv6(self):
        hp = extract_host_port("vless://uuid@[::1]:443?security=tls")
        assert hp is not None
        assert hp[1] == 443

    def test_ssr_with_urlsafe_base64(self):
        hp = extract_host_port("ssr://c2VydmVyLmNvbTo0NDM")
        assert hp is not None
        assert hp[0] == "server.com"
        assert hp[1] == 443


class TestSimpleTester:
    """Test SimpleTester class with mocked internals."""

    def test_init_default_concurrency(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester()
        assert t.timeout == 3.0
        assert t.concurrency > 0

    def test_init_custom_values(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=10, timeout=5.0)
        assert t.timeout == 5.0
        assert t.concurrency == 10

    @pytest.mark.asyncio
    async def test_tcp_ping_one_success(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=10, timeout=3.0)

        async def _slow_open_connection(host, port):
            await asyncio.sleep(0.05)
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _slow_open_connection):
            sem = asyncio.Semaphore(10)
            ok, rtt = await t._tcp_ping_one("example.com", 443, sem)

        assert ok is True
        assert rtt > 0

    @pytest.mark.asyncio
    async def test_tcp_ping_one_timeout(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=10, timeout=3.0)

        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError):
            sem = asyncio.Semaphore(10)
            ok, rtt = await t._tcp_ping_one("example.com", 443, sem)

        assert ok is False
        assert rtt == 0.0

    @pytest.mark.asyncio
    async def test_tcp_ping_one_refused(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=10, timeout=3.0)

        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            sem = asyncio.Semaphore(10)
            ok, rtt = await t._tcp_ping_one("example.com", 9999, sem)

        assert ok is False
        assert rtt == 0.0

    def test_test_batch_empty(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester()
        results = t.test_batch([])
        assert results == []

    def test_test_batch_all_parse_fail(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester()
        configs = ["invalid text", "also invalid"]
        results = t.test_batch(configs)
        assert len(results) == 2
        assert all(not ok for _, ok, _ in results)

    def test_test_batch_custom_timeout(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=5)
        assert t.timeout == 3.0  # default
        t.test_batch([], timeout=7.0)
        # timeout is NOT mutated — the method uses a local effective_timeout
        assert t.timeout == 3.0, "self.timeout should not be mutated by test_batch"

    @pytest.mark.asyncio
    async def test_run_batch_sorts_by_latency(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=10, timeout=3.0)

        targets = [
            ("slow.com", 443, "vless://uuid@slow.com:443"),
            ("fast.com", 443, "vless://uuid@fast.com:443"),
        ]

        async def fake_ping(host, port, sem, timeout=None):
            if "fast" in host:
                return True, 10.0
            return True, 100.0

        with patch.object(t, "_tcp_ping_one", fake_ping):
            results = await t.run_batch_async(targets)

        assert len(results) == 2
        assert "fast.com" in results[0][0]

    def test_test_batch_mixed_success_and_failure(self):
        from utils.simple_tester import SimpleTester

        t = SimpleTester(concurrency=5, timeout=3.0)

        with patch.object(t, "run_batch_async", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = [
                ("vless://uuid@good.com:443", True, 50.0),
                ("vless://uuid@bad.com:443", False, 0.0),
            ]
            configs = ["vless://uuid@good.com:443", "vless://uuid@bad.com:443"]
            results = t.test_batch(configs)

        assert len(results) == 2
        assert results[0][1] is True
        assert results[1][1] is False
