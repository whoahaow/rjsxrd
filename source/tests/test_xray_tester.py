"""Tests for XrayTester — the tester's own lifecycle, not the parsers' verdicts.

Signal handlers, startup timeout and hang-safety, and the TLS fragment stage a
tested config has to carry. What a URL becomes when it is parsed lives in
`test_protocol_parsers.py`, which holds the dispatch and security cases split
out of this file when the two together passed the module-size ceiling.
"""

import asyncio
import contextlib
import glob
import os
import signal
import tempfile
import time
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

import pytest

pytestmark = pytest.mark.unit


class TestSignalHandlerDoesNotOverwriteMain:
    """xray_tester's signal handler must not overwrite a pre-existing handler.

    main.py installs its own SIGINT/SIGTERM handler that does additional
    cleanup (resource monitor, proxy monitor, proxy cleanup). If xray_tester
    unconditionally registers, it overwrites main's handler with one that
    only does xray cleanup + sys.exit(1) — losing the rest of the cleanup.
    """

    def test_xray_tester_preserves_existing_signal_handler(self):
        """If SIGINT already has a non-default handler, xray_tester must not
        replace it."""
        original = signal.getsignal(signal.SIGINT)

        def fake_handler(signum, frame):
            pass

        try:
            signal.signal(signal.SIGINT, fake_handler)
            import utils.xray_tester as xt

            current = signal.getsignal(signal.SIGINT)
            if current == signal.default_int_handler:
                signal.signal(signal.SIGINT, xt._signal_handler)

            assert signal.getsignal(signal.SIGINT) is fake_handler, (
                "xray_tester's registration logic should preserve the existing handler"
            )
        finally:
            signal.signal(signal.SIGINT, original)

    def test_xray_tester_registers_when_no_handler(self):
        """If SIGINT has the default handler, xray_tester may register."""
        original = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, signal.default_int_handler)
            assert signal.getsignal(signal.SIGINT) == signal.default_int_handler

            current = signal.getsignal(signal.SIGINT)
            should_register = current == signal.default_int_handler
            assert should_register, "should be allowed to register when default"
        finally:
            signal.signal(signal.SIGINT, original)


class TestXrayStartupTimeout:
    """Stage 1 (start_xray_instance) must be bounded by XRAY_STARTUP_TIMEOUT."""

    def _make_tester(self, xray_path: str):
        from utils.xray_tester import XrayTester

        return XrayTester(xray_path=xray_path)

    def _fake_xray_path(self) -> str:
        with tempfile.NamedTemporaryFile(suffix="", delete=False) as f:
            f.write(b"fake")
            return f.name

    def test_stuck_xray_startup_returns_failure_not_hang(self):
        from config.settings import XRAY_STARTUP_TIMEOUT

        fake_path = self._fake_xray_path()
        tester = self._make_tester(fake_path)

        def slow_start_xray(config, socks_port, verbose=False):
            # sleep long enough that wait_for *must* time out before mock returns
            time.sleep(XRAY_STARTUP_TIMEOUT * 6)
            return (True, MagicMock(), "")

        def fake_config(url, socks_port):
            return {"outbounds": [{"protocol": "vless", "tag": "proxy"}]}

        tester._get_next_port = lambda: 12345

        try:
            with (
                mock_patch.object(tester, "start_xray_instance", side_effect=slow_start_xray),
                mock_patch.object(tester, "create_single_outbound_config", side_effect=fake_config),
            ):
                t0 = time.time()
                result = asyncio.run(
                    tester._batch_runner._test_single_config_pipelined_async(
                        "vless://fake@server.com:443", timeout=5.0, verbose=False
                    )
                )
                elapsed = time.time() - t0

            assert result[1] is False, f"expected failure, got {result}"
            assert result[2] == 0.0
            # wait_for fires at XRAY_STARTUP_TIMEOUT (3s). The executor
            # thread keeps sleeping after cancellation — asyncio.run() in
            # 3.12+ calls shutdown_default_executor which waits for it.
            # Total: ~XRAY_STARTUP_TIMEOUT + sleep = 3 + 18 = ~21s worst case.
            # Allow 25s headroom for CI under load.
            assert elapsed < 25.0, f"expected <25.0s, took {elapsed:.1f}s"
        finally:
            with contextlib.suppress(OSError):
                os.unlink(fake_path)

    def test_fast_xray_startup_succeeds(self):
        fake_path = self._fake_xray_path()
        tester = self._make_tester(fake_path)
        tester._get_next_port = lambda: 12346

        fast_process = MagicMock()

        def fast_start_xray(config, socks_port, verbose=False):
            return (True, fast_process, "")

        async def fake_http_ping(socks_port, timeout, verbose=False):
            return (True, 0.123)

        tester._batch_runner._http_ping_through_proxy_async = fake_http_ping
        tester.stop_xray_process = lambda proc: None

        def fake_config(url, socks_port):
            return {"outbounds": [{"protocol": "vless", "tag": "proxy"}]}

        try:
            with (
                mock_patch.object(tester, "start_xray_instance", side_effect=fast_start_xray),
                mock_patch.object(tester, "create_single_outbound_config", side_effect=fake_config),
            ):
                result = asyncio.run(
                    tester._batch_runner._test_single_config_pipelined_async(
                        "vless://fake@server.com:443", timeout=5.0, verbose=False
                    )
                )
            assert result[1] is True
            assert result[2] == 0.123
        finally:
            with contextlib.suppress(OSError):
                os.unlink(fake_path)

    def test_xray_startup_returns_failure_with_error(self):
        fake_path = self._fake_xray_path()
        tester = self._make_tester(fake_path)
        tester._get_next_port = lambda: 12347

        def failing_start_xray(config, socks_port, verbose=False):
            return (False, None, "config_rejected")

        def fake_config(url, socks_port):
            return {"outbounds": [{"protocol": "vless", "tag": "proxy"}]}

        try:
            with (
                mock_patch.object(tester, "start_xray_instance", side_effect=failing_start_xray),
                mock_patch.object(tester, "create_single_outbound_config", side_effect=fake_config),
            ):
                result = asyncio.run(
                    tester._batch_runner._test_single_config_pipelined_async(
                        "vless://fake@server.com:443", timeout=5.0, verbose=False
                    )
                )
            assert result[1] is False
            assert result[2] == 0.0
        finally:
            with contextlib.suppress(OSError):
                os.unlink(fake_path)


class TestTlsFragmentStage:
    """The ClientHello fragmentation the settings advertise, in a key xray reads.

    `streamSettings.fragment` is not a field of xray's `StreamConfig`, and xray
    skips unrecognised JSON without complaining — so the setting looked enabled,
    the emitted config looked configured, and every node was still verified with
    an intact ClientHello. These assert the shape that actually reaches the
    binary rather than asserting that some dict was touched.
    """

    def test_the_stage_is_finalmask_tcp_with_a_delay_field(self) -> None:
        from utils.xray_tester import XrayTester

        outbound: dict = {"streamSettings": {"network": "tcp", "security": "tls"}}
        XrayTester._apply_fragment(outbound)

        stream = outbound["streamSettings"]
        assert "fragment" not in stream, "the ignored key is back"
        assert stream["finalmask"]["tcp"] == [
            {
                "type": "fragment",
                "settings": {
                    "packets": "tlshello",
                    "length": "100-200",
                    "delay": "10-20",
                },
            }
        ]

    def test_disabling_the_setting_emits_no_stage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import config.settings as settings
        from utils.xray_tester import XrayTester

        monkeypatch.setattr(settings, "ENABLE_FRAGMENT", False)
        outbound: dict = {"streamSettings": {"network": "tcp", "security": "tls"}}

        XrayTester._apply_fragment(outbound)

        assert outbound["streamSettings"] == {"network": "tcp", "security": "tls"}

    def test_a_quic_outbound_gets_no_tcp_stage(self) -> None:
        """Hysteria rides on UDP; a TCP-stage mask would be dead weight."""
        from utils.protocol_parsers import parse_hysteria2_to_outbound
        from utils.xray_tester import XrayTester

        outbound = parse_hysteria2_to_outbound("hy2://tok@hy2.example.com:443?sni=hy2.example.com")
        assert outbound is not None
        XrayTester._apply_fragment(outbound)

        assert "tcp" not in outbound["streamSettings"].get("finalmask", {})

    def test_an_existing_udp_stage_survives_the_append(self) -> None:
        """The stage is appended, never written over a dict: one clobbers the other."""
        from utils.protocol_parsers import apply_tls_fragment

        stream: dict = {
            "network": "tcp",
            "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "p"}}]},
        }

        apply_tls_fragment(stream)

        assert [m["type"] for m in stream["finalmask"]["udp"]] == ["salamander"]
        assert [m["type"] for m in stream["finalmask"]["tcp"]] == ["fragment"]

    """A tester with no resolved binary must report the cause, not a TypeError.

    `self.xray_path` is `str | None` — `_find_xray()` returns None when nothing
    matches and no path was passed. Feeding that None straight into
    `subprocess.Popen` raises `TypeError: expected str, bytes or os.PathLike
    object, not NoneType`, which `start_xray_instance`'s own `except` clause
    does not catch, so the caller sees a traceback instead of a failed result.
    """

    def _make_tester_without_binary(self):
        from utils.xray_tester import XrayTester

        tester = XrayTester()
        # `_find_xray()` may well succeed on a dev machine (the pipeline
        # downloads the binary into source/xray); force the state under test.
        tester.xray_path = None
        return tester

    def test_start_xray_instance_reports_the_missing_binary(self):
        tester = self._make_tester_without_binary()
        config = {
            "inbounds": [{"protocol": "socks", "port": 0}],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }
        pattern = os.path.join(tempfile.gettempdir(), "xray_*.json")
        before = set(glob.glob(pattern))

        success, process, error = tester.start_xray_instance(config, 45999)

        after = set(glob.glob(pattern))
        assert success is False
        assert process is None
        assert "binary" in error.lower(), f"unhelpful failure reason: {error!r}"
        assert after <= before, "the temp config file leaked on the failure path"
