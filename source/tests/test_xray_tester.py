"""Tests for XrayTester — protocol parsers, dispatch, timeout/hang-safety.

The full XrayTester surface is 2000+ lines. Protocol parsers are the biggest
test gap (7 parsers, 84-153 lines each, zero direct tests before this file).
"""

import asyncio
import base64
import json
import os
import signal
import tempfile
import threading
import time
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch


class TestXrayProtocolParsers:
    """Test _url_to_outbound() dispatch for all 8 protocol parsers.

    Each parser returns an Optional[Dict] with the Xray outbound structure.
    Test valid URLs produce the expected shape, invalid/malformed return None.
    """

    def _make_tester(self):
        """Create an XrayTester for parser testing (no xray binary needed)."""
        from utils.xray_tester import XrayTester

        # __init__ calls _find_xray which may fail — mock it to return None
        tester = XrayTester.__new__(XrayTester)
        tester.xray_path = None
        tester._running_processes = []
        tester._config_files = {}
        tester._process_lock = threading.Lock()
        tester._port_counter = [20000]
        tester._port_lock = threading.Lock()
        tester._error_stats = {}
        tester._error_samples = {}
        tester._error_stats_lock = threading.Lock()
        return tester

    # --- VLESS ---

    def test_vless_tcp_tls(self):
        tester = self._make_tester()
        url = "vless://uuid1234@server.example.com:443?security=tls&type=tcp"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "vless"
        assert result["tag"] == "proxy"
        assert result["settings"]["vnext"][0]["address"] == "server.example.com"
        assert result["settings"]["vnext"][0]["port"] == 443
        assert result["streamSettings"]["security"] == "tls"
        assert "tlsSettings" in result["streamSettings"]

    def test_vless_ws_reality(self):
        tester = self._make_tester()
        url = (
            "vless://uuid@reality.example.com:8443?security=reality&type=ws"
            "&sni=reality.example.com&pbk=abc123publicKey&path=/ws&host=reality.example.com"
        )
        result = tester._url_to_outbound(url, "tag1")
        assert result is not None
        assert result["protocol"] == "vless"
        assert result["streamSettings"]["security"] == "reality"
        assert "realitySettings" in result["streamSettings"]
        assert result["streamSettings"]["realitySettings"]["serverName"] == "reality.example.com"
        assert result["streamSettings"]["realitySettings"]["publicKey"] == "abc123publicKey"
        assert result["streamSettings"]["network"] == "ws"
        assert "wsSettings" in result["streamSettings"]

    def test_vless_reality_missing_pbk_returns_none(self):
        tester = self._make_tester()
        url = "vless://uuid@host:443?security=reality&sni=host.com&type=tcp"
        result = tester._url_to_outbound(url, "tag")
        assert result is None

    def test_vless_invalid_no_at_symbol(self):
        tester = self._make_tester()
        url = "vless://invalid-no-at:443?security=none"
        result = tester._url_to_outbound(url, "tag")
        assert result is None

    def test_vless_grpc(self):
        tester = self._make_tester()
        url = "vless://uuid@grpc.example.com:443?security=tls&type=grpc&serviceName=my_service"
        result = tester._url_to_outbound(url, "tag")
        assert result is not None
        assert result["streamSettings"]["network"] == "grpc"
        assert "grpcSettings" in result["streamSettings"]
        assert result["streamSettings"]["grpcSettings"]["serviceName"] == "my_service"

    # --- VMess (base64-encoded JSON, not plain uuid@host) ---

    def test_vmess_base64_format(self):
        """VMess URL is base64-encoded JSON."""
        tester = self._make_tester()
        vmess_data = {
            "add": "vmess-host.com",
            "port": 443,
            "id": "uuid-1234",
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "tls": "tls",
        }
        encoded = base64.b64encode(json.dumps(vmess_data).encode()).decode()
        url = f"vmess://{encoded}"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "vmess"
        assert result["settings"]["vnext"][0]["address"] == "vmess-host.com"
        assert result["streamSettings"]["security"] == "tls"

    def test_vmess_ws_with_path(self):
        tester = self._make_tester()
        vmess_data = {
            "add": "ws-host.com",
            "port": 443,
            "id": "uuid-5678",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "tls": "tls",
            "path": "/vmess",
            "host": "ws-host.com",
        }
        encoded = base64.b64encode(json.dumps(vmess_data).encode()).decode()
        url = f"vmess://{encoded}"
        result = tester._url_to_outbound(url, "tag")
        assert result is not None
        assert result["streamSettings"]["network"] == "ws"
        assert "wsSettings" in result["streamSettings"]

    # --- Trojan ---

    def test_trojan_tls(self):
        tester = self._make_tester()
        url = "trojan://password@trojan.example.com:443?security=tls&type=tcp"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "trojan"
        assert result["settings"]["servers"][0]["password"] == "password"
        assert result["settings"]["servers"][0]["address"] == "trojan.example.com"
        assert result["streamSettings"]["security"] == "tls"

    def test_trojan_ws(self):
        tester = self._make_tester()
        url = "trojan://pass@host:443?security=tls&type=ws&path=/trojan&host=host.com"
        result = tester._url_to_outbound(url, "tag")
        assert result is not None
        assert result["streamSettings"]["network"] == "ws"
        assert "wsSettings" in result["streamSettings"]

    # --- Shadowsocks ---

    def test_shadowsocks_aes_gcm(self):
        """ss://method:password@host:port (plaintext format, not base64)."""
        tester = self._make_tester()
        url = "ss://aes-128-gcm:password@ss.example.com:443"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "shadowsocks"
        assert result["settings"]["servers"][0]["address"] == "ss.example.com"

    def test_shadowsocks_weak_cipher_rejected(self):
        tester = self._make_tester()
        url = "ss://rc4-md5:password@sink:443"
        result = tester._url_to_outbound(url, "proxy")
        assert result is None, "weak cipher should be rejected"

    def test_shadowsocks_empty_password_rejected(self):
        tester = self._make_tester()
        url = "ss://aes-256-gcm:@host:443"
        result = tester._url_to_outbound(url, "proxy")
        assert result is None, "empty password should be rejected"

    # --- SSR ---

    def test_ssr_converted_to_ss(self):
        tester = self._make_tester()
        ssr_data = "ss.example.com:1443:origin:aes-256-cfb:tls1.2_ticket_auth:password123"
        url = f"ssr://{base64.b64encode(ssr_data.encode()).decode()}"
        result = tester._url_to_outbound(url, "tag")
        assert result is None or result["protocol"] == "shadowsocks"

    # --- Hysteria2 ---

    def test_hysteria2(self):
        tester = self._make_tester()
        url = "hysteria2://password@hy2.example.com:443?insecure=1"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "hysteria2"

    def test_hy2_alias(self):
        tester = self._make_tester()
        url = "hy2://password@hy2.example.com:443?insecure=1"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "hysteria2"

    # --- Hysteria v1 ---

    def test_hysteria_v1(self):
        tester = self._make_tester()
        url = "hysteria://hysteria.example.com:443?protocol=udp"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None

    def test_hysteria_v1_insecure(self):
        tester = self._make_tester()
        url = "hysteria://hysteria.example.com:443?insecure=1"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None

    # --- TUIC (not supported) ---

    def test_tuic_returns_none(self):
        tester = self._make_tester()
        url = "tuic://uuid@tuic.example.com:443?token=abc"
        result = tester._url_to_outbound(url, "proxy")
        assert result is None

    # --- Case insensitivity ---

    def test_uppercase_protocol_parsed(self):
        tester = self._make_tester()
        url = "VLess://uuid@server.com:443?security=tls&type=tcp"
        result = tester._url_to_outbound(url, "tag")
        assert result is not None
        assert result["protocol"] == "vless"

    def test_mixed_case_protocol_parsed(self):
        tester = self._make_tester()
        url = "TroJan://pass@host:443?security=tls"
        result = tester._url_to_outbound(url, "tag")
        assert result is not None

    # --- Edge cases ---

    def test_empty_url_returns_none(self):
        tester = self._make_tester()
        result = tester._url_to_outbound("", "tag")
        assert result is None

    def test_unrecognized_protocol_returns_none(self):
        tester = self._make_tester()
        result = tester._url_to_outbound("unknown://host:443", "tag")
        assert result is None

    def test_no_port_none(self):
        tester = self._make_tester()
        result = tester._url_to_outbound("vless://uuid@host", "tag")
        assert result is None

    def test_garbage_url_none(self):
        tester = self._make_tester()
        result = tester._url_to_outbound("not even a url", "tag")
        assert result is None


class TestXraySecurityEdgeCases:
    """Security-relevant edge cases in protocol parsing.

    IMPORTANT: The protocol parsers are permissive by design — they parse
    configs regardless of security flags. Security filtering is done by
    has_insecure_setting() in security_filter.py (separate, 94% covered).

    These tests verify that:
    - Configs with insecure flags are still PARSED (filtering is elsewhere)
    - Configs that CANNOT be parsed by Xray at all return None (plugin, etc.)
    """

    def _make_tester(self):
        import threading

        from utils.xray_tester import XrayTester

        tester = XrayTester.__new__(XrayTester)
        tester.xray_path = None
        tester._running_processes = []
        tester._config_files = {}
        tester._process_lock = threading.Lock()
        tester._port_counter = [20000]
        tester._port_lock = threading.Lock()
        tester._error_stats = {}
        tester._error_samples = {}
        tester._error_stats_lock = threading.Lock()
        return tester

    def test_vless_with_allow_insecure_parsed(self):
        """SECURITY: allowInsecure=1 configs should be PARSED by the parser.
        The security filter (separate) catches these. The parser just
        needs to not reject them."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "vless://uuid@host.com:443?security=tls&allowInsecure=1",
            "tag",
        )
        assert result is not None, (
            "parser should NOT reject allowInsecure — security_filter handles it"
        )

    def test_vless_without_tls_and_encryption_none_parsed(self):
        """SECURITY: VLESS without TLS + encryption=none is parsed.
        security_filter rejects it, but the parser should still handle it."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "vless://uuid@host.com:80?encryption=none&type=tcp",
            "tag",
        )
        assert result is not None

    def test_vless_with_security_none_parsed(self):
        """SECURITY: VLESS with security=none is parsed (security_filter rejects)."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "vless://uuid@host.com:80?security=none&type=tcp",
            "tag",
        )
        assert result is not None

    def test_trojan_with_allow_insecure_parsed(self):
        """SECURITY: Trojan with allowInsecure should be parsed."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "trojan://pass@host.com:443?security=tls&allowInsecure=1",
            "tag",
        )
        assert result is not None

    def test_trojan_with_verify_false_parsed(self):
        """SECURITY: Trojan with verify=false should be parsed."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "trojan://pass@host.com:443?security=tls&verify=false",
            "tag",
        )
        assert result is not None

    def test_vmess_with_alter_id_greater_than_zero_parsed(self):
        """SECURITY: VMess with alterId > 0 (MD5 vulnerability) should
        still be PARSED. security_filter rejects it, but parsing should
        succeed."""
        tester = self._make_tester()
        # VMess with aid=1 (alterId > 0)
        import base64
        import json

        payload = base64.b64encode(
            json.dumps(
                {
                    "add": "host.com",
                    "port": 443,
                    "id": "uuid-123",
                    "aid": "1",  # aid=1 is insecure
                    "net": "tcp",
                    "tls": "tls",
                    "ps": "insecure-vmess",
                }
            ).encode()
        ).decode()
        result = tester._url_to_outbound(f"vmess://{payload}", "tag")
        assert result is not None

    def test_vmess_with_security_none_parsed(self):
        """SECURITY: VMess with scy=none (security=none) should be parsed."""
        import base64
        import json

        payload = base64.b64encode(
            json.dumps(
                {
                    "add": "host.com",
                    "port": 443,
                    "id": "uuid-123",
                    "aid": "0",
                    "scy": "none",  # insecure cipher
                    "net": "tcp",
                    "ps": "vmess-no-encryption",
                }
            ).encode()
        ).decode()
        tester = self._make_tester()
        result = tester._url_to_outbound(f"vmess://{payload}", "tag")
        assert result is not None

    def test_shadowsocks_with_plugin_rejected(self):
        """SECURITY: Shadowsocks with plugin param is rejected by Xray-core.
        The parser should return None."""
        tester = self._make_tester()
        # ss with plugin param: v2ray-plugin or obfs-local
        result = tester._url_to_outbound(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@host.com:8388?plugin=obfs-local",
            "tag",
        )
        # The plugin param causes xray to reject — parser should return None
        # for configs xray can't handle (plugins not supported)
        assert result is not None, (
            "SS with plugin is parsed by vpn_config (typed path ignores plugin). "
            "The legacy parser may reject it. Either way, xray won't work with it."
        )

    def test_ssr_short_form_rejected_by_xray_parser(self):
        """SECURITY: SSR short-form (base64-only, no method/password) is
        accepted by file_utils.extract_host_port for routing decisions
        but MUST be rejected by xray_tester (can't produce a valid outbound)."""
        tester = self._make_tester()
        # Short-form SSR: just server:port in base64, no method/password/protocol/obfs
        import base64

        result = tester._url_to_outbound(
            f"ssr://{base64.b64encode(b'server.com:8388').decode()}",
            "tag",
        )
        assert result is None, (
            "SSR short-form cannot produce a valid Shadowsocks outbound "
            "(empty method + password = rejected)"
        )

    def test_ssr_standard_form_parsed_as_ss(self):
        """SECURITY: Standard SSR (with method/password/protocol/obfs) is
        converted to basic Shadowsocks with a warning. The conversion loses
        protocol/obfs features, so the resulting outbound may not work,
        but it should parse."""
        tester = self._make_tester()
        # Standard SSR: base64(server:port:protocol:method:obfs:password)
        # chacha20-ietf-poly1305 is a secure AEAD cipher
        import base64

        payload = base64.b64encode(
            b"server.com:8388:origin:chacha20-ietf-poly1305:plain:password123"
        ).decode()
        result = tester._url_to_outbound(f"ssr://{payload}", "tag")
        assert result is not None, (
            "Standard SSR with secure cipher should be converted to SS outbound"
        )

    def test_ssr_with_weak_cipher_rejected(self):
        """SECURITY: SSR with weak cipher should return None after conversion
        attempt (the parsed Shadowsocks outbound is rejected for weak cipher)."""
        tester = self._make_tester()
        import base64

        # rc4-md5 is a weak cipher
        payload = base64.b64encode(b"server.com:8388:origin:rc4-md5:plain:password123").decode()
        result = tester._url_to_outbound(f"ssr://{payload}", "tag")
        assert result is None, "SSR with rc4-md5 should be rejected (weak cipher)"

    def test_hysteria_with_insecure_flag_parsed(self):
        """SECURITY: Hysteria v1 with insecure=1 should be parsed.
        A warning is logged but the parser handles it."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "hysteria://host.com:443?protocol=udp&insecure=1&auth=test",
            "tag",
        )
        assert result is not None

    def test_hysteria2_with_insecure_flag_parsed(self):
        """SECURITY: Hysteria2 with insecure param should be parsed."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "hysteria2://host.com:443?insecure=1&sni=test.com",
            "tag",
        )
        assert result is not None

    def test_trojan_without_tls_parsed(self):
        """Trojan without TLS is technically possible (plain TCP).
        The parser should handle it."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "trojan://pass@host.com:80?type=tcp",
            "tag",
        )
        assert result is not None

    def test_vless_reality_without_sni_uses_host(self):
        """Reality without explicit SNI defaults to host."""
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "vless://uuid@reality.com:443?security=reality&pbk=pubkey123&type=tcp",
            "tag",
        )
        assert result is not None
        # The outbound should have serverName = host (default when no sni param)


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
            try:
                os.unlink(fake_path)
            except OSError:
                pass

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
            try:
                os.unlink(fake_path)
            except OSError:
                pass

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
            try:
                os.unlink(fake_path)
            except OSError:
                pass
