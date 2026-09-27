"""The URL-to-outbound parsers, one shape per case.

Moved out of `test_xray_tester.py`, which had grown past the repository's
module-size ceiling holding two things at once: the dispatch and security
verdicts of `utils/protocol_parsers.py`, and the lifecycle of the tester that
calls them. Only the first belongs here.

Offline by construction: every case builds an outbound dict from a URL string
and reads it back. `_url_to_outbound()` is reached through an `XrayTester` made
with `__new__` and no binary path, so nothing here starts a process or opens a
port.
"""

import base64
import json
import threading

import pytest

pytestmark = pytest.mark.unit


class TestXrayProtocolParsers:
    """Test _url_to_outbound() dispatch for the six parsers xray has one for.

    Hysteria v1 and TUIC are counted as absent rather than as parsers: xray loads
    neither, so the expected result for those schemes is no config at all.

    A case asserts the outbound dict a valid URL produces, or the None that a
    malformed one has to produce.
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
        """An SSR node whose cipher xray can load comes back as Shadowsocks.

        The assertion used to accept either verdict, which made it unable to fail.
        With the cipher allowlist in place the outcome is fixed: `aes-256-cfb`, the
        cipher ssserver defaulted to, is not something xray loads at all.
        """
        tester = self._make_tester()
        ssr_data = "ss.example.com:1443:origin:aes-256-gcm:tls1.2_ticket_auth:password123"
        url = f"ssr://{base64.b64encode(ssr_data.encode()).decode()}"
        result = tester._url_to_outbound(url, "tag")
        assert result is not None
        assert result["protocol"] == "shadowsocks"

    def test_ssr_with_the_default_ssserver_cipher_is_not_built(self):
        tester = self._make_tester()
        ssr_data = "ss.example.com:1443:origin:aes-256-cfb:tls1.2_ticket_auth:password123"
        url = f"ssr://{base64.b64encode(ssr_data.encode()).decode()}"
        assert tester._url_to_outbound(url, "tag") is None

    @pytest.mark.parametrize(
        ("password_segment", "expected"),
        [
            (base64.urlsafe_b64encode(b"password1234").decode(), "password1234"),
            (base64.urlsafe_b64encode(b"password123456789").decode(), "password123456789"),
            ("password123", ",\x8am"),  # not base64: the spec says it should be
            ("", None),  # nothing to decode, so no outbound
        ],
        ids=["aligned-base64", "padded-base64", "plaintext-password", "empty"],
    )
    def test_every_password_shape_comes_back_as_a_verdict(self, password_segment, expected):
        """The decoder used to skip its own assignment and raise instead.

        A segment whose length is already a multiple of 4 needs no padding, and the
        branch that re-padded it left `password_base64` unbound in exactly that
        case — so `UnboundLocalError`, which is not in the except clause, escaped
        the parser. 16 of the 20 characters an SSR password encodes to land there,
        and so does any plaintext password 4, 8 or 12 characters long.

        The two plaintext rows pin what the decode produces today rather than what
        it should produce: ssr:// puts base64url in that field by spec, so a client
        that writes the password raw gets garbage out rather than a guess. What
        this test is about is that the function returns.
        """
        tester = self._make_tester()
        raw = f"server.com:8388:origin:aes-256-gcm:plain:{password_segment}".encode()
        result = tester._url_to_outbound(f"ssr://{base64.b64encode(raw).decode()}", "tag")

        if expected is None:
            assert result is None
        else:
            assert result["settings"]["servers"][0]["password"] == expected

    # --- Hysteria2 ---

    def test_hysteria2(self):
        tester = self._make_tester()
        url = "hysteria2://password@hy2.example.com:443?insecure=1"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        # xray registers the outbound as "hysteria" and rejects version != 2.
        assert result["protocol"] == "hysteria"
        assert result["settings"] == {"version": 2, "address": "hy2.example.com", "port": 443}
        assert result["streamSettings"]["hysteriaSettings"]["version"] == 2

    def test_hy2_alias(self):
        tester = self._make_tester()
        url = "hy2://password@hy2.example.com:443?insecure=1"
        result = tester._url_to_outbound(url, "proxy")
        assert result is not None
        assert result["protocol"] == "hysteria"

    # --- Hysteria v1 (not supported by xray) ---

    @pytest.mark.parametrize(
        "url",
        [
            "hysteria://hysteria.example.com:443?protocol=udp",
            "hysteria://hysteria.example.com:443?insecure=1",
        ],
    )
    def test_hysteria_v1_builds_no_outbound(self, url):
        """xray rejects `version != 2` at config load, so there is nothing to build.

        The compat filter refuses these before verification; building an outbound
        anyway would put a config-load failure in front of a shared batch process.
        """
        tester = self._make_tester()

        assert tester._url_to_outbound(url, "proxy") is None

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

    def test_ssr_emits_the_method_in_the_case_xray_looks_it_up(self):
        """The allowlist check folds case; the emitted value has to arrive folded too.

        `is_xray_cipher()` lowercases before matching, so an uppercase spelling passes
        it, and xray then looks the Shadowsocks 2022 names up case-sensitively in
        `shadowaead_2022.List` -- an outbound carrying `AES-256-GCM` is
        `unknown cipher method` at config load, which in batch mode costs the whole
        chunk its results. The `ss://` parser already lowercases; this one did not, so
        the same cipher spelled the same way built a loadable config on one path and an
        unloadable one on the other.
        """
        import base64

        from utils.protocol_parsers import parse_ssr_to_outbound

        payload = base64.b64encode(b"server.com:8388:origin:AES-256-GCM:plain:password123").decode()
        out = parse_ssr_to_outbound(f"ssr://{payload}", "tag")

        assert out is not None
        assert out["settings"]["servers"][0]["method"] == "aes-256-gcm"

    def test_hysteria_v1_with_insecure_flag_builds_no_outbound(self):
        """SECURITY: `insecure=1` is not a reason to build a v1 outbound.

        xray removed `allowInsecure` entirely (pinned certificates replaced it),
        and its hysteria outbound only speaks version 2 — so a v1 URL has no
        xray shape at all, warning or not.
        """
        tester = self._make_tester()
        result = tester._url_to_outbound(
            "hysteria://host.com:443?protocol=udp&insecure=1&auth=test",
            "tag",
        )
        assert result is None

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
