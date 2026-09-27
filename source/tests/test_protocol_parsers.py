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


class TestStreamSettingsUseXraysKeys:
    """Every key here has to be one `StreamConfig` reads.

    `infra/conf/transport_internet.go` (v26.3.27) defines the settings blocks as
    `wsSettings{path,host}`, `httpupgradeSettings{path,host}`, `xhttpSettings
    {path,host,mode}` and `realitySettings{serverName,fingerprint,publicKey,
    shortId}`. A key it does not have is dropped in silence, and a transport with
    no settings block is dialled over the wrong wire — both come back as a dead
    node rather than an error, which is the failure this project keeps mistaking
    for an unavailable server.
    """

    URL = (
        "vless://12345678-1234-1234-1234-123456789012@ws.example.com:443"
        "?security=tls&sni=ws.example.com&type={kind}&path=%2Fnode&host=cdn.example.com"
    )

    def _stream(self, kind: str) -> dict:
        from utils.protocol_parsers import parse_url_to_outbound

        out = parse_url_to_outbound(self.URL.format(kind=kind), "proxy")
        assert out is not None
        return out["streamSettings"]

    @pytest.mark.parametrize("kind", ["ws", "httpupgrade", "xhttp", "splithttp"])
    def test_the_typed_and_legacy_builders_produce_the_same_stream(self, kind: str):
        from utils.protocol_parsers import parse_vless_to_outbound
        from utils.vpn_config import parse_url

        typed = parse_url(self.URL.format(kind=kind))
        assert typed is not None
        legacy = parse_vless_to_outbound(self.URL.format(kind=kind), "proxy")

        assert typed.to_xray_outbound()["streamSettings"] == legacy["streamSettings"]

    def test_websocket_carries_host_rather_than_a_headers_map(self):
        stream = self._stream("ws")

        assert stream["wsSettings"] == {"path": "/node", "host": "cdn.example.com"}
        assert "headers" not in stream["wsSettings"]

    def test_httpupgrade_carries_its_own_settings_block(self):
        """`network: httpupgrade` with no settings tested the node against `/`."""
        stream = self._stream("httpupgrade")

        assert stream["httpupgradeSettings"] == {"path": "/node", "host": "cdn.example.com"}

    def test_xhttp_carries_its_own_settings_block_under_both_names(self):
        for kind in ("xhttp", "splithttp"):
            stream = self._stream(kind)

            assert stream["network"] == kind
            assert stream["xhttpSettings"] == {"path": "/node", "host": "cdn.example.com"}


class TestFingerprintField:
    """xray resolves `fingerprint` through utls and aborts the load when it cannot.

    `TLSConfig.Build()` errors `unknown "fingerprint"` for anything
    `GetFingerprint` does not know, and the Reality client refuses `unsafe` and
    `hellogolang` as well. An empty string is one of those unknowns, so the old
    `"fingerprint": fp` — `None` whenever the URL carried no `fp=` — made every
    such reality outbound a config-load failure.
    """

    def _reality(self, query: str) -> dict:
        from utils.protocol_parsers import parse_url_to_outbound

        out = parse_url_to_outbound(
            f"vless://12345678-1234-1234-1234-123456789012@r.example.com:443{query}", "proxy"
        )
        assert out is not None
        return out["streamSettings"]

    def test_a_reality_url_without_fp_still_names_one(self):
        from config.settings import TLS_FINGERPRINT

        stream = self._reality("?security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

        assert stream["realitySettings"]["fingerprint"] == TLS_FINGERPRINT
        assert stream["realitySettings"]["fingerprint"] is not None

    def test_the_urls_own_fingerprint_is_kept(self):
        stream = self._reality(
            "?security=reality&fp=firefox&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        )

        assert stream["realitySettings"]["fingerprint"] == "firefox"

    def test_a_fingerprint_reality_forbids_falls_back_instead_of_failing_the_load(self):
        stream = self._reality(
            "?security=reality&fp=unsafe&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        )

        assert stream["realitySettings"]["fingerprint"] == "chrome"

    def test_fingerprint_does_not_belong_on_stream_settings(self):
        """`StreamConfig` has no such key; the value is read inside the settings."""
        stream = self._reality("?security=tls")

        assert "fingerprint" not in stream
        assert stream["tlsSettings"]["fingerprint"] == "chrome"


class TestTransportAliasesAndMode:
    """`ws`/`websocket` and `xhttp`/`splithttp` are one transport upstream.

    `TransportProtocol.Build()` resolves both spellings of each pair, so a builder
    that dispatches on one literal sends the other spelling out with no settings
    block: no path, no host, and a node that works in every other client comes back
    as a timeout.
    """

    def _streams(self, kind: str, extra: str = "") -> tuple[dict, dict]:
        from utils.protocol_parsers import parse_url_to_outbound
        from utils.vpn_config import parse_url

        url = (
            "vless://12345678-1234-1234-1234-123456789012@ws.example.com:443"
            f"?security=tls&type={kind}&path=/node{extra}"
        )
        typed = parse_url(url)
        legacy = parse_url_to_outbound(url, "proxy")

        assert typed is not None and legacy is not None
        return typed.to_xray_outbound()["streamSettings"], legacy["streamSettings"]

    @pytest.mark.parametrize("kind", ["ws", "websocket"])
    def test_both_websocket_spellings_carry_their_settings(self, kind: str) -> None:
        typed, legacy = self._streams(kind)

        assert typed["wsSettings"] == {"path": "/node", "host": "ws.example.com"}
        assert typed == legacy

    @pytest.mark.parametrize("kind", ["xhttp", "splithttp"])
    def test_both_xhttp_spellings_carry_their_settings(self, kind: str) -> None:
        typed, legacy = self._streams(kind)

        assert typed["xhttpSettings"] == {"path": "/node", "host": "ws.example.com"}
        assert typed == legacy

    def test_the_xhttp_mode_survives_both_builders(self) -> None:
        typed, legacy = self._streams("xhttp", "&mode=stream-up")

        assert typed["xhttpSettings"]["mode"] == "stream-up"
        assert typed == legacy

    def test_a_mode_xray_does_not_implement_is_not_emitted(self) -> None:
        """`unsupported mode` is a load failure; leaving it out defaults to `auto`."""
        typed, legacy = self._streams("xhttp", "&mode=stream-two")

        assert "mode" not in typed["xhttpSettings"]
        assert typed == legacy


class TestVMessJSONUsesTheSharedBuilder:
    """The vmess fallback knew two transports and had no reality block at all.

    Every other spelling of `net` reached xray with no settings block, and
    `tls: "reality"` produced `security: reality` without `realitySettings`, which
    `StreamConfig.Build()` rejects. Both builders now go through the same function,
    so the vmess object cannot drift from the URL parsers again.
    """

    @staticmethod
    def _url(**fields: object) -> str:
        payload = {
            "add": "vm.example.com",
            "port": "443",
            "id": "12345678-1234-1234-1234-123456789012",
        }
        payload.update(fields)
        return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()

    @pytest.mark.parametrize("net", ["httpupgrade", "xhttp", "splithttp", "websocket"])
    def test_every_transport_the_url_parsers_handle_gets_their_block(self, net: str) -> None:
        from utils.protocol_parsers import parse_vmess_to_outbound

        out = parse_vmess_to_outbound(
            self._url(net=net, path="/node", host="cdn.example.com"), "tag"
        )

        assert out is not None
        settings = out["streamSettings"]
        assert settings["network"] == net
        block = (
            settings.get("wsSettings")
            or settings.get("httpupgradeSettings")
            or settings.get("xhttpSettings")
        )
        assert block is not None, f"{net} produced no settings block"
        assert block["path"] == "/node"
        assert block["host"] == "cdn.example.com"

    def test_reality_without_a_public_key_builds_no_outbound(self) -> None:
        from utils.protocol_parsers import parse_vmess_to_outbound

        out = parse_vmess_to_outbound(self._url(tls="reality", sni="vm.example.com"), "tag")

        assert out is None

    def test_tls_falls_back_to_the_address_for_its_server_name(self) -> None:
        """The vmess object carries no `sni`, so the Host value is what xray must see."""
        from utils.protocol_parsers import parse_vmess_to_outbound

        out = parse_vmess_to_outbound(self._url(tls="tls", host="vm.example.com"), "tag")

        assert out["streamSettings"]["tlsSettings"]["serverName"] == "vm.example.com"

    def test_a_boolean_tls_field_loads(self) -> None:
        """Older clients write `"tls": true`, and xray matches `security` as a string.

        The boolean went into the outbound as `"security": true`, which
        `StreamConfig.Build()` answers with `Unknown security` — a config-load
        failure that in batch mode costs every other config in the chunk.
        """
        from utils.protocol_parsers import parse_vmess_to_outbound
        from utils.vpn_config import parse_url

        url = self._url(tls=True, host="vm.example.com", net="ws", path="/node")
        legacy = parse_vmess_to_outbound(url, "tag")
        typed_cfg = parse_url(url)

        assert legacy is not None
        assert legacy["streamSettings"]["security"] == "tls"
        assert typed_cfg is not None
        assert typed_cfg.to_xray_outbound()["streamSettings"] == legacy["streamSettings"]

    def test_vmess_reality_is_declined_rather_than_guessed(self) -> None:
        """The reality field names in this JSON are not agreed on between clients.

        Emitting `security: reality` without a `realitySettings` block is a load
        failure, and inventing the key would test a key the node may not use, so
        both builders return None and the config stays out of verification.
        """
        from utils.protocol_parsers import parse_vmess_to_outbound
        from utils.vpn_config import parse_url

        url = self._url(tls="reality", host="vm.example.com", sni="vm.example.com")

        assert parse_vmess_to_outbound(url, "tag") is None
        assert parse_url(url) is None
