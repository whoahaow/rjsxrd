"""Tests for VPNConfig dataclass hierarchy (utils/vpn_config.py).

Tests the typed config parsers that replace the ad-hoc str->Dict parsers.
All tests are pure unit — no network, no xray binary, no subprocesses.
"""

import base64
import json

from utils.vpn_config import (
    Hysteria2Config,
    ShadowsocksConfig,
    TrojanConfig,
    VLESSConfig,
    VMessConfig,
    parse_url,
)


class TestParseUrlFactory:
    """parse_url() is the entry point — dispatches by URL scheme."""

    def test_parse_vless_url(self):
        cfg = parse_url("vless://uuid@host.com:443?security=tls&type=tcp")
        assert cfg is not None
        assert isinstance(cfg, VLESSConfig)
        assert cfg.host == "host.com"
        assert cfg.port == 443
        assert cfg.uuid == "uuid"

    def test_parse_vmess_url(self):
        payload = base64.b64encode(
            json.dumps(
                {
                    "add": "vmess-host.com",
                    "port": 443,
                    "id": "uuid-123",
                    "aid": "0",
                    "net": "ws",
                    "tls": "tls",
                    "scy": "auto",
                    "ps": "test-vmess",
                }
            ).encode()
        ).decode()
        cfg = parse_url(f"vmess://{payload}")
        assert cfg is not None
        assert isinstance(cfg, VMessConfig)
        assert cfg.host == "vmess-host.com"
        assert cfg.port == 443
        assert cfg.uuid == "uuid-123"

    def test_parse_trojan_url(self):
        cfg = parse_url("trojan://password@trojan-host.com:443?security=tls")
        assert cfg is not None
        assert isinstance(cfg, TrojanConfig)
        assert cfg.host == "trojan-host.com"
        assert cfg.password == "password"

    def test_parse_shadowsocks_url(self):
        cfg = parse_url("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss-host.com:8388")
        assert cfg is not None
        assert isinstance(cfg, ShadowsocksConfig)
        assert cfg.host == "ss-host.com"
        assert cfg.port == 8388

    def test_parse_hysteria2_url(self):
        cfg = parse_url("hysteria2://hysteria2-host.com:443?auth=secret&sni=sni.com")
        assert cfg is not None
        assert isinstance(cfg, Hysteria2Config)
        assert cfg.host == "hysteria2-host.com"
        assert cfg.auth == "secret"
        assert cfg.sni == "sni.com"

    def test_parse_hy2_alias(self):
        """'hy2://' is an alias for hysteria2."""
        cfg = parse_url("hy2://hy2-host.com:8443")
        assert cfg is not None
        assert isinstance(cfg, Hysteria2Config)
        assert cfg.host == "hy2-host.com"

    def test_parse_invalid_scheme_returns_none(self):
        assert parse_url("tuic://host:443") is None
        assert parse_url("ssr://host:443") is None
        assert parse_url("unknown://host:443") is None

    def test_parse_empty_or_malformed_returns_none(self):
        assert parse_url("") is None
        assert parse_url(None) is None  # type: ignore
        assert parse_url("not-a-url") is None
        assert parse_url("http://example.com") is None

    def test_parse_no_at_vless_returns_none(self):
        """VLESS requires uuid@host:port — reject if no @."""
        cfg = parse_url("vless://host.com:443?security=tls")
        assert cfg is None

    def test_parse_missing_host_or_port_returns_none(self):
        cfg = parse_url("vless://uuid@:443")
        assert cfg is None
        cfg = parse_url("vless://uuid@host.com")
        assert cfg is None

    def test_parse_uppercase_scheme(self):
        """Scheme matching is case-insensitive."""
        cfg = parse_url("VLESS://uuid@host.com:443?security=tls")
        assert cfg is not None
        assert isinstance(cfg, VLESSConfig)


class TestVLESSConfig:
    """VLESSConfig.to_xray_outbound()"""

    def test_tcp_tls_outbound_dict(self):
        cfg = VLESSConfig(
            host="example.com",
            port=443,
            uuid="test-uuid",
            tls=True,
            sni="sni.example.com",
            transport="tcp",
        )
        out = cfg.to_xray_outbound(tag="proxy")
        assert out is not None
        assert out["tag"] == "proxy"
        assert out["protocol"] == "vless"
        assert out["settings"]["vnext"][0]["address"] == "example.com"
        assert out["settings"]["vnext"][0]["users"][0]["id"] == "test-uuid"
        assert out["streamSettings"]["security"] == "tls"
        assert out["streamSettings"]["tlsSettings"]["serverName"] == "sni.example.com"

    def test_reality_outbound(self):
        cfg = VLESSConfig(
            host="reality.com",
            port=443,
            uuid="uuid-reality",
            tls=True,
            reality=True,
            public_key="test-pubkey",
            short_id="1234",
            sni="reality-sni.com",
        )
        out = cfg.to_xray_outbound()
        assert out is not None
        assert out["streamSettings"]["security"] == "reality"
        assert out["streamSettings"]["realitySettings"]["publicKey"] == "test-pubkey"
        assert out["streamSettings"]["realitySettings"]["shortId"] == "1234"
        assert out["streamSettings"]["realitySettings"]["fingerprint"] == "chrome"

    def test_reality_without_public_key_returns_none(self):
        """SECURITY: Reality VLESS requires publicKey — return None otherwise."""
        cfg = VLESSConfig(
            host="reality.com",
            port=443,
            uuid="uuid",
            tls=True,
            reality=True,
            public_key="",
        )
        assert cfg.to_xray_outbound() is None

    def test_ws_transport(self):
        cfg = VLESSConfig(
            host="ws-host.com",
            port=443,
            uuid="uuid",
            tls=True,
            transport="ws",
            ws_path="/v2ray",
            ws_host="ws-host-alt.com",
        )
        out = cfg.to_xray_outbound()
        assert out is not None
        assert out["streamSettings"]["network"] == "ws"
        assert out["streamSettings"]["wsSettings"]["path"] == "/v2ray"
        assert out["streamSettings"]["wsSettings"]["headers"]["Host"] == "ws-host-alt.com"

    def test_grpc_transport(self):
        cfg = VLESSConfig(
            host="grpc.com",
            port=443,
            uuid="uuid",
            tls=True,
            transport="grpc",
            grpc_service_name="test-service",
        )
        out = cfg.to_xray_outbound()
        assert out is not None
        assert out["streamSettings"]["network"] == "grpc"
        assert out["streamSettings"]["grpcSettings"]["serviceName"] == "test-service"

    def test_no_tls_sets_security_none(self):
        """SECURITY: VLESS without TLS/Reality must have security=none.
        This means the config is effectively plaintext — the caller should
        reject it via security_filter.py, but vpn_config should still
        produce a parseable outbound."""
        cfg = VLESSConfig(
            host="plain.com",
            port=80,
            uuid="uuid",
            tls=False,
        )
        out = cfg.to_xray_outbound()
        assert out is not None
        assert out["streamSettings"]["security"] == "none"

    def test_default_remark_empty(self):
        cfg = VLESSConfig(host="h.com", port=80, uuid="u")
        assert cfg.remark == ""


class TestVMessConfig:
    """VMessConfig.to_xray_outbound()"""

    def test_basic_tls_outbound(self):
        cfg = VMessConfig(
            host="vmess.com",
            port=443,
            uuid="uuid-v",
            tls=True,
            sni="vmess-sni.com",
            security="auto",
            alter_id=0,
        )
        out = cfg.to_xray_outbound(tag="vmess-proxy")
        assert out is not None
        assert out["tag"] == "vmess-proxy"
        assert out["protocol"] == "vmess"
        assert out["settings"]["vnext"][0]["users"][0]["security"] == "auto"
        assert out["settings"]["vnext"][0]["users"][0]["alterId"] == 0
        assert out["streamSettings"]["tlsSettings"]["serverName"] == "vmess-sni.com"

    def test_ws_grpc_transport(self):
        cfg = VMessConfig(
            host="vmess-ws.com",
            port=443,
            uuid="uuid",
            tls=True,
            transport="grpc",
            grpc_service_name="vmess-grpc",
        )
        out = cfg.to_xray_outbound()
        assert out is not None
        assert out["streamSettings"]["network"] == "grpc"
        assert out["streamSettings"]["grpcSettings"]["serviceName"] == "vmess-grpc"

    def test_h2_hosts_as_tuple(self):
        cfg = VMessConfig(
            host="vmess-h2.com",
            port=443,
            uuid="uuid",
            tls=True,
            transport="tcp",
            h2_hosts=tuple(),
        )
        out = cfg.to_xray_outbound()
        assert out is not None


class TestTrojanConfig:
    """TrojanConfig.to_xray_outbound()"""

    def test_tls_outbound(self):
        cfg = TrojanConfig(
            host="trojan.com",
            port=443,
            password="pass123",
            tls=True,
            sni="trojan-sni.com",
        )
        out = cfg.to_xray_outbound(tag="trojan-proxy")
        assert out is not None
        assert out["tag"] == "trojan-proxy"
        assert out["protocol"] == "trojan"
        assert out["settings"]["servers"][0]["password"] == "pass123"

    def test_reality_with_public_key(self):
        cfg = TrojanConfig(
            host="trojan-reality.com",
            port=443,
            password="pass",
            tls=True,
            reality=True,
            public_key="trojan-pubkey",
            short_id="abc",
        )
        out = cfg.to_xray_outbound()
        assert out is not None
        assert out["streamSettings"]["realitySettings"]["publicKey"] == "trojan-pubkey"

    def test_reality_without_public_key_returns_none(self):
        """SECURITY: Reality Trojan requires publicKey."""
        cfg = TrojanConfig(
            host="trojan-no-pub.com",
            port=443,
            password="pass",
            tls=True,
            reality=True,
            public_key="",
        )
        assert cfg.to_xray_outbound() is None


class TestShadowsocksConfig:
    """ShadowsocksConfig.to_xray_outbound()"""

    def test_standard_outbound(self):
        cfg = ShadowsocksConfig(
            host="ss.com",
            port=8388,
            method="aes-256-gcm",
            password="pass123",
        )
        out = cfg.to_xray_outbound(tag="ss-proxy")
        assert out is not None
        assert out["tag"] == "ss-proxy"
        assert out["protocol"] == "shadowsocks"
        assert out["settings"]["servers"][0]["method"] == "aes-256-gcm"
        assert out["settings"]["servers"][0]["password"] == "pass123"

    def test_dedup_key_excludes_password(self):
        """Shadowsocks dedup uses method, not password (same server
        with different passwords is the same config for dedup purposes)."""
        cfg1 = ShadowsocksConfig(host="ss.com", port=8388, method="aes-256-gcm", password="p1")
        cfg2 = ShadowsocksConfig(host="ss.com", port=8388, method="aes-256-gcm", password="p2")
        assert cfg1.dedup_key() == cfg2.dedup_key()


class TestHysteria2Config:
    """Hysteria2Config.to_xray_outbound()"""

    def test_basic_outbound(self):
        cfg = Hysteria2Config(
            host="hy2.com",
            port=443,
            auth="secret123",
            sni="hy2-sni.com",
        )
        out = cfg.to_xray_outbound(tag="hy2-proxy")
        assert out is not None
        assert out["tag"] == "hy2-proxy"
        assert out["protocol"] == "hysteria2"
        assert out["settings"]["auth"] == "secret123"
        assert out["settings"]["serverName"] == "hy2-sni.com"

    def test_no_auth_no_secretfield(self):
        """If no auth, the field should not be in the settings dict
        (the HY2 parser only sets it if present)."""
        cfg = Hysteria2Config(host="hy2.com", port=443, auth="")
        out = cfg.to_xray_outbound()
        assert "auth" not in out["settings"]


class TestSecurityEdgeCases:
    """Security-related edge cases in the dataclass layer."""

    def test_vless_with_ws_path_defaults_to_slash(self):
        """WS without explicit path defaults to '/'."""
        cfg = VLESSConfig(
            host="ws.com",
            port=443,
            uuid="uuid",
            tls=True,
            transport="ws",
            ws_path="",
        )
        out = cfg.to_xray_outbound()
        assert out["streamSettings"]["wsSettings"]["path"] == "/"

    def test_vmess_invalid_base64_returns_none(self):
        """parse_url for vmess with garbage in base64 should return None."""
        cfg = parse_url("vmess://!!!not-base64!!!")
        assert cfg is None

    def test_vmess_non_json_base64_returns_none(self):
        """parse_url for vmess with non-JSON decoded payload returns None."""
        payload = base64.b64encode(b"not-json-at-all").decode()
        cfg = parse_url(f"vmess://{payload}")
        assert cfg is None

    def test_shadowsocks_with_weak_cipher_returns_none_from_parse(self):
        """SECURITY: parse_url shadowsocks with weak cipher should
        return None (weak ciphers are rejected in _parse_shadowsocks)."""
        assert parse_url("ss://cmM0LW1kNTpwYXNz@ss.com:8388") is None  # rc4-md5

    def test_shadowsocks_with_empty_password_returns_none_from_parse(self):
        """SECURITY: parse_url shadowsocks with empty password should
        return None."""
        assert (
            parse_url("ss://YWVzLTI1Ni1nY206@ss.com:8388") is None
        )  # method:password = aes-256-gcm:

    def test_vless_with_flow_none(self):
        """When flow is empty, the outbound should have flow=None (not empty string)."""
        cfg = VLESSConfig(host="h.com", port=443, uuid="uuid", flow="")
        out = cfg.to_xray_outbound()
        assert out["settings"]["vnext"][0]["users"][0]["flow"] is None

    def test_vless_with_flow_set(self):
        cfg = VLESSConfig(host="h.com", port=443, uuid="uuid", flow="xtls-rprx-vision")
        out = cfg.to_xray_outbound()
        assert out["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
